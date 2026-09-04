/*
 * JOCKY — Phase 11: Thread Hijacking Verification
 * =================================================
 * Spawns notepad.exe, hijacks one of its threads to execute a minimal
 * Sleep(100) payload, then verifies notepad.exe is still running cleanly.
 *
 * Build:
 *   clang execution_engine/thread_hijacker/hijack.c \
 *         execution_engine/thread_hijacker/test_hijack.c \
 *         -o test_hijack.exe -lkernel32
 *
 * Expected output:
 *   JOCKY Phase 11 -- Thread Hijacking Verification
 *   =================================================
 *   Spawning notepad.exe...           ok (pid=NNNN)
 *   Building Sleep(100) payload...    ok (NN bytes)
 *   Hijacking thread in notepad...    [hijack] ...
 *                                     ok
 *   Verifying notepad still alive...  ok (exit code still STILL_ACTIVE)
 *   Terminating notepad...            ok
 *   Phase 11 complete.
 */

#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "hijack.h"

/*
 * Build a minimal x64 Sleep(100) shellcode at runtime.
 *
 * Shellcode does:
 *   sub  rsp, 0x28        ; shadow space (32) + alignment pad (8)
 *   mov  rcx, 100         ; Sleep(100ms)
 *   mov  rax, <Sleep_addr> ; resolved via GetProcAddress
 *   call rax
 *   add  rsp, 0x28
 *   ret
 *
 * Total: 30 bytes.
 * The Sleep address is patched in at runtime.
 */
static DWORD
build_sleep_payload(LPBYTE buf, DWORD buf_size, ULONG_PTR sleep_addr)
{
    BYTE template[] = {
        /* sub rsp, 0x28 */
        0x48, 0x83, 0xEC, 0x28,
        /* mov rcx, 100 (imm64) */
        0x48, 0xC7, 0xC1, 0x64, 0x00, 0x00, 0x00,
        /* mov rax, <sleep_addr> */
        0x48, 0xB8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* placeholder */
        /* call rax */
        0xFF, 0xD0,
        /* add rsp, 0x28 */
        0x48, 0x83, 0xC4, 0x28,
        /* ret */
        0xC3
    };

    DWORD size = (DWORD)sizeof(template);
    if (size > buf_size) return 0;

    memcpy(buf, template, size);
    /* Patch Sleep address at offset 13 */
    memcpy(buf + 13, &sleep_addr, sizeof(ULONG_PTR));
    return size;
}

int main(void)
{
    printf("JOCKY Phase 11 -- Thread Hijacking Verification\n");
    printf("=================================================\n\n");

    /* ── Step 1: spawn notepad.exe ───────────────────────────────────────── */
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
            0,              /* not suspended — needs live threads to hijack */
            NULL, NULL, &si, &pi))
    {
        printf("FAILED error=%lu\n", GetLastError());
        return 1;
    }
    printf("ok (pid=%lu)\n", pi.dwProcessId);

    /* Give notepad a moment to fully initialize its threads */
    Sleep(1000);

    /* ── Step 2: build Sleep(100) payload ────────────────────────────────── */
    printf("Building Sleep(100) payload...    ");
    fflush(stdout);

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    ULONG_PTR sleep_addr = (ULONG_PTR)GetProcAddress(hK32, "Sleep");
    if (!sleep_addr) {
        printf("FAILED -- GetProcAddress(Sleep) error=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    BYTE payload[64];
    DWORD payload_size = build_sleep_payload(payload, sizeof(payload), sleep_addr);
    if (!payload_size) {
        printf("FAILED -- payload buffer too small\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("ok (%lu bytes, Sleep@0x%llX)\n",
           payload_size, (unsigned long long)sleep_addr);

    /* ── Step 3: hijack a thread ─────────────────────────────────────────── */
    printf("Hijacking thread in notepad...    ");
    fflush(stdout);

    BOOL ok = jocky_hijack_thread(pi.dwProcessId, payload, payload_size);
    if (!ok) {
        printf("FAILED error=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    printf("ok\n");

    /* ── Step 4: verify notepad still alive ──────────────────────────────── */
    printf("Verifying notepad still alive...  ");
    fflush(stdout);

    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    if (exit_code != STILL_ACTIVE) {
        printf("FAILED -- notepad exited with code %lu (crashed)\n", exit_code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }
    printf("ok (still running, exit_code=STILL_ACTIVE)\n");

    /* ── Step 5: clean up ────────────────────────────────────────────────── */
    printf("Terminating notepad...            ");
    fflush(stdout);
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    printf("ok\n");

    printf("\nPhase 11 complete.\n");
    return 0;
}