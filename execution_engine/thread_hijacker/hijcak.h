#pragma once
#include <windows.h>

/*
 * jocky_hijack_thread
 * ====================
 * Injects and executes a payload in a target process by hijacking an
 * existing thread — no new thread created, no CreateRemoteThread call.
 *
 * Steps:
 *   1. Enumerate threads belonging to target_pid
 *   2. Open and suspend one thread
 *   3. Save full CONTEXT (all GPRs + RIP)
 *   4. Write payload + restore stub into remote RWX allocation
 *   5. Redirect RIP to stub; stub calls payload then restores context
 *   6. Resume thread; wait for stub to finish; thread continues normally
 *
 * Parameters:
 *   target_pid    — PID of the target process (must already be running)
 *   payload_bytes — position-independent shellcode; must end with ret
 *   payload_size  — byte count of payload
 *
 * Returns TRUE on success; FALSE on failure (GetLastError for detail).
 *
 * The hijacked thread resumes its original execution after payload returns.
 * Payload must be position-independent and must not corrupt the stack
 * beyond its own frame (must balance push/pop and return cleanly).
 */
BOOL jocky_hijack_thread(
    DWORD  target_pid,
    LPBYTE payload_bytes,
    DWORD  payload_size
);