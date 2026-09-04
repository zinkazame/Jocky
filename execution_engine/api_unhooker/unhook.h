#pragma once
#include <windows.h>

/*
 * jocky_unhook_ntdll
 * ==================
 * Restores the clean .text section of the in-process NTDLL from the
 * on-disk copy at C:\Windows\System32\ntdll.dll.
 *
 * Mechanism:
 *   1. Locate in-memory NTDLL via GetModuleHandleW
 *   2. Map on-disk ntdll.dll as SEC_IMAGE read-only
 *   3. Parse PE headers of both copies → find .text section
 *   4. VirtualProtect → memcpy clean bytes → VirtualProtect restore
 *
 * Returns:
 *   TRUE  — unhooking succeeded (or no hooks were present)
 *   FALSE — a Windows API call failed; call GetLastError() for detail
 *
 * Call once at agent startup, before any forensic primitives run.
 * Not re-entrant — do not call from multiple threads simultaneously.
 */
BOOL jocky_unhook_ntdll(void);