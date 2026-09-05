/*
 * ntdll_unhook.h — NTDLL .text Section Restoration (Enhancement 4)
 * execution_engine/ntdll_unhook/ntdll_unhook.h
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * EDR/AV plants inline hooks by overwriting the first 5 bytes of
 * selected Nt* stubs with E9 xx xx xx xx (JMP rel32 → trampoline).
 *
 * unhook_ntdll() reads the clean .text from the on-disk ntdll.dll image
 * and copies it over the live (hooked) copy, restoring every stub.
 *
 * Call order in test_phase12.c:
 *   unhook_ntdll()   ← wipe hooks
 *   sgx_init()       ← now sees clean stubs, extracts real SSNs
 *   jocky_hijack_*   ← thread ops through restored ntdll
 */
#pragma once
#include <windows.h>

BOOL unhook_ntdll(void);