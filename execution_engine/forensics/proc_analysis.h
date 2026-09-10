/*
 * proc_analysis.h — DORM Phase 13.1: Process Analysis Collector
 * execution_engine/forensics/proc_analysis.h
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Collects:
 *   — Full process list: PID, PPID, session, image name, thread/handle count
 *   — Per-process thread list: TID, start VA, state, wait reason, priority
 *   — Per-process module list: base, size, name, full path
 *   — Process hollow detection: .text section hash (memory vs disk)
 *
 * All output is JSON, written to a file path or stdout ("-").
 *
 * Requires SeDebugPrivilege for cross-process module + hollow inspection.
 * Link: -lkernel32 -lpsapi
 */

#pragma once
#include <windows.h>

/*
 * dorm_enum_processes
 * ===================
 * Enumerates all running processes and their threads via
 * NtQuerySystemInformation(SystemProcessInformation).
 * Runs hollow detection on each accessible process.
 * Writes JSON to output_path (or stdout if "-").
 *
 * Returns process count on success, -1 on failure.
 */
int dorm_enum_processes(const char *output_path);

/*
 * dorm_enum_modules
 * =================
 * Walks the virtual address space of target_pid via VirtualQueryEx,
 * identifies MEM_IMAGE|MEM_COMMIT regions, resolves file paths via
 * K32GetMappedFileNameW.  Deduplicates on AllocationBase.
 * Writes JSON to output_path (or stdout if "-").
 *
 * Returns module count on success, -1 on failure.
 */
int dorm_enum_modules(DWORD target_pid, const char *output_path);

/*
 * dorm_detect_hollow
 * ==================
 * Checks whether target_pid's main image has been hollowed.
 *
 * Method:
 *   1. Get ImageBaseAddress from PEB via NtQueryInformationProcess.
 *   2. Read PE headers + locate .text section from live process memory.
 *   3. Get on-disk path via K32GetMappedFileNameW.
 *   4. Hash first 4 KB of .text from memory and from the on-disk file.
 *   5. Mismatch → hollowed.
 *
 * Sets *is_hollow on return.
 * Returns TRUE if check completed, FALSE on access/read failure (conservative).
 */
BOOL dorm_detect_hollow(DWORD target_pid, BOOL *is_hollow);

/*
 * dorm_full_process_report
 * ========================
 * Convenience wrapper: runs dorm_enum_processes (which internally
 * calls dorm_detect_hollow on every process) and writes the full
 * JSON report to output_path.
 *
 * Returns TRUE on success.
 */
BOOL dorm_full_process_report(const char *output_path);