/*
 * mem_acquire.h — DORM Phase 13.2: Memory Acquisition Collector
 * execution_engine/forensics/mem_acquire.h
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Collects:
 *   — Full VAD walk per-process: base, size, state, type, protect, path
 *   — Suspicious region detection: MEM_PRIVATE + PAGE_EXECUTE_* (injection IOC)
 *   — Raw region dump: reads bytes from a specific VA range
 *   — Physical memory range enumeration via NtQuerySystemInformation
 *
 * Requires SeDebugPrivilege for cross-process reads.
 * Link: -lkernel32 -lpsapi
 */

#pragma once
#include <windows.h>

/*
 * dorm_map_vad
 * ============
 * Walks the full virtual address space of target_pid via VirtualQueryEx.
 * Every MEMORY_BASIC_INFORMATION region is emitted as a JSON object.
 * MEM_IMAGE regions include the mapped file path (device → drive resolved).
 * Writes JSON array to output_path (or stdout if "-").
 *
 * Returns region count on success, -1 on failure.
 */
int dorm_map_vad(DWORD target_pid, const char *output_path);

/*
 * dorm_dump_suspicious
 * ====================
 * Scans the VAD of target_pid for injection IOCs:
 *   MEM_PRIVATE + any PAGE_EXECUTE_* protection
 *   MEM_COMMIT  + PAGE_EXECUTE_READWRITE (classic shellcode alloc)
 *
 * For each flagged region:
 *   — Emits JSON metadata (base, size, protect)
 *   — Reads up to dump_cap bytes of raw content
 *   — Hex-encodes first 256 bytes inline in JSON for quick triage
 *   — Writes full raw bytes to <output_dir>\region_<base>.bin if output_dir != NULL
 *
 * Returns suspicious region count, -1 on failure.
 */
int dorm_dump_suspicious(DWORD       target_pid,
                         const char *output_path,
                         const char *output_dir,
                         SIZE_T      dump_cap);

/*
 * dorm_read_region
 * ================
 * Reads exactly `size` bytes from target_pid starting at base_va.
 * Writes raw bytes to output_path (binary mode).
 * Splits across page boundaries safely (partial reads on guard pages).
 *
 * Returns bytes read on success, -1 on failure.
 */
SSIZE_T dorm_read_region(DWORD       target_pid,
                          ULONG_PTR   base_va,
                          SIZE_T      size,
                          const char *output_path);

/*
 * dorm_physical_ranges
 * ====================
 * Enumerates physical memory ranges via
 * NtQuerySystemInformation(SystemPhysicalMemoryInformation).
 * Falls back to GlobalMemoryStatusEx for total/available figures.
 * Writes JSON to output_path (or stdout if "-").
 *
 * Returns range count on success (≥1 even on fallback), -1 on failure.
 */
int dorm_physical_ranges(const char *output_path);