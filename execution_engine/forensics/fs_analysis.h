/*
 * fs_analysis.h — JOCKY Phase 13.5: Filesystem Analysis Collector
 * execution_engine/forensics/fs_analysis.h
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Collects:
 *   MFT sample    FSCTL_GET_NTFS_FILE_RECORD → per-file timestamps
 *   Prefetch      C:\Windows\Prefetch\*.pf   → executed program list
 *   ADS           FindFirstStreamW           → alternate data stream detection
 *
 * Link: -lkernel32
 */
#pragma once
#include <windows.h>

/*
 * JOCKY_scan_mft_sample — read first sample_count inodes from volume_letter
 * via FSCTL_GET_NTFS_FILE_RECORD. Parses $STANDARD_INFORMATION and $FILE_NAME
 * attributes for per-file timestamps. Writes JSON to output_path.
 * Returns records emitted, -1 on failure.
 */
int JOCKY_scan_mft_sample(const char *volume_letter,
                          DWORD       sample_count,
                          const char *output_path);

/*
 * JOCKY_enum_prefetch — enumerate C:\Windows\Prefetch\*.pf files.
 * Detects MAM compression (Win10+), decompresses via RtlDecompressBufferEx,
 * extracts executable name and prefetch hash from SCCA header.
 * Writes JSON to output_path. Returns file count, -1 on failure.
 */
int JOCKY_enum_prefetch(const char *output_path);

/*
 * JOCKY_detect_ads — walk scan_root_utf8 (max max_files files, max depth 4)
 * using FindFirstStreamW/FindNextStreamW. Flags any stream != "::$DATA".
 * Writes JSON to output_path. Returns ADS stream count, -1 on failure.
 */
int JOCKY_detect_ads(const char *scan_root_utf8,
                     DWORD       max_files,
                     const char *output_path);

/*
 * JOCKY_fs_report — combined wrapper: MFT + prefetch + ADS.
 * Returns TRUE on full success.
 */
BOOL JOCKY_fs_report(const char *output_path);