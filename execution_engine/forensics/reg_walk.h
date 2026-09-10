/*
 * reg_walk.h — DORM Phase 13.4: Registry Inspection Collector
 * execution_engine/forensics/reg_walk.h
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Collects:
 *   Persistence keys  Run / RunOnce (HKLM + HKCU)
 *   Services          HKLM\SYSTEM\CurrentControlSet\Services → ImagePath + Start
 *   TypedURLs         HKCU\...\Explorer\TypedURLs
 *
 * All NT registry ops via dynamically-resolved NtOpenKey / NtEnumerateKey /
 * NtEnumerateValueKey — no registry.h, no RegOpenKey Win32 wrapper.
 * Link: -lkernel32 -ladvapi32
 */
#pragma once
#include <windows.h>

/*
 * dorm_enum_persistence — walk HKLM + HKCU Run / RunOnce keys.
 * Returns total entry count, -1 on failure.
 */
int dorm_enum_persistence(const char *output_path);

/*
 * dorm_enum_services_reg — enumerate top-level service subkeys,
 * extracting ImagePath + Start type per service.
 * Returns service count, -1 on failure.
 */
int dorm_enum_services_reg(const char *output_path);

/*
 * dorm_enum_typed_urls — read HKCU TypedURLs (browser address-bar history).
 * Returns URL count, -1 on failure.
 */
int dorm_enum_typed_urls(const char *output_path);

/*
 * dorm_reg_report — combined wrapper: calls all three and writes a summary.
 * Returns TRUE on full success.
 */
BOOL dorm_reg_report(const char *output_path);