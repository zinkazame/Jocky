/*
 * forensics.h — DORM Forensic Primitives — Unified Header
 * execution_engine/forensics/forensics.h
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Umbrella header for all 5 forensic collectors.
 * Include this in any translation unit that calls into the forensics suite.
 *
 * Collector map:
 *   Phase 13.1  proc_analysis.h   — process list, modules, hollow detection
 *   Phase 13.2  mem_acquire.h     — VAD walk, region read, physical ranges
 *   Phase 13.3  net_state.h       — TCP/UDP tables, DNS cache
 *   Phase 13.4  reg_walk.h        — NtEnumerateKey hive walker
 *   Phase 13.5  fs_analysis.h     — MFT reader, ADS detection, prefetch
 */

#pragma once
#include <windows.h>

#define DORM_FORENSICS_VERSION  "1.0.0"
#define DORM_FORENSICS_PHASE    13

/* available now */
#include "proc_analysis.h"

/* stubs — added each sub-phase */
#include "mem_acquire.h" 
#include "net_state.h"    
#include "reg_walk.h"
#include "fs_analysis.h" 