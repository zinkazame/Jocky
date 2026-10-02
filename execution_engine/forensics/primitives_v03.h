/*
 * primitives_v03.h — JOCKY Phase 13.6: v0.3 Primitive Declarations
 * execution_engine/forensics/primitives_v03.h
 *
 * Include via forensics.h — do not include directly.
 */

#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Hash ── */
int JOCKY_hash_memory_region(int pid, long long base, long long size);
int JOCKY_hash_directory(const char *path);

/* ── Dump ── */
int JOCKY_dump_process(int pid);
int JOCKY_dump_registry_hive(const char *hive);
int JOCKY_dump_mft_raw(const char *volume);
int JOCKY_dump_pagefile(void);

/* ── Acquire — process internals ── */
int JOCKY_acquire_loaded_modules(int pid);
int JOCKY_acquire_handles(int pid);
int JOCKY_acquire_tokens(int pid);
int JOCKY_acquire_heap_strings(int pid, int min_len);
int JOCKY_acquire_proc_memory(int pid);
int JOCKY_acquire_drivers(void);

/* ── Acquire — network ── */
int JOCKY_acquire_arp_cache(void);
int JOCKY_acquire_route_table(void);
int JOCKY_acquire_sockets(void);

/* ── Capture ── */
int JOCKY_capture_clipboard(void);
int JOCKY_capture_screen(void);
int JOCKY_capture_keystrokes(int duration);

/* ── Inspect ── */
int JOCKY_inspect_event_log(const char *log_name, int count);
int JOCKY_inspect_file_tree(const char *path, int max_depth);
int JOCKY_inspect_ads(const char *path);
int JOCKY_inspect_named_pipes(void);
int JOCKY_inspect_shares(void);
int JOCKY_inspect_scheduled_tasks(void);
int JOCKY_inspect_usb_history(void);
int JOCKY_inspect_prefetch_history(void);
int JOCKY_inspect_wifi_profiles(void);
int JOCKY_inspect_installed_apps(void);
int JOCKY_inspect_sms(void);
int JOCKY_inspect_call_log(void);
int JOCKY_inspect_location(void);
int JOCKY_inspect_whatsapp_db(void);
int JOCKY_inspect_telegram_db(void);
int JOCKY_inspect_contacts(void);

/* ── List ── */
int JOCKY_list_processes(void);
int JOCKY_list_connections(void);
int JOCKY_list_users(void);
int JOCKY_list_groups(void);
int JOCKY_list_sessions(void);
int JOCKY_list_patches(void);
int JOCKY_list_software(void);
int JOCKY_list_environment(void);
int JOCKY_list_timezone(void);

/* ── Extract ── */
int JOCKY_extract_mft(const char *volume);
int JOCKY_extract_evtx(const char *path);
int JOCKY_extract_prefetch(const char *path);
int JOCKY_extract_lnk(const char *path);
int JOCKY_extract_registry_hive(const char *path);
int JOCKY_extract_memory_strings(const char *dump_path, int min_len);
int JOCKY_extract_browser_history(const char *browser);
int JOCKY_extract_browser_cookies(const char *browser);
int JOCKY_extract_browser_downloads(const char *browser);

#ifdef __cplusplus
}
#endif
