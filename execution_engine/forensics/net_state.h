/*
 * net_state.h — DORM Phase 13.3: Network State Collector
 * execution_engine/forensics/net_state.h
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Collects:
 *   TCP connections  IPv4 + IPv6, with owning PID + process name + state
 *   UDP endpoints    IPv4 + IPv6, with owning PID + process name
 *   DNS cache        via DnsGetCacheDataTable (dnsapi.dll, dynamic resolve)
 *   Suspicious flags known-bad remote ports, external IPs on unusual procs
 *
 * Link: -liphlpapi -lkernel32
 * Note: dnsapi.dll loaded at runtime via LoadLibrary — no link-time dep.
 */
#pragma once
#include <windows.h>

/*
 * dorm_enum_connections
 * =====================
 * Enumerates all TCP (v4 + v6) and UDP (v4 + v6) endpoints via
 * GetExtendedTcpTable / GetExtendedUdpTable with TCP_TABLE_OWNER_PID_ALL.
 * Per row: local/remote address+port, TCP state, owning PID + process name,
 * suspicious flag (known-bad port OR external IP on unrecognised process).
 * Writes JSON to output_path (or stdout if "-").
 * Returns total connection+endpoint count, -1 on failure.
 */
int dorm_enum_connections(const char *output_path);

/*
 * dorm_dns_cache
 * ==============
 * Reads the Windows DNS resolver cache via the undocumented but stable
 * DnsGetCacheDataTable export in dnsapi.dll (dynamically resolved).
 * Each entry: name, record type (A/AAAA/CNAME/MX/...).
 * Falls back to an empty list with a diagnostic note on failure.
 * Writes JSON to output_path (or stdout if "-").
 * Returns cache entry count, -1 on failure.
 */
int dorm_dns_cache(const char *output_path);

/*
 * dorm_net_report
 * ===============
 * Convenience wrapper: runs dorm_enum_connections + dorm_dns_cache and
 * writes a combined JSON report to output_path.
 * Returns TRUE on success.
 */
BOOL dorm_net_report(const char *output_path);