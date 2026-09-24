/*
 * net_state.c — JOCKY Phase 13.3: Network State Collector
 * execution_engine/forensics/net_state.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * GetExtendedTcpTable / GetExtendedUdpTable: double-call pattern —
 *   first call with NULL buf returns required size in *pdwSize,
 *   second call with allocated buf fills the MIB table.
 *
 * Port byte order: MIB rows carry ports in network byte order (big-endian).
 *   net_port() byte-swaps DWORD→WORD without ws2_32 dependency.
 *
 * IPv4 formatting: manual octet extraction, no inet_ntop needed.
 * IPv6 formatting: manual hex pair formatting from UCHAR[16].
 *
 * DNS cache: DnsGetCacheDataTable is undocumented but present in dnsapi.dll
 *   since XP, stable on Windows 10/11.  Dynamic LoadLibrary/GetProcAddress
 *   avoids any link-time dnsapi.dll dependency.  Graceful fallback on failure.
 *
 * Suspicious flag heuristics:
 *   Remote port in known-bad set (Metasploit default, common RAT ports)
 *   OR ESTABLISHED to non-RFC1918/non-loopback with an unrecognised process
 */

#include <stdio.h>        /* FILE, fprintf, fputs, fputc, fopen_s, fclose     */
#include <string.h>       /* strcmp, strncpy, wcsrchr, etc.                   */
#include <time.h>         /* time_t, gmtime, strftime                         */
#define _WINSOCKAPI_      /* suppress winsock.h conflict with windows.h       */
#ifndef AF_INET
#define AF_INET  2        /* IPv4 — IANA-stable constant, avoids winsock2.h   */
#define AF_INET6 23       /* IPv6 — same                                       */
#endif
#include "forensics.h"    /* pulls windows.h + proc_analysis.h + mem_acquire.h */
#include "net_state.h"
#include <iphlpapi.h>     /* GetExtendedTcpTable, GetExtendedUdpTable, MIB_*  */
#include <psapi.h>        /* K32GetProcessImageFileNameW                       */

/* ============================================================
   INTERNAL HELPERS
   ============================================================ */

static void json_escape(FILE *fp, const char *s)
{
    if (!s) { fputs("\"\"", fp); return; }
    fputc('"', fp);
    for (const char *p = s; *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\n': fputs("\\n",  fp); break;
            case '\r': fputs("\\r",  fp); break;
            case '\t': fputs("\\t",  fp); break;
            default:
                if ((unsigned char)*p < 0x20)
                    fprintf(fp, "\\u%04X", (unsigned char)*p);
                else
                    fputc(*p, fp);
        }
    }
    fputc('"', fp);
}

static FILE *open_output(const char *path, const char *mode)
{
    if (!path || strcmp(path, "-") == 0) return stdout;
    FILE *fp = NULL;
    fopen_s(&fp, path, mode);
    return fp;
}

/* IPv4 from network-byte-order DWORD: byte 0 = first octet */
static void fmt_ipv4(DWORD addr, char *buf, int len)
{
    snprintf(buf, len, "%lu.%lu.%lu.%lu",
             (addr >>  0) & 0xFF,
             (addr >>  8) & 0xFF,
             (addr >> 16) & 0xFF,
             (addr >> 24) & 0xFF);
}

/* IPv6 from 16-byte array (big-endian, network order) */
static void fmt_ipv6(const UCHAR *a, char *buf, int len)
{
    snprintf(buf, len,
        "%02X%02X:%02X%02X:%02X%02X:%02X%02X:"
        "%02X%02X:%02X%02X:%02X%02X:%02X%02X",
        a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
        a[8], a[9], a[10],a[11],a[12],a[13],a[14],a[15]);
}

/*
 * net_port — convert MIB port DWORD (network byte order) to host WORD.
 * MIB_TCPROW stores ports as DWORD; only low WORD is meaningful.
 * Network byte order: byte[0]=high, byte[1]=low → swap.
 */
static WORD net_port(DWORD p)
{
    WORD w = (WORD)p;
    return (WORD)(((w & 0xFF) << 8) | ((w >> 8) & 0xFF));
}

/* TCP state → human-readable string */
static const char *tcp_state_str(DWORD s)
{
    switch (s) {
        case  1: return "CLOSED";
        case  2: return "LISTEN";
        case  3: return "SYN_SENT";
        case  4: return "SYN_RECEIVED";
        case  5: return "ESTABLISHED";
        case  6: return "FIN_WAIT_1";
        case  7: return "FIN_WAIT_2";
        case  8: return "CLOSE_WAIT";
        case  9: return "CLOSING";
        case 10: return "LAST_ACK";
        case 11: return "TIME_WAIT";
        case 12: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

/* DNS record type → name */
static const char *dns_type_str(WORD t)
{
    switch (t) {
        case  1: return "A";
        case  2: return "NS";
        case  5: return "CNAME";
        case  6: return "SOA";
        case 12: return "PTR";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 33: return "SRV";
        default: return "UNKNOWN";
    }
}

/* TRUE if IPv4 is RFC1918, loopback, or any-address */
static BOOL is_private_ipv4(DWORD addr)
{
    BYTE b0 = (BYTE)( addr        & 0xFF);
    BYTE b1 = (BYTE)((addr >>  8) & 0xFF);
    if (b0 == 10)  return TRUE;                               /* 10/8     */
    if (b0 == 172 && b1 >= 16 && b1 <= 31) return TRUE;      /* 172.16/12*/
    if (b0 == 192 && b1 == 168) return TRUE;                  /* 192.168/16*/
    if (b0 == 127) return TRUE;                               /* loopback */
    if (addr == 0) return TRUE;                               /* 0.0.0.0  */
    return FALSE;
}

/* TRUE if port is in known-bad / common-C2 set */
static BOOL is_bad_port(WORD port)
{
    static const WORD bad[] = {
        4444,   /* Metasploit default shell */
        1337,   /* common leet backdoor     */
        31337,  /* Back Orifice / elite     */
        8888,   /* common C2 HTTP           */
        9090,   /* common C2 HTTP           */
        4899,   /* Radmin                   */
        5555,   /* ADB / Android RAT        */
        6666,   /* IRC / common malware     */
        7777,   /* common backdoor          */
        1234,   /* common test/backdoor     */
        12345,  /* NetBus                   */
        27374,  /* SubSeven                 */
        65535,  /* common high-port backdoor*/
    };
    for (int i = 0; i < (int)(sizeof(bad)/sizeof(bad[0])); i++)
        if (port == bad[i]) return TRUE;
    return FALSE;
}

/*
 * pid_to_name — resolve process name from PID.
 * K32GetProcessImageFileNameW → extract filename component.
 * Falls back to "<unknown>" on access failure (e.g. PPL-protected).
 */
static void pid_to_name(DWORD pid, char *out, int len)
{
    out[0] = '\0';
    if (pid == 0) { strncpy(out, "Idle",   len - 1); return; }
    if (pid == 4) { strncpy(out, "System", len - 1); return; }

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h) {
        WCHAR path[MAX_PATH] = {0};
        if (K32GetProcessImageFileNameW(h, path, MAX_PATH)) {
            const WCHAR *sep = wcsrchr(path, L'\\');
            WideCharToMultiByte(CP_UTF8, 0,
                                sep ? sep + 1 : path, -1,
                                out, len - 1, NULL, NULL);
        }
        CloseHandle(h);
    }
    if (!out[0]) strncpy(out, "<unknown>", len - 1);
}

/* ============================================================
   CONNECTION ENUMERATION
   ============================================================ */

int JOCKY_enum_connections(const char *output_path)
{
    /* *every socket: a promise made to the network, laid out for inspection* */

    FILE *fp = open_output(output_path, "w");
    if (!fp) return -1;

    time_t     now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char       ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD hlen = sizeof(hostname);
    GetComputerNameA(hostname, &hlen);

    fprintf(fp,
        "{\n"
        "  \"collector\": \"net_state_connections\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"hostname\": \"%s\",\n",
        ts, hostname);

    int  total      = 0;
    int  suspicious = 0;
    BOOL first_row;

    /* ── TCP IPv4 ─────────────────────────────────────────────── */
    fputs("  \"tcp4\": [\n", fp);
    first_row = TRUE;
    {
        DWORD  sz  = 0;
        GetExtendedTcpTable(NULL, &sz, TRUE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0);
        sz += 0x1000;   /* small headroom for race between calls */
        BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);

        if (buf && GetExtendedTcpTable(buf, &sz, TRUE, AF_INET,
                                       TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            MIB_TCPTABLE_OWNER_PID *tbl = (MIB_TCPTABLE_OWNER_PID *)buf;
            for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
                MIB_TCPROW_OWNER_PID *r = &tbl->table[i];

                char la[20] = {0}, ra[20] = {0}, proc[260] = {0};
                fmt_ipv4(r->dwLocalAddr,  la, sizeof(la));
                fmt_ipv4(r->dwRemoteAddr, ra, sizeof(ra));
                WORD lp = net_port(r->dwLocalPort);
                WORD rp = net_port(r->dwRemotePort);
                pid_to_name(r->dwOwningPid, proc, sizeof(proc));

                BOOL sus = is_bad_port(rp)
                        || (r->dwState == 5          /* ESTABLISHED */
                            && !is_private_ipv4(r->dwRemoteAddr)
                            && r->dwRemoteAddr != 0
                            && is_bad_port(lp));
                if (sus) suspicious++;

                if (!first_row) fputs(",\n", fp);
                first_row = FALSE;

                fprintf(fp,
                    "    {\"local\":\"%s\",\"lport\":%u,"
                    "\"remote\":\"%s\",\"rport\":%u,"
                    "\"state\":\"%s\",\"pid\":%lu,\"process\":",
                    la, lp, ra, rp,
                    tcp_state_str(r->dwState), r->dwOwningPid);
                json_escape(fp, proc);
                fprintf(fp, ",\"suspicious\":%s}", sus ? "true" : "false");
                total++;
            }
        }
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
    }
    fputs("\n  ],\n", fp);

    /* ── TCP IPv6 ─────────────────────────────────────────────── */
    fputs("  \"tcp6\": [\n", fp);
    first_row = TRUE;
    {
        DWORD  sz = 0;
        GetExtendedTcpTable(NULL, &sz, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_ALL, 0);
        sz += 0x1000;
        BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);

        if (buf && GetExtendedTcpTable(buf, &sz, FALSE, AF_INET6,
                                       TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            MIB_TCP6TABLE_OWNER_PID *tbl = (MIB_TCP6TABLE_OWNER_PID *)buf;
            for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
                MIB_TCP6ROW_OWNER_PID *r = &tbl->table[i];

                char la[48] = {0}, ra[48] = {0}, proc[260] = {0};
                fmt_ipv6(r->ucLocalAddr,  la, sizeof(la));
                fmt_ipv6(r->ucRemoteAddr, ra, sizeof(ra));
                WORD lp = net_port(r->dwLocalPort);
                WORD rp = net_port(r->dwRemotePort);
                pid_to_name(r->dwOwningPid, proc, sizeof(proc));

                BOOL sus = is_bad_port(rp) || is_bad_port(lp);
                if (sus) suspicious++;

                if (!first_row) fputs(",\n", fp);
                first_row = FALSE;

                fprintf(fp,
                    "    {\"local\":\"%s\",\"lport\":%u,"
                    "\"remote\":\"%s\",\"rport\":%u,"
                    "\"state\":\"%s\",\"pid\":%lu,\"process\":",
                    la, lp, ra, rp,
                    tcp_state_str(r->dwState), r->dwOwningPid);
                json_escape(fp, proc);
                fprintf(fp, ",\"suspicious\":%s}", sus ? "true" : "false");
                total++;
            }
        }
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
    }
    fputs("\n  ],\n", fp);

    /* ── UDP IPv4 ─────────────────────────────────────────────── */
    fputs("  \"udp4\": [\n", fp);
    first_row = TRUE;
    {
        DWORD  sz = 0;
        GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0);
        sz += 0x1000;
        BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);

        if (buf && GetExtendedUdpTable(buf, &sz, FALSE, AF_INET,
                                       UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
        {
            MIB_UDPTABLE_OWNER_PID *tbl = (MIB_UDPTABLE_OWNER_PID *)buf;
            for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
                MIB_UDPROW_OWNER_PID *r = &tbl->table[i];

                char la[20] = {0}, proc[260] = {0};
                fmt_ipv4(r->dwLocalAddr, la, sizeof(la));
                WORD lp = net_port(r->dwLocalPort);
                pid_to_name(r->dwOwningPid, proc, sizeof(proc));

                BOOL sus = is_bad_port(lp);
                if (sus) suspicious++;

                if (!first_row) fputs(",\n", fp);
                first_row = FALSE;

                fprintf(fp,
                    "    {\"local\":\"%s\",\"lport\":%u,"
                    "\"pid\":%lu,\"process\":",
                    la, lp, r->dwOwningPid);
                json_escape(fp, proc);
                fprintf(fp, ",\"suspicious\":%s}", sus ? "true" : "false");
                total++;
            }
        }
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
    }
    fputs("\n  ],\n", fp);

    /* ── UDP IPv6 ─────────────────────────────────────────────── */
    fputs("  \"udp6\": [\n", fp);
    first_row = TRUE;
    {
        DWORD  sz = 0;
        GetExtendedUdpTable(NULL, &sz, FALSE, AF_INET6,
                            UDP_TABLE_OWNER_PID, 0);
        sz += 0x1000;
        BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);

        if (buf && GetExtendedUdpTable(buf, &sz, FALSE, AF_INET6,
                                       UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
        {
            MIB_UDP6TABLE_OWNER_PID *tbl = (MIB_UDP6TABLE_OWNER_PID *)buf;
            for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
                MIB_UDP6ROW_OWNER_PID *r = &tbl->table[i];

                char la[48] = {0}, proc[260] = {0};
                fmt_ipv6(r->ucLocalAddr, la, sizeof(la));
                WORD lp = net_port(r->dwLocalPort);
                pid_to_name(r->dwOwningPid, proc, sizeof(proc));

                BOOL sus = is_bad_port(lp);
                if (sus) suspicious++;

                if (!first_row) fputs(",\n", fp);
                first_row = FALSE;

                fprintf(fp,
                    "    {\"local\":\"%s\",\"lport\":%u,"
                    "\"pid\":%lu,\"process\":",
                    la, lp, r->dwOwningPid);
                json_escape(fp, proc);
                fprintf(fp, ",\"suspicious\":%s}", sus ? "true" : "false");
                total++;
            }
        }
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
    }
    fputs("\n  ],\n", fp);

    fprintf(fp,
        "  \"summary\": {\n"
        "    \"total_endpoints\": %d,\n"
        "    \"suspicious_count\": %d\n"
        "  }\n"
        "}\n",
        total, suspicious);

    if (fp != stdout) fclose(fp);
    return total;
}

/* ============================================================
   DNS CACHE
   ============================================================ */

/*
 * JOCKY_DNS_CACHE_ENTRY — mirrors the undocumented DNS_CACHE_ENTRY
 * structure from dnsapi.dll.  Stable since Windows XP; present on
 * Windows 10 / 11.  Layout verified against public reverse-engineering.
 */
typedef struct _JOCKY_DNS_CACHE_ENTRY {
    struct _JOCKY_DNS_CACHE_ENTRY *pNext;
    PWSTR  pszName;
    WORD   wType;
    WORD   wDataLength;
    DWORD  dwFlags;
} JOCKY_DNS_CACHE_ENTRY;

typedef BOOL (WINAPI *DnsGetCacheDataTable_t)(JOCKY_DNS_CACHE_ENTRY **);

int JOCKY_dns_cache(const char *output_path)
{
    FILE *fp = open_output(output_path, "w");
    if (!fp) return -1;

    time_t     now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char       ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    fprintf(fp,
        "{\n"
        "  \"collector\": \"net_state_dns_cache\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"entries\": [\n", ts);

    int count = 0;

    HMODULE hDns = LoadLibraryA("dnsapi.dll");
    if (!hDns) {
        fputs("  ],\n"
              "  \"note\": \"dnsapi.dll load failed\",\n"
              "  \"count\": 0\n}\n", fp);
        if (fp != stdout) fclose(fp);
        return 0;
    }

    DnsGetCacheDataTable_t pfn =
        (DnsGetCacheDataTable_t)GetProcAddress(hDns, "DnsGetCacheDataTable");

    if (!pfn) {
        FreeLibrary(hDns);
        fputs("  ],\n"
              "  \"note\": \"DnsGetCacheDataTable not found in dnsapi.dll\",\n"
              "  \"count\": 0\n}\n", fp);
        if (fp != stdout) fclose(fp);
        return 0;
    }

    JOCKY_DNS_CACHE_ENTRY *head = NULL;
    BOOL first = TRUE;

    if (pfn(&head) && head) {
        for (JOCKY_DNS_CACHE_ENTRY *e = head; e; e = e->pNext) {
            char name_utf8[512] = {0};
            if (e->pszName)
                WideCharToMultiByte(CP_UTF8, 0, e->pszName, -1,
                                    name_utf8, sizeof(name_utf8) - 1,
                                    NULL, NULL);

            if (!first) fputs(",\n", fp);
            first = FALSE;

            fprintf(fp, "    {\"name\":");
            json_escape(fp, name_utf8);
            fprintf(fp, ",\"type\":\"%s\",\"type_id\":%u}",
                    dns_type_str(e->wType), e->wType);
            count++;
        }
    } else {
        printf("[net] DnsGetCacheDataTable returned no entries "
               "(DNS client may be disabled)\n");
    }

    FreeLibrary(hDns);

    fprintf(fp,
        "\n  ],\n"
        "  \"count\": %d\n"
        "}\n", count);

    if (fp != stdout) fclose(fp);
    return count;
}

/* ============================================================
   COMBINED REPORT
   ============================================================ */

BOOL JOCKY_net_report(const char *output_path)
{
    FILE *fp = open_output(output_path, "w");
    if (!fp) return FALSE;

    time_t     now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char       ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD hlen = sizeof(hostname);
    GetComputerNameA(hostname, &hlen);

    fprintf(fp,
        "{\n"
        "  \"collector\": \"net_state_full\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"hostname\": \"%s\",\n"
        "  \"connections\": \"connections.json\",\n"
        "  \"dns_cache\":   \"dns_cache.json\"\n"
        "}\n",
        ts, hostname);

    if (fp != stdout) fclose(fp);

    int conn = JOCKY_enum_connections("connections.json");
    int dns  = JOCKY_dns_cache("dns_cache.json");

    printf("[net] connections: %d  dns_entries: %d\n", conn, dns);
    return (conn >= 0 && dns >= 0);
}