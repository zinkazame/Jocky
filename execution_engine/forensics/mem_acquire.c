/*
 * mem_acquire.c — JOCKY Phase 13.2: Memory Acquisition Collector
 * execution_engine/forensics/mem_acquire.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * VAD walk: VirtualQueryEx loop, page-aligned region coalescing.
 *   MEM_IMAGE → K32GetMappedFileNameW → device_to_drive_path.
 *   Protection flags decoded to human-readable string for JSON.
 *
 * Suspicious region detection:
 *   Private + executable = classic shellcode / reflective injection IOC.
 *   First 256 bytes hex-encoded inline; full raw dump to .bin on request.
 *
 * Raw region read: page-by-page loop so a single guard page doesn't
 *   abort the entire acquisition — partial reads preserved.
 *
 * Physical ranges: NtQuerySystemInformation(0x86 SystemPhysicalMemoryInformation)
 *   returns PHYSICAL_MEMORY_DESCRIPTOR with Run[] array (base PFN + page count).
 *   Multiply by PAGE_SIZE (4096) for byte addresses.
 */

#include "forensics.h"
#include "mem_acquire.h"
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ============================================================
   NT INTERNALS
   ============================================================ */

typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

/*
 * PHYSICAL_MEMORY_DESCRIPTOR — undocumented, verified against WDK.
 * NtQuerySystemInformation class 0x86 (SystemPhysicalMemoryInformation).
 */
typedef struct {
    ULONG NumberOfRuns;
    ULONG_PTR NumberOfPages;
    struct {
        ULONG_PTR BasePage;   /* first PFN of run */
        ULONG_PTR PageCount;  /* pages in run     */
    } Run[1];
} JOCKY_PHYS_MEM_DESC;

/* ============================================================
   INTERNAL HELPERS (shared with proc_analysis)
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

/*
 * device_to_drive_path — \Device\HarddiskVolumeN\... → C:\...
 */
static BOOL device_to_drive_path(const WCHAR *dev, WCHAR *out, int out_len)
{
    WCHAR drives[512] = {0};
    if (!GetLogicalDriveStringsW((DWORD)(sizeof(drives)/2) - 1, drives))
        return FALSE;
    for (WCHAR *d = drives; *d; d += wcslen(d) + 1) {
        WCHAR letter[3]  = { d[0], d[1], 0 };
        WCHAR device[MAX_PATH] = {0};
        if (!QueryDosDeviceW(letter, device, MAX_PATH)) continue;
        size_t dl = wcslen(device);
        if (_wcsnicmp(dev, device, dl) == 0) {
            _snwprintf(out, out_len, L"%s%s", letter, dev + dl);
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * protect_str — decode MEMORY_BASIC_INFORMATION.Protect into a short label.
 */
static const char *protect_str(DWORD p)
{
    /* strip modifier flags first */
    DWORD base = p & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
    switch (base) {
        case PAGE_NOACCESS:          return "NOACCESS";
        case PAGE_READONLY:          return "READONLY";
        case PAGE_READWRITE:         return "READWRITE";
        case PAGE_WRITECOPY:         return "WRITECOPY";
        case PAGE_EXECUTE:           return "EXECUTE";
        case PAGE_EXECUTE_READ:      return "EXECUTE_READ";
        case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
        case PAGE_EXECUTE_WRITECOPY: return "EXECUTE_WRITECOPY";
        default:                     return "UNKNOWN";
    }
}

/*
 * type_str — MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
 */
static const char *type_str(DWORD t)
{
    if (t == MEM_IMAGE)   return "IMAGE";
    if (t == MEM_MAPPED)  return "MAPPED";
    if (t == MEM_PRIVATE) return "PRIVATE";
    return "UNKNOWN";
}

/*
 * state_str — MEM_COMMIT / MEM_RESERVE / MEM_FREE
 */
static const char *state_str(DWORD s)
{
    if (s == MEM_COMMIT)  return "COMMIT";
    if (s == MEM_RESERVE) return "RESERVE";
    if (s == MEM_FREE)    return "FREE";
    return "UNKNOWN";
}

/*
 * is_executable — TRUE if any execute bit is set in protect flags.
 */
static BOOL is_executable(DWORD p)
{
    DWORD exec_mask = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (p & exec_mask) != 0;
}

/* ============================================================
   VAD WALK
   ============================================================ */

int JOCKY_map_vad(DWORD pid, const char *output_path)
{
    /* *the VAD: every promise the allocator ever made, laid out in address order* */

    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return -1;

    FILE *fp = open_output(output_path, "w");
    if (!fp) { CloseHandle(hProc); return -1; }

    /* ── header ── */
    time_t     now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char       ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    fprintf(fp,
        "{\n"
        "  \"collector\": \"mem_acquire_vad\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"pid\": %lu,\n"
        "  \"regions\": [\n",
        ts, pid);

    int    count = 0;
    PVOID  addr  = NULL;
    BOOL   first = TRUE;
    MEMORY_BASIC_INFORMATION mbi = {0};

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {

        /* ── skip FREE regions for brevity; they carry no forensic value ── */
        if (mbi.State != MEM_FREE) {

            /* resolve mapped file if IMAGE or MAPPED */
            char utf8_path[MAX_PATH * 3] = {0};
            if ((mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED)
                && mbi.State == MEM_COMMIT)
            {
                WCHAR dev_path[MAX_PATH] = {0};
                WCHAR drv_path[MAX_PATH] = {0};
                if (K32GetMappedFileNameW(hProc, mbi.BaseAddress,
                                          dev_path, MAX_PATH)) {
                    if (!device_to_drive_path(dev_path, drv_path, MAX_PATH))
                        wcscpy_s(drv_path, MAX_PATH, dev_path);
                    WideCharToMultiByte(CP_UTF8, 0, drv_path, -1,
                                        utf8_path, sizeof(utf8_path)-1, NULL, NULL);
                }
            }

            BOOL suspicious = (mbi.Type    == MEM_PRIVATE)
                           && (mbi.State   == MEM_COMMIT)
                           && is_executable(mbi.Protect);

            if (!first) fputs(",\n", fp);
            first = FALSE;

            fprintf(fp,
                "    {"
                "\"base\":\"0x%016llX\","
                "\"size\":%zu,"
                "\"state\":\"%s\","
                "\"type\":\"%s\","
                "\"protect\":\"%s\","
                "\"suspicious\":%s,"
                "\"path\":",
                (unsigned long long)(ULONG_PTR)mbi.BaseAddress,
                mbi.RegionSize,
                state_str(mbi.State),
                type_str(mbi.Type),
                protect_str(mbi.Protect),
                suspicious ? "true" : "false");
            json_escape(fp, utf8_path[0] ? utf8_path : NULL);
            fputc('}', fp);

            count++;
        }

        PVOID next = (BYTE *)addr + (mbi.RegionSize ? mbi.RegionSize : 0x1000);
        if (next <= addr) break;
        addr = next;
    }

    fprintf(fp, "\n  ],\n  \"region_count\": %d\n}\n", count);
    if (fp != stdout) fclose(fp);
    CloseHandle(hProc);
    return count;
}

/* ============================================================
   SUSPICIOUS REGION DUMP
   ============================================================ */

int JOCKY_dump_suspicious(DWORD       pid,
                          const char *output_path,
                          const char *output_dir,
                          SIZE_T      dump_cap)
{
    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return -1;

    FILE *fp = open_output(output_path, "w");
    if (!fp) { CloseHandle(hProc); return -1; }

    time_t     now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char       ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    fprintf(fp,
        "{\n"
        "  \"collector\": \"mem_acquire_suspicious\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"pid\": %lu,\n"
        "  \"ioc_regions\": [\n",
        ts, pid);

    int    count = 0;
    BOOL   first = TRUE;
    PVOID  addr  = NULL;
    MEMORY_BASIC_INFORMATION mbi = {0};

    /* hex alphabet for inline preview */
    static const char hex[] = "0123456789ABCDEF";

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {

        BOOL suspicious = (mbi.Type  == MEM_PRIVATE)
                       && (mbi.State == MEM_COMMIT)
                       && is_executable(mbi.Protect);

        if (suspicious) {
            /* cap dump size */
            SIZE_T cap = mbi.RegionSize < dump_cap ? mbi.RegionSize : dump_cap;
            BYTE  *raw = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cap);
            SIZE_T nread = 0;

            if (raw)
                ReadProcessMemory(hProc, mbi.BaseAddress, raw, cap, &nread);

            /* hex-preview: first 256 bytes max */
            SIZE_T preview_len = nread < 256 ? nread : 256;
            char   hex_preview[513] = {0};
            for (SIZE_T i = 0; i < preview_len; i++) {
                hex_preview[i*2]   = hex[(raw[i] >> 4) & 0xF];
                hex_preview[i*2+1] = hex[ raw[i]       & 0xF];
            }
            hex_preview[preview_len * 2] = '\0';

            if (!first) fputs(",\n", fp);
            first = FALSE;

            fprintf(fp,
                "    {\n"
                "      \"base\":\"0x%016llX\",\n"
                "      \"size\":%zu,\n"
                "      \"protect\":\"%s\",\n"
                "      \"bytes_read\":%zu,\n"
                "      \"hex_preview\":\"%s\"",
                (unsigned long long)(ULONG_PTR)mbi.BaseAddress,
                mbi.RegionSize,
                protect_str(mbi.Protect),
                nread,
                hex_preview);

            /* optional .bin dump */
            if (output_dir && raw && nread > 0) {
                char bin_path[MAX_PATH] = {0};
                snprintf(bin_path, sizeof(bin_path) - 1,
                         "%s\\region_0x%016llX.bin",
                         output_dir,
                         (unsigned long long)(ULONG_PTR)mbi.BaseAddress);

                FILE *bf = NULL;
                if (fopen_s(&bf, bin_path, "wb") == 0 && bf) {
                    fwrite(raw, 1, nread, bf);
                    fclose(bf);
                    fprintf(fp, ",\n      \"bin_path\":");
                    json_escape(fp, bin_path);
                }
            }

            fputs("\n    }", fp);
            if (raw) HeapFree(GetProcessHeap(), 0, raw);
            count++;
        }

        PVOID next = (BYTE *)addr + (mbi.RegionSize ? mbi.RegionSize : 0x1000);
        if (next <= addr) break;
        addr = next;
    }

    fprintf(fp, "\n  ],\n  \"suspicious_count\": %d\n}\n", count);
    if (fp != stdout) fclose(fp);
    CloseHandle(hProc);
    return count;
}

/* ============================================================
   RAW REGION READ
   ============================================================ */

SSIZE_T JOCKY_read_region(DWORD       pid,
                          ULONG_PTR   base_va,
                          SIZE_T      size,
                          const char *output_path)
{
    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                               FALSE, pid);
    if (!hProc) return -1;

    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!buf) { CloseHandle(hProc); return -1; }

    /* page-by-page read — guard pages don't abort the whole acquisition */
    DWORD    page_size = 0x1000;
    SIZE_T   total_rd  = 0;
    ULONG_PTR cur      = base_va;
    SIZE_T   remaining = size;

    while (remaining > 0) {
        SIZE_T   chunk = remaining < page_size ? remaining : page_size;
        SIZE_T   rd    = 0;

        ReadProcessMemory(hProc, (PVOID)cur, buf + total_rd, chunk, &rd);
        /* rd == 0 on guard page — buf already zeroed, advance anyway */
        total_rd  += chunk;
        cur       += chunk;
        remaining -= chunk;
    }

    SSIZE_T result = -1;
    FILE   *fp     = open_output(output_path, "wb");
    if (fp) {
        fwrite(buf, 1, total_rd, fp);
        if (fp != stdout) fclose(fp);
        result = (SSIZE_T)total_rd;
    }

    HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(hProc);
    return result;
}

/* ============================================================
   PHYSICAL MEMORY RANGES
   ============================================================ */

int JOCKY_physical_ranges(const char *output_path)
{
    /* *physical memory: the one map the OS can't lie about* */

    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
                        GetModuleHandleA("ntdll.dll"),
                        "NtQuerySystemInformation");
    if (!NtQSI) return -1;

    FILE *fp = open_output(output_path, "w");
    if (!fp) return -1;

    time_t     now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char       ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    /* ── GlobalMemoryStatusEx: total + available figures ── */
    MEMORYSTATUSEX ms = { .dwLength = sizeof(ms) };
    GlobalMemoryStatusEx(&ms);

    fprintf(fp,
        "{\n"
        "  \"collector\": \"mem_acquire_physical\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"total_physical_bytes\": %llu,\n"
        "  \"available_physical_bytes\": %llu,\n"
        "  \"load_percent\": %lu,\n",
        ts,
        (unsigned long long)ms.ullTotalPhys,
        (unsigned long long)ms.ullAvailPhys,
        ms.dwMemoryLoad);

    /* ── physical runs via NtQuerySystemInformation(0x86) ── */
    ULONG    buf_sz = sizeof(JOCKY_PHYS_MEM_DESC) + 256 * sizeof(ULONG_PTR) * 2;
    BYTE    *buf    = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_sz);

    int      range_count = 0;
    NTSTATUS nt = STATUS_INFO_LENGTH_MISMATCH;

    if (buf) {
        int max_iters = 24;   /* guard: exit after 24 tries regardless */
        do {
            HeapFree(GetProcessHeap(), 0, buf);
            buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_sz);
            if (!buf) break;
            ULONG needed = 0;
            nt = NtQSI(0x86 /*SystemPhysicalMemoryInformation*/,
                       buf, buf_sz, &needed);
            /*
             * needed == 0 means the kernel didn't tell us how much space it
             * wants — clamp to a sane floor so buf_sz keeps growing and
             * eventually either succeeds or the iter cap fires.
             */
            buf_sz = (needed > buf_sz ? needed : buf_sz) + 0x1000;
        } while (nt == STATUS_INFO_LENGTH_MISMATCH && --max_iters > 0);

        if (max_iters == 0) {
            /* 0x86 not accessible from user mode on this build — use fallback */
            nt = (NTSTATUS)0xC0000003L;   /* STATUS_INVALID_INFO_CLASS sentinel */
        }
    }

    if (buf && nt == STATUS_SUCCESS) {
        JOCKY_PHYS_MEM_DESC *pmd = (JOCKY_PHYS_MEM_DESC *)buf;
        fprintf(fp,
            "  \"physical_page_count\": %zu,\n"
            "  \"physical_ranges\": [\n",
            (size_t)pmd->NumberOfPages);

        for (ULONG i = 0; i < pmd->NumberOfRuns; i++) {
            ULONG_PTR base_pa  = pmd->Run[i].BasePage  * 0x1000;
            ULONG_PTR size_pa  = pmd->Run[i].PageCount * 0x1000;
            fprintf(fp,
                "%s    {\"base_pa\":\"0x%016llX\",\"size_bytes\":%llu,\"pages\":%llu}",
                i ? ",\n" : "",
                (unsigned long long)base_pa,
                (unsigned long long)size_pa,
                (unsigned long long)pmd->Run[i].PageCount);
            range_count++;
        }

        fputs("\n  ]\n}\n", fp);
        HeapFree(GetProcessHeap(), 0, buf);
    } else {
        /* ── fallback: no run-level data, just totals ── */
        if (buf) HeapFree(GetProcessHeap(), 0, buf);
        fputs("  \"physical_ranges\": [],\n"
              "  \"note\": \"NtQuerySystemInformation(0x86) not available\"\n"
              "}\n", fp);
        range_count = 0;
    }

    if (fp != stdout) fclose(fp);
    return range_count >= 0 ? range_count : 1;   /* 1 = fallback path */
}