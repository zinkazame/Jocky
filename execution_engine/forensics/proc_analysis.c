/*
 * proc_analysis.c — DORM Phase 13.1: Process Analysis Collector
 * execution_engine/forensics/proc_analysis.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * NtQuerySystemInformation(SystemProcessInformation) — same kernel call
 * proven in hijack.c, used here for forensic enumeration instead of
 * thread-scoring.  Every offset is byte-verified against the WDK layout.
 *
 * Module walk: VirtualQueryEx loop over target PID's address space.
 *   MEM_IMAGE | MEM_COMMIT regions → mapped PE sections.
 *   K32GetMappedFileNameW resolves device path → QueryDosDeviceW converts
 *   \Device\HarddiskVolumeN\ prefix to drive letter.
 *
 * Hollow detection: PEB→ImageBaseAddress → .text hash (djb2, 4 KB cap)
 *   vs on-disk .text hash.  Conservative: FALSE on any read failure.
 *
 * JSON output: hand-written fprintf, no external serialiser.
 */

#include "forensics.h"     /* pulls proc_analysis.h + DORM_FORENSICS_VERSION */
#include <psapi.h>         /* K32GetMappedFileNameW                           */
#include <stdio.h>
#include <string.h>
#include <time.h>

/* ============================================================
   NT INTERNALS — DYNAMIC RESOLUTION
   ============================================================ */

typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

/* ── SYSTEM_PROCESS_INFORMATION offsets (x64, verified) ── */
#define SYSPI_OFF_NEXT      0x000   /* ULONG  NextEntryOffset         */
#define SYSPI_OFF_NTHRD     0x004   /* ULONG  NumberOfThreads         */
#define SYSPI_OFF_IMGLEN    0x038   /* USHORT ImageName.Length        */
#define SYSPI_OFF_IMGBUF    0x040   /* PWSTR  ImageName.Buffer        */
#define SYSPI_OFF_PID       0x050   /* HANDLE UniqueProcessId         */
#define SYSPI_OFF_PPID      0x058   /* HANDLE InheritedFromProcessId  */
#define SYSPI_OFF_HANDLES   0x060   /* ULONG  HandleCount             */
#define SYSPI_OFF_SESSION   0x064   /* ULONG  SessionId               */
#define SYSPI_OFF_THREADS   0x100   /* SYSTEM_THREAD_INFORMATION[0]   */

/* ── SYSTEM_THREAD_INFORMATION offsets (80 bytes, verified) ── */
#define SYSTI_SIZE          80
#define SYSTI_OFF_START     0x020   /* PVOID  StartAddress            */
#define SYSTI_OFF_TID       0x030   /* HANDLE ClientId.UniqueThread   */
#define SYSTI_OFF_PRIORITY  0x038   /* LONG   Priority                */
#define SYSTI_OFF_STATE     0x044   /* ULONG  ThreadState             */
#define SYSTI_OFF_REASON    0x048   /* ULONG  WaitReason              */

/* ── PROCESS_BASIC_INFORMATION + PEB offsets (x64) ── */
#define PBI_OFF_PEB         0x008   /* PebBaseAddress in PBI struct   */
#define PEB_OFF_IMAGEBASE   0x010   /* ImageBaseAddress in PEB        */

/* ============================================================
   INTERNAL HELPERS
   ============================================================ */

/*
 * wcs_to_utf8 — convert PWSTR (explicit char count) to NUL-terminated
 * UTF-8 in out[0..out_len-1].
 */
static BOOL wcs_to_utf8(PCWSTR wcs, int char_count, char *out, int out_len)
{
    if (!wcs || char_count <= 0) { out[0] = '\0'; return TRUE; }
    int r = WideCharToMultiByte(CP_UTF8, 0, wcs, char_count,
                                out, out_len - 1, NULL, NULL);
    out[r > 0 ? r : 0] = '\0';
    return r > 0;
}

/*
 * json_escape — write a C string to fp with JSON escaping.
 * Wraps the output in double-quotes.
 */
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

/*
 * device_to_drive_path — convert \Device\HarddiskVolumeN\path to C:\path.
 * Returns TRUE if conversion succeeded; drive_path unchanged on failure.
 */
static BOOL device_to_drive_path(const WCHAR *device_path,
                                  WCHAR       *drive_path,
                                  int          drive_path_len)
{
    WCHAR drives[512] = {0};
    if (!GetLogicalDriveStringsW((DWORD)(sizeof(drives)/sizeof(WCHAR)) - 1, drives))
        return FALSE;

    for (WCHAR *d = drives; *d; d += wcslen(d) + 1) {
        WCHAR letter[3]        = { d[0], d[1], 0 };   /* "C:"       */
        WCHAR device[MAX_PATH] = {0};
        if (!QueryDosDeviceW(letter, device, MAX_PATH)) continue;

        size_t dev_len = wcslen(device);
        if (_wcsnicmp(device_path, device, dev_len) == 0) {
            _snwprintf(drive_path, drive_path_len,
                       L"%s%s", letter, device_path + dev_len);
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * djb2_hash — non-cryptographic hash for .text section comparison.
 * Speed over strength: hollow detection only, not evidence logging.
 */
static DWORD djb2_hash(const BYTE *data, SIZE_T len)
{
    DWORD h = 5381;
    for (SIZE_T i = 0; i < len; i++)
        h = ((h << 5) + h) ^ data[i];
    return h;
}

/*
 * open_output — open output_path for writing, or return stdout for "-".
 */
static FILE *open_output(const char *path)
{
    if (!path || strcmp(path, "-") == 0) return stdout;
    FILE *fp = NULL;
    fopen_s(&fp, path, "w");
    return fp;
}

/* ============================================================
   HOLLOW DETECTION
   ============================================================ */

BOOL dorm_detect_hollow(DWORD pid, BOOL *is_hollow)
{
    /* *the .text section: where every injected lie hides between the real instructions* */
    *is_hollow = FALSE;

    /* skip kernel processes — access is denied and they can't be hollowed */
    if (pid == 0 || pid == 4) return TRUE;

    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return FALSE;

    BOOL result = FALSE;

    /* ── 1. Resolve NtQueryInformationProcess ── */
    NtQIP_t NtQIP = (NtQIP_t)GetProcAddress(
                        GetModuleHandleA("ntdll.dll"),
                        "NtQueryInformationProcess");
    if (!NtQIP) goto cleanup;

    /* ── 2. PROCESS_BASIC_INFORMATION → PEB base ── */
    BYTE  pbi[48] = {0};   /* sizeof(PROCESS_BASIC_INFORMATION) on x64 = 48 */
    ULONG pbi_ret = 0;
    if (NtQIP(hProc, 0 /*ProcessBasicInformation*/,
              pbi, sizeof(pbi), &pbi_ret) < 0) goto cleanup;

    PVOID peb_base = *(PVOID *)(pbi + PBI_OFF_PEB);
    if (!peb_base) goto cleanup;

    /* ── 3. ImageBaseAddress from PEB+0x10 ── */
    PVOID  image_base = NULL;
    SIZE_T rd         = 0;
    if (!ReadProcessMemory(hProc, (BYTE *)peb_base + PEB_OFF_IMAGEBASE,
                           &image_base, sizeof(image_base), &rd)
        || !image_base) goto cleanup;

    /* ── 4. DOS header ── */
    IMAGE_DOS_HEADER dos = {0};
    if (!ReadProcessMemory(hProc, image_base, &dos, sizeof(dos), &rd))
        goto cleanup;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        *is_hollow = TRUE; result = TRUE; goto cleanup;
    }

    /* ── 5. NT headers ── */
    IMAGE_NT_HEADERS64 nt = {0};
    if (!ReadProcessMemory(hProc, (BYTE *)image_base + dos.e_lfanew,
                           &nt, sizeof(nt), &rd)) goto cleanup;
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        *is_hollow = TRUE; result = TRUE; goto cleanup;
    }

    /* ── 6. Section headers → find .text ── */
    WORD  nsec = nt.FileHeader.NumberOfSections;
    if (nsec > 96) nsec = 96;

    IMAGE_SECTION_HEADER secs[96] = {0};
    SIZE_T sec_off = (SIZE_T)dos.e_lfanew
                   + sizeof(DWORD)
                   + sizeof(IMAGE_FILE_HEADER)
                   + nt.FileHeader.SizeOfOptionalHeader;

    if (!ReadProcessMemory(hProc, (BYTE *)image_base + sec_off,
                           secs, nsec * sizeof(IMAGE_SECTION_HEADER), &rd))
        goto cleanup;

    DWORD text_rva  = 0;
    DWORD text_raw  = 0;
    DWORD text_size = 0;

    for (WORD i = 0; i < nsec; i++) {
        if (memcmp(secs[i].Name, ".text", 5) == 0) {
            text_rva  = secs[i].VirtualAddress;
            text_raw  = secs[i].PointerToRawData;
            text_size = secs[i].SizeOfRawData;
            break;
        }
    }
    if (!text_rva || !text_size) { result = TRUE; goto cleanup; }

    DWORD cmp_bytes = text_size < 0x1000 ? text_size : 0x1000;   /* cap 4 KB */

    /* ── 7. Hash .text from memory ── */
    BYTE *mbuf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cmp_bytes);
    if (!mbuf) goto cleanup;

    BOOL mem_ok = ReadProcessMemory(hProc, (BYTE *)image_base + text_rva,
                                    mbuf, cmp_bytes, &rd)
                  && rd == cmp_bytes;
    DWORD mem_hash = mem_ok ? djb2_hash(mbuf, cmp_bytes) : 0;
    HeapFree(GetProcessHeap(), 0, mbuf);
    if (!mem_ok) goto cleanup;

    /* ── 8. Resolve on-disk path ── */
    WCHAR dev_path[MAX_PATH]   = {0};
    WCHAR drv_path[MAX_PATH]   = {0};

    if (!K32GetMappedFileNameW(hProc, image_base, dev_path, MAX_PATH))
        goto cleanup;
    if (!device_to_drive_path(dev_path, drv_path, MAX_PATH))
        wcscpy_s(drv_path, MAX_PATH, dev_path);  /* fallback to device path */

    /* ── 9. Hash .text from disk ── */
    HANDLE hFile = CreateFileW(drv_path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto cleanup;

    DWORD disk_hash = 0;
    BYTE *dbuf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cmp_bytes);
    if (dbuf) {
        SetFilePointer(hFile, (LONG)text_raw, NULL, FILE_BEGIN);
        DWORD disk_rd = 0;
        if (ReadFile(hFile, dbuf, cmp_bytes, &disk_rd, NULL)
            && disk_rd == cmp_bytes)
            disk_hash = djb2_hash(dbuf, cmp_bytes);
        HeapFree(GetProcessHeap(), 0, dbuf);
    }
    CloseHandle(hFile);

    /* ── 10. Compare hashes ── */
    *is_hollow = (disk_hash != 0 && mem_hash != disk_hash);
    result     = TRUE;

cleanup:
    CloseHandle(hProc);
    return result;
}

/* ============================================================
   MODULE ENUMERATION
   ============================================================ */

int dorm_enum_modules(DWORD pid, const char *output_path)
{
    HANDLE hProc = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return -1;

    FILE *fp = open_output(output_path);
    if (!fp) { CloseHandle(hProc); return -1; }

    fprintf(fp, "{\"pid\":%lu,\"modules\":[\n", pid);

    PVOID  addr       = NULL;
    PVOID  last_alloc = (PVOID)(ULONG_PTR)-1;  /* sentinel */
    BOOL   first      = TRUE;
    int    count      = 0;

    MEMORY_BASIC_INFORMATION mbi = {0};

    while (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE
            && mbi.AllocationBase != last_alloc)
        {
            last_alloc = mbi.AllocationBase;

            /* ── resolve path ── */
            WCHAR dev_path[MAX_PATH] = {0};
            WCHAR drv_path[MAX_PATH] = {0};
            char  utf8_path[MAX_PATH * 3] = {0};
            char  utf8_name[260]          = {0};

            if (K32GetMappedFileNameW(hProc, mbi.AllocationBase,
                                      dev_path, MAX_PATH)) {
                if (!device_to_drive_path(dev_path, drv_path, MAX_PATH))
                    wcscpy_s(drv_path, MAX_PATH, dev_path);
                WideCharToMultiByte(CP_UTF8, 0, drv_path, -1,
                                    utf8_path, sizeof(utf8_path) - 1, NULL, NULL);
                const char *sep = strrchr(utf8_path, '\\');
                strncpy(utf8_name,
                        sep ? sep + 1 : utf8_path,
                        sizeof(utf8_name) - 1);
            } else {
                strcpy(utf8_path, "<unknown>");
                strcpy(utf8_name, "<unknown>");
            }

            /* ── sum total mapped size across all sections of this image ── */
            SIZE_T total_size = 0;
            {
                MEMORY_BASIC_INFORMATION scan_mbi = {0};
                PVOID scan = mbi.AllocationBase;
                while (VirtualQueryEx(hProc, scan, &scan_mbi,
                                      sizeof(scan_mbi)) == sizeof(scan_mbi)
                       && scan_mbi.AllocationBase == mbi.AllocationBase) {
                    total_size += scan_mbi.RegionSize;
                    scan        = (BYTE *)scan + scan_mbi.RegionSize;
                }
            }

            if (!first) fputs(",\n", fp);
            first = FALSE;

            fprintf(fp,
                "  {\"base\":\"0x%016llX\",\"size\":%zu,\"name\":",
                (unsigned long long)(ULONG_PTR)mbi.AllocationBase,
                total_size);
            json_escape(fp, utf8_name);
            fputs(",\"path\":", fp);
            json_escape(fp, utf8_path);
            fputc('}', fp);

            count++;
        }

        /* advance — guard against zero-size region infinite loop */
        PVOID next = (BYTE *)addr + (mbi.RegionSize ? mbi.RegionSize : 0x1000);
        if (next <= addr) break;
        addr = next;
    }

    fputs("\n]}\n", fp);
    if (fp != stdout) fclose(fp);
    CloseHandle(hProc);
    return count;
}

/* ============================================================
   PROCESS ENUMERATION — MAIN COLLECTOR
   ============================================================ */

int dorm_enum_processes(const char *output_path)
{
    /* *the process list: every secret the machine keeps, enumerated and judged* */

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return -1;

    /* ── grow buffer until STATUS_SUCCESS ── */
    ULONG    buf_size = 0x80000;   /* 512 KB initial */
    BYTE    *buf      = NULL;
    NTSTATUS nt;

    do {
        HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
        if (!buf) return -1;
        nt = NtQSI(5 /*SystemProcessInformation*/, buf, buf_size, &buf_size);
        buf_size += 0x8000;
    } while (nt == STATUS_INFO_LENGTH_MISMATCH);

    if (nt != STATUS_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, buf);
        return -1;
    }

    FILE *fp = open_output(output_path);
    if (!fp) { HeapFree(GetProcessHeap(), 0, buf); return -1; }

    /* ── header ── */
    char  hostname[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD hlen = (DWORD)sizeof(hostname);
    GetComputerNameA(hostname, &hlen);

    time_t     now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char       ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    fprintf(fp,
        "{\n"
        "  \"dorm_version\": \"%s\",\n"
        "  \"collector\": \"proc_analysis\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"hostname\": \"%s\",\n"
        "  \"processes\": [\n",
        DORM_FORENSICS_VERSION, ts, hostname);

    int   proc_count = 0;
    BYTE *entry      = buf;
    BOOL  first_proc = TRUE;

    for (;;) {
        ULONG  next    = *(ULONG  *)(entry + SYSPI_OFF_NEXT);
        ULONG  nthrd   = *(ULONG  *)(entry + SYSPI_OFF_NTHRD);
        DWORD  pid     = (DWORD)(ULONG_PTR)*(HANDLE *)(entry + SYSPI_OFF_PID);
        DWORD  ppid    = (DWORD)(ULONG_PTR)*(HANDLE *)(entry + SYSPI_OFF_PPID);
        ULONG  handles = *(ULONG  *)(entry + SYSPI_OFF_HANDLES);
        ULONG  session = *(ULONG  *)(entry + SYSPI_OFF_SESSION);

        /* ── image name from embedded UNICODE_STRING ── */
        USHORT img_len_bytes = *(USHORT *)(entry + SYSPI_OFF_IMGLEN);
        PWSTR  img_buf       = *(PWSTR  *)(entry + SYSPI_OFF_IMGBUF);
        char   img_utf8[260] = {0};

        if (img_buf && img_len_bytes > 0)
            wcs_to_utf8(img_buf, img_len_bytes / sizeof(WCHAR),
                        img_utf8, sizeof(img_utf8));
        if (img_utf8[0] == '\0')
            strcpy(img_utf8, pid == 0 ? "System Idle Process" : "[unknown]");

        /* ── hollow detection ── */
        BOOL is_hollow = FALSE;
        if (pid > 4) dorm_detect_hollow(pid, &is_hollow);

        /* ── emit process object ── */
        if (!first_proc) fputs(",\n", fp);
        first_proc = FALSE;

        fprintf(fp,
            "    {\n"
            "      \"pid\": %lu,\n"
            "      \"ppid\": %lu,\n"
            "      \"session\": %lu,\n"
            "      \"image\": ",
            pid, ppid, session);
        json_escape(fp, img_utf8);
        fprintf(fp,
            ",\n"
            "      \"thread_count\": %lu,\n"
            "      \"handle_count\": %lu,\n"
            "      \"hollow\": %s,\n"
            "      \"threads\": [\n",
            nthrd, handles,
            is_hollow ? "true" : "false");

        /* ── thread list ── */
        BYTE *t       = entry + SYSPI_OFF_THREADS;
        BOOL  first_t = TRUE;

        for (ULONG i = 0; i < nthrd; i++, t += SYSTI_SIZE) {
            DWORD     tid    = (DWORD)(ULONG_PTR)*(HANDLE *)(t + SYSTI_OFF_TID);
            ULONG_PTR start  = (ULONG_PTR)*(PVOID  *)(t + SYSTI_OFF_START);
            LONG      prio   = *(LONG  *)(t + SYSTI_OFF_PRIORITY);
            ULONG     state  = *(ULONG *)(t + SYSTI_OFF_STATE);
            ULONG     reason = *(ULONG *)(t + SYSTI_OFF_REASON);

            if (!first_t) fputs(",\n", fp);
            first_t = FALSE;

            fprintf(fp,
                "        {"
                "\"tid\":%lu,"
                "\"start\":\"0x%016llX\","
                "\"state\":%lu,"
                "\"wait_reason\":%lu,"
                "\"priority\":%ld"
                "}",
                tid,
                (unsigned long long)start,
                state, reason, (long)prio);
        }

        fputs("\n      ]\n    }", fp);
        proc_count++;

        if (!next) break;
        entry += next;
    }

    fprintf(fp,
        "\n  ],\n"
        "  \"process_count\": %d\n"
        "}\n",
        proc_count);

    if (fp != stdout) fclose(fp);
    HeapFree(GetProcessHeap(), 0, buf);
    return proc_count;
}

/* ============================================================
   FULL REPORT — CONVENIENCE WRAPPER
   ============================================================ */

BOOL dorm_full_process_report(const char *output_path)
{
    return dorm_enum_processes(output_path) >= 0;
}