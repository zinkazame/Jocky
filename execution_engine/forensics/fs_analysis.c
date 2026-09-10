/*
 * fs_analysis.c — DORM Phase 13.5: Filesystem Analysis Collector
 * execution_engine/forensics/fs_analysis.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Three collectors:
 *
 *   13.5a  dorm_scan_mft_sample — FSCTL_GET_NTFS_FILE_RECORD per inode,
 *                                  parse $STANDARD_INFORMATION + $FILE_NAME
 *
 *   13.5b  dorm_enum_prefetch   — C:\Windows\Prefetch\*.pf enumeration,
 *                                  MAM decompression via RtlDecompressBufferEx,
 *                                  SCCA header parse: exe name + hash
 *
 *   13.5c  dorm_detect_ads      — FindFirstStreamW / FindNextStreamW per file,
 *                                  flag any stream whose name != "::$DATA"
 *
 * Fixes applied vs original:
 *   1. <stddef.h> added — provides offsetof() used in $FILE_NAME attribute parse
 *   2. WIN32_FIND_STREAM_DATA typedef removed — MinGW winbase.h already defines
 *      it; redefinition causes "typedef redefinition with different types" error
 *   3. FindStreamInfoStandard_DORM enum removed — replaced with plain 0 at
 *      the single call site; enum was also redundant with the SDK definition
 *
 * Link: -lkernel32
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600   /* Vista+ — FindFirstStreamW / FindNextStreamW */
#endif

#include <stdio.h>
#include <string.h>
#include <stddef.h>     /* offsetof()                                         */
#include <time.h>
#include <wchar.h>
#include <windows.h>
#include <winioctl.h>   /* FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_GET_NTFS_FILE_RECORD */

#include "forensics.h"
#include "fs_analysis.h"

/* ============================================================
   NT TYPEDEFS
   ============================================================ */

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

/* Xpress+Huffman compression format tag (Win10 prefetch) */
#define DORM_COMPRESSION_XPRESS_HUFF  0x0208UL

typedef NTSTATUS (NTAPI *RtlGetCWS_t)(USHORT, PULONG, PULONG);
typedef NTSTATUS (NTAPI *RtlDecompress_t)(USHORT, PUCHAR, ULONG,
                                           PUCHAR, ULONG, PULONG, PVOID);

/* ============================================================
   MFT STRUCTURES — NTFS 3.1 spec, self-contained definitions
   ============================================================ */

/* NTFS volume data — mirrors NTFS_VOLUME_DATA_BUFFER from winioctl.h */
typedef struct {
    LARGE_INTEGER VolumeSerialNumber;
    LARGE_INTEGER NumberSectors;
    LARGE_INTEGER TotalClusters;
    LARGE_INTEGER FreeClusters;
    LARGE_INTEGER TotalReserved;
    DWORD         BytesPerSector;
    DWORD         BytesPerCluster;
    DWORD         BytesPerFileRecordSegment;   /* typically 1024 */
    DWORD         ClustersPerFileRecordSegment;
    LARGE_INTEGER MftValidDataLength;
    LARGE_INTEGER MftStartLcn;
    LARGE_INTEGER Mft2StartLcn;
    LARGE_INTEGER MftZoneStart;
    LARGE_INTEGER MftZoneEnd;
} DORM_NTFS_VOL;

#ifndef FSCTL_GET_NTFS_VOLUME_DATA
#define FSCTL_GET_NTFS_VOLUME_DATA \
    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 25, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_GET_NTFS_FILE_RECORD
#define FSCTL_GET_NTFS_FILE_RECORD \
    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 26, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

/* FSCTL_GET_NTFS_FILE_RECORD input/output buffers */
typedef struct { LARGE_INTEGER FileReferenceNumber; }  DORM_NFRI;
typedef struct {
    LARGE_INTEGER FileReferenceNumber;
    DWORD         FileRecordLength;
    BYTE          FileRecordBuffer[1];
} DORM_NFRO;

/*
 * MFT FILE record header — NTFS 3.1 layout
 *   +0x00  Signature          DWORD   "FILE" = 0x454C4946
 *   +0x04  UpdateSeqOffset    WORD
 *   +0x06  UpdateSeqSize      WORD
 *   +0x08  LogSeqNum          ULONGLONG
 *   +0x10  SequenceNum        WORD
 *   +0x12  HardLinkCount      WORD
 *   +0x14  FirstAttrOffset    WORD    byte offset to first attribute
 *   +0x16  Flags              WORD    bit0=InUse, bit1=Directory
 *   +0x18  BytesInUse         DWORD
 *   +0x1C  BytesAllocated     DWORD
 *   +0x20  BaseRecord         ULONGLONG
 *   +0x28  NextAttrId         WORD
 *   +0x2A  _pad               WORD
 *   +0x2C  RecordNum          DWORD
 */
typedef struct {
    DWORD     Signature;
    WORD      UpdateSeqOffset;
    WORD      UpdateSeqSize;
    ULONGLONG LogSeqNum;
    WORD      SequenceNum;
    WORD      HardLinkCount;
    WORD      FirstAttrOffset;
    WORD      Flags;
    DWORD     BytesInUse;
    DWORD     BytesAllocated;
    ULONGLONG BaseRecord;
    WORD      NextAttrId;
    WORD      _pad;
    DWORD     RecordNum;
} DORM_MFT_HDR;

/*
 * Attribute common header
 *   +0x00  Type        DWORD   0x10=$SI, 0x30=$FN, 0xFFFFFFFF=end
 *   +0x04  Length      DWORD   total attribute length including header
 *   +0x08  NonResident BYTE    0=resident, 1=non-resident
 *   +0x09  NameLength  BYTE
 *   +0x0A  NameOffset  WORD
 *   +0x0C  Flags       WORD
 *   +0x0E  Id          WORD
 */
typedef struct {
    DWORD Type;
    DWORD Length;
    BYTE  NonResident;
    BYTE  NameLength;
    WORD  NameOffset;
    WORD  Flags;
    WORD  Id;
} DORM_ATTR_HDR;

/*
 * Resident attribute extension (follows DORM_ATTR_HDR when NonResident==0)
 *   +0x10  ValueLength  DWORD
 *   +0x14  ValueOffset  WORD   byte offset from attribute start to data
 *   +0x16  IndexedFlag  BYTE
 *   +0x17  _pad         BYTE
 */
typedef struct {
    DORM_ATTR_HDR H;
    DWORD ValueLength;
    WORD  ValueOffset;
    BYTE  IndexedFlag;
    BYTE  _pad;
} DORM_RESIDENT;

/*
 * $STANDARD_INFORMATION value — first 32 bytes, version-independent
 *   +0x00  Created    ULONGLONG  (100ns since 1601-01-01)
 *   +0x08  Modified   ULONGLONG
 *   +0x10  MftChanged ULONGLONG
 *   +0x18  Accessed   ULONGLONG
 *   +0x20  FileAttr   DWORD
 */
typedef struct {
    ULONGLONG Created;
    ULONGLONG Modified;
    ULONGLONG MftChanged;
    ULONGLONG Accessed;
    DWORD     FileAttr;
} DORM_STD_INFO;

/*
 * $FILE_NAME value
 *   +0x00  ParentRef   ULONGLONG
 *   +0x08  Created     ULONGLONG
 *   +0x10  Modified    ULONGLONG
 *   +0x18  MftChanged  ULONGLONG
 *   +0x20  Accessed    ULONGLONG
 *   +0x28  AllocSize   ULONGLONG
 *   +0x30  RealSize    ULONGLONG
 *   +0x38  Flags       DWORD
 *   +0x3C  ReparseVal  DWORD
 *   +0x40  NameLen     BYTE    (characters, not bytes)
 *   +0x41  Namespace   BYTE    0=POSIX,1=Win32,2=DOS,3=Win32&DOS
 *   +0x42  Name        WCHAR[NameLen]
 */
typedef struct {
    ULONGLONG ParentRef;
    ULONGLONG Created;
    ULONGLONG Modified;
    ULONGLONG MftChanged;
    ULONGLONG Accessed;
    ULONGLONG AllocSize;
    ULONGLONG RealSize;
    DWORD     Flags;
    DWORD     ReparseVal;
    BYTE      NameLen;
    BYTE      Namespace;
    WCHAR     Name[1];
} DORM_FILE_NAME;

#define ATTR_STD_INFO   0x10u
#define ATTR_FILE_NAME  0x30u
#define ATTR_END        0xFFFFFFFFu
#define MFT_IN_USE      0x0001u
#define MFT_DIRECTORY   0x0002u
#define MFT_SIG         0x454C4946ul   /* "FILE" */

/* ============================================================
   SHARED HELPERS
   ============================================================ */

static void json_escape(FILE *fp, const char *s)
{
    /* *the filename: the last honest thing a file record ever admits to* */
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

/* 100ns FILETIME ticks → "YYYY-MM-DDTHH:MM:SSZ" */
static void ft_to_iso(ULONGLONG ft, char *buf, int len)
{
    if (!ft) { strncpy(buf, "N/A", (size_t)(len - 1)); buf[len-1] = '\0'; return; }
    FILETIME f = { (DWORD)(ft & 0xFFFFFFFFULL), (DWORD)(ft >> 32) };
    SYSTEMTIME s = {0};
    FileTimeToSystemTime(&f, &s);
    snprintf(buf, (size_t)len, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             s.wYear, s.wMonth, s.wDay,
             s.wHour, s.wMinute, s.wSecond);
}

static void ts_now(char *buf, int len)
{
    time_t n = time(NULL);
    struct tm *g = gmtime(&n);
    strftime(buf, (size_t)len, "%Y-%m-%dT%H:%M:%SZ", g);
}

/* ============================================================
   13.5a — MFT SAMPLE READER
   ============================================================ */

int dorm_scan_mft_sample(const char *vol_letter,
                          DWORD       sample_count,
                          const char *output_path)
{
    /* Build volume path: "\\.\C:" */
    char vol[8] = {0};
    snprintf(vol, sizeof(vol), "\\\\.\\%c:", vol_letter ? vol_letter[0] : 'C');

    HANDLE hVol = CreateFileA(
        vol, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (hVol == INVALID_HANDLE_VALUE) {
        printf("[fs] CreateFile(%s) failed error=%lu\n", vol, GetLastError());
        return -1;
    }

    /* NTFS volume data → BytesPerFileRecordSegment, MftStartLcn */
    DORM_NTFS_VOL nvd = {0};
    DWORD got = 0;
    if (!DeviceIoControl(hVol, FSCTL_GET_NTFS_VOLUME_DATA,
                         NULL, 0, &nvd, sizeof(nvd), &got, NULL))
    {
        printf("[fs] FSCTL_GET_NTFS_VOLUME_DATA failed error=%lu\n", GetLastError());
        CloseHandle(hVol);
        return -1;
    }

    DWORD rec_sz = nvd.BytesPerFileRecordSegment;
    if (rec_sz < 512 || rec_sz > 65536) rec_sz = 1024;  /* sane default */

    DWORD  out_sz  = (DWORD)(sizeof(DORM_NFRO) - 1 + rec_sz);
    BYTE  *out_buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, out_sz);
    if (!out_buf) { CloseHandle(hVol); return -1; }

    FILE *fp = open_output(output_path, "w");
    if (!fp) { HeapFree(GetProcessHeap(), 0, out_buf); CloseHandle(hVol); return -1; }

    char ts[32] = {0}; ts_now(ts, sizeof(ts));
    fprintf(fp,
        "{\n"
        "  \"collector\": \"fs_mft_sample\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"volume\": \"%c:\",\n"
        "  \"bytes_per_record\": %lu,\n"
        "  \"mft_start_lcn\": %llu,\n"
        "  \"sample_requested\": %lu,\n"
        "  \"records\": [\n",
        ts, vol[4], rec_sz,
        (unsigned long long)nvd.MftStartLcn.QuadPart,
        sample_count);

    int  emitted = 0;
    BOOL first   = TRUE;

    for (DWORD inode = 0; inode < sample_count; inode++) {
        DORM_NFRI in;
        in.FileReferenceNumber.QuadPart = (LONGLONG)inode;

        ZeroMemory(out_buf, out_sz);
        DWORD ret = 0;

        if (!DeviceIoControl(hVol, FSCTL_GET_NTFS_FILE_RECORD,
                              &in, sizeof(in),
                              out_buf, out_sz, &ret, NULL))
            continue;

        DORM_NFRO    *fro = (DORM_NFRO *)out_buf;
        DORM_MFT_HDR *hdr = (DORM_MFT_HDR *)fro->FileRecordBuffer;

        if (fro->FileRecordLength < sizeof(DORM_MFT_HDR)) continue;
        if (hdr->Signature != MFT_SIG)                    continue;
        if (!(hdr->Flags & MFT_IN_USE))                   continue;

        /* Walk attributes */
        DWORD aoff   = hdr->FirstAttrOffset;
        BOOL  is_dir = (hdr->Flags & MFT_DIRECTORY) != 0;
        char  name[512] = {0};
        char  c[32]={0}, m[32]={0}, a[32]={0}, mc[32]={0};
        BOOL  has_si = FALSE, has_fn = FALSE;

        while (aoff + sizeof(DORM_ATTR_HDR) <= fro->FileRecordLength) {
            DORM_ATTR_HDR *ah = (DORM_ATTR_HDR *)((BYTE *)hdr + aoff);
            if (ah->Type == ATTR_END || ah->Length < 8) break;

            /* Only process resident attributes */
            if (!ah->NonResident) {
                DORM_RESIDENT *rh  = (DORM_RESIDENT *)ah;
                BYTE          *val = (BYTE *)rh + rh->ValueOffset;

                if (ah->Type == ATTR_STD_INFO
                    && !has_si
                    && rh->ValueLength >= (DWORD)sizeof(DORM_STD_INFO))
                {
                    DORM_STD_INFO *si = (DORM_STD_INFO *)val;
                    ft_to_iso(si->Created,    c,  sizeof(c));
                    ft_to_iso(si->Modified,   m,  sizeof(m));
                    ft_to_iso(si->Accessed,   a,  sizeof(a));
                    ft_to_iso(si->MftChanged, mc, sizeof(mc));
                    has_si = TRUE;
                }

                if (ah->Type == ATTR_FILE_NAME
                    && rh->ValueLength >= (DWORD)offsetof(DORM_FILE_NAME, Name))
                {
                    DORM_FILE_NAME *fn = (DORM_FILE_NAME *)val;
                    /* prefer Win32 (1) or Win32&DOS (3) namespace */
                    if (!has_fn || fn->Namespace == 1 || fn->Namespace == 3) {
                        int nc = (int)fn->NameLen;
                        WideCharToMultiByte(CP_UTF8, 0, fn->Name, nc,
                                            name, (int)sizeof(name) - 1,
                                            NULL, NULL);
                        has_fn = TRUE;
                    }
                }
            }
            aoff += ah->Length;
        }

        if (!has_si && !has_fn) continue;

        if (!first) fputs(",\n", fp);
        first = FALSE;

        fprintf(fp,
            "    {\"inode\":%lu,\"dir\":%s,\"name\":",
            inode, is_dir ? "true" : "false");
        json_escape(fp, name[0] ? name : "<unnamed>");
        fprintf(fp,
            ",\"created\":\"%s\",\"modified\":\"%s\","
            "\"accessed\":\"%s\",\"mft_changed\":\"%s\"}",
            c, m, a, mc);
        emitted++;
    }

    fprintf(fp, "\n  ],\n  \"records_emitted\": %d\n}\n", emitted);
    if (fp != stdout) fclose(fp);
    HeapFree(GetProcessHeap(), 0, out_buf);
    CloseHandle(hVol);
    return emitted;
}

/* ============================================================
   13.5b — PREFETCH ENUMERATOR
   ============================================================ */

/*
 * Prefetch header layout (uncompressed SCCA):
 *   +0x00  file_magic   DWORD   (version-specific, e.g. 0x00000011 for v17)
 *   +0x04  scca_magic   DWORD   "SCCA" = 0x41434353
 *   +0x08  file_size    DWORD
 *   +0x0C  unknown      DWORD
 *   +0x10  exe_name     WCHAR[29]  (58 bytes, null-padded)
 *   +0x4C  pf_hash      DWORD
 *
 * MAM-compressed format (Win10+):
 *   +0x00  "MAM\x04"   DWORD   = 0x044D414D
 *   +0x04  uncompressed_size DWORD
 *   +0x08  compressed payload (Xpress+Huffman)
 *   After decompression → standard SCCA header above at offset 0
 */
#define DORM_MAM_SIG   0x044D414DUL   /* "MAM\x04" little-endian */
#define DORM_SCCA_MAG  0x41434353UL   /* "SCCA"    little-endian */

int dorm_enum_prefetch(const char *output_path)
{
    /* *prefetch: the OS logging its own crimes, compressed with its own key* */

    FILE *fp = open_output(output_path, "w");
    if (!fp) return -1;

    char ts[32] = {0}; ts_now(ts, sizeof(ts));
    fprintf(fp,
        "{\n"
        "  \"collector\": \"fs_prefetch\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"prefetch_dir\": \"C:\\\\Windows\\\\Prefetch\",\n"
        "  \"entries\": [\n", ts);

    /* Dynamically resolve RtlDecompressBufferEx from ntdll
     * (not exported on Server SKUs that disable prefetch)       */
    HMODULE ntdll       = GetModuleHandleA("ntdll.dll");
    RtlGetCWS_t    pfGW = (RtlGetCWS_t)
        GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize");
    RtlDecompress_t pfD = (RtlDecompress_t)
        GetProcAddress(ntdll, "RtlDecompressBufferEx");

    BYTE *ws = NULL;
    if (pfGW && pfD) {
        ULONG wssz = 0, fssz = 0;
        if (NT_SUCCESS(pfGW((USHORT)DORM_COMPRESSION_XPRESS_HUFF,
                            &wssz, &fssz)) && wssz > 0)
            ws = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, wssz);
    }

    WIN32_FIND_DATAW fd  = {0};
    HANDLE hFind = FindFirstFileW(L"C:\\Windows\\Prefetch\\*.pf", &fd);

    int  count = 0;
    BOOL first = TRUE;

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            WCHAR full[MAX_PATH] = {0};
            _snwprintf(full, MAX_PATH - 1,
                       L"C:\\Windows\\Prefetch\\%s", fd.cFileName);

            char pf_u8[MAX_PATH] = {0};
            char exe_u8[128]     = {0};
            char lw_u8[32]       = {0};

            WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1,
                                pf_u8, (int)sizeof(pf_u8) - 1, NULL, NULL);

            ULONGLONG lw = ((ULONGLONG)fd.ftLastWriteTime.dwHighDateTime << 32)
                         |  (ULONGLONG)fd.ftLastWriteTime.dwLowDateTime;
            ft_to_iso(lw, lw_u8, sizeof(lw_u8));

            DWORD pf_hash    = 0;
            BOOL  decomp_ok  = FALSE;

            HANDLE hf = CreateFileW(full, GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_DELETE,
                                    NULL, OPEN_EXISTING, 0, NULL);
            if (hf != INVALID_HANDLE_VALUE) {
                DWORD fsz = GetFileSize(hf, NULL);

                if (fsz > 8 && fsz < 10 * 1024 * 1024) {
                    BYTE *raw = (BYTE *)HeapAlloc(GetProcessHeap(),
                                                   HEAP_ZERO_MEMORY, fsz);
                    if (raw) {
                        DWORD nr = 0;
                        if (ReadFile(hf, raw, fsz, &nr, NULL) && nr >= 8) {
                            BYTE *scca = NULL;
                            BYTE *dbuf = NULL;

                            /* MAM-compressed? */
                            if (*(DWORD *)raw == DORM_MAM_SIG
                                && ws && pfD && nr > 8)
                            {
                                ULONG dsz = *(ULONG *)(raw + 4);
                                if (dsz > 0 && dsz < 10 * 1024 * 1024) {
                                    dbuf = (BYTE *)HeapAlloc(GetProcessHeap(),
                                                              HEAP_ZERO_MEMORY,
                                                              dsz);
                                    if (dbuf) {
                                        ULONG actual = 0;
                                        NTSTATUS s = pfD(
                                            (USHORT)DORM_COMPRESSION_XPRESS_HUFF,
                                            dbuf, dsz,
                                            raw + 8, nr - 8,
                                            &actual, ws);
                                        if (NT_SUCCESS(s) && actual >= 84) {
                                            scca      = dbuf;
                                            decomp_ok = TRUE;
                                        }
                                    }
                                }
                            } else if (nr >= 84) {
                                scca = raw;
                            }

                            if (scca) {
                                DWORD magic = *(DWORD *)(scca + 4);
                                if (magic == DORM_SCCA_MAG) {
                                    /* exe name: WCHAR[29] at offset 0x10 */
                                    WCHAR exew[30] = {0};
                                    memcpy(exew, scca + 0x10, 58);
                                    exew[29] = L'\0';
                                    WideCharToMultiByte(CP_UTF8, 0, exew, 29,
                                                        exe_u8,
                                                        (int)sizeof(exe_u8) - 1,
                                                        NULL, NULL);
                                    /* strip trailing NUL / spaces */
                                    for (int i = (int)strlen(exe_u8) - 1;
                                         i >= 0 && (exe_u8[i] == ' '
                                                    || exe_u8[i] == '\0');
                                         i--)
                                        exe_u8[i] = '\0';

                                    pf_hash = *(DWORD *)(scca + 0x4C);
                                }
                            }
                            if (dbuf) HeapFree(GetProcessHeap(), 0, dbuf);
                        }
                        HeapFree(GetProcessHeap(), 0, raw);
                    }
                }
                CloseHandle(hf);
            }

            if (!first) fputs(",\n", fp);
            first = FALSE;

            fprintf(fp, "    {\"pf\":");
            json_escape(fp, pf_u8);
            fprintf(fp, ",\"exe\":");
            json_escape(fp, exe_u8[0] ? exe_u8 : "<parse failed>");
            fprintf(fp,
                ",\"hash\":\"0x%08lX\""
                ",\"last_write\":\"%s\""
                ",\"size_bytes\":%lu"
                ",\"mam_compressed\":%s}",
                (unsigned long)pf_hash, lw_u8,
                fd.nFileSizeLow,
                decomp_ok ? "true" : "false");

            count++;

        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }

    if (ws) HeapFree(GetProcessHeap(), 0, ws);

    fprintf(fp, "\n  ],\n  \"count\": %d\n}\n", count);
    if (fp != stdout) fclose(fp);
    return count;
}

/* ============================================================
   13.5c — ADS DETECTION (Alternate Data Streams)
   ============================================================ */

/*
 * WIN32_FIND_STREAM_DATA is declared in MinGW's winbase.h (pulled via
 * windows.h). We do NOT redefine it — that caused the typedef clash.
 *
 * FindFirstStreamW / FindNextStreamW are Vista+ kernel32 exports.
 * Resolved at runtime via GetProcAddress so the binary still loads on
 * older systems (they just skip ADS scanning).
 *
 * Stream name format: ":stream_name:$DATA"
 * Default stream:     "::$DATA" — skip it, flag everything else.
 */

typedef HANDLE (WINAPI *FindFirstStreamW_t)(LPCWSTR, DWORD, PVOID, DWORD);
typedef BOOL   (WINAPI *FindNextStreamW_t)(HANDLE, PVOID);

static int g_ads_total = 0;
static BOOL g_ads_first_entry;

static void scan_streams_on_file(const WCHAR           *full_path,
                                 FILE                  *fp,
                                 FindFirstStreamW_t     pfFFS,
                                 FindNextStreamW_t      pfFNS)
{
    WIN32_FIND_STREAM_DATA sfd = {0};

    /*
     * FindStreamInfoStandard = 0 — level enum value per MSDN.
     * Written as plain 0 here; SDK enum may or may not be present
     * depending on MinGW version.
     */
    HANDLE hs = pfFFS(full_path, 0 /* FindStreamInfoStandard */, &sfd, 0);
    if (hs == INVALID_HANDLE_VALUE) return;

    do {
        /* Skip "::$DATA" — that is the default (unnamed) data stream */
        if (_wcsicmp(sfd.cStreamName, L"::$DATA") == 0) continue;

        char path_u8[MAX_PATH * 3] = {0};
        char strm_u8[MAX_PATH]     = {0};
        WideCharToMultiByte(CP_UTF8, 0, full_path,       -1,
                            path_u8, (int)sizeof(path_u8) - 1, NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, sfd.cStreamName, -1,
                            strm_u8, (int)sizeof(strm_u8) - 1, NULL, NULL);

        if (!g_ads_first_entry) fputs(",\n", fp);
        g_ads_first_entry = FALSE;

        fprintf(fp, "    {\"file\":");
        json_escape(fp, path_u8);
        fprintf(fp, ",\"stream\":");
        json_escape(fp, strm_u8);
        fprintf(fp, ",\"size_bytes\":%lld}",
                (long long)sfd.StreamSize.QuadPart);

        g_ads_total++;

    } while (pfFNS(hs, &sfd));

    FindClose(hs);
}

static void walk_dir_for_ads(const WCHAR           *dir,
                             int                    depth,
                             int                    max_depth,
                             DWORD                  max_files,
                             DWORD                 *scanned,
                             FILE                  *fp,
                             FindFirstStreamW_t     pfFFS,
                             FindNextStreamW_t      pfFNS)
{
    if (depth > max_depth) return;
    if (*scanned >= max_files) return;

    WCHAR pattern[MAX_PATH] = {0};
    _snwprintf(pattern, MAX_PATH - 1, L"%s\\*", dir);

    WIN32_FIND_DATAW fd = {0};
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.cFileName[0] == L'.' &&
            (fd.cFileName[1] == L'\0' ||
             (fd.cFileName[1] == L'.' && fd.cFileName[2] == L'\0')))
            continue;

        WCHAR full[MAX_PATH] = {0};
        _snwprintf(full, MAX_PATH - 1, L"%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Skip noisy / inaccessible system dirs */
            if (_wcsicmp(fd.cFileName, L"System Volume Information") == 0) continue;
            if (_wcsicmp(fd.cFileName, L"$Recycle.Bin")              == 0) continue;
            walk_dir_for_ads(full, depth + 1, max_depth,
                             max_files, scanned, fp, pfFFS, pfFNS);
        } else {
            if (*scanned >= max_files) continue;
            (*scanned)++;
            scan_streams_on_file(full, fp, pfFFS, pfFNS);
        }

    } while (FindNextFileW(hFind, &fd) && *scanned < max_files);

    FindClose(hFind);
}

int dorm_detect_ads(const char *scan_root_utf8,
                     DWORD       max_files,
                     const char *output_path)
{
    /* Resolve FindFirstStreamW / FindNextStreamW at runtime */
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FindFirstStreamW_t pfFFS =
        (FindFirstStreamW_t)GetProcAddress(k32, "FindFirstStreamW");
    FindNextStreamW_t  pfFNS =
        (FindNextStreamW_t) GetProcAddress(k32, "FindNextStreamW");

    FILE *fp = open_output(output_path, "w");
    if (!fp) return -1;

    const char *root = scan_root_utf8 ? scan_root_utf8 : "C:\\Windows\\Temp";

    char ts[32] = {0}; ts_now(ts, sizeof(ts));
    fprintf(fp,
        "{\n"
        "  \"collector\": \"fs_ads\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"scan_root\": ", ts);
    json_escape(fp, root);
    fprintf(fp, ",\n  \"max_files\": %lu,\n", max_files);
    fprintf(fp, "  \"api_available\": %s,\n",
            (pfFFS && pfFNS) ? "true" : "false");
    fprintf(fp, "  \"streams\": [\n");

    g_ads_total       = 0;
    g_ads_first_entry = TRUE;
    DWORD scanned     = 0;

    if (pfFFS && pfFNS) {
        WCHAR root_w[MAX_PATH] = {0};
        MultiByteToWideChar(CP_UTF8, 0, root, -1, root_w, MAX_PATH - 1);
        walk_dir_for_ads(root_w, 0, 4 /* max_depth */,
                         max_files, &scanned,
                         fp, pfFFS, pfFNS);
    } else {
        printf("[fs] FindFirstStreamW not available (need Vista+)\n");
    }

    fprintf(fp,
        "\n  ],\n"
        "  \"files_scanned\": %lu,\n"
        "  \"ads_count\": %d\n"
        "}\n", scanned, g_ads_total);

    if (fp != stdout) fclose(fp);
    return g_ads_total;
}

/* ============================================================
   COMBINED REPORT
   ============================================================ */

BOOL dorm_fs_report(const char *output_path)
{
    int mft = dorm_scan_mft_sample("C", 1000, "mft_sample.json");
    int pf  = dorm_enum_prefetch("prefetch.json");
    int ads = dorm_detect_ads("C:\\Windows\\Temp", 500, "ads.json");

    FILE *fp = open_output(output_path, "w");
    if (!fp) return (mft >= 0 && pf >= 0 && ads >= 0);

    char ts[32] = {0}; ts_now(ts, sizeof(ts));
    fprintf(fp,
        "{\n"
        "  \"collector\": \"fs_full_report\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"mft_records_parsed\": %d,\n"
        "  \"prefetch_entries\": %d,\n"
        "  \"ads_streams_found\": %d,\n"
        "  \"files\": [\"mft_sample.json\",\"prefetch.json\",\"ads.json\"]\n"
        "}\n", ts, mft, pf, ads);

    if (fp != stdout) fclose(fp);
    return (mft >= 0 && pf >= 0 && ads >= 0);
}