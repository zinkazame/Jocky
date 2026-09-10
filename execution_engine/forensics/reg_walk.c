/*
 * reg_walk.c — DORM Phase 13.4: Registry Inspection Collector
 * execution_engine/forensics/reg_walk.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * All registry access through NT-layer functions resolved dynamically
 * from ntdll.dll — bypasses Win32 registry layer entirely.
 *
 * NT types (DORM_USTR, DORM_OA, DORM_KEY_BASIC, DORM_KVF) are
 * self-defined with DORM_ prefix to avoid winternl.h conflicts.
 * Binary layout is WDK-verified and identical to what the kernel expects.
 *
 * NT registry root paths:
 *   HKLM  →  \Registry\Machine
 *   HKCU  →  \Registry\User\<current-user-SID>   (resolved at runtime)
 *
 * Value decoding:
 *   REG_SZ / REG_EXPAND_SZ → UTF-8 string
 *   REG_DWORD              → decimal integer
 *   REG_QWORD              → decimal integer
 *   REG_MULTI_SZ           → JSON array of strings
 *   REG_BINARY / other     → uppercase hex (first 64 bytes, "..." suffix if truncated)
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <windows.h>
#include <sddl.h>       /* ConvertSidToStringSidW */

#include "forensics.h"
#include "reg_walk.h"

/* ============================================================
   NT TYPE DEFINITIONS — self-contained, WDK-verified layout
   ============================================================ */

#ifndef NT_SUCCESS
#define NT_SUCCESS(s)  ((NTSTATUS)(s) >= 0)
#endif
#define DORM_STATUS_NO_MORE_ENTRIES  ((NTSTATUS)0x8000001AL)
#define DORM_STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define DORM_STATUS_BUFFER_OVERFLOW  ((NTSTATUS)0x80000005L)

/* UNICODE_STRING clone */
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } DORM_USTR;

/* OBJECT_ATTRIBUTES clone */
typedef struct {
    ULONG     Length;
    HANDLE    RootDirectory;
    DORM_USTR *ObjectName;
    ULONG     Attributes;
    PVOID     SecurityDescriptor;
    PVOID     SecurityQualityOfService;
} DORM_OA;

#define DORM_OBJ_CASE_INSENSITIVE 0x00000040UL

/* KEY_BASIC_INFORMATION clone */
typedef struct {
    LARGE_INTEGER LastWriteTime;
    ULONG         TitleIndex;
    ULONG         NameLength;   /* bytes, not chars */
    WCHAR         Name[1];
} DORM_KEY_BASIC;

/* KEY_VALUE_FULL_INFORMATION clone */
typedef struct {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataOffset;    /* byte offset from struct start to data */
    ULONG DataLength;    /* data size in bytes                   */
    ULONG NameLength;    /* name size in bytes                   */
    WCHAR Name[1];
} DORM_KVF;

/* KEY_INFORMATION_CLASS ordinal */
#define DORM_KIC_BASIC   0    /* KeyBasicInformation    */
/* KEY_VALUE_INFORMATION_CLASS ordinal */
#define DORM_KVIC_FULL   1    /* KeyValueFullInformation */

/* KEY_READ: STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY */
#define DORM_KEY_READ    0x20019UL

/* NT function typedefs */
typedef NTSTATUS (NTAPI *NtOpenKey_f)    (HANDLE*, ULONG, DORM_OA*);
typedef NTSTATUS (NTAPI *NtEnumKey_f)    (HANDLE, ULONG, ULONG, PVOID, ULONG, ULONG*);
typedef NTSTATUS (NTAPI *NtEnumValKey_f) (HANDLE, ULONG, ULONG, PVOID, ULONG, ULONG*);
typedef NTSTATUS (NTAPI *NtClose_f)      (HANDLE);

/* module-level resolved pointers */
static NtOpenKey_f    g_NtOpenKey    = NULL;
static NtEnumKey_f    g_NtEnumKey    = NULL;
static NtEnumValKey_f g_NtEnumValKey = NULL;
static NtClose_f      g_NtClose      = NULL;
static BOOL           g_resolved     = FALSE;

/* ============================================================
   INTERNAL HELPERS
   ============================================================ */

static void json_escape(FILE *fp, const char *s)
{
    /* *the value name: whatever the registrant wanted future readers to see* */
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

static void dorm_ustr_set(DORM_USTR *us, PCWSTR s)
{
    us->Buffer        = (PWSTR)s;
    us->Length        = (USHORT)(wcslen(s) * sizeof(WCHAR));
    us->MaximumLength = us->Length + (USHORT)sizeof(WCHAR);
}

static void dorm_oa_init(DORM_OA *oa, DORM_USTR *name)
{
    oa->Length                   = sizeof(DORM_OA);
    oa->RootDirectory            = NULL;
    oa->ObjectName               = name;
    oa->Attributes               = DORM_OBJ_CASE_INSENSITIVE;
    oa->SecurityDescriptor       = NULL;
    oa->SecurityQualityOfService = NULL;
}

static BOOL resolve_nt(void)
{
    if (g_resolved) return TRUE;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    g_NtOpenKey    = (NtOpenKey_f)   GetProcAddress(ntdll, "NtOpenKey");
    g_NtEnumKey    = (NtEnumKey_f)   GetProcAddress(ntdll, "NtEnumerateKey");
    g_NtEnumValKey = (NtEnumValKey_f)GetProcAddress(ntdll, "NtEnumerateValueKey");
    g_NtClose      = (NtClose_f)     GetProcAddress(ntdll, "NtClose");
    g_resolved = (g_NtOpenKey && g_NtEnumKey && g_NtEnumValKey && g_NtClose);
    return g_resolved;
}

static HANDLE nt_open_key(PCWSTR nt_path)
{
    DORM_USTR us; dorm_ustr_set(&us, nt_path);
    DORM_OA   oa; dorm_oa_init(&oa, &us);
    HANDLE h = NULL;
    return NT_SUCCESS(g_NtOpenKey(&h, DORM_KEY_READ, &oa)) ? h : NULL;
}

/* FILETIME (100ns since 1601) → "YYYY-MM-DDTHH:MM:SSZ" */
static void filetime_to_iso(LARGE_INTEGER ft, char *buf, int len)
{
    if (ft.QuadPart == 0) { strncpy(buf, "N/A", len - 1); return; }
    FILETIME ft2 = {
        (DWORD)(ft.QuadPart & 0xFFFFFFFF),
        (DWORD)((ft.QuadPart >> 32) & 0xFFFFFFFF)
    };
    SYSTEMTIME st = {0};
    FileTimeToSystemTime(&ft2, &st);
    snprintf(buf, len, "%04d-%02d-%02dT%02d:%02d:%02dZ",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
}

/* registry value type number → name string */
static const char *regtype_str(ULONG t)
{
    switch (t) {
        case  0: return "REG_NONE";
        case  1: return "REG_SZ";
        case  2: return "REG_EXPAND_SZ";
        case  3: return "REG_BINARY";
        case  4: return "REG_DWORD";
        case  5: return "REG_DWORD_BIG_ENDIAN";
        case  6: return "REG_LINK";
        case  7: return "REG_MULTI_SZ";
        case 11: return "REG_QWORD";
        default: return "REG_UNKNOWN";
    }
}

/*
 * emit_value — decode one DORM_KVF block and append a JSON object to fp.
 * *first is cleared after the first call so subsequent calls prepend ",\n".
 */
static void emit_value(FILE *fp, DORM_KVF *kv, BOOL *first)
{
    char name_u8[512] = {0};
    WideCharToMultiByte(CP_UTF8, 0, kv->Name, kv->NameLength / sizeof(WCHAR),
                        name_u8, (int)sizeof(name_u8) - 1, NULL, NULL);

    BYTE *data = (BYTE*)kv + kv->DataOffset;
    ULONG dlen = kv->DataLength;

    if (!*first) fputs(",\n", fp);
    *first = FALSE;

    fprintf(fp, "      {\"name\":"); json_escape(fp, name_u8);
    fprintf(fp, ",\"type\":\"%s\"", regtype_str(kv->Type));

    switch (kv->Type) {
        case 1: case 2: {  /* REG_SZ / REG_EXPAND_SZ */
            char v8[1024] = {0};
            int  wc = (int)(dlen / sizeof(WCHAR));
            if (wc > 0 && ((WCHAR*)data)[wc-1] == 0) wc--;
            WideCharToMultiByte(CP_UTF8, 0, (WCHAR*)data, wc,
                                v8, (int)sizeof(v8) - 1, NULL, NULL);
            fprintf(fp, ",\"data\":"); json_escape(fp, v8);
            break;
        }
        case 4:   /* REG_DWORD */
            if (dlen >= 4) fprintf(fp, ",\"data\":%lu", *(DWORD*)data);
            break;
        case 11:  /* REG_QWORD */
            if (dlen >= 8) fprintf(fp, ",\"data\":%llu", *(ULONGLONG*)data);
            break;
        case 7: { /* REG_MULTI_SZ */
            fprintf(fp, ",\"data\":[");
            WCHAR *p = (WCHAR*)data;
            BOOL fa = TRUE;
            ULONG rem = dlen;
            while (rem > sizeof(WCHAR) && *p) {
                int sl = (int)wcslen(p);
                char s8[512] = {0};
                WideCharToMultiByte(CP_UTF8, 0, p, sl,
                                    s8, (int)sizeof(s8)-1, NULL, NULL);
                if (!fa) fputc(',', fp);
                fa = FALSE;
                json_escape(fp, s8);
                p   += sl + 1;
                rem -= (ULONG)((sl + 1) * sizeof(WCHAR));
            }
            fputc(']', fp);
            break;
        }
        default: { /* REG_BINARY + unknown: hex preview */
            static const char hx[] = "0123456789ABCDEF";
            ULONG cap = dlen < 64 ? dlen : 64;
            char hex[129] = {0};
            for (ULONG i = 0; i < cap; i++) {
                hex[i*2]   = hx[(data[i] >> 4) & 0xF];
                hex[i*2+1] = hx[ data[i]       & 0xF];
            }
            fprintf(fp, ",\"data\":\"%s%s\"", hex, dlen > 64 ? "..." : "");
            break;
        }
    }
    fputc('}', fp);
}

/*
 * walk_key_values — enumerate all values of hKey, emit JSON objects.
 * Returns value count.
 */
static int walk_key_values(HANDLE hKey, FILE *fp, BOOL *first_val)
{
    BYTE  buf[4096];
    int   count = 0;

    for (ULONG idx = 0; ; idx++) {
        ULONG needed = sizeof(buf);
        NTSTATUS s = g_NtEnumValKey(hKey, idx, DORM_KVIC_FULL,
                                     buf, needed, &needed);

        if (s == DORM_STATUS_NO_MORE_ENTRIES) break;

        if (!NT_SUCCESS(s)) {
            /* oversized value — allocate and retry once */
            if (needed > sizeof(buf) && needed < 0x100000) {
                BYTE *big = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
                if (big) {
                    ULONG needed2 = needed;
                    s = g_NtEnumValKey(hKey, idx, DORM_KVIC_FULL,
                                       big, needed2, &needed2);
                    if (NT_SUCCESS(s)) {
                        emit_value(fp, (DORM_KVF*)big, first_val);
                        count++;
                    }
                    HeapFree(GetProcessHeap(), 0, big);
                }
            }
            continue;
        }

        emit_value(fp, (DORM_KVF*)buf, first_val);
        count++;
    }
    return count;
}

/* resolve current-user SID → wide string for NT path construction */
static BOOL get_user_sid(WCHAR *out, int out_chars)
{
    HANDLE hTok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok))
        return FALSE;

    DWORD needed = 0;
    GetTokenInformation(hTok, TokenUser, NULL, 0, &needed);
    BYTE *buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    BOOL ok = FALSE;

    if (buf && GetTokenInformation(hTok, TokenUser, buf, needed, &needed)) {
        WCHAR *sid_w = NULL;
        if (ConvertSidToStringSidW(((TOKEN_USER*)buf)->User.Sid, &sid_w)) {
            wcsncpy(out, sid_w, out_chars - 1);
            out[out_chars - 1] = L'\0';
            LocalFree(sid_w);
            ok = TRUE;
        }
    }

    if (buf) HeapFree(GetProcessHeap(), 0, buf);
    CloseHandle(hTok);
    return ok;
}

/* ============================================================
   PERSISTENCE KEYS — Run / RunOnce (HKLM + HKCU)
   ============================================================ */

int dorm_enum_persistence(const char *output_path)
{
    /* *every autorun entry: a program that decided it deserved to survive reboots* */
    if (!resolve_nt()) return -1;

    FILE *fp = open_output(output_path, "w");
    if (!fp) return -1;

    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    fprintf(fp,
        "{\n"
        "  \"collector\": \"reg_persistence\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"keys\": [\n", ts);

    WCHAR sid[256] = {0};
    BOOL has_sid = get_user_sid(sid, 256);

    /* table: { NT path, display label } */
    struct { WCHAR path[512]; char label[128]; } keys[4];
    int nkeys = 0;

    /* HKLM Run + RunOnce */
    wcscpy(keys[nkeys].path,
           L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    strcpy(keys[nkeys].label, "HKLM\\SOFTWARE\\...\\Run");
    nkeys++;

    wcscpy(keys[nkeys].path,
           L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    strcpy(keys[nkeys].label, "HKLM\\SOFTWARE\\...\\RunOnce");
    nkeys++;

    /* HKCU Run + RunOnce (if SID available) */
    if (has_sid) {
        _snwprintf(keys[nkeys].path, 511,
                   L"\\Registry\\User\\%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                   sid);
        strcpy(keys[nkeys].label, "HKCU\\SOFTWARE\\...\\Run");
        nkeys++;

        _snwprintf(keys[nkeys].path, 511,
                   L"\\Registry\\User\\%s\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                   sid);
        strcpy(keys[nkeys].label, "HKCU\\SOFTWARE\\...\\RunOnce");
        nkeys++;
    }

    int total = 0;

    for (int i = 0; i < nkeys; i++) {
        HANDLE h = nt_open_key(keys[i].path);

        if (i > 0) fputs(",\n", fp);
        fprintf(fp, "    {\n      \"key\": ");
        json_escape(fp, keys[i].label);
        fprintf(fp, ",\n      \"accessible\": %s,\n      \"values\": [\n",
                h ? "true" : "false");

        if (h) {
            BOOL first_val = TRUE;
            total += walk_key_values(h, fp, &first_val);
            g_NtClose(h);
        }
        fputs("\n      ]\n    }", fp);
    }

    fprintf(fp,
        "\n  ],\n"
        "  \"total_entries\": %d\n"
        "}\n", total);

    if (fp != stdout) fclose(fp);
    return total;
}

/* ============================================================
   SERVICES — HKLM\SYSTEM\CurrentControlSet\Services
   ============================================================ */

int dorm_enum_services_reg(const char *output_path)
{
    if (!resolve_nt()) return -1;

    FILE *fp = open_output(output_path, "w");
    if (!fp) return -1;

    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    PCWSTR svc_root = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services";
    HANDLE hRoot    = nt_open_key(svc_root);

    fprintf(fp,
        "{\n"
        "  \"collector\": \"reg_services\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"accessible\": %s,\n"
        "  \"services\": [\n",
        ts, hRoot ? "true" : "false");

    int   count    = 0;
    BOOL  first_sv = TRUE;

    if (hRoot) {
        BYTE buf[2048];

        for (ULONG idx = 0; ; idx++) {
            ULONG needed = sizeof(buf);
            NTSTATUS s = g_NtEnumKey(hRoot, idx, DORM_KIC_BASIC,
                                      buf, needed, &needed);
            if (s == DORM_STATUS_NO_MORE_ENTRIES) break;
            if (!NT_SUCCESS(s)) continue;

            DORM_KEY_BASIC *kb = (DORM_KEY_BASIC*)buf;
            int nc = kb->NameLength / sizeof(WCHAR);

            char svc_name[256] = {0};
            WideCharToMultiByte(CP_UTF8, 0, kb->Name, nc,
                                svc_name, (int)sizeof(svc_name)-1, NULL, NULL);

            char lwt[32] = {0};
            filetime_to_iso(kb->LastWriteTime, lwt, sizeof(lwt));

            /* open service subkey */
            WCHAR svc_path[1024] = {0};
            _snwprintf(svc_path, 1023,
                       L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%.*s",
                       nc, kb->Name);

            HANDLE hSvc = nt_open_key(svc_path);

            char  image_path[1024] = {0};
            DWORD start_type       = 0xFFFFFFFF;

            if (hSvc) {
                BYTE vbuf[2048];
                for (ULONG vi = 0; ; vi++) {
                    ULONG vn = sizeof(vbuf);
                    NTSTATUS vs = g_NtEnumValKey(hSvc, vi, DORM_KVIC_FULL,
                                                  vbuf, vn, &vn);
                    if (vs == DORM_STATUS_NO_MORE_ENTRIES) break;
                    if (!NT_SUCCESS(vs)) continue;

                    DORM_KVF *kv = (DORM_KVF*)vbuf;
                    int vnc = kv->NameLength / sizeof(WCHAR);
                    WCHAR vname[64] = {0};
                    wcsncpy(vname, kv->Name, vnc < 63 ? vnc : 63);

                    BYTE *data = (BYTE*)kv + kv->DataOffset;

                    if (_wcsicmp(vname, L"ImagePath") == 0
                        && (kv->Type == 1 || kv->Type == 2))
                    {
                        int wc = kv->DataLength / sizeof(WCHAR);
                        WideCharToMultiByte(CP_UTF8, 0, (WCHAR*)data, wc,
                                            image_path, (int)sizeof(image_path)-1,
                                            NULL, NULL);
                    }
                    else if (_wcsicmp(vname, L"Start") == 0
                             && kv->Type == 4 && kv->DataLength >= 4)
                    {
                        start_type = *(DWORD*)data;
                    }
                }
                g_NtClose(hSvc);
            }

            const char *start_str = "UNKNOWN";
            switch (start_type) {
                case 0: start_str = "BOOT";     break;
                case 1: start_str = "SYSTEM";   break;
                case 2: start_str = "AUTO";     break;
                case 3: start_str = "DEMAND";   break;
                case 4: start_str = "DISABLED"; break;
            }

            if (!first_sv) fputs(",\n", fp);
            first_sv = FALSE;

            fprintf(fp, "    {\"name\":"); json_escape(fp, svc_name);
            fprintf(fp, ",\"start\":\"%s\",\"last_write\":\"%s\",\"image\":",
                    start_str, lwt);
            json_escape(fp, image_path[0] ? image_path : "<none>");
            fputc('}', fp);

            count++;
        }
        g_NtClose(hRoot);
    }

    fprintf(fp,
        "\n  ],\n"
        "  \"service_count\": %d\n"
        "}\n", count);

    if (fp != stdout) fclose(fp);
    return count;
}

/* ============================================================
   TYPED URLS — HKCU\...\Explorer\TypedURLs
   ============================================================ */

int dorm_enum_typed_urls(const char *output_path)
{
    if (!resolve_nt()) return -1;

    FILE *fp = open_output(output_path, "w");
    if (!fp) return -1;

    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    WCHAR sid[256] = {0};
    BOOL has_sid = get_user_sid(sid, 256);

    WCHAR path[1024] = {0};
    if (has_sid)
        _snwprintf(path, 1023,
                   L"\\Registry\\User\\%s\\Software\\Microsoft\\Windows\\"
                   L"CurrentVersion\\Explorer\\TypedURLs", sid);

    HANDLE h = has_sid ? nt_open_key(path) : NULL;

    fprintf(fp,
        "{\n"
        "  \"collector\": \"reg_typed_urls\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"accessible\": %s,\n"
        "  \"urls\": [\n",
        ts, h ? "true" : "false");

    int count = 0;
    if (h) {
        BOOL first_val = TRUE;
        count = walk_key_values(h, fp, &first_val);
        g_NtClose(h);
    }

    fprintf(fp, "\n  ],\n  \"count\": %d\n}\n", count);
    if (fp != stdout) fclose(fp);
    return count;
}

/* ============================================================
   COMBINED REPORT
   ============================================================ */

BOOL dorm_reg_report(const char *output_path)
{
    int p = dorm_enum_persistence("persistence.json");
    int s = dorm_enum_services_reg("services.json");
    int u = dorm_enum_typed_urls("typed_urls.json");

    FILE *fp = open_output(output_path, "w");
    if (!fp) return FALSE;

    time_t now = time(NULL);
    struct tm *gmt = gmtime(&now);
    char ts[32] = {0};
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmt);

    fprintf(fp,
        "{\n"
        "  \"collector\": \"reg_full_report\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"persistence_entries\": %d,\n"
        "  \"services_enumerated\": %d,\n"
        "  \"typed_urls\": %d,\n"
        "  \"files\": [\"persistence.json\",\"services.json\",\"typed_urls.json\"]\n"
        "}\n",
        ts, p, s, u);

    if (fp != stdout) fclose(fp);
    return (p >= 0 && s >= 0 && u >= 0);
}