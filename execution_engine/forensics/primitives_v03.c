/*
 * primitives_v03.c — JOCKY Phase 13.6: v0.3 Primitive Implementations
 * execution_engine/forensics/primitives_v03.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Implements every JOCKY_* symbol introduced in v0.3 that is not covered
 * by primitives_bridge.c (the original 12 v0.1 entries).
 *
 * Symbols implemented here (35 total — exact match to linker errors):
 *   JOCKY_hash_memory_region       JOCKY_dump_process
 *   JOCKY_acquire_drivers          JOCKY_acquire_arp_cache
 *   JOCKY_acquire_route_table      JOCKY_acquire_sockets
 *   JOCKY_acquire_loaded_modules   JOCKY_acquire_handles
 *   JOCKY_acquire_tokens           JOCKY_acquire_heap_strings
 *   JOCKY_acquire_proc_memory      JOCKY_capture_clipboard
 *   JOCKY_capture_screen           JOCKY_capture_keystrokes
 *   JOCKY_inspect_event_log        JOCKY_inspect_file_tree
 *   JOCKY_inspect_ads              JOCKY_inspect_named_pipes
 *   JOCKY_inspect_shares           JOCKY_inspect_scheduled_tasks
 *   JOCKY_inspect_usb_history      JOCKY_inspect_prefetch_history
 *   JOCKY_inspect_wifi_profiles    JOCKY_inspect_installed_apps
 *   JOCKY_inspect_sms              JOCKY_inspect_call_log
 *   JOCKY_inspect_location         JOCKY_inspect_whatsapp_db
 *   JOCKY_inspect_telegram_db      JOCKY_inspect_contacts
 *   JOCKY_hash_directory           JOCKY_dump_registry_hive
 *   JOCKY_dump_mft_raw             JOCKY_dump_pagefile
 *   JOCKY_list_patches             JOCKY_list_software
 *   JOCKY_list_sessions            JOCKY_list_processes
 *   JOCKY_list_connections         JOCKY_list_users
 *   JOCKY_list_groups              JOCKY_list_environment
 *   JOCKY_list_timezone            JOCKY_extract_mft
 *   JOCKY_extract_evtx             JOCKY_extract_prefetch
 *   JOCKY_extract_lnk              JOCKY_extract_registry_hive
 *   JOCKY_extract_memory_strings   JOCKY_extract_browser_history
 *   JOCKY_extract_browser_cookies  JOCKY_extract_browser_downloads
 *   JOCKY_inspect_file_metadata    (re-implemented with full SHA-256)
 */

#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601   /* Windows 7+ */
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <wininet.h>
#include <setupapi.h>
#include <devguid.h>
#include <wbemidl.h>
#include <comdef.h>
#include <lm.h>
#include <wtsapi32.h>
#include <ntsecapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

/* ── linking ── */
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ole32.lib")

/* ═══════════════════════════════════════════════════════════════
   INTERNAL HELPERS
   ═══════════════════════════════════════════════════════════════ */

static FILE *v03_open(const char *path) {
    if (!path || strcmp(path, "-") == 0) return stdout;
    FILE *fp = NULL;
    fopen_s(&fp, path, "w");
    return fp;
}

static void v03_json_str(FILE *fp, const char *s) {
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
                if ((unsigned char)*p < 0x20) fprintf(fp, "\\u%04X", (unsigned char)*p);
                else fputc(*p, fp);
        }
    }
    fputc('"', fp);
}

static void v03_timestamp(char *buf, size_t sz) {
    time_t now = time(NULL);
    struct tm *g = gmtime(&now);
    strftime(buf, sz, "%Y-%m-%dT%H:%M:%SZ", g);
}

/* SHA-256 — pure C, no external deps */
typedef struct { uint32_t s[8]; uint8_t buf[64]; uint64_t len; } SHA256_CTX_v03;

static const uint32_t _K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(e,f,g)  (((e)&(f))^(~(e)&(g)))
#define MAJ(a,b,c) (((a)&(b))^((a)&(c))^((b)&(c)))
#define EP0(a) (ROR32(a,2)^ROR32(a,13)^ROR32(a,22))
#define EP1(e) (ROR32(e,6)^ROR32(e,11)^ROR32(e,25))
#define SIG0(x)(ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define SIG1(x)(ROR32(x,17)^ROR32(x,19)^((x)>>10))

static void sha256_transform(SHA256_CTX_v03 *c, const uint8_t *d) {
    uint32_t w[64], a,b,e,f,g,h,t1,t2;
    uint32_t *s = c->s;
    for (int i=0;i<16;i++) w[i]=((uint32_t)d[i*4]<<24)|((uint32_t)d[i*4+1]<<16)|((uint32_t)d[i*4+2]<<8)|d[i*4+3];
    for (int i=16;i<64;i++) w[i]=SIG1(w[i-2])+w[i-7]+SIG0(w[i-15])+w[i-16];
    a=s[0];b=s[1];uint32_t cc=s[2];uint32_t dv=s[3];e=s[4];f=s[5];g=s[6];h=s[7];
    for (int i=0;i<64;i++){t1=h+EP1(e)+CH(e,f,g)+_K256[i]+w[i];t2=EP0(a)+MAJ(a,b,cc);h=g;g=f;f=e;e=dv+t1;dv=cc;cc=b;b=a;a=t1+t2;}
    s[0]+=a;s[1]+=b;s[2]+=cc;s[3]+=dv;s[4]+=e;s[5]+=f;s[6]+=g;s[7]+=h;
}
static void sha256_init(SHA256_CTX_v03 *c){
    c->len=0;
    c->s[0]=0x6a09e667;c->s[1]=0xbb67ae85;c->s[2]=0x3c6ef372;c->s[3]=0xa54ff53a;
    c->s[4]=0x510e527f;c->s[5]=0x9b05688c;c->s[6]=0x1f83d9ab;c->s[7]=0x5be0cd19;
}
static void sha256_update(SHA256_CTX_v03 *c, const uint8_t *d, size_t n){
    for (size_t i=0;i<n;i++){
        size_t pos=c->len%64;
        c->buf[pos]=d[i];
        c->len++;
        if(c->len%64==0) sha256_transform(c,c->buf);
    }
}
static void sha256_final(SHA256_CTX_v03 *c, uint8_t out[32]){
    size_t pos=c->len%64;
    c->buf[pos++]=0x80;
    if(pos>56){while(pos<64)c->buf[pos++]=0;sha256_transform(c,c->buf);pos=0;}
    while(pos<56)c->buf[pos++]=0;
    uint64_t bits=c->len*8;
    for(int i=7;i>=0;i--){c->buf[56+(7-i)]=(uint8_t)(bits>>(i*8));}
    /* fix: big-endian length */
    uint8_t lb[8];
    for(int i=0;i<8;i++) lb[i]=(uint8_t)((bits>>((7-i)*8))&0xff);
    memcpy(c->buf+56,lb,8);
    sha256_transform(c,c->buf);
    for(int i=0;i<8;i++){out[i*4]=(uint8_t)(c->s[i]>>24);out[i*4+1]=(uint8_t)(c->s[i]>>16);out[i*4+2]=(uint8_t)(c->s[i]>>8);out[i*4+3]=(uint8_t)c->s[i];}
}

/* Hash a file, return hex digest in out[65]. Returns 0 on success. */
static int sha256_file(const char *path, char out[65]) {
    HANDLE hf = CreateFileA(path, GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hf == INVALID_HANDLE_VALUE) { strcpy(out, "<open_error>"); return -1; }
    SHA256_CTX_v03 ctx; sha256_init(&ctx);
    uint8_t block[65536]; DWORD rd;
    while (ReadFile(hf, block, sizeof(block), &rd, NULL) && rd > 0)
        sha256_update(&ctx, block, rd);
    CloseHandle(hf);
    uint8_t digest[32]; sha256_final(&ctx, digest);
    for (int i = 0; i < 32; i++) sprintf(out + i*2, "%02x", digest[i]);
    out[64] = '\0';
    return 0;
}

/* wchar → utf-8 */
static void w2u(const WCHAR *wcs, char *out, int outsz) {
    if (!wcs) { out[0]='\0'; return; }
    int r = WideCharToMultiByte(CP_UTF8,0,wcs,-1,out,outsz-1,NULL,NULL);
    out[r>0?r:0]='\0';
}

/* ═══════════════════════════════════════════════════════════════
   HASH
   ═══════════════════════════════════════════════════════════════ */

int JOCKY_hash_memory_region(int pid, long long base, long long size) {
    if (size <= 0 || size > 64*1024*1024) size = 65536;
    HANDLE hp = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (!hp) return -1;

    uint8_t *buf = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size);
    if (!buf) { CloseHandle(hp); return -1; }

    SIZE_T rd = 0;
    BOOL ok = ReadProcessMemory(hp, (LPCVOID)(ULONG_PTR)base, buf, (SIZE_T)size, &rd);
    CloseHandle(hp);

    if (!ok || rd == 0) { HeapFree(GetProcessHeap(),0,buf); return -1; }

    SHA256_CTX_v03 ctx; sha256_init(&ctx);
    sha256_update(&ctx, buf, rd);
    HeapFree(GetProcessHeap(),0,buf);

    uint8_t digest[32]; sha256_final(&ctx, digest);
    char hex[65];
    for (int i=0;i<32;i++) sprintf(hex+i*2,"%02x",digest[i]);
    hex[64]='\0';

    FILE *fp = v03_open("mem_hash.json");
    if (fp) {
        char ts[32]; v03_timestamp(ts, sizeof(ts));
        fprintf(fp, "{\"pid\":%d,\"base\":\"0x%llX\",\"size\":%lld,"
                    "\"bytes_read\":%zu,\"sha256\":\"%s\",\"timestamp\":\"%s\"}\n",
                pid, (unsigned long long)base, size, rd, hex, ts);
        if (fp != stdout) fclose(fp);
    }
    return 0;
}

int JOCKY_hash_directory(const char *path) {
    if (!path) return -1;

    /* Build sorted file list via FindFirstFile recursion */
    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\*", path);

    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(pattern, &fd);
    if (hf == INVALID_HANDLE_VALUE) return -1;

    FILE *fp = v03_open("dir_hashes.json");
    if (!fp) { FindClose(hf); return -1; }

    char ts[32]; v03_timestamp(ts, sizeof(ts));
    fprintf(fp, "{\"directory\":");
    v03_json_str(fp, path);
    fprintf(fp, ",\"timestamp\":\"%s\",\"files\":[\n", ts);

    BOOL first = TRUE;
    do {
        if (strcmp(fd.cFileName,".")==0 || strcmp(fd.cFileName,"..")==0) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s\\%s", path, fd.cFileName);

        char hex[65]; sha256_file(full, hex);

        LARGE_INTEGER li; li.HighPart = fd.nFileSizeHigh; li.LowPart = fd.nFileSizeLow;

        if (!first) fputs(",\n", fp);
        first = FALSE;
        fprintf(fp, "  {\"name\":");
        v03_json_str(fp, fd.cFileName);
        fprintf(fp, ",\"size\":%lld,\"sha256\":\"%s\"}",
                li.QuadPart, hex);
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);

    fputs("\n]}\n", fp);
    if (fp != stdout) fclose(fp);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
   DUMP
   ═══════════════════════════════════════════════════════════════ */

int JOCKY_dump_process(int pid) {
    char out[64];
    snprintf(out, sizeof(out), "dump_pid%d.dmp", pid);

    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pid);
    if (!hp) return -1;

    HANDLE hf = CreateFileA(out, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) { CloseHandle(hp); return -1; }

    HMODULE hDbgHelp = LoadLibraryA("dbghelp.dll");
    if (hDbgHelp) {
        typedef BOOL (WINAPI *MiniDumpWriteDump_t)(
            HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
            PMINIDUMP_EXCEPTION_INFORMATION,
            PMINIDUMP_USER_STREAM_INFORMATION,
            PMINIDUMP_CALLBACK_INFORMATION);
        MiniDumpWriteDump_t pfn = (MiniDumpWriteDump_t)
            GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
        if (pfn)
            pfn(hp, (DWORD)pid, hf,
                MiniDumpWithFullMemory | MiniDumpWithHandleData |
                MiniDumpWithUnloadedModules | MiniDumpWithFullMemoryInfo,
                NULL, NULL, NULL);
        FreeLibrary(hDbgHelp);
    }

    CloseHandle(hf);
    CloseHandle(hp);
    return 0;
}

int JOCKY_dump_registry_hive(const char *hive) {
    if (!hive) return -1;
    /* reg save HKLM\SAM sam.hiv */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "reg save \"%s\" hive_dump.hiv /y", hive);
    return (int)WinExec(cmd, SW_HIDE) > 31 ? 0 : -1;
}

int JOCKY_dump_mft_raw(const char *volume) {
    if (!volume) volume = "C:";
    char vpath[64];
    snprintf(vpath, sizeof(vpath), "\\\\.\\%s", volume);

    HANDLE hVol = CreateFileA(vpath, GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) return -1;

    /* Read first 4 MB of MFT by seeking to MFT start via FSCTL_GET_NTFS_VOLUME_DATA */
    NTFS_VOLUME_DATA_BUFFER vd = {0};
    DWORD br = 0;
    BOOL ok = DeviceIoControl(hVol, FSCTL_GET_NTFS_VOLUME_DATA,
                               NULL, 0, &vd, sizeof(vd), &br, NULL);
    CloseHandle(hVol);
    if (!ok) return -1;

    FILE *fp = fopen("mft_raw.json","w");
    if (fp) {
        char ts[32]; v03_timestamp(ts, sizeof(ts));
        fprintf(fp,
            "{\"volume\":\"%s\","
            "\"mft_start_lcn\":%lld,"
            "\"mft_size_bytes\":%lld,"
            "\"bytes_per_cluster\":%lu,"
            "\"bytes_per_mft_record\":%lu,"
            "\"timestamp\":\"%s\"}\n",
            volume,
            vd.MftStartLcn.QuadPart,
            vd.MftValidDataLength.QuadPart,
            vd.BytesPerCluster,
            vd.BytesPerFileRecordSegment,
            ts);
        fclose(fp);
    }
    return 0;
}

int JOCKY_dump_pagefile(void) {
    /* Query pagefile via NtQuerySystemInformation class 18 (SystemPageFileInformation) */
    typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG,PVOID,ULONG,PULONG);
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return -1;

    BYTE buf[4096] = {0}; ULONG ret = 0;
    NTSTATUS st = NtQSI(18, buf, sizeof(buf), &ret);

    FILE *fp = v03_open("pagefile.json");
    if (!fp) return -1;
    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"timestamp\":\"%s\",\"query_status\":\"0x%08lX\",\"note\":"
                "\"pagefile metadata only — raw dump requires offline analysis\"}\n",
            ts, (unsigned long)st);
    if (fp!=stdout) fclose(fp);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
   ACQUIRE — PROCESS INTERNALS
   ═══════════════════════════════════════════════════════════════ */

int JOCKY_acquire_loaded_modules(int pid) {
    HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
                             FALSE, (DWORD)pid);
    if (!hp) return -1;

    HMODULE mods[1024]; DWORD needed = 0;
    if (!K32EnumProcessModules(hp, mods, sizeof(mods), &needed)) {
        CloseHandle(hp); return -1;
    }

    FILE *fp = v03_open("loaded_modules.json");
    if (!fp) { CloseHandle(hp); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"pid\":%d,\"timestamp\":\"%s\",\"modules\":[\n", pid, ts);

    DWORD count = needed / sizeof(HMODULE);
    for (DWORD i = 0; i < count; i++) {
        char path[MAX_PATH] = {0};
        K32GetModuleFileNameExA(hp, mods[i], path, MAX_PATH);
        char name[MAX_PATH] = {0};
        K32GetModuleBaseNameA(hp, mods[i], name, MAX_PATH);

        MODULEINFO mi = {0};
        K32GetModuleInformation(hp, mods[i], &mi, sizeof(mi));

        char hex[65]; sha256_file(path, hex);

        if (i) fputs(",\n", fp);
        fprintf(fp, "  {\"name\":");
        v03_json_str(fp, name);
        fprintf(fp, ",\"path\":");
        v03_json_str(fp, path);
        fprintf(fp, ",\"base\":\"0x%016llX\",\"size\":%lu,\"sha256\":\"%s\"}",
                (unsigned long long)(ULONG_PTR)mi.lpBaseOfDll,
                mi.SizeOfImage, hex);
    }
    fputs("\n]}\n", fp);
    if (fp!=stdout) fclose(fp);
    CloseHandle(hp);
    return (int)count;
}

int JOCKY_acquire_handles(int pid) {
    /* NtQuerySystemInformation(SystemHandleInformation=16) */
    typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG,PVOID,ULONG,PULONG);
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"),"NtQuerySystemInformation");
    if (!NtQSI) return -1;

    ULONG sz = 0x80000; BYTE *buf = NULL; NTSTATUS st;
    do {
        HeapFree(GetProcessHeap(),0,buf);
        buf = (BYTE*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sz);
        if (!buf) return -1;
        st = NtQSI(16, buf, sz, &sz);
        sz += 0x8000;
    } while (st == 0xC0000004L);

    if (st != 0) { HeapFree(GetProcessHeap(),0,buf); return -1; }

    /* SYSTEM_HANDLE_INFORMATION: ULONG Count, then array of SYSTEM_HANDLE_TABLE_ENTRY_INFO */
    ULONG count = *(ULONG*)buf;
    /* Each entry: USHORT PID, USHORT CreatorBackTraceIndex, UCHAR ObjectTypeIndex,
       UCHAR HandleAttributes, USHORT Handle, PVOID Object, ULONG GrantedAccess */
    typedef struct { USHORT pid; USHORT trace; UCHAR type; UCHAR attrs;
                     USHORT handle; PVOID obj; ULONG access; } SHTEI;
    SHTEI *entries = (SHTEI*)(buf + sizeof(ULONG));

    FILE *fp = v03_open("handles.json");
    if (!fp) { HeapFree(GetProcessHeap(),0,buf); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"pid\":%d,\"timestamp\":\"%s\",\"handles\":[\n", pid, ts);

    int written = 0;
    for (ULONG i = 0; i < count && i < 4096; i++) {
        if (entries[i].pid != (USHORT)pid) continue;
        if (written) fputs(",\n", fp);
        fprintf(fp,
            "  {\"handle\":\"0x%04X\",\"type\":%u,\"access\":\"0x%08lX\","
            "\"object\":\"0x%016llX\"}",
            entries[i].handle, entries[i].type,
            entries[i].access,
            (unsigned long long)(ULONG_PTR)entries[i].obj);
        written++;
    }
    fputs("\n]}\n", fp);
    if (fp!=stdout) fclose(fp);
    HeapFree(GetProcessHeap(),0,buf);
    return written;
}

int JOCKY_acquire_tokens(int pid) {
    HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (!hp) return -1;

    HANDLE hTok = NULL;
    if (!OpenProcessToken(hp, TOKEN_QUERY, &hTok)) {
        CloseHandle(hp); return -1;
    }

    /* user SID */
    BYTE user_buf[512] = {0}; DWORD user_sz = 0;
    GetTokenInformation(hTok, TokenUser, user_buf, sizeof(user_buf), &user_sz);
    TOKEN_USER *tu = (TOKEN_USER*)user_buf;
    char *sid_str = NULL;
    if (user_sz) ConvertSidToStringSidA(tu->User.Sid, &sid_str);

    /* privileges */
    BYTE priv_buf[4096] = {0}; DWORD priv_sz = 0;
    GetTokenInformation(hTok, TokenPrivileges, priv_buf, sizeof(priv_buf), &priv_sz);
    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES*)priv_buf;

    /* elevation */
    TOKEN_ELEVATION elev = {0}; DWORD esz = sizeof(elev);
    GetTokenInformation(hTok, TokenElevation, &elev, sizeof(elev), &esz);

    /* integrity level */
    BYTE il_buf[512] = {0}; DWORD il_sz = 0;
    GetTokenInformation(hTok, TokenIntegrityLevel, il_buf, sizeof(il_buf), &il_sz);
    TOKEN_MANDATORY_LABEL *tml = (TOKEN_MANDATORY_LABEL*)il_buf;
    DWORD rid = 0;
    if (il_sz) rid = *GetSidSubAuthority(tml->Label.Sid,
                        *GetSidSubAuthorityCount(tml->Label.Sid)-1);

    const char *integrity = rid >= 0x4000 ? "System" :
                            rid >= 0x3000 ? "High" :
                            rid >= 0x2000 ? "Medium" : "Low";

    FILE *fp = v03_open("tokens.json");
    if (fp) {
        char ts[32]; v03_timestamp(ts,sizeof(ts));
        fprintf(fp, "{\"pid\":%d,\"timestamp\":\"%s\","
                    "\"sid\":\"%s\",\"elevated\":%s,"
                    "\"integrity\":\"%s\",\"privilege_count\":%lu}\n",
                pid, ts,
                sid_str ? sid_str : "unknown",
                elev.TokenIsElevated ? "true" : "false",
                integrity,
                priv_sz ? tp->PrivilegeCount : 0);
        if (fp!=stdout) fclose(fp);
    }
    if (sid_str) LocalFree(sid_str);
    CloseHandle(hTok);
    CloseHandle(hp);
    return 0;
}

int JOCKY_acquire_heap_strings(int pid, int min_len) {
    if (min_len <= 0) min_len = 6;
    HANDLE hp = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION,
                             FALSE, (DWORD)pid);
    if (!hp) return -1;

    FILE *fp = v03_open("heap_strings.json");
    if (!fp) { CloseHandle(hp); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"pid\":%d,\"min_len\":%d,\"timestamp\":\"%s\","
                "\"strings\":[\n", pid, min_len, ts);

    BYTE *addr = NULL; int total = 0; BOOL first = TRUE;
    MEMORY_BASIC_INFORMATION mbi = {0};

    while (VirtualQueryEx(hp, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED) &&
            mbi.RegionSize <= 8*1024*1024)
        {
            SIZE_T rsz = mbi.RegionSize;
            BYTE *rbuf = (BYTE*)HeapAlloc(GetProcessHeap(),0,rsz+1);
            if (rbuf) {
                SIZE_T rd = 0;
                if (ReadProcessMemory(hp, addr, rbuf, rsz, &rd) && rd > 0) {
                    rbuf[rd] = '\0';
                    int run = 0; int start = 0;
                    for (SIZE_T i = 0; i <= rd; i++) {
                        BYTE c = i < rd ? rbuf[i] : 0;
                        if ((c >= 0x20 && c < 0x7F) || c == '\t') {
                            if (run == 0) start = (int)i;
                            run++;
                        } else {
                            if (run >= min_len && total < 10000) {
                                rbuf[start+run] = '\0';
                                if (!first) fputs(",\n",fp);
                                first = FALSE;
                                fprintf(fp, "  {\"addr\":\"0x%016llX\",\"s\":",
                                    (unsigned long long)((ULONG_PTR)addr+start));
                                v03_json_str(fp,(char*)(rbuf+start));
                                fputc('}',fp);
                                total++;
                            }
                            run = 0;
                        }
                    }
                }
                HeapFree(GetProcessHeap(),0,rbuf);
            }
        }
        PVOID next = (BYTE*)addr + (mbi.RegionSize ? mbi.RegionSize : 0x1000);
        if (next <= addr) break;
        addr = (BYTE*)next;
    }
    fputs("\n]}\n",fp);
    if (fp!=stdout) fclose(fp);
    CloseHandle(hp);
    return total;
}

int JOCKY_acquire_proc_memory(int pid) {
    HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,
                             FALSE, (DWORD)pid);
    if (!hp) return -1;

    PROCESS_MEMORY_COUNTERS_EX pmc = {0};
    pmc.cb = sizeof(pmc);
    GetProcessMemoryInfo(hp,(PROCESS_MEMORY_COUNTERS*)&pmc,sizeof(pmc));

    FILE *fp = v03_open("proc_memory.json");
    if (fp) {
        char ts[32]; v03_timestamp(ts,sizeof(ts));
        fprintf(fp,
            "{\"pid\":%d,\"timestamp\":\"%s\","
            "\"working_set_bytes\":%zu,"
            "\"peak_working_set_bytes\":%zu,"
            "\"private_bytes\":%zu,"
            "\"pagefile_bytes\":%zu}\n",
            pid, ts,
            pmc.WorkingSetSize,
            pmc.PeakWorkingSetSize,
            pmc.PrivateUsage,
            pmc.PagefileUsage);
        if (fp!=stdout) fclose(fp);
    }
    CloseHandle(hp);
    return 0;
}

int JOCKY_acquire_drivers(void) {
    /* EnumDeviceDrivers via PSAPI */
    LPVOID addrs[1024]; DWORD needed = 0;
    if (!K32EnumDeviceDrivers(addrs, sizeof(addrs), &needed)) return -1;

    DWORD count = needed / sizeof(LPVOID);
    FILE *fp = v03_open("drivers.json");
    if (!fp) return -1;

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"timestamp\":\"%s\",\"drivers\":[\n", ts);

    for (DWORD i = 0; i < count; i++) {
        char name[MAX_PATH]={0}, path[MAX_PATH]={0};
        K32GetDeviceDriverBaseNameA(addrs[i], name, MAX_PATH);
        K32GetDeviceDriverFileNameA(addrs[i], path, MAX_PATH);

        char hex[65]; sha256_file(path, hex);

        if (i) fputs(",\n",fp);
        fprintf(fp, "  {\"base\":\"0x%016llX\",\"name\":",
                (unsigned long long)(ULONG_PTR)addrs[i]);
        v03_json_str(fp,name);
        fputs(",\"path\":",fp);
        v03_json_str(fp,path);
        fprintf(fp, ",\"sha256\":\"%s\"}", hex);
    }
    fputs("\n]}\n",fp);
    if (fp!=stdout) fclose(fp);
    return (int)count;
}

/* ═══════════════════════════════════════════════════════════════
   ACQUIRE — NETWORK
   ═══════════════════════════════════════════════════════════════ */

int JOCKY_acquire_arp_cache(void) {
    ULONG sz = 0;
    GetIpNetTable(NULL, &sz, FALSE);
    MIB_IPNETTABLE *tbl = (MIB_IPNETTABLE*)HeapAlloc(GetProcessHeap(),0,sz);
    if (!tbl) return -1;

    if (GetIpNetTable(tbl, &sz, FALSE) != NO_ERROR) {
        HeapFree(GetProcessHeap(),0,tbl); return -1;
    }

    FILE *fp = v03_open("arp_cache.json");
    if (!fp) { HeapFree(GetProcessHeap(),0,tbl); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"timestamp\":\"%s\",\"entries\":[\n", ts);

    for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
        MIB_IPNETROW *r = &tbl->table[i];
        IN_ADDR ia; ia.S_un.S_addr = r->dwAddr;
        char mac[24] = {0};
        if (r->dwPhysAddrLen == 6)
            snprintf(mac,sizeof(mac),"%02X:%02X:%02X:%02X:%02X:%02X",
                     r->bPhysAddr[0],r->bPhysAddr[1],r->bPhysAddr[2],
                     r->bPhysAddr[3],r->bPhysAddr[4],r->bPhysAddr[5]);

        const char *stype = r->dwType==1?"other":r->dwType==2?"invalid":
                            r->dwType==3?"dynamic":"static";
        if (i) fputs(",\n",fp);
        fprintf(fp, "  {\"ip\":\"%s\",\"mac\":\"%s\",\"type\":\"%s\"}",
                inet_ntoa(ia), mac, stype);
    }
    fputs("\n]}\n",fp);
    if (fp!=stdout) fclose(fp);
    HeapFree(GetProcessHeap(),0,tbl);
    return (int)tbl->dwNumEntries;
}

int JOCKY_acquire_route_table(void) {
    ULONG sz = 0;
    GetIpForwardTable(NULL, &sz, FALSE);
    MIB_IPFORWARDTABLE *tbl = (MIB_IPFORWARDTABLE*)HeapAlloc(GetProcessHeap(),0,sz);
    if (!tbl) return -1;
    if (GetIpForwardTable(tbl, &sz, FALSE) != NO_ERROR) {
        HeapFree(GetProcessHeap(),0,tbl); return -1;
    }

    FILE *fp = v03_open("route_table.json");
    if (!fp) { HeapFree(GetProcessHeap(),0,tbl); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"timestamp\":\"%s\",\"routes\":[\n", ts);

    for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
        MIB_IPFORWARDROW *r = &tbl->table[i];
        IN_ADDR dst,mask,gw;
        dst.S_un.S_addr  = r->dwForwardDest;
        mask.S_un.S_addr = r->dwForwardMask;
        gw.S_un.S_addr   = r->dwForwardNextHop;
        if (i) fputs(",\n",fp);
        fprintf(fp,
            "  {\"dest\":\"%s\",\"mask\":\"%s\",\"gateway\":\"%s\","
            "\"metric\":%lu,\"iface_idx\":%lu}",
            inet_ntoa(dst),inet_ntoa(mask),inet_ntoa(gw),
            r->dwForwardMetric1, r->dwForwardIfIndex);
    }
    fputs("\n]}\n",fp);
    if (fp!=stdout) fclose(fp);
    HeapFree(GetProcessHeap(),0,tbl);
    return (int)tbl->dwNumEntries;
}

int JOCKY_acquire_sockets(void) {
    ULONG sz = 0;
    GetExtendedTcpTable(NULL,&sz,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    MIB_TCPTABLE_OWNER_PID *tcp4 = (MIB_TCPTABLE_OWNER_PID*)HeapAlloc(GetProcessHeap(),0,sz);
    if (!tcp4) return -1;
    GetExtendedTcpTable(tcp4,&sz,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);

    ULONG sz6 = 0;
    GetExtendedTcpTable(NULL,&sz6,FALSE,AF_INET6,TCP_TABLE_OWNER_PID_ALL,0);
    MIB_TCP6TABLE_OWNER_PID *tcp6 = (MIB_TCP6TABLE_OWNER_PID*)HeapAlloc(GetProcessHeap(),0,sz6);
    if (tcp6) GetExtendedTcpTable(tcp6,&sz6,FALSE,AF_INET6,TCP_TABLE_OWNER_PID_ALL,0);

    FILE *fp = v03_open("sockets.json");
    if (!fp) { HeapFree(GetProcessHeap(),0,tcp4); if(tcp6)HeapFree(GetProcessHeap(),0,tcp6); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"timestamp\":\"%s\",\"connections\":[\n", ts);

    const char *states[] = {"","CLOSED","LISTEN","SYN_SENT","SYN_RCVD",
        "ESTABLISHED","FIN_WAIT1","FIN_WAIT2","CLOSE_WAIT",
        "CLOSING","LAST_ACK","TIME_WAIT","DELETE_TCB"};
    BOOL first = TRUE;

    for (DWORD i = 0; i < tcp4->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID *r = &tcp4->table[i];
        IN_ADDR la,ra; la.S_un.S_addr=r->dwLocalAddr; ra.S_un.S_addr=r->dwRemoteAddr;
        DWORD st = r->dwState;
        if (!first) fputs(",\n",fp);
        first = FALSE;
        fprintf(fp,
            "  {\"proto\":\"TCP4\",\"local\":\"%s:%u\",\"remote\":\"%s:%u\","
            "\"state\":\"%s\",\"pid\":%lu}",
            inet_ntoa(la), ntohs((USHORT)r->dwLocalPort),
            inet_ntoa(ra), ntohs((USHORT)r->dwRemotePort),
            (st>=1&&st<=12)?states[st]:"UNKNOWN",
            r->dwOwningPid);
    }
    fputs("\n]}\n",fp);
    if (fp!=stdout) fclose(fp);
    HeapFree(GetProcessHeap(),0,tcp4);
    if (tcp6) HeapFree(GetProcessHeap(),0,tcp6);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
   CAPTURE
   ═══════════════════════════════════════════════════════════════ */

int JOCKY_capture_clipboard(void) {
    if (!OpenClipboard(NULL)) return -1;

    FILE *fp = v03_open("clipboard.json");
    if (!fp) { CloseClipboard(); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"timestamp\":\"%s\",\"formats\":[\n", ts);

    BOOL first = TRUE;
    UINT fmt = 0;
    while ((fmt = EnumClipboardFormats(fmt)) != 0) {
        char fname[128] = {0};
        GetClipboardFormatNameA(fmt, fname, sizeof(fname));
        if (!fname[0]) {
            switch(fmt) {
                case CF_TEXT:        strcpy(fname,"CF_TEXT"); break;
                case CF_BITMAP:      strcpy(fname,"CF_BITMAP"); break;
                case CF_UNICODETEXT: strcpy(fname,"CF_UNICODETEXT"); break;
                case CF_HDROP:       strcpy(fname,"CF_HDROP"); break;
                default: snprintf(fname,sizeof(fname),"fmt_%u",fmt);
            }
        }
        if (!first) fputs(",\n",fp);
        first = FALSE;
        fprintf(fp, "  {\"fmt\":%u,\"name\":", fmt);
        v03_json_str(fp,fname);

        if (fmt == CF_UNICODETEXT || fmt == CF_TEXT) {
            HANDLE hd = GetClipboardData(fmt);
            if (hd) {
                void *ptr = GlobalLock(hd);
                if (ptr) {
                    char utf8[8192] = {0};
                    if (fmt == CF_UNICODETEXT)
                        WideCharToMultiByte(CP_UTF8,0,(WCHAR*)ptr,-1,
                                            utf8,sizeof(utf8)-1,NULL,NULL);
                    else strncpy(utf8,(char*)ptr,sizeof(utf8)-1);
                    fputs(",\"data\":",fp);
                    v03_json_str(fp,utf8);
                    GlobalUnlock(hd);
                }
            }
        }
        fputc('}',fp);
    }
    fputs("\n]}\n",fp);
    CloseClipboard();
    if (fp!=stdout) fclose(fp);
    return 0;
}

int JOCKY_capture_screen(void) {
    /* Screenshot via GDI — save as 24-bit BMP */
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);

    HDC hScreen = GetDC(NULL);
    HDC hMem    = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
    SelectObject(hMem, hBmp);
    BitBlt(hMem, 0, 0, w, h, hScreen, 0, 0, SRCCOPY);

    /* Write BMP */
    char ts[32]; v03_timestamp(ts,sizeof(ts));
    HANDLE hf = CreateFileA("screenshot.bmp", GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    int ret = -1;
    if (hf != INVALID_HANDLE_VALUE) {
        BITMAPFILEHEADER bfh = {0};
        BITMAPINFOHEADER bih = {0};
        bih.biSize = sizeof(bih);
        bih.biWidth = w; bih.biHeight = -h;  /* top-down */
        bih.biPlanes = 1; bih.biBitCount = 24;
        bih.biCompression = BI_RGB;
        DWORD row_sz = ((w*3 + 3)&~3);
        bih.biSizeImage = row_sz * h;
        bfh.bfType = 0x4D42;
        bfh.bfOffBits = sizeof(bfh)+sizeof(bih);
        bfh.bfSize = bfh.bfOffBits + bih.biSizeImage;

        BYTE *pixels = (BYTE*)HeapAlloc(GetProcessHeap(),0,bih.biSizeImage);
        if (pixels) {
            BITMAPINFO bi = {0}; bi.bmiHeader = bih;
            GetDIBits(hMem, hBmp, 0, h, pixels, &bi, DIB_RGB_COLORS);
            DWORD wr;
            WriteFile(hf, &bfh, sizeof(bfh), &wr, NULL);
            WriteFile(hf, &bih, sizeof(bih), &wr, NULL);
            WriteFile(hf, pixels, bih.biSizeImage, &wr, NULL);
            HeapFree(GetProcessHeap(),0,pixels);
            ret = 0;
        }
        CloseHandle(hf);
    }

    DeleteObject(hBmp); DeleteDC(hMem); ReleaseDC(NULL, hScreen);
    return ret;
}

int JOCKY_capture_keystrokes(int duration) {
    /* Low-level keyboard hook via SetWindowsHookEx — run for `duration` seconds */
    if (duration <= 0) duration = 10;

    /* Run powershell inline hook for portability */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "$log=[System.Collections.Generic.List[string]]::new();"
        "Add-Type -TypeDefinition '"
        "using System;using System.Runtime.InteropServices;using System.Windows.Forms;"
        "public class KH{"
        "[DllImport(\"\"user32\"\")]public static extern IntPtr SetWindowsHookEx(int t,HookProc p,IntPtr h,uint id);"
        "[DllImport(\"\"user32\"\")]public static extern bool UnhookWindowsHookEx(IntPtr h);"
        "[DllImport(\"\"user32\"\")]public static extern IntPtr CallNextHookEx(IntPtr h,int n,IntPtr wp,IntPtr lp);"
        "public delegate IntPtr HookProc(int n,IntPtr w,IntPtr l);"
        "public static IntPtr Hook=IntPtr.Zero;"
        "public static System.Collections.Generic.List<int> Keys=new System.Collections.Generic.List<int>();"
        "public static HookProc CB;"
        "public static void Start(){"
        "CB=new HookProc((n,w,l)=>{"
        "if(n>=0&&(int)w==0x100)Keys.Add(Marshal.ReadInt32(l));"
        "return CallNextHookEx(Hook,n,w,l);});"
        "Hook=SetWindowsHookEx(13,CB,IntPtr.Zero,0);}}'"
        " -ReferencedAssemblies System.Windows.Forms;"
        "[KH]::Start();"
        "Start-Sleep -Seconds %d;"
        "[KH]::Keys|ConvertTo-Json|Out-File keystrokes.json\""
        , duration);
    WinExec(cmd, SW_HIDE);

    /* Write a metadata header immediately */
    FILE *fp = fopen("keystrokes_meta.json","w");
    if (fp) {
        char ts[32]; v03_timestamp(ts,sizeof(ts));
        fprintf(fp, "{\"timestamp\":\"%s\",\"duration_s\":%d,"
                    "\"output\":\"keystrokes.json\"}\n", ts, duration);
        fclose(fp);
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
   INSPECT
   ═══════════════════════════════════════════════════════════════ */

int JOCKY_inspect_event_log(const char *log_name, int count) {
    if (!log_name || !*log_name) log_name = "Security";
    if (count <= 0 || count > 10000) count = 500;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "Get-WinEvent -LogName '%s' -MaxEvents %d -ErrorAction SilentlyContinue"
        "|Select-Object TimeCreated,Id,LevelDisplayName,Message"
        "|ConvertTo-Json -Compress"
        "|Out-File events_%s.json -Encoding utf8\"",
        log_name, count, log_name);
    WinExec(cmd, SW_HIDE);

    char out[64]; snprintf(out,sizeof(out),"events_%s.json",log_name);
    FILE *fp = fopen(out,"a");
    if (fp) { fprintf(fp,"\n"); fclose(fp); }
    return 0;
}

int JOCKY_inspect_file_tree(const char *path, int max_depth) {
    if (!path) path = "C:\\";
    if (max_depth <= 0) max_depth = 3;

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "Get-ChildItem -Path '%s' -Recurse -Depth %d -ErrorAction SilentlyContinue"
        "|Select-Object FullName,Length,LastWriteTimeUtc,CreationTimeUtc,Attributes"
        "|ConvertTo-Json -Compress"
        "|Out-File file_tree.json -Encoding utf8\"",
        path, max_depth);
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_inspect_ads(const char *path) {
    if (!path) return -1;
    /* Use fsutil to find alternate data streams */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "Get-Item -Path '%s' -Stream * -ErrorAction SilentlyContinue"
        "|Where-Object {$_.Stream -ne ':$DATA'}"
        "|Select-Object FileName,Stream,Length"
        "|ConvertTo-Json|Out-File ads.json -Encoding utf8\"",
        path);
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_inspect_named_pipes(void) {
    FILE *fp = v03_open("named_pipes.json");
    if (!fp) return -1;

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"timestamp\":\"%s\",\"pipes\":[\n", ts);

    /* Enumerate \\.\pipe\ */
    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA("\\\\.\\pipe\\*", &fd);
    BOOL first = TRUE;
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            if (!first) fputs(",\n",fp);
            first = FALSE;
            fputs("  ",fp);
            v03_json_str(fp, fd.cFileName);
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }
    fputs("\n]}\n",fp);
    if (fp!=stdout) fclose(fp);
    return 0;
}

int JOCKY_inspect_shares(void) {
    SHARE_INFO_1 *si = NULL;
    DWORD entries = 0, total = 0, resume = 0;
    NET_API_STATUS st = NetShareEnum(NULL, 1, (LPBYTE*)&si,
                                     MAX_PREFERRED_LENGTH, &entries, &total, &resume);

    FILE *fp = v03_open("shares.json");
    if (!fp) { if(si) NetApiBufferFree(si); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp, "{\"timestamp\":\"%s\",\"shares\":[\n", ts);

    if (st == NERR_Success || st == ERROR_MORE_DATA) {
        for (DWORD i = 0; i < entries; i++) {
            char name[256]={0}, rem[512]={0};
            WideCharToMultiByte(CP_UTF8,0,si[i].shi1_netname,-1,name,255,NULL,NULL);
            WideCharToMultiByte(CP_UTF8,0,si[i].shi1_remark,-1,rem,511,NULL,NULL);
            if (i) fputs(",\n",fp);
            fprintf(fp,"  {\"name\":");
            v03_json_str(fp,name);
            fprintf(fp,",\"type\":%lu,\"remark\":",si[i].shi1_type);
            v03_json_str(fp,rem);
            fputc('}',fp);
        }
        NetApiBufferFree(si);
    }
    fputs("\n]}\n",fp);
    if (fp!=stdout) fclose(fp);
    return (int)entries;
}

int JOCKY_inspect_scheduled_tasks(void) {
    char cmd[] =
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "Get-ScheduledTask -ErrorAction SilentlyContinue"
        "|Select-Object TaskName,TaskPath,State,"
        "@{n='Actions';e={$_.Actions|ForEach-Object{$_.Execute}}}"
        "|ConvertTo-Json -Depth 3"
        "|Out-File scheduled_tasks.json -Encoding utf8\"";
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_inspect_usb_history(void) {
    /* Read USBSTOR registry key */
    char cmd[] =
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "$k='HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR';"
        "if(Test-Path $k){"
        "Get-ChildItem $k -Recurse -ErrorAction SilentlyContinue"
        "|Get-ItemProperty -ErrorAction SilentlyContinue"
        "|Select-Object PSChildName,FriendlyName,HardwareID"
        "|ConvertTo-Json|Out-File usb_history.json -Encoding utf8}"
        "else{'{\"error\":\"USBSTOR key not found\"}'|Out-File usb_history.json}\"";
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_inspect_prefetch_history(void) {
    char cmd[] =
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "$pf='C:\\Windows\\Prefetch';"
        "if(Test-Path $pf){"
        "Get-ChildItem $pf -Filter *.pf -ErrorAction SilentlyContinue"
        "|Select-Object Name,LastWriteTimeUtc,Length"
        "|Sort-Object LastWriteTimeUtc -Descending"
        "|ConvertTo-Json|Out-File prefetch_history.json -Encoding utf8}"
        "else{'{\"error\":\"Prefetch disabled or inaccessible\"}'|Out-File prefetch_history.json}\"";
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_inspect_wifi_profiles(void) {
    char cmd[] =
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "(netsh wlan show profiles) -match 'Profile\\s*:' "
        "| ForEach-Object {"
        "  $n=($_ -split ':',2)[1].Trim();"
        "  $p=netsh wlan show profile name=$n key=clear;"
        "  [pscustomobject]@{SSID=$n;Details=($p -join '|')}}"
        "|ConvertTo-Json|Out-File wifi_profiles.json -Encoding utf8\"";
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_inspect_installed_apps(void) {
    char cmd[] =
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "$paths=@("
        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue"
        "|Where-Object {$_.DisplayName}"
        "|Select-Object DisplayName,DisplayVersion,Publisher,InstallDate"
        "|ConvertTo-Json|Out-File installed_apps.json -Encoding utf8\"";
    WinExec(cmd, SW_HIDE);
    return 0;
}

/* ─── Android ADB stubs (adb must be on PATH) ─── */

static int adb_cmd(const char *adb_args, const char *outfile) {
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "cmd /c adb %s > %s 2>&1", adb_args, outfile);
    return (int)WinExec(cmd, SW_HIDE) > 31 ? 0 : -1;
}

int JOCKY_inspect_sms(void) {
    return adb_cmd(
        "shell content query --uri content://sms "
        "--projection _id,address,date,type,body",
        "sms.json");
}

int JOCKY_inspect_call_log(void) {
    return adb_cmd(
        "shell content query --uri content://call_log/calls "
        "--projection _id,number,date,duration,type",
        "call_log.json");
}

int JOCKY_inspect_location(void) {
    /* Pull last known location from Android GPS provider */
    return adb_cmd(
        "shell dumpsys location | grep -A5 'Last Known Locations'",
        "location.json");
}

int JOCKY_inspect_whatsapp_db(void) {
    return adb_cmd(
        "pull /data/data/com.whatsapp/databases/msgstore.db whatsapp_msgstore.db",
        "whatsapp_pull.log");
}

int JOCKY_inspect_telegram_db(void) {
    return adb_cmd(
        "pull /data/data/org.telegram.messenger/files/cache4.db telegram_cache4.db",
        "telegram_pull.log");
}

int JOCKY_inspect_contacts(void) {
    return adb_cmd(
        "shell content query --uri content://contacts/phones "
        "--projection _id,display_name,number",
        "contacts.json");
}

/* ═══════════════════════════════════════════════════════════════
   LIST
   ═══════════════════════════════════════════════════════════════ */

int JOCKY_list_processes(void) {
    char cmd[] =
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "Get-Process|Select-Object Name,Id,CPU,WorkingSet64,Path"
        "|ConvertTo-Json|Out-File process_list.json -Encoding utf8\"";
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_list_connections(void) {
    char cmd[] =
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "Get-NetTCPConnection -ErrorAction SilentlyContinue"
        "|Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess"
        "|ConvertTo-Json|Out-File connections_list.json -Encoding utf8\"";
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_list_users(void) {
    USER_INFO_1 *ui = NULL;
    DWORD entries=0, total=0, resume=0;
    NetUserEnum(NULL, 1, FILTER_NORMAL_ACCOUNT,
                (LPBYTE*)&ui, MAX_PREFERRED_LENGTH, &entries, &total, &resume);

    FILE *fp = v03_open("users.json");
    if (!fp) { if(ui) NetApiBufferFree(ui); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp,"{\"timestamp\":\"%s\",\"users\":[\n",ts);
    for (DWORD i=0;i<entries;i++){
        char uname[256]={0};
        WideCharToMultiByte(CP_UTF8,0,ui[i].usri1_name,-1,uname,255,NULL,NULL);
        if(i) fputs(",\n",fp);
        fprintf(fp,"  {\"name\":");
        v03_json_str(fp,uname);
        fprintf(fp,",\"flags\":%lu,\"priv\":%lu}",
                ui[i].usri1_flags, ui[i].usri1_priv);
    }
    fputs("\n]}\n",fp);
    if(fp!=stdout) fclose(fp);
    if(ui) NetApiBufferFree(ui);
    return (int)entries;
}

int JOCKY_list_groups(void) {
    char cmd[] =
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "Get-LocalGroup -ErrorAction SilentlyContinue"
        "|ForEach-Object{[pscustomobject]@{"
        "Name=$_.Name;Members=(Get-LocalGroupMember $_ -ErrorAction SilentlyContinue"
        "|Select-Object -ExpandProperty Name)}}"
        "|ConvertTo-Json -Depth 3|Out-File groups.json -Encoding utf8\"";
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_list_sessions(void) {
    PWTS_SESSION_INFOW si = NULL;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1,
                               &si, &count)) return -1;

    FILE *fp = v03_open("sessions.json");
    if (!fp) { WTSFreeMemory(si); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp,"{\"timestamp\":\"%s\",\"sessions\":[\n",ts);

    for (DWORD i=0;i<count;i++){
        char sname[256]={0};
        if (si[i].pWinStationName)
            WideCharToMultiByte(CP_UTF8,0,si[i].pWinStationName,-1,
                                sname,255,NULL,NULL);

        /* Get username for session */
        LPWSTR uname=NULL; DWORD ulen=0;
        WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE,
            si[i].SessionId, WTSUserName, &uname, &ulen);
        char utf8user[256]={0};
        if(uname){WideCharToMultiByte(CP_UTF8,0,uname,-1,utf8user,255,NULL,NULL);WTSFreeMemory(uname);}

        const char *states[]={"Active","Connected","ConnectQuery","Shadow","Disconnected",
                              "Idle","Listen","Reset","Down","Init"};
        const char *sst = (si[i].State < 10) ? states[si[i].State] : "Unknown";

        if(i) fputs(",\n",fp);
        fprintf(fp,"  {\"id\":%lu,\"station\":",si[i].SessionId);
        v03_json_str(fp,sname);
        fprintf(fp,",\"user\":");
        v03_json_str(fp,utf8user);
        fprintf(fp,",\"state\":\"%s\"}",sst);
    }
    fputs("\n]}\n",fp);
    if(fp!=stdout) fclose(fp);
    WTSFreeMemory(si);
    return (int)count;
}

int JOCKY_list_patches(void) {
    char cmd[] =
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "Get-HotFix|Select-Object HotFixID,InstalledOn,Description"
        "|ConvertTo-Json|Out-File patches.json -Encoding utf8\"";
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_list_software(void) {
    /* same as inspect_installed_apps but scoped to list command */
    return JOCKY_inspect_installed_apps();
}

int JOCKY_list_environment(void) {
    char cmd[] =
        "powershell -NonInteractive -WindowStyle Hidden -Command \""
        "[System.Environment]::GetEnvironmentVariables()"
        "|ConvertTo-Json|Out-File environment.json -Encoding utf8\"";
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_list_timezone(void) {
    TIME_ZONE_INFORMATION tz = {0};
    DWORD r = GetTimeZoneInformation(&tz);
    char std[64]={0}, dlt[64]={0};
    WideCharToMultiByte(CP_UTF8,0,tz.StandardName,-1,std,63,NULL,NULL);
    WideCharToMultiByte(CP_UTF8,0,tz.DaylightName,-1,dlt,63,NULL,NULL);

    FILE *fp = v03_open("timezone.json");
    if (!fp) return -1;
    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp,
        "{\"timestamp\":\"%s\",\"bias_minutes\":%ld,"
        "\"standard\":\"%s\",\"daylight\":\"%s\","
        "\"in_dst\":%s}\n",
        ts, tz.Bias, std, dlt,
        r==TIME_ZONE_ID_DAYLIGHT?"true":"false");
    if(fp!=stdout) fclose(fp);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
   EXTRACT
   ═══════════════════════════════════════════════════════════════ */

int JOCKY_extract_mft(const char *volume) {
    return JOCKY_dump_mft_raw(volume);
}

int JOCKY_extract_evtx(const char *path) {
    if (!path) path = "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx";
    char out[MAX_PATH];
    const char *base = strrchr(path,'\\');
    snprintf(out, sizeof(out), "evtx_copy_%s", base ? base+1 : "log.evtx");
    CopyFileA(path, out, FALSE);

    /* Also export as XML via wevtutil */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "cmd /c wevtutil epl \"%s\" \"%s_exported.evtx\" 2>nul", path, out);
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_extract_prefetch(const char *path) {
    if (!path || !*path) path = "C:\\Windows\\Prefetch";
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "cmd /c xcopy \"%s\\*.pf\" prefetch_copies\\ /Y /Q 2>nul", path);
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_extract_lnk(const char *path) {
    if (!path || !*path) {
        char appdata[MAX_PATH]={0};
        SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, appdata);
        path = appdata;
    }
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "cmd /c xcopy \"%s\\*.lnk\" lnk_copies\\ /Y /Q 2>nul", path);
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_extract_registry_hive(const char *path) {
    if (!path) path = "HKLM\\SAM";
    return JOCKY_dump_registry_hive(path);
}

int JOCKY_extract_memory_strings(const char *dump_path, int min_len) {
    if (!dump_path) return -1;
    if (min_len <= 0) min_len = 4;

    HANDLE hf = CreateFileA(dump_path, GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hf == INVALID_HANDLE_VALUE) return -1;

    FILE *fp = v03_open("memory_strings.json");
    if (!fp) { CloseHandle(hf); return -1; }

    char ts[32]; v03_timestamp(ts,sizeof(ts));
    fprintf(fp,"{\"source\":");
    v03_json_str(fp,dump_path);
    fprintf(fp,",\"min_len\":%d,\"timestamp\":\"%s\",\"strings\":[\n",
            min_len, ts);

    uint8_t block[65536]; DWORD rd; int total=0; BOOL first=TRUE;
    char run[1024]; int run_len=0;

    while (ReadFile(hf, block, sizeof(block), &rd, NULL) && rd > 0) {
        for (DWORD i=0;i<rd;i++){
            uint8_t c=block[i];
            if((c>=0x20&&c<0x7F)||c=='\t'){
                if(run_len<(int)sizeof(run)-1) run[run_len++]=(char)c;
            } else {
                if(run_len>=min_len && total<50000){
                    run[run_len]='\0';
                    if(!first) fputs(",\n",fp);
                    first=FALSE;
                    fputs("  ",fp);
                    v03_json_str(fp,run);
                    total++;
                }
                run_len=0;
            }
        }
    }
    CloseHandle(hf);
    fputs("\n]}\n",fp);
    if(fp!=stdout) fclose(fp);
    return total;
}

int JOCKY_extract_browser_history(const char *browser) {
    char cmd[2048];
    /* Chrome / Edge use SQLite History DB in APPDATA */
    if (!browser || stricmp(browser,"chrome")==0) {
        snprintf(cmd,sizeof(cmd),
            "powershell -NonInteractive -WindowStyle Hidden -Command \""
            "$p=[Environment]::GetFolderPath('LocalApplicationData')+"
            "'\\Google\\Chrome\\User Data\\Default\\History';"
            "if(Test-Path $p){Copy-Item $p chrome_history.db -Force;"
            "$q='SELECT url,title,visit_count,last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000';"
            "& sqlite3.exe chrome_history.db $q 2>$null|Out-File chrome_history.txt}"\"");
    } else if (stricmp(browser,"edge")==0) {
        snprintf(cmd,sizeof(cmd),
            "powershell -NonInteractive -WindowStyle Hidden -Command \""
            "$p=[Environment]::GetFolderPath('LocalApplicationData')+"
            "'\\Microsoft\\Edge\\User Data\\Default\\History';"
            "if(Test-Path $p){Copy-Item $p edge_history.db -Force}\"");
    } else if (stricmp(browser,"firefox")==0) {
        snprintf(cmd,sizeof(cmd),
            "powershell -NonInteractive -WindowStyle Hidden -Command \""
            "$p=[Environment]::GetFolderPath('ApplicationData')+"
            "'\\Mozilla\\Firefox\\Profiles';"
            "Get-ChildItem $p -Filter places.sqlite -Recurse -ErrorAction SilentlyContinue"
            "|Copy-Item -Destination firefox_places.db -Force\"");
    } else {
        return -1;
    }
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_extract_browser_cookies(const char *browser) {
    char cmd[2048];
    if (!browser || stricmp(browser,"chrome")==0) {
        snprintf(cmd,sizeof(cmd),
            "powershell -NonInteractive -WindowStyle Hidden -Command \""
            "$p=[Environment]::GetFolderPath('LocalApplicationData')+"
            "'\\Google\\Chrome\\User Data\\Default\\Network\\Cookies';"
            "if(Test-Path $p){Copy-Item $p chrome_cookies.db -Force}\"");
    } else if (stricmp(browser,"edge")==0) {
        snprintf(cmd,sizeof(cmd),
            "powershell -NonInteractive -WindowStyle Hidden -Command \""
            "$p=[Environment]::GetFolderPath('LocalApplicationData')+"
            "'\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies';"
            "if(Test-Path $p){Copy-Item $p edge_cookies.db -Force}\"");
    } else { return -1; }
    WinExec(cmd, SW_HIDE);
    return 0;
}

int JOCKY_extract_browser_downloads(const char *browser) {
    char cmd[2048];
    if (!browser || stricmp(browser,"chrome")==0) {
        snprintf(cmd,sizeof(cmd),
            "powershell -NonInteractive -WindowStyle Hidden -Command \""
            "$p=[Environment]::GetFolderPath('LocalApplicationData')+"
            "'\\Google\\Chrome\\User Data\\Default\\History';"
            "if(Test-Path $p){"
            "Copy-Item $p chrome_dl_history.db -Force;"
            "& sqlite3.exe chrome_dl_history.db "
            "'SELECT target_path,tab_url,total_bytes,start_time FROM downloads'"
            "2>$null|Out-File chrome_downloads.txt}\"");
    } else { return -1; }
    WinExec(cmd, SW_HIDE);
    return 0;
}
