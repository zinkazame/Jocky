#include <stdio.h>
#include <windows.h>
#include "unhook.h"

static const char *
error_name(DWORD code)
{
    switch (code) {
        case ERROR_SUCCESS:           return "Success";
        case ERROR_ACCESS_DENIED:     return "Access Denied";
        case ERROR_FILE_NOT_FOUND:    return "File Not Found";
        case ERROR_PATH_NOT_FOUND:    return "Path Not Found";
        case ERROR_BAD_FORMAT:        return "Bad PE Format";
        case ERROR_NOT_FOUND:         return ".text section not found in PE";
        case ERROR_NOT_ENOUGH_MEMORY: return "Not Enough Memory";
        case ERROR_INVALID_HANDLE:    return "Invalid Handle";
        default:                      return "Unknown";
    }
}

int main(void)
{
    printf("DORM Phase 8 -- API Unhooker Verification\n");
    printf("==========================================\n\n");

    printf("Unhooking NTDLL...\n");

    BOOL ok = dorm_unhook_ntdll();

    if (ok) {
        printf("dorm_unhook_ntdll: success\n");
        printf("NTDLL .text section restored from disk copy.\n");
    } else {
        DWORD err = GetLastError();
        printf("dorm_unhook_ntdll: FAILED -- GetLastError() = %lu (%s)\n",
               (unsigned long)err, error_name(err));
        return 1;
    }

    /* Bonus: call NtQuerySystemInformation through restored NTDLL stub */
    typedef LONG (NTAPI *PFN_NTQSI)(ULONG, PVOID, ULONG, PULONG);
    PFN_NTQSI NtQSI = (PFN_NTQSI)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"),
        "NtQuerySystemInformation"
    );

    if (NtQSI) {
        BYTE  buf[256] = {0};
        ULONG ret      = 0;
        LONG  status   = NtQSI(0, buf, sizeof(buf), &ret);

        printf("\nPost-unhook NtQuerySystemInformation via NTDLL:\n");
        printf("  status  = 0x%08lX\n", (unsigned long)status);
        printf("  ret_len = %lu bytes\n", (unsigned long)ret);

        if (status == 0 || status == (LONG)0xC0000004L) {
            printf("  -> NTDLL stub alive and callable after restore\n");
        } else {
            printf("  -> Unexpected status -- .text may be corrupt\n");
            return 1;
        }
    } else {
        printf("\nWARN: GetProcAddress could not resolve NtQuerySystemInformation\n");
    }

    printf("\nPhase 8 complete.\n");
    return 0;
}