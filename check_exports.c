#include <stdio.h>
#include <windows.h>

int main(void) {
    HMODULE h = LoadLibraryA("execution_engine\\\\reflective_loader\\\\test_dll\\\\test_dll.dll");
    if (!h) { printf("LoadLibraryA failed: %lu\n", GetLastError()); return 1; }

    ULONG_PTR base = (ULONG_PTR)h;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[0].VirtualAddress;

    if (!exp_rva) { printf("No export directory\n"); return 1; }

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);

    printf("DLL name: %s\n", (char*)(base + exp->Name));
    printf("Exported functions: %lu\n", exp->NumberOfNames);
    for (DWORD i = 0; i < exp->NumberOfNames; i++)
        printf("  [%lu] %s\n", i, (char*)(base + names[i]));

    FreeLibrary(h);
    return 0;
}
