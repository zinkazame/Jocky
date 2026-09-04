/*
 * JOCKY — Phase 10 test DLL (LoadLibraryA loader)
 * =================================================
 * On DLL_PROCESS_ATTACH, writes a marker file.
 * Also exports a function that takes a file path and loads it via LoadLibraryA.
 */

#include <windows.h>

#define MARKER_PATH L"C:\\Windows\\Temp\\jocky_reflect_test.txt"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL;
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH) {
        HANDLE hf = CreateFileW(
            MARKER_PATH,
            GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL, NULL
        );
        if (hf != INVALID_HANDLE_VALUE) {
            const char msg[] = "JOCKY Phase 10 reflective injection: DllMain ran.\r\n";
            DWORD written = 0;
            WriteFile(hf, msg, sizeof(msg) - 1, &written, NULL);
            CloseHandle(hf);
        }
    }
    return TRUE;
}

/* Exported function: loads a library by path using LoadLibraryA */
__declspec(dllexport) BOOL WINAPI LoadDllRemote(LPCSTR dll_path)
{
    HMODULE h = LoadLibraryA(dll_path);
    return h != NULL;
}