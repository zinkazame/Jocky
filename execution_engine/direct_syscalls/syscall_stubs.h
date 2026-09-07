#pragma once
#include <windows.h>

/*
 * DORM — Direct Syscall Wrappers
 * ================================
 * Implemented in syscall_stubs.asm (NASM, x64).
 * Bypass NTDLL entirely — EDR hooks on ntdll stubs are never reached.
 *
 * SSN table (Windows 10 1507 – Windows 11 23H2):
 *   NtQuerySystemInformation   0x36
 *   NtReadVirtualMemory        0x3F
 *   NtQueryDirectoryFile       0x35
 *
 * Link: nasm -f win64 syscall_stubs.asm -o syscall_stubs.obj
 *       clang your_code.c syscall_stubs.obj -o output.exe
 */

NTSTATUS dorm_nt_query_system_information(
    ULONG   SystemInformationClass,
    PVOID   SystemInformation,
    ULONG   SystemInformationLength,
    PULONG  ReturnLength
);

NTSTATUS dorm_nt_read_virtual_memory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  BufferSize,
    PSIZE_T NumberOfBytesRead
);

NTSTATUS dorm_nt_query_directory_file(
    HANDLE  FileHandle,
    HANDLE  Event,
    PVOID   ApcRoutine,
    PVOID   ApcContext,
    PVOID   IoStatusBlock,
    PVOID   FileInformation,
    ULONG   Length,
    ULONG   FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PVOID   FileName,
    BOOLEAN RestartScan
);