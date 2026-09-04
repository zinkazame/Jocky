/*
 * JOCKY — Phase 7 verification harness
 *
 * Build:
 *   nasm -f win64 syscall_stubs.asm -o syscall_stubs.obj
 *   clang test_stubs.c syscall_stubs.obj -o test_stubs.exe -lntdll
 *
 * Expected:
 *   STATUS_SUCCESS           (0x00000000) → buffer was large enough
 *   STATUS_INFO_LENGTH_MISMATCH (0xC0000004) → buffer too small, but
 *     kernel was reached and responded correctly. Both are pass.
 */

#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "syscall_stubs.h"

/* SystemBasicInformation — class 0. Tiny struct, always fits in 256 bytes. */
#define SystemBasicInformation 0

static void check(const char *name, NTSTATUS s, ULONG ret_len) {
    printf("%-40s status=0x%08X  ret_len=%lu\n", name, (unsigned)s, (unsigned long)ret_len);
    if (s == 0x00000000 || s == 0xC0000004) {
        printf("  → kernel reached — syscall stub operational\n\n");
    } else {
        printf("  → UNEXPECTED STATUS — check SSN or calling convention\n\n");
    }
}

int main(void) {
    printf("JOCKY Phase 7 — Direct Syscall Verification\n");
    printf("============================================\n\n");

    /* ── Test 1: NtQuerySystemInformation ── */
    {
        BYTE  buf[256] = {0};
        ULONG ret_len  = 0;
        NTSTATUS s = jocky_nt_query_system_information(
            SystemBasicInformation, buf, sizeof(buf), &ret_len
        );
        check("NtQuerySystemInformation", s, ret_len);
    }

    /* ── Test 2: NtReadVirtualMemory — read our own stack ── */
    /* Reading our own process memory at a known-good address.
     * GetCurrentProcess() returns a pseudo-handle (-1) valid for this. */
    {
        BYTE   src[64]  = {0xDE, 0xAD, 0xBE, 0xEF};
        BYTE   dst[64]  = {0};
        SIZE_T got      = 0;
        NTSTATUS s = jocky_nt_read_virtual_memory(
            GetCurrentProcess(),   /* pseudo-handle, always valid */
            src,                   /* source: our own stack buffer */
            dst,                   /* destination: another stack buffer */
            sizeof(src),
            &got
        );
        /* Expect STATUS_SUCCESS — same process, readable memory */
        printf("%-40s status=0x%08X  bytes_read=%zu\n",
               "NtReadVirtualMemory", (unsigned)s, got);
        if (s == 0 && got == sizeof(src) && dst[0] == 0xDE && dst[1] == 0xAD) {
            printf("  → read verified (0xDEADBEEF in dst) — stub operational\n\n");
        } else if (s == 0) {
            printf("  → kernel reached — stub operational\n\n");
        } else {
            printf("  → UNEXPECTED STATUS — check SSN or calling convention\n\n");
        }
    }

    /* ── Test 3: NtQueryDirectoryFile — we don't have a file handle here.
     *    Pass NULL handle → expect STATUS_INVALID_HANDLE (0xC0000008).
     *    This still proves the stub reached the kernel and got a real response
     *    rather than crashing — the calling convention is correct.          */
    {
        IO_STATUS_BLOCK iosb = {0};
        BYTE            buf[512] = {0};
        ULONG           ret_len  = 0;
        NTSTATUS s = jocky_nt_query_directory_file(
            NULL,   /* invalid handle — kernel returns C0000008 */
            NULL, NULL, NULL,
            &iosb,
            buf, sizeof(buf),
            1,      /* FileDirectoryInformation */
            FALSE, NULL, FALSE
        );
        printf("%-40s status=0x%08X\n", "NtQueryDirectoryFile (null handle)", (unsigned)s);
        if (s == 0xC0000008 /* STATUS_INVALID_HANDLE */ || s == 0) {
            printf("  → kernel reached — stub operational\n\n");
        } else {
            printf("  → UNEXPECTED STATUS — check SSN or calling convention\n\n");
        }
    }

    return 0;
}