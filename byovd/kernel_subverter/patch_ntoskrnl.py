import sys, re

WINRING = r"D:\Dinku\projects\JOCKY\byovd\kernel_subverter\backend_winring0x64.c"
SCRUBBER = r"D:\Dinku\projects\JOCKY\byovd\kernel_subverter\callback_scrubber.c"

NEW_WINRING_FN = r"""static BOOL _get_ntoskrnl_info(uint64_t *kva_out, uint64_t *size_out)
{
    /* EnumDeviceDrivers: ntoskrnl is always index 0.
     * Documented stable API -- no NtQSI struct layout guessing. */
    LPVOID kbases[512] = {0};
    DWORD  needed      = 0;

    if (!EnumDeviceDrivers(kbases, sizeof(kbases), &needed) || !needed) {
        printf("[winring0] EnumDeviceDrivers failed: %lu\n", GetLastError());
        return FALSE;
    }
    *kva_out = (uint64_t)(uintptr_t)kbases[0];

    /* SizeOfImage from PE header on disk */
    *size_out = 0;
    HANDLE f = CreateFileA("C:\\Windows\\System32\\ntoskrnl.exe",
                            GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        HANDLE m = CreateFileMappingA(f, NULL, PAGE_READONLY, 0, 0, NULL);
        if (m) {
            uint8_t *base = (uint8_t *)MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0);
            if (base) {
                IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
                IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
                *size_out = nt->OptionalHeader.SizeOfImage;
                UnmapViewOfFile(base);
            }
            CloseHandle(m);
        }
        CloseHandle(f);
    }
    if (!*size_out) { *size_out = 0x2000000; }

    printf("[winring0] ntoskrnl KVA=0x%016llX  size=0x%llX\n",
           (unsigned long long)*kva_out, (unsigned long long)*size_out);
    return (*kva_out != 0);
}"""

NEW_SCRUBBER_FN = r"""static uintptr_t get_ntoskrnl_base(void) {
    LPVOID kbases[512] = {0};
    DWORD  needed      = 0;
    if (!EnumDeviceDrivers(kbases, sizeof(kbases), &needed) || !needed) {
        printf("[scrubber] EnumDeviceDrivers failed: %lu\n", GetLastError());
        return 0;
    }
    uintptr_t base = (uintptr_t)kbases[0];
    printf("[scrubber] ntoskrnl KVA: 0x%016llX\n", (unsigned long long)base);
    return base;
}"""

def replace_function(path, fn_name, new_body):
    with open(path, 'r', encoding='utf-8') as f:
        content = f.read()
    # find function start to closing brace
    pattern = re.compile(
        r'(static\s+\w[\w\s\*]+\s+' + re.escape(fn_name) +
        r'\s*\([^)]*\)\s*\{)',
        re.DOTALL)
    m = pattern.search(content)
    if not m:
        print(f"  ERROR: {fn_name} not found in {path}")
        return False
    start = m.start()
    # find matching closing brace
    depth = 0
    i = m.start()
    found_open = False
    end = -1
    while i < len(content):
        if content[i] == '{':
            depth += 1
            found_open = True
        elif content[i] == '}':
            depth -= 1
            if found_open and depth == 0:
                end = i + 1
                break
        i += 1
    if end == -1:
        print(f"  ERROR: could not find end of {fn_name}")
        return False
    content = content[:start] + new_body + content[end:]
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"  [+] {fn_name} replaced in {path}")
    return True

replace_function(WINRING,   "_get_ntoskrnl_info", NEW_WINRING_FN)
replace_function(SCRUBBER,  "get_ntoskrnl_base",  NEW_SCRUBBER_FN)
print("done")