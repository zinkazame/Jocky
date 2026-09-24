path = r"D:\Dinku\projects\JOCKY\byovd\kernel_subverter\backend_winring0x64.c"
with open(path, "r", encoding="utf-8") as f:
    c = f.read()

# extend scan END from 4GB to 32GB
c = c.replace(
    "const uint64_t END   = 0x100000000ULL;     /* 4 GB   */",
    "const uint64_t END   = 0x800000000ULL;     /* 32 GB  */"
)

# add progress print every 512 probes so we can see it working
c = c.replace(
    "    for (uint64_t pa = START; pa < END; pa += STEP) {\n        DWORD dw0 = 0;\n        probes++;",
    """    for (uint64_t pa = START; pa < END; pa += STEP) {
        DWORD dw0 = 0;
        probes++;
        if (probes % 512 == 0)
            printf("[winring0]   scan progress: PA=0x%09llX  probes=%u\\n",
                   (unsigned long long)pa, probes);"""
)

with open(path, "w", encoding="utf-8") as f:
    f.write(c)
print("[+] scan range extended to 32GB")

# verify
for i, line in enumerate(open(path, encoding="utf-8")):
    if "32 GB" in line or "progress" in line:
        print(f"  line {i+1}: {line.rstrip()}")