import sys

files_c = [
    r"D:\Dinku\projects\JOCKY\byovd\kernel_subverter\backend_winring0x64.c",
    r"D:\Dinku\projects\JOCKY\byovd\kernel_subverter\callback_scrubber.c",
]
bat = r"D:\Dinku\projects\JOCKY\byovd\kernel_subverter\build.bat"

for path in files_c:
    with open(path, "r", encoding="utf-8") as f:
        c = f.read()
    if "<psapi.h>" not in c:
        c = c.replace(
            "#include <windows.h>",
            "#include <windows.h>\n#include <psapi.h>",
            1
        )
        with open(path, "w", encoding="utf-8") as f:
            f.write(c)
        print(f"[+] psapi.h added: {path}")
    else:
        print(f"[=] already present: {path}")

with open(bat, "r", encoding="ascii", errors="replace") as f:
    c = f.read()
if "-lpsapi" not in c:
    c = c.replace(
        "-lkernel32 -ladvapi32",
        "-lkernel32 -ladvapi32 -lpsapi"
    )
    with open(bat, "w", encoding="ascii") as f:
        f.write(c)
    print("[+] -lpsapi added to build.bat")
else:
    print("[=] -lpsapi already in build.bat")

print("done")