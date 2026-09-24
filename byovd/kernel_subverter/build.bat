@echo off
set SOURCES=jocky_byovd_main.c byovd.c backend_rtcore64.c backend_winring0x64.c backend_asrdrv107.c callback_scrubber.c
set OUTPUT=jocky_byovd.exe
set LIBS=-lkernel32 -ladvapi32 -lpsapi

echo [*] JOCKY BYOVD -- clang build
echo [*] sources: %SOURCES%
echo.

clang %SOURCES% -o %OUTPUT% -O2 -Wall -Wno-deprecated-declarations -Wno-format -D_WIN32_WINNT=0x0A00 -masm=intel %LIBS%

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] build SUCCESS: %OUTPUT%
    echo [+] run from Admin PowerShell:
    echo [+]   .\%OUTPUT% ..\..\AsrDrv107.sys
) else (
    echo.
    echo [-] build FAILED -- check errors above
)