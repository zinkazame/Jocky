@echo off
REM prepare_usb.bat -- One-click USB forensic deployment
REM Run as Admin on INVESTIGATOR machine
REM Usage: prepare_usb.bat E: NTRO-2026-001 INV-ALPHA
REM        prepare_usb.bat E: NTRO-2026-001 INV-ALPHA 192.168.1.100

setlocal

set USB_DRIVE=%1
set CASE_ID=%2
set INVESTIGATOR=%3
set C2_IP=%4

if "%USB_DRIVE%"=="" (
    echo Usage: prepare_usb.bat ^<USB_DRIVE^> ^<CASE_ID^> ^<INVESTIGATOR^> [C2_IP]
    echo Example: prepare_usb.bat E: NTRO-2026-001 INV-ALPHA 192.168.1.100
    exit /b 1
)
if "%CASE_ID%"=="" set CASE_ID=NTRO-2026-001
if "%INVESTIGATOR%"=="" set INVESTIGATOR=INV-ALPHA

echo.
echo  JOCKY -- USB Forensic Deployment Preparation
echo  =============================================
echo  USB Drive:    %USB_DRIVE%
echo  Case ID:      %CASE_ID%
echo  Investigator: %INVESTIGATOR%
echo.

REM activate venv
call D:\Dinku\projects\JOCKY\.venv\Scripts\activate.bat

REM run USB deploy
set ARGS=--case %CASE_ID% --investigator %INVESTIGATOR% --usb %USB_DRIVE%
if NOT "%C2_IP%"=="" set ARGS=%ARGS% --c2 %C2_IP%

cd /d D:\Dinku\projects\JOCKY
python usb_deploy/usb_deploy.py %ARGS%

endlocal