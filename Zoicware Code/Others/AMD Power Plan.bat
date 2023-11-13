@echo off
:menu
cls
echo ------------------------------------------------------
echo (1)EDIT CURRENT PLAN WITH AMD SETTINGS
echo (2)IMPORT CUSTOM AMD PLAN
echo.
set /p choice=Enter your choice (1 or 2): 

if "%choice%"=="" goto menu
if "%choice%"=="1" goto option1
if "%choice%"=="2" goto option2

echo Invalid choice. Please enter 1 or 2.
pause
goto menu


:option1
:: Run the powercfg command and capture the output
for /f "tokens=2 delims=:(" %%a in ('powercfg /getactivescheme') do (
    set "ACTIVE_GUID=%%a"
)

set "SUB_PROCESSOR=54533251-82be-4824-96c1-47b60b740d00"

:: set processor performance increase threshold
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 06cadf0e-64ed-448a-8927-ce7bf90eb35d 60
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 06cadf0e-64ed-448a-8927-ce7bf90eb35e 85

:: disable core parking
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 0cc5b647-c1df-4637-891a-dec35c318583 100
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 0cc5b647-c1df-4637-891a-dec35c318584 0

:: set processor performance decrease threshold
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 45
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 12a0ab44-fe28-4fa9-b3bd-4b64f44960a7 60

:: processor core parking increase and decrease time
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 2ddd5a84-5a71-437e-912a-db0b8c788732 100
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 4009efa7-e72d-4cba-9edf-91084ea8cbc3 100
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% d8edeb9b-95cf-4f95-a73c-b061973693c9 100
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% dfd10d17-d5eb-45dd-877a-9a34ddd15c82 100

:: processor performance decrease policy (ideal)
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 40fbefc7-2e9d-4d25-a185-0cfd8574bac6 0
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 40fbefc7-2e9d-4d25-a185-0cfd8574bac7 0
:: decrease time
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 7f2492b6-60b1-45e5-ae55-773f8cd5caec 100

:: processor performance increase policy (rocket/agressive)
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 465e1f50-b610-473a-ab58-00d1077dc418 2
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 465e1f50-b610-473a-ab58-00d1077dc419 3

:: set boost mode (enabled and agressive)
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% be337238-0d82-4146-a960-4f3749d470c7 2


:: set usb and pcie power saving modes off (avoid amd usb issues)
powercfg /setacvalueindex %ACTIVE_GUID% 2a737441-1930-4402-8d77-b2bebba308a3 0853a681-27c8-4100-a2fd-82013e970683 0
powercfg /setacvalueindex %ACTIVE_GUID% 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /setacvalueindex %ACTIVE_GUID% 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0
powercfg /setacvalueindex %ACTIVE_GUID% 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0
powercfg /setacvalueindex %ACTIVE_GUID% 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0
powercfg /setacvalueindex %ACTIVE_GUID% 0012ee47-9041-4b5d-9b77-535fba8b1442 0b2d69d7-a2a1-449c-9680-f91c70521c60 0
powercfg /setacvalueindex %ACTIVE_GUID% 0012ee47-9041-4b5d-9b77-535fba8b1442 51dea550-bb38-4bc4-991b-eacf37be5ec8 100

:: disable deep sleep and throttle states
powercfg /setacvalueindex %ACTIVE_GUID% 2e601130-5351-4d9d-8e04-252966bad054 d502f7ee-1dc7-4efd-a55d-f04b6f5c0545 0
powercfg /setacvalueindex %ACTIVE_GUID% %SUB_PROCESSOR% 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb 0
exit

:option2
:: Set the URL of the ZIP file
set "zipUrl=https://github.com/zoicware/AMDPLAN/archive/refs/heads/main.zip"

:: Download the ZIP file
powershell -command "& { Invoke-WebRequest -Uri '%zipUrl%' -OutFile 'download.zip' | Wait-Event }"

:: Check if the download was successful
if %errorlevel% neq 0 (
    echo Failed to download the ZIP file.
    exit /b 1
)

:: Extract the contents of the ZIP file
powershell -command "& { Expand-Archive -Path 'download.zip' -DestinationPath '%~dp0' -Force | Wait-Event }"

:: Check if the extraction was successful
if %errorlevel% neq 0 (
    echo Failed to extract the ZIP file.
    exit /b 1
)

:: Get path to pow file
for /f "delims=" %%i in ('powershell -command "& { Get-ChildItem -Path C:\ -Filter 'zoic''s ultimate performance(amd).pow' -ErrorAction SilentlyContinue -Recurse | Select-Object -First 1 | ForEach-Object { $_.FullName; } }"') do set "path=%%i"

:: Import plan
C:\Windows\System32\powercfg /import "%path%" 55555555-5555-5555-5555-555555555555 
C:\Windows\System32\powercfg /setactive 55555555-5555-5555-5555-555555555555

:: Cleanup
del download.zip
rd /s /q AMDPLAN-main
exit


