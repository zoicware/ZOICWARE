@echo off

reg query "HKCU\Software\Spotify" >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: You Must Install Spotify First.
    pause
    exit /b 1
)



powershell.exe -WindowStyle Hidden -Command "$path = \"$env:APPDATA\Spotify\prefs\"; Add-Content $path -Value 'ui.hardware_acceleration=false' -Force"
