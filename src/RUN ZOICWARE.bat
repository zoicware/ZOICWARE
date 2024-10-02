@(set "0=%~f0"^)#) & powershell -nop -ExecutionPolicy Bypass -c "iex([io.file]::ReadAllText($env:0))" & exit /b


#allow ps1 scripts to run
if ((Get-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Force).Property -notcontains 'ExecutionPolicy' -or (Get-Item -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Force).Property -notcontains 'ExecutionPolicy' ) {
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null

}
else {
    if ((Get-ItemPropertyValue -path 'registry::HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -name 'ExecutionPolicy') -ne 'Bypass' -or (Get-ItemPropertyValue -path 'registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -name 'ExecutionPolicy') -ne 'Bypass') {
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null
        Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null

    }

}

#check if script is in pack
$exePath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
$root = Split-Path -Path $exePath -Parent
$path = $root + '\_FOLDERMUSTBEONCDRIVE\ZOICWARE.ps1'
if (Test-Path $path) {
    $script = $path
}
else {
    #search on c drive if script isnt found
    $sysDrive = $env:SystemDrive + '\'
    $script = (Get-ChildItem -Path $sysDrive -Filter ZOICWARE.ps1 -Recurse -File -ErrorAction SilentlyContinue -Force | Where-Object Name -NotIn '$Recycle.Bin' | Select-Object -First 1).FullName
}

if ($script -eq $null) {
    Write-Error 'ZOICWARE.ps1 NOT Found'
    $inputKey = Read-Host 'Press Any Key to EXIT'
    if ($inputKey) { exit }
}
else {
    &$script
}

