#allow ps1 scripts to run
if ((Get-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Force).Property -notcontains 'ExecutionPolicy' -or (Get-Item -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Force).Property -notcontains 'ExecutionPolicy' ) {
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f
    Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f

}
else {
    if ((Get-ItemPropertyValue -path 'registry::HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -name 'ExecutionPolicy') -ne 'Bypass' -or (Get-ItemPropertyValue -path 'registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -name 'ExecutionPolicy') -ne 'Bypass') {
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f
        Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f

    }

}

#check if script is in pack
$path = $PSScriptRoot -replace '1 Setup', '_FOLDERMUSTBEONCDRIVE\ZOICWARE.ps1'
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

