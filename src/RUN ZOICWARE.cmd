@(set "0=%~f0"^)#) & powershell -nop -ExecutionPolicy Bypass -c "Unblock-File $env:0; iex([io.file]::ReadAllText($env:0))" & exit /b


#allow ps1 scripts to run
if ((Get-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Force).Property -notcontains 'ExecutionPolicy' -or (Get-Item -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Force).Property -notcontains 'ExecutionPolicy' ) {
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null
    if(Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue){
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'EnableScripts' /t REG_DWORD /d '1' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
    }
}
else {
    if ((Get-ItemPropertyValue -path 'registry::HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -name 'ExecutionPolicy') -ne 'Bypass' -or (Get-ItemPropertyValue -path 'registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -name 'ExecutionPolicy') -ne 'Bypass') {
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null
        Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null
         if(Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' -ErrorAction SilentlyContinue){
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'EnableScripts' /t REG_DWORD /d '1' /f >$null
            Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
        }
    }

}

$LocationCache = "$env:USERPROFILE\zLocation.tmp"
if(test-path $LocationCache){
    $path = Get-Content $LocationCache
    if(test-path $path){
        $script = $path
    }
}
if(!$script){
$sysDrive = $env:SystemDrive + '\'
$zoicwareOS = (Get-ChildItem -Path $sysDrive -Filter zoicwareOS* -Recurse -Directory -ErrorAction SilentlyContinue -Force | Where-Object Name -NotIn '$Recycle.Bin' | Select-Object -First 1).FullName
$path = "$zoicwareOS\_FOLDERMUSTBEONCDRIVE\ZOICWARE.ps1"
if (Test-Path $path) {
    New-Item $LocationCache -Value $path -Force | Out-Null
    $script = $path
}
else {
    #search on c drive if script isnt found
    #$sysDrive = $env:SystemDrive + '\'
    $script = (Get-ChildItem -Path $sysDrive -Filter ZOICWARE.ps1 -Recurse -File -ErrorAction SilentlyContinue -Force | Where-Object Name -NotIn '$Recycle.Bin' | Select-Object -First 1).FullName
    if($script){
      New-Item $LocationCache -Value $script -Force | Out-Null
    }
}

if ($script -eq $null) {
    Write-Error 'ZOICWARE.ps1 NOT Found'
    $inputKey = Read-Host 'Press Any Key to EXIT'
    if ($inputKey) { exit }
}
else {
    Unblock-File $script
    &$script
}
}
else{
    Unblock-File $script
    &$script
}


