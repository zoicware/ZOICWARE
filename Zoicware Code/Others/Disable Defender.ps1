#DISABLE DEFENDER SCRIPT BY ZOIC


If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

    try{
if((Get-ItemPropertyValue -path registry::HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -name "ExecutionPolicy") -ne "Bypass" -or (Get-ItemPropertyValue -path registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -name "ExecutionPolicy") -ne "Bypass"){
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Bypass" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Bypass" /f


}

}catch{
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Bypass" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Bypass" /f

}

$uacON = $false
#disable uac
if((Get-ItemPropertyValue -path registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -name "EnableLUA") -ne "0"){
$uacON = $true 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
kill -name 'sihost' -force
}
#restart explorer

sleep 2






$path = "C:\DisableDefender"

if(-Not(Test-Path $path -PathType Leaf)){
#downloading necessary files
Write-Host "downloading necessary files..."
Invoke-RestMethod 'https://github.com/zoicware/Defender/archive/refs/heads/main.zip' -OutFile "C:\Defender.zip"
Expand-Archive "C:\Defender.zip" -DestinationPath "C:\"
Remove-Item "C:\Defender.zip"
Expand-Archive "C:\Defender-main\DisableDefender.zip" -DestinationPath "C:\"
Remove-Item  "C:\Defender-main" -Force -Recurse
}





#disables defender through gp edit
Write-Host "Disabling Defender with Group Policy" 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Cache Maintenance'} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Cleanup'} | Disable-ScheduledTask 
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Scheduled Scan'} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Verification'} | Disable-ScheduledTask
    

#apply gpedit tweaks

gpupdate /force


#searching c drive for bat file and power run and then running the bat file with power run
Write-Host "Disabling Services"

 $defender = Get-ChildItem -Path C:\ -Filter DisableDefend.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
 $nsudo = Get-ChildItem -Path C:\ -Filter NSudoLG.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
       $arguments = "-U:T -P:E -M:S "+"`"$defender`"" 
        Start-Process -FilePath $nsudo -ArgumentList $arguments -Wait







#clean up files
Remove-Item "C:\DisableDefender" -Force -Recurse



[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer?','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {

  if($uacON){
  #setting uac back to default
  Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "1" /f

  }

  Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f

  #you can guess what this does
Restart-Computer
 }

'No'{

Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f


}

}