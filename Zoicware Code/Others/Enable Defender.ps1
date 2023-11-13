#Enable defender by zoic

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

    #downloading necessary files
Write-Host "downloading necessary files..."
Invoke-RestMethod 'https://github.com/zoicware/EnableDefender/archive/refs/heads/main.zip' -OutFile "C:\Defender.zip"
Expand-Archive "C:\Defender.zip" -DestinationPath "C:\"
Remove-Item "C:\Defender.zip"
Expand-Archive "C:\EnableDefender-main\EnableDefender.zip" -DestinationPath "C:\"
Remove-Item  "C:\EnableDefender-main" -Force -Recurse


Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware"  /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring"  /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen"  /f
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Cache Maintenance'} | Enable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Cleanup'} | Enable-ScheduledTask 
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Scheduled Scan'} | Enable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Verification'} | Enable-ScheduledTask

$defender = Get-ChildItem -Path C:\ -Filter EnableDefend.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
 $nsudo = Get-ChildItem -Path C:\ -Filter NSudoLG.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
       $arguments = "-U:T -P:E -M:S "+"`"$defender`"" 
        Start-Process -FilePath $nsudo -ArgumentList $arguments -Wait


gpupdate /force

Remove-Item "C:\EnableDefender" -Force -Recurse


[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer?','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {

  Restart-Computer
 }

'No'{

}

}