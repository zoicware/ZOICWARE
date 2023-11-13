If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

    
    
    
    Add-Type -AssemblyName System.Windows.Forms

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Restore Changes"
$form.Size = New-Object System.Drawing.Size(300, 250)
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

# Create the checkboxes
$checkbox1 = New-Object System.Windows.Forms.CheckBox
$checkbox1.Text = "Enable Updates"
$checkbox1.Location = New-Object System.Drawing.Point(20, 20)
$checkbox1.AutoSize = $true
$form.Controls.Add($checkbox1)

$checkbox2 = New-Object System.Windows.Forms.CheckBox
$checkbox2.Text = "Enable Defender"
$checkbox2.Location = New-Object System.Drawing.Point(20, 50)
$checkbox2.AutoSize = $true
$form.Controls.Add($checkbox2)

$checkbox3 = New-Object System.Windows.Forms.CheckBox
$checkbox3.Text = "Enable Services"
$checkbox3.Location = New-Object System.Drawing.Point(20, 80)
$checkbox3.AutoSize = $true
$form.Controls.Add($checkbox3)


$checkbox4 = New-Object System.Windows.Forms.CheckBox
$checkbox4.Text = "Install Microsoft Store"
$checkbox4.Location = New-Object System.Drawing.Point(20, 110)
$checkbox4.AutoSize = $true
$form.Controls.Add($checkbox4)


# Create the OK button
$okButton = New-Object System.Windows.Forms.Button
$okButton.Text = "OK"
$okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$okButton.Location = New-Object System.Drawing.Point(70, 140)
$form.Controls.Add($okButton)

# Create the Cancel button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Text = "Cancel"
$cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$cancelButton.Location = New-Object System.Drawing.Point(150, 140)
$form.Controls.Add($cancelButton)


# Show the form and wait for user input
$result = $form.ShowDialog()

# Check the selected checkboxes
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {


if($checkbox1.Checked){

 [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Pause Updates First?','Zoic','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  $pause = (Get-Date).AddDays(365); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause

} 

'No'{}

    }

Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "WUServer" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "WUStatusServer" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "UpdateServiceUrlAlternate" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetProxyBehaviorForUpdateDetection" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "UseWUServer" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "2" /f


}



if($checkbox2.Checked){

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

Remove-Item "C:\EnableDefender" -Force -Recurse


}


if($checkbox3.Checked){

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RmSvc" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v "Start" /t REG_DWORD /d "3" /f


}


if($checkbox4.Checked){


$store = Get-ChildItem -Path C:\ -Filter InstallStore.cmd -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
Start-Process -FilePath $store -Verb RunAs -Wait

}



Write-host "UPDATING POLICY" 
gpupdate /force 
}


    
