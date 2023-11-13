@(set "0=%~f0"^)#) & powershell -nop -c iex([io.file]::ReadAllText($env:0)) & exit /b
sp 'HKCU:\Volatile Environment' 'Windows_Optimizer' @'


$host.ui.RawUI.WindowTitle = 'ZOICWARE'  

#windows 10 22h2 automatic setup script by zoic and help from Narf

#if not ran as admin ask for admin rights
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



#changes console to black
function color ($bc,$fc) {
$a = (Get-Host).UI.RawUI
$a.BackgroundColor = $bc
$a.ForegroundColor = $fc ; cls}	

color "black" "white"


$registry = $false

$installPacks = {
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Install DX, C++ Packages and NET 3.5?','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  
  #searches c drive for respective installers and creates shortcuts 


  Write-host "------------------------------------"
  Write-host "|                                  |"
  Write-host "|       Packges Installing...      |"
  Write-host "|                                  |"
  Write-host "------------------------------------"

  $pathDX = Get-ChildItem -Path C:\ -Filter DIRECTXSETUP.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\DIRECTXSETUP.lnk")
$Shortcut.TargetPath = ([string]$pathDX)
$Shortcut.Arguments = "/silent"
$Shortcut.Save()
  
  $pathCpp = Get-ChildItem -Path C:\ -Filter VisualCppRedist_AIO_x86_x64.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Cpp.lnk")
$Shortcut.TargetPath = ([string]$pathCpp)
$Shortcut.Arguments = "/ai /gm2"
$Shortcut.Save()

  start-process -FilePath "C:\DIRECTXSETUP.lnk" -Wait

  start-process -FilePath "C:\Cpp.lnk" -Wait 

  $vclibs = Get-ChildItem -Path C:\ -Filter MicrosoftVCLibs14.Appx -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  Add-AppxPackage -path ([String]$vclibs)

  [System.Windows.Forms.MessageBox]::Show('Please make sure your USB Flash Drive is plugged in.', 'Installing Net 3.5')
  
    $pathNET = Get-ChildItem -Path C:\ -Filter NET_Framework_Installer.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$pathNET) -Wait

  Remove-item "C:\DIRECTXSETUP.lnk" -force
  Remove-item "C:\Cpp.lnk" -force
 
  [System.Windows.Forms.MessageBox]::Show('Packages Installed.')
 }

'No'{}

}

}

$importReg = {
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Import Registry Tweaks?','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  
  $registry = $true
  $reg = Get-ChildItem -Path C:\ -Filter RegTweak.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
       & $reg
  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d "4" /f
  [System.Windows.Forms.MessageBox]::Show('Registry Tweaks Applied.')
 }

'No'{}

}

}



$removeSchdTasks = {

$schdTasks = $false
#question msg box
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Remove Scheduled Tasks?','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  
  #removes all schd tasks 
Get-ScheduledTask -TaskPath '*' | Stop-ScheduledTask
Unregister-ScheduledTask -TaskPath '*' -Confirm:$false
Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineCore*'} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineUA*'} | Disable-ScheduledTask

#restoring two tasks that are needed
New-Item -Path C:\Windows\System32\Tasks\Microsoft\Windows\'TextServicesFramework\MsCtfMonitor' -ItemType File -Force
$content = '<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <SecurityDescriptor>D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)</SecurityDescriptor>
    <Source>$(@%systemRoot%\system32\MsCtfMonitor.dll,-1000)</Source>
    <Description>$(@%systemRoot%\system32\MsCtfMonitor.dll,-1001)</Description>
    <URI>Microsoft\Windows\TextServicesFramework\MsCtfMonitor</URI>
  </RegistrationInfo>
  <Principals>
    <Principal id="AnyUser">
      <GroupId>S-1-5-32-545</GroupId>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Hidden>true</Hidden>
    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
    <Priority>5</Priority>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
  </Settings>
  <Triggers>
    <LogonTrigger />
  </Triggers>
  <Actions Context="AnyUser">
    <ComHandler>
      <ClassId>{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}</ClassId>
    </ComHandler>
  </Actions>
</Task>' | out-file C:\Windows\System32\Tasks\Microsoft\Windows\TextServicesFramework\MsCtfMonitor

schtasks /create /xml C:\Windows\System32\Tasks\Microsoft\Windows\TextServicesFramework\MsCtfMonitor /tn "\MyTasks\FixSearch"  
  
  #searches c drive for the xml and imports it to task schd
$pathSPP = Get-ChildItem -Path C:\ -Filter SvcRestartTask.xml -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
schtasks /create /xml ([String]$pathSPP) /tn "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" 
  
$schdTasks = $true
[System.Windows.Forms.MessageBox]::Show('Scheduled Tasks have been removed.')
 }

'No'{}

}



}



$groupPolicy = {

$updates = $false

Add-Type -AssemblyName System.Windows.Forms

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Group Policy Tweaks"
$form.Size = New-Object System.Drawing.Size(300, 200)
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

# Create the checkboxes
$checkbox1 = New-Object System.Windows.Forms.CheckBox
$checkbox1.Text = "Disable Updates"
$checkbox1.Location = New-Object System.Drawing.Point(20, 20)
$checkbox1.AutoSize = $true
$form.Controls.Add($checkbox1)

$checkbox2 = New-Object System.Windows.Forms.CheckBox
$checkbox2.Text = "Disable Defender"
$checkbox2.Location = New-Object System.Drawing.Point(20, 50)
$checkbox2.AutoSize = $true
$form.Controls.Add($checkbox2)

$checkbox3 = New-Object System.Windows.Forms.CheckBox
$checkbox3.Text = "Disable Telemetry"
$checkbox3.Location = New-Object System.Drawing.Point(20, 80)
$checkbox3.AutoSize = $true
$form.Controls.Add($checkbox3)


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
  $updates = $true
  #disables updates through gp edit and servives
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "WUServer" /t REG_SZ /d "https://DoNotUpdateWindows10.com/" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "WUStatusServer" /t REG_SZ /d "https://DoNotUpdateWindows10.com/" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "UpdateServiceUrlAlternate" /t REG_SZ /d "https://DoNotUpdateWindows10.com/" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetProxyBehaviorForUpdateDetection" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "UseWUServer" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f
Disable-ScheduledTask -TaskName "Microsoft\Windows\WindowsUpdate\Scheduled Start" -Erroraction SilentlyContinue

}


if($checkbox2.Checked){

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
    

#searching c drive for bat file and power run and then running the bat file with power run
Write-Host "Disabling Services"

 $defender = Get-ChildItem -Path C:\ -Filter DisableDefend.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
 $nsudo = Get-ChildItem -Path C:\ -Filter NSudoLG.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
       $arguments = "-U:T -P:E -M:S "+"`"$defender`"" 
        Start-Process -FilePath $nsudo -ArgumentList $arguments -Wait

}

  
if($checkbox3.Checked){
  #removes telemetry through gp edit
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\System\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\System\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f

if($schdTasks -eq $false){

Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

    }

}



    #updates group policy so that the previous changes are applied 
    gpupdate /force
  }

  }


$disableServices = {

$services = $false
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Do you want to disable Bluetooth, Printing and others?','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  
  $services = $true
  #disables some unecessary services 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Fax" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\defragsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RmSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /v "Start" /t REG_DWORD /d "4" /f
[System.Windows.Forms.MessageBox]::Show('Services have been disabled.')
 }

'No'{}

}

}

$debloat = {

#creating powershell list box 
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Debloat'
$form.Size = New-Object System.Drawing.Size(300,300)
$form.StartPosition = 'CenterScreen'

$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(75,230)
$OKButton.Size = New-Object System.Drawing.Size(75,23)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(150,230)
$CancelButton.Size = New-Object System.Drawing.Size(75,23)
$CancelButton.Text = 'Cancel'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,10)
$label.Size = New-Object System.Drawing.Size(280,20)
$label.Text = 'Please select what debloat option you want:'
$form.Controls.Add($label)

    $checkbox2 = New-Object System.Windows.Forms.RadioButton
    $checkbox2.Location = new-object System.Drawing.Size(10,40)
    $checkbox2.Size = new-object System.Drawing.Size(150,20)
    $checkbox2.Text = "Debloat All"
    $checkbox2.Checked = $false
    $Form.Controls.Add($checkbox2)  
    

    $checkbox3 = New-Object System.Windows.Forms.RadioButton
    $checkbox3.Location = new-object System.Drawing.Size(10,70)
    $checkbox3.Size = new-object System.Drawing.Size(170,30)
    $checkbox3.Text = "Keep Store,Xbox and Edge"
    $checkbox3.Checked = $false
    $Form.Controls.Add($checkbox3)
    

    $checkbox4 = New-Object System.Windows.Forms.RadioButton
    $checkbox4.Location = new-object System.Drawing.Size(10,110)
    $checkbox4.Size = new-object System.Drawing.Size(170,30)
    $checkbox4.Text = "Keep Store and Xbox"
    $checkbox4.Checked = $false
    $Form.Controls.Add($checkbox4)
   

    $checkbox5 = New-Object System.Windows.Forms.RadioButton
    $checkbox5.Location = new-object System.Drawing.Size(10,150)
    $checkbox5.Size = new-object System.Drawing.Size(200,20)
    $checkbox5.Text = "Debloat All Keep Edge"
    $checkbox5.Checked = $false
    $Form.Controls.Add($checkbox5)
    

    $checkbox6 = New-Object System.Windows.Forms.RadioButton
    $checkbox6.Location = new-object System.Drawing.Size(10,190)
    $checkbox6.Size = new-object System.Drawing.Size(200,20)
    $checkbox6.Text = "Debloat All Keep Store"
    $checkbox6.Checked = $false
    $Form.Controls.Add($checkbox6)
    



$form.Topmost = $true

$result = $form.ShowDialog()

#debloating based on user selection

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    
    

    if($checkbox2.Checked)
    {
        
  $debloat = Get-ChildItem -Path C:\ -Filter debloatALL.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        & $debloat
      
  $edge = Get-ChildItem -Path C:\ -Filter EdgeRemoval.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$edge) -Wait
  Remove-item -Path "C:\Scripts" -Force -Recurse 
Reg.exe add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f
  $unpin = Get-ChildItem -Path C:\ -Filter unpin.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        & $unpin

[System.Windows.Forms.MessageBox]::Show('Bloat Removed.')
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" /v "ProgId" /t REG_SZ /d "IE.HTTP" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" /v "ProgId" /t REG_SZ /d "IE.HTTPS" /f
    }
    if($checkbox3.Checked)
    {
   
   if($updates){
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
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "1" /f
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Scheduled Start'} | Enable-ScheduledTask

$pause = (Get-Date).AddDays(365); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause

   }
   if($services){
   Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "2" /f
   Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "DelayedAutostart" /t REG_DWORD /d "1" /f


   }
   
        
  $debloat = Get-ChildItem -Path C:\ -Filter debloatKeepStoreXbox.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        & $debloat


  $unpin = Get-ChildItem -Path C:\ -Filter unpin.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        & $unpin

[System.Windows.Forms.MessageBox]::Show('Bloat Removed.')
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
    }
    if($checkbox4.Checked)
    {

    if($updates){
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
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "1" /f
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Scheduled Start'} | Enable-ScheduledTask
$pause = (Get-Date).AddDays(365); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause

   }
   if($services){
   Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "2" /f
   Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "DelayedAutostart" /t REG_DWORD /d "1" /f


   }

  $debloat = Get-ChildItem -Path C:\ -Filter debloatKeepStoreXbox.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        & $debloat
  

  $edge = Get-ChildItem -Path C:\ -Filter EdgeRemoval.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$edge) -Wait
  Remove-item -Path "C:\Scripts" -Force -Recurse
Reg.exe add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f
  $unpin = Get-ChildItem -Path C:\ -Filter unpin.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        & $unpin

[System.Windows.Forms.MessageBox]::Show('Bloat Removed.')
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f       
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" /v "ProgId" /t REG_SZ /d "IE.HTTP" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" /v "ProgId" /t REG_SZ /d "IE.HTTPS" /f
    }
    if($checkbox5.Checked)
    {
   $debloat = Get-ChildItem -Path C:\ -Filter debloatALL.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        & $debloat

   $unpin = Get-ChildItem -Path C:\ -Filter unpin.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        & $unpin

[System.Windows.Forms.MessageBox]::Show('Bloat Removed.')
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
    }
    if($checkbox6.Checked)
    {
        
  
  if($updates){
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
Reg.exe add "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "1" /f
Get-ScheduledTask | Where-Object {$_.Taskname -match 'Scheduled Start'} | Enable-ScheduledTask
$pause = (Get-Date).AddDays(365); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause

   }
   if($services){
   Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "2" /f
   Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "DelayedAutostart" /t REG_DWORD /d "1" /f


   }
  
  
  $debloat = Get-ChildItem -Path C:\ -Filter debloatKeepStore.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        & $debloat


  $edge = Get-ChildItem -Path C:\ -Filter EdgeRemoval.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$edge) -Wait
  Remove-item -Path "C:\Scripts" -Force -Recurse
Reg.exe add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f
  $unpin = Get-ChildItem -Path C:\ -Filter unpin.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        & $unpin

[System.Windows.Forms.MessageBox]::Show('Bloat Removed.')
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" /v "ProgId" /t REG_SZ /d "IE.HTTP" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" /v "ProgId" /t REG_SZ /d "IE.HTTPS" /f 
    }
   
}

}

$optionalTweaks = {

$optweaks = Get-ChildItem -Path C:\ -Filter OptionalTweaks.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }

& $optweaks

}

$powerPlan = {

[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Import Zoics Ultimate Performance Power Plan?','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
        
        #imports power plan
        $p = Get-ChildItem -path C:\ -Filter zoicsultimateperformance.pow -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; } 

        powercfg -import ([string]$p ) 88888888-8888-8888-8888-888888888888     
        powercfg /setactive 88888888-8888-8888-8888-888888888888 
        powercfg -h off 

    [System.Windows.Forms.MessageBox]::Show('Zoics Ultimate Performance is successfully enabled.')
   }

'No'{}

}

Add-Type -AssemblyName System.Windows.Forms

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Remove Unwanted Plans"
$form.Size = New-Object System.Drawing.Size(300, 200)
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

# Create the checkboxes
$checkbox1 = New-Object System.Windows.Forms.CheckBox
$checkbox1.Text = "Remove ALL"
$checkbox1.Location = New-Object System.Drawing.Point(20, 20)
$form.Controls.Add($checkbox1)

$checkbox2 = New-Object System.Windows.Forms.CheckBox
$checkbox2.Text = "Power Saver"
$checkbox2.Location = New-Object System.Drawing.Point(20, 50)
$form.Controls.Add($checkbox2)

$checkbox3 = New-Object System.Windows.Forms.CheckBox
$checkbox3.Text = "Balanced"
$checkbox3.Location = New-Object System.Drawing.Point(20, 80)
$form.Controls.Add($checkbox3)

$checkbox4 = New-Object System.Windows.Forms.CheckBox
$checkbox4.Text = "High Performance"
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
#deletes balanced, high performance, and power saver
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a 


}
if($checkbox2.Checked){
powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a

}    
if($checkbox3.Checked){
powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e

}    
if($checkbox4.Checked){
powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

}    
    
}

}

$restartPC = {

[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  #setting execution policy back to remote signed  
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

}





#do while with gui menu 
#8 different functions
$fromStart = $false


do {

# Load the necessary assemblies for Windows Forms
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

# Create a form
$form = New-Object Windows.Forms.Form
$form.Text = "ZOICWARE"
$form.Size = New-Object Drawing.Size(400, 430)

# Create 9 buttons and add them to the form
$button1 = New-Object Windows.Forms.Button
$button1.Text = "Install Necessary Packages"
$button1.Location = New-Object Drawing.Point(20, 20)
$button1.Size = New-Object Drawing.Size(150, 40)
$button1.Add_Click({

$form.Visible = $false
&$installPacks
$form.Visible = $true

})
$form.Controls.Add($button1)


$button2 = New-Object Windows.Forms.Button
$button2.Text = "Import Registry Tweaks"
$button2.Location = New-Object Drawing.Point(20, 80)
$button2.Size = New-Object Drawing.Size(150, 40)
$button2.Add_Click({

$form.Visible = $false
&$importReg
$form.Visible = $true

})
$form.Controls.Add($button2)

$button3 = New-Object Windows.Forms.Button
$button3.Text = "Remove Scheduled Tasks"
$button3.Location = New-Object Drawing.Point(20, 140)
$button3.Size = New-Object Drawing.Size(150, 40)
$button3.Add_Click({

$form.Visible = $false
&$removeSchdTasks
$form.Visible = $true

})
$form.Controls.Add($button3)

$button4 = New-Object Windows.Forms.Button
$button4.Text = "Group Policy Tweaks"
$button4.Location = New-Object Drawing.Point(20, 200)
$button4.Size = New-Object Drawing.Size(150, 40)
$button4.Add_Click({

$form.Visible = $false
&$groupPolicy
$form.Visible = $true

})
$form.Controls.Add($button4)

$button5 = New-Object Windows.Forms.Button
$button5.Text = "Disable Services"
$button5.Location = New-Object Drawing.Point(200, 20)
$button5.Size = New-Object Drawing.Size(150, 40)
$button5.Add_Click({

$form.Visible = $false
&$disableServices
$form.Visible = $true

})
$form.Controls.Add($button5)

$button6 = New-Object Windows.Forms.Button
$button6.Text = "Debloat"
$button6.Location = New-Object Drawing.Point(200, 80)
$button6.Size = New-Object Drawing.Size(150, 40)
$button6.Add_Click({

$form.Visible = $false
&$debloat
$form.Visible = $true

})
$form.Controls.Add($button6)

$button7 = New-Object Windows.Forms.Button
$button7.Text = "Optional Tweaks"
$button7.Location = New-Object Drawing.Point(200, 140)
$button7.Size = New-Object Drawing.Size(150, 40)
$button7.Add_Click({

$form.Visible = $false
&$optionalTweaks
$form.Visible = $true

})
$form.Controls.Add($button7)

$button8 = New-Object Windows.Forms.Button
$button8.Text = "Import/Remove Power Plans"
$button8.Location = New-Object Drawing.Point(200, 200)
$button8.Size = New-Object Drawing.Size(150, 40)
$button8.Add_Click({

$form.Visible = $false
&$powerPlan
$form.Visible = $true

})
$form.Controls.Add($button8)

$button9 = New-Object Windows.Forms.Button
$button9.Text = "Run From Start"
$button9.Location = New-Object Drawing.Point(105, 280)
$button9.Size = New-Object Drawing.Size(150, 40)
$button9.Add_Click({
$form.Visible = $false
&$installPacks
&$importReg
&$removeSchdTasks
&$groupPolicy
&$disableServices
&$debloat
&$optionalTweaks
&$powerPlan
&$restartPC
#$form.Close()
})
$form.Controls.Add($button9)


$restartButton = New-Object Windows.Forms.Button
$restartButton.Text = "Restart PC"
$restartButton.Location = New-Object Drawing.Point(60, 340)
$restartButton.Size = New-Object Drawing.Size(120, 30)
$restartButton.Add_Click({
    $form.Visible = $false
    &$restartPC
})
$form.Controls.Add($restartButton)



$restoreButton = New-Object Windows.Forms.Button
$restoreButton.Text = "Restore Changes"
$restoreButton.Location = New-Object Drawing.Point(180, 340)
$restoreButton.Size = New-Object Drawing.Size(120, 30)
$restoreButton.Add_Click({
    $form.Visible = $false
    $restore = Get-ChildItem -path C:\ -Filter Restore.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; } 
    &$restore
    $form.Visible = $true
})
$form.Controls.Add($restoreButton)

    $result = $form.ShowDialog()
} while ($result -ne [System.Windows.Forms.DialogResult]::Cancel)

# Dispose of the form when it's closed
$form.Dispose()




'@.replace("$@","'@").replace("@$","@'") -force -ea 0;
$A = '-nop -noe -c & {iex((gp ''Registry::HKEY_Users\S-1-5-21*\Volatile*'' Windows_Optimizer -ea 0)[0].Windows_Optimizer)}'
start powershell -args $A -verb runas
$_Press_Enter   
 