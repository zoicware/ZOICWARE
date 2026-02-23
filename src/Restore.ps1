If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
  Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
  Exit	
}

    
$Global:tempDir = (([System.IO.Path]::GetTempPath())).trimend('\')   
    
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Restore Changes'
$form.Size = New-Object System.Drawing.Size(675, 310)
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
$form.MaximizeBox = $false
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
$form.BackColor = 'Black'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9) 
$form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

$type = $form.GetType()
$propInfo = $type.GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
$propInfo.SetValue($form, $true, $null)

$startColor = [System.Drawing.Color]::FromArgb(61, 74, 102)   #rgb(61, 74, 102)
$endColor = [System.Drawing.Color]::FromArgb(0, 0, 0)       #rgb(0, 0, 0)

# Override the form's paint event to apply the gradient
$form.Add_Paint({
    param($sender, $e)
    $rect = New-Object System.Drawing.Rectangle(0, 0, $form.Width, $form.Height)
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
      $rect, 
      $startColor, 
      $endColor, 
      [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal
    )
    $e.Graphics.FillRectangle($brush, $rect)
    $brush.Dispose()
  })


$lineStartPoint = New-Object System.Drawing.Point(170, 15)
$lineEndPoint = New-Object System.Drawing.Point(170, 165)
$lineColor = [System.Drawing.Color]::Gray
$lineWidth = 1.5

$form.Add_Paint({
    $graphics = $form.CreateGraphics()
    $pen = New-Object System.Drawing.Pen($lineColor, $lineWidth)
    $graphics.DrawLine($pen, $lineStartPoint, $lineEndPoint)
    $pen.Dispose()
    $graphics.Dispose()
  })


$lineStartPoint2 = New-Object System.Drawing.Point(395, 15)
$lineEndPoint2 = New-Object System.Drawing.Point(395, 165)
$lineColor2 = [System.Drawing.Color]::Gray
$lineWidth2 = 1.5

$form.Add_Paint({
    $graphics = $form.CreateGraphics()
    $pen = New-Object System.Drawing.Pen($lineColor2, $lineWidth2)
    $graphics.DrawLine($pen, $lineStartPoint2, $lineEndPoint2)
    $pen.Dispose()
    $graphics.Dispose()
  })


# Create the checkboxes
$checkbox1 = New-Object System.Windows.Forms.CheckBox
$checkbox1.Text = 'Enable Updates'
$checkbox1.Location = New-Object System.Drawing.Point(20, 20)
$checkbox1.ForeColor = 'White'
$checkbox1.BackColor = [System.Drawing.Color]::Transparent
$checkbox1.AutoSize = $true
$form.Controls.Add($checkbox1)

$checkbox2 = New-Object System.Windows.Forms.CheckBox
$checkbox2.Text = 'Enable Defender'
$checkbox2.Location = New-Object System.Drawing.Point(20, 50)
$checkbox2.ForeColor = 'White'
$checkbox2.BackColor = [System.Drawing.Color]::Transparent
$checkbox2.AutoSize = $true
$form.Controls.Add($checkbox2)

$checkbox3 = New-Object System.Windows.Forms.CheckBox
$checkbox3.Text = 'Enable Services'
$checkbox3.ForeColor = 'White'
$checkbox3.BackColor = [System.Drawing.Color]::Transparent
$checkbox3.Location = New-Object System.Drawing.Point(20, 80)
$checkbox3.AutoSize = $true
$form.Controls.Add($checkbox3)


$checkbox4 = New-Object System.Windows.Forms.CheckBox
$checkbox4.Text = 'Install Microsoft Store'
$checkbox4.ForeColor = 'White'
$checkbox4.BackColor = [System.Drawing.Color]::Transparent
$checkbox4.Location = New-Object System.Drawing.Point(190, 20)
$checkbox4.AutoSize = $true
$form.Controls.Add($checkbox4)

$checkbox5 = New-Object System.Windows.Forms.CheckBox
$checkbox5.Text = 'Revert Registry Tweaks'
$checkbox5.ForeColor = 'White'
$checkbox5.BackColor = [System.Drawing.Color]::Transparent
$checkbox5.Location = New-Object System.Drawing.Point(190, 50)
$checkbox5.AutoSize = $true
$form.Controls.Add($checkbox5)

$checkbox6 = New-Object System.Windows.Forms.CheckBox
$checkbox6.Text = 'Repair Xbox Apps'
$checkbox6.ForeColor = 'White'
$checkbox6.BackColor = [System.Drawing.Color]::Transparent
$checkbox6.Location = New-Object System.Drawing.Point(20, 110)
$checkbox6.AutoSize = $true
$form.Controls.Add($checkbox6)


$checkbox7 = New-Object System.Windows.Forms.CheckBox
$checkbox7.Text = 'Disable Qos for Upload'
$checkbox7.ForeColor = 'White'
$checkbox7.BackColor = [System.Drawing.Color]::Transparent
$checkbox7.Location = New-Object System.Drawing.Point(190, 80)
$checkbox7.AutoSize = $true
$form.Controls.Add($checkbox7)


$checkbox8 = New-Object System.Windows.Forms.CheckBox
$checkbox8.Text = 'Unblock Razer && Asus Downloads'
$checkbox8.ForeColor = 'White'
$checkbox8.BackColor = [System.Drawing.Color]::Transparent
$checkbox8.Location = New-Object System.Drawing.Point(415, 20)
$checkbox8.AutoSize = $true
$form.Controls.Add($checkbox8)

$checkbox9 = New-Object System.Windows.Forms.CheckBox
$checkbox9.Text = 'Unpause Updates'
$checkbox9.ForeColor = 'White'
$checkbox9.BackColor = [System.Drawing.Color]::Transparent
$checkbox9.Location = New-Object System.Drawing.Point(190, 110)
$checkbox9.AutoSize = $true
$form.Controls.Add($checkbox9)

$checkbox10 = New-Object System.Windows.Forms.CheckBox
$checkbox10.Text = 'Restore Default Context Menu'
$checkbox10.ForeColor = 'White'
$checkbox10.BackColor = [System.Drawing.Color]::Transparent
$checkbox10.Location = New-Object System.Drawing.Point(415, 50)
$checkbox10.AutoSize = $true
$form.Controls.Add($checkbox10)

$checkbox11 = New-Object System.Windows.Forms.CheckBox
$checkbox11.Text = 'Remove Dark Winver'
$checkbox11.ForeColor = 'White'
$checkbox11.BackColor = [System.Drawing.Color]::Transparent
$checkbox11.Location = New-Object System.Drawing.Point(415, 80)
$checkbox11.AutoSize = $true
$form.Controls.Add($checkbox11)

$checkbox12 = New-Object System.Windows.Forms.CheckBox
$checkbox12.Text = 'Restore Win 11 Task Manager'
$checkbox12.ForeColor = 'White'
$checkbox12.BackColor = [System.Drawing.Color]::Transparent
$checkbox12.Location = New-Object System.Drawing.Point(415, 110)
$checkbox12.AutoSize = $true
$form.Controls.Add($checkbox12)

$checkbox13 = New-Object System.Windows.Forms.CheckBox
$checkbox13.Text = 'Restore Win 11 Explorer Ribbon'
$checkbox13.ForeColor = 'White'
$checkbox13.BackColor = [System.Drawing.Color]::Transparent
$checkbox13.Location = New-Object System.Drawing.Point(190, 140)
$checkbox13.AutoSize = $true
$form.Controls.Add($checkbox13)

$checkbox14 = New-Object System.Windows.Forms.CheckBox
$checkbox14.Text = 'Enable Backup App'
$checkbox14.ForeColor = 'White'
$checkbox14.BackColor = [System.Drawing.Color]::Transparent
$checkbox14.Location = New-Object System.Drawing.Point(20, 140)
$checkbox14.AutoSize = $true
$form.Controls.Add($checkbox14)

$checkbox15 = New-Object System.Windows.Forms.CheckBox
$checkbox15.Text = 'Enable HVCI/VBS'
$checkbox15.ForeColor = 'White'
$checkbox15.BackColor = [System.Drawing.Color]::Transparent
$checkbox15.Location = New-Object System.Drawing.Point(415, 140)
$checkbox15.AutoSize = $true
$form.Controls.Add($checkbox15)

$OKButton = Create-ModernButton -Text 'OK' -Size (New-Object Drawing.Size(95, 28)) -DialogResult ([System.Windows.Forms.DialogResult]::OK) -borderSize 2
$OKButton.Dock = [System.Windows.Forms.DockStyle]::Bottom
$form.Controls.Add($OKButton)

$CancelButton = Create-ModernButton -Text 'Cancel' -Size (New-Object Drawing.Size(95, 28)) -DialogResult ([System.Windows.Forms.DialogResult]::OK) -borderSize 2
$CancelButton.Dock = [System.Windows.Forms.DockStyle]::Bottom
$form.Controls.Add($CancelButton)
    

# Show the form and wait for user input
$result = $form.ShowDialog()

# Check the selected checkboxes
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {


  if ($checkbox1.Checked) {

    [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Pause Updates First?', 'Zoic', 'YesNo', 'Question')

    switch ($msgBoxInput) {

      'Yes' {
        #pause for 1 year
        Write-Status -Message 'Pausing Updates for 1 Year...' -Type Output
        $pause = (Get-Date).AddDays(365) 
        $today = Get-Date
        $today = $today.ToUniversalTime().ToString( 'yyyy-MM-ddTHH:mm:ssZ' )
        $pause = $pause.ToUniversalTime().ToString( 'yyyy-MM-ddTHH:mm:ssZ' ) 
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesEndTime' -Value $pause -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesStartTime' -Value $today -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesEndTime' -Value $pause -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesStartTime' -Value $today -Force
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesStartTime' -Value $today -Force
      } 

      'No' {}

    }
    Write-Status -Message 'Enabling Updates...' -Type Output
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /f *>$null
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc' /v 'Start' /t REG_DWORD /d '2' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'Start' /t REG_DWORD /d '2' /f
    Start-Service UsoSvc -ErrorAction SilentlyContinue
    
    gpupdate /force 
  }



  if ($checkbox2.Checked) {

    $file1 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=-
"ServiceKeepAlive"=-
"AllowFastServiceStartup"=-
"DisableLocalAdminMerge"=-

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=-
'@
    $file2 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"PUAProtection"=-
"DisableAntiSpyware"=-
"RandomizeScheduleTaskTimes"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowCloudProtection]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowEmailScanning]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanOnMappedNetworkDrives]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanRemovableDriveScanning]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScanningNetworkFiles]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScriptScanning]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowUserUIAccess]
"value"=dword:00000001

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager]
"DisableScanningNetworkFiles"=-

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\SpyNet]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting]
'@
    $file3 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\HideWindowsSecurityNotificationAreaControl]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center]
"FirstRunDisabled"=-
"AntiVirusOverride"=-
"FirewallOverride"=-

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications]

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance]
"Enabled"=-
'@
    $file4 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]
@="Windows Defender IOfficeAntiVirus implementation"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories\{56FFCC30-D398-11D0-B2AE-00A0C908FA49}]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32]
@=hex(2):22,00,43,00,3a,00,5c,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,\
  00,61,00,74,00,61,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,\
  74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,\
  00,65,00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,\
  72,00,6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,\
  00,2e,00,37,00,2d,00,30,00,5c,00,58,00,38,00,36,00,5c,00,4d,00,70,00,4f,00,\
  61,00,76,00,2e,00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]
@="Windows Defender IOfficeAntiVirus implementation"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts]
@="Scanned Hosting Applications"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts\shdocvw]
@="IAttachmentExecute"
"Enable"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts\urlmon]
@="ActiveX controls"
"Enable"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories\{56FFCC30-D398-11D0-B2AE-00A0C908FA49}]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,4d,00,70,00,4f,00,61,00,76,00,2e,00,64,00,6c,00,\
  6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}]
@="Windows Defender IAmsiUacProvider implementation"
"AppId"="{2781761E-28E2-4109-99FE-B9D127C57AFE}"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}]
@="Defender CSP"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,\
  43,00,53,00,50,00,2e,00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Free"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}]
@="InfectionState WMI Provider"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,70,00,50,00,72,00,6f,\
  00,76,00,69,00,64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}]
@="Defender Pua Shield Broker"
"AppID"="{37096FBE-2F09-4FF6-8507-C6E4E1179839}"
"LocalizedString"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-12001"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}\Elevation]
"Enabled"=dword:00000001
"IconReference"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-101"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}\InprocServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}]
@="Defender Shield Broker"
"AppID"="{37096FBE-2F09-4FF6-8507-C6E4E1179839}"
"LocalizedString"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-12001"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}\Elevation]
"Enabled"=dword:00000001
"IconReference"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-101"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}\InprocServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll"
"ThreadingModel"="Both"


[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}]
@="Status WMI Provider"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,70,00,50,00,72,00,6f,\
  00,76,00,69,00,64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}]
@="Defender Shield Class"
"AppID"="{2eb6d15c-5239-41cf-82fb-353d20b816cf}"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}]
@="Microsoft Windows Defender"
"AppID"="{A79DB36D-6218-48e6-9EC9-DCBA9A39BF0F}"
"LocalizedString"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,\
  46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,\
  00,73,00,20,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,\
  70,00,41,00,73,00,44,00,65,00,73,00,63,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,\
  00,33,00,30,00,30,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}\Elevation]
"Enabled"=dword:00000001
"IconReference"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,\
  46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,\
  00,73,00,20,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,\
  70,00,41,00,73,00,44,00,65,00,73,00,63,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,\
  00,31,00,30,00,33,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}\InprocServer32]
@="C:\\Program Files\\Windows Defender\\MsMpCom.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}]
@="Windows Defender WMI Provider"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,50,00,72,00,6f,00,74,00,65,00,63,00,74,00,69,00,\
  6f,00,6e,00,4d,00,61,00,6e,00,61,00,67,00,65,00,6d,00,65,00,6e,00,74,00,2e,\
  00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}]
@="AMMonitoring WMI Provider"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,41,00,4d,00,4d,00,6f,00,6e,\
  00,69,00,74,00,6f,00,72,00,69,00,6e,00,67,00,50,00,72,00,6f,00,76,00,69,00,\
  64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}]
@="Defender SSO"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}\InProcServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthSSO.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}]
@="Defender Pua Shield Class"
"AppID"="{2eb6d15c-5239-41cf-82fb-353d20b816cf}"

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]
@="Windows Defender IOfficeAntiVirus implementation"

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories]

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories\{56FFCC30-D398-11D0-B2AE-00A0C908FA49}]

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32]
@=hex(2):22,00,43,00,3a,00,5c,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,\
  00,61,00,74,00,61,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,\
  74,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,\
  00,65,00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,\
  72,00,6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,\
  00,2e,00,37,00,2d,00,30,00,5c,00,58,00,38,00,36,00,5c,00,4d,00,70,00,4f,00,\
  61,00,76,00,2e,00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]
@="Windows Defender IOfficeAntiVirus implementation"

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts]
@="Scanned Hosting Applications"

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts\shdocvw]
@="IAttachmentExecute"
"Enable"=dword:00000001

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Hosts\urlmon]
@="ActiveX controls"
"Enable"=dword:00000001

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories]

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\Implemented Categories\{56FFCC30-D398-11D0-B2AE-00A0C908FA49}]

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,4d,00,70,00,4f,00,61,00,76,00,2e,00,64,00,6c,00,\
  6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}]
@="Windows Defender IAmsiUacProvider implementation"
"AppId"="{2781761E-28E2-4109-99FE-B9D127C57AFE}"

[HKEY_CLASSES_ROOT\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}]
@="Defender CSP"

[HKEY_CLASSES_ROOT\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,\
  43,00,53,00,50,00,2e,00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Free"

[HKEY_CLASSES_ROOT\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}]
@="InfectionState WMI Provider"

[HKEY_CLASSES_ROOT\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,70,00,50,00,72,00,6f,\
  00,76,00,69,00,64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}]
@="Defender Pua Shield Broker"
"AppID"="{37096FBE-2F09-4FF6-8507-C6E4E1179839}"
"LocalizedString"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-12001"

[HKEY_CLASSES_ROOT\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}\Elevation]
"Enabled"=dword:00000001
"IconReference"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-101"

[HKEY_CLASSES_ROOT\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}\InprocServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}]
@="Defender Shield Broker"
"AppID"="{37096FBE-2F09-4FF6-8507-C6E4E1179839}"
"LocalizedString"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-12001"

[HKEY_CLASSES_ROOT\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}\Elevation]
"Enabled"=dword:00000001
"IconReference"="@\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll,-101"

[HKEY_CLASSES_ROOT\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}\InprocServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthAgent.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}]
@="Status WMI Provider"

[HKEY_CLASSES_ROOT\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,70,00,50,00,72,00,6f,\
  00,76,00,69,00,64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}]
@="Defender Shield Class"
"AppID"="{2eb6d15c-5239-41cf-82fb-353d20b816cf}"

[HKEY_CLASSES_ROOT\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}]
@="Microsoft Windows Defender"
"AppID"="{A79DB36D-6218-48e6-9EC9-DCBA9A39BF0F}"
"LocalizedString"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,\
  46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,\
  00,73,00,20,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,\
  70,00,41,00,73,00,44,00,65,00,73,00,63,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,\
  00,33,00,30,00,30,00,00,00

[HKEY_CLASSES_ROOT\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}\Elevation]
"Enabled"=dword:00000001
"IconReference"=hex(2):40,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,\
  46,00,69,00,6c,00,65,00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,\
  00,73,00,20,00,44,00,65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,4d,00,\
  70,00,41,00,73,00,44,00,65,00,73,00,63,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,\
  00,31,00,30,00,33,00,00,00

[HKEY_CLASSES_ROOT\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}\InprocServer32]
@="C:\\Program Files\\Windows Defender\\MsMpCom.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}]
@="Windows Defender WMI Provider"

[HKEY_CLASSES_ROOT\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}\InprocServer32]
@=hex(2):22,00,25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,44,00,61,00,74,\
  00,61,00,25,00,5c,00,4d,00,69,00,63,00,72,00,6f,00,73,00,6f,00,66,00,74,00,\
  5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,65,00,66,00,65,\
  00,6e,00,64,00,65,00,72,00,5c,00,50,00,6c,00,61,00,74,00,66,00,6f,00,72,00,\
  6d,00,5c,00,34,00,2e,00,31,00,38,00,2e,00,32,00,34,00,30,00,36,00,30,00,2e,\
  00,37,00,2d,00,30,00,5c,00,50,00,72,00,6f,00,74,00,65,00,63,00,74,00,69,00,\
  6f,00,6e,00,4d,00,61,00,6e,00,61,00,67,00,65,00,6d,00,65,00,6e,00,74,00,2e,\
  00,64,00,6c,00,6c,00,22,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}]
@="AMMonitoring WMI Provider"

[HKEY_CLASSES_ROOT\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}\InprocServer32]
@=hex(2):25,00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,\
  00,73,00,25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,44,00,\
  65,00,66,00,65,00,6e,00,64,00,65,00,72,00,5c,00,41,00,4d,00,4d,00,6f,00,6e,\
  00,69,00,74,00,6f,00,72,00,69,00,6e,00,67,00,50,00,72,00,6f,00,76,00,69,00,\
  64,00,65,00,72,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}]
@="Defender SSO"

[HKEY_CLASSES_ROOT\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}\InProcServer32]
@="\\\\?\\C:\\Windows\\System32\\SecurityHealth\\1.0.2402.27001-0\\SecurityHealthSSO.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}]
@="Defender Pua Shield Class"
"AppID"="{2eb6d15c-5239-41cf-82fb-353d20b816cf}"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger]
"Age"=dword:00000001
"BufferSize"=dword:00000040
"ClockType"=dword:00000002
"EnableSecurityProvider"=dword:00000001
"FlushTimer"=dword:00000001
"GUID"="{6B4012D0-22B6-464D-A553-20E9618403A1}"
"LogFileMode"=dword:180001c0
"MaximumBuffers"=dword:00000010
"MinimumBuffers"=dword:00000000
"Start"=dword:00000001
"Status"=dword:00000000
'@
    $file5 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger]
"Age"=dword:00000001
"BufferSize"=dword:00000040
"ClockType"=dword:00000002
"FlushTimer"=dword:00000001
"GUID"="{6B4012D0-22B6-464D-A553-20E9618403A2}"
"LogFileMode"=dword:18000180
"MaximumBuffers"=dword:00000010
"MinimumBuffers"=dword:00000000
"Start"=dword:00000001
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{0063715b-eeda-4007-9429-ad526f62696e}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"MatchAnyKeyword"=hex(b):00,00,70,00,00,00,00,00
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{099614a5-5dd7-4788-8bc9-e29f43db28fc}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"MatchAnyKeyword"=hex(b):01,00,00,00,00,00,00,00
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:17

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{1edeee53-0afe-4609-b846-d8c0b2075b1f}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{1edeee53-0afe-4609-b846-d8c0b2075b1f}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:0b,00,16,00,e5,16,17,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{54849625-5478-4994-a5ba-3e3b0328c30d}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{54849625-5478-4994-a5ba-3e3b0328c30d}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:10,12,11,12,5a,12,5e,12,73,12,74,12,82,12,00,15,03,15,04,15,05,\
  15,06,15,70,12

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{85a62a0d-7e17-485f-9d4f-749a287193a6}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{8c416c79-d49b-4f01-a467-e56d3aa8234c}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"MatchAnyKeyword"=hex(b):00,04,00,00,00,0c,00,00
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:10,00,fe,ff

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{c688cf83-9945-5ff6-0e1e-1ff1f8a2ec9a}]
"Enabled"=dword:00000001
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}]
"Enabled"=dword:00000001
"EnableLevel"=dword:0000001f
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:01,00,02,00,03,00,04,00,07,00,08,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{ef1cc15b-46c1-414e-bb95-e76b077bd51e}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{ef1cc15b-46c1-414e-bb95-e76b077bd51e}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:03,00,fe,ff

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"MatchAnyKeyword"=hex(b):55,55,fa,dc,14,01,00,00
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:01,00,02,00,03,00,04,00,05,00,06,00,07,00,08,00,09,00,0a,00,0b,\
  00,0c,00,0d,00,0e,00,0f,00,10,00,11,00,12,00,13,00,14,00,15,00,16,00,17,00,\
  18,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}]
"Enabled"=dword:00000001
"EnableLevel"=dword:00000000
"Status"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger\{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}\Filters]
"Enabled"=dword:00000001
"EventIdFilterIn"=dword:00000001
"EventIds"=hex:4e,04,68,00
'@
    $file6 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefsvc]
"DependOnService"=hex(7):52,00,70,00,63,00,53,00,73,00,00,00,77,00,74,00,64,00,\
  00,00,00,00
"Description"="@%systemroot%\\system32\\webthreatdefsvc.dll,-101"
"DisplayName"="@%systemroot%\\system32\\webthreatdefsvc.dll,-100"
"ErrorControl"=dword:00000001
"FailureActions"=hex:80,51,01,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,60,ea,00,00,01,00,00,00,c0,d4,01,00,00,00,00,00,00,00,00,00
"FailureActionsOnNonCrashFailures"=dword:00000001
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,73,\
  00,76,00,63,00,68,00,6f,00,73,00,74,00,2e,00,65,00,78,00,65,00,20,00,2d,00,\
  6b,00,20,00,57,00,65,00,62,00,54,00,68,00,72,00,65,00,61,00,74,00,44,00,65,\
  00,66,00,65,00,6e,00,73,00,65,00,20,00,2d,00,70,00,00,00
"ObjectName"="NT AUTHORITY\\LocalService"
"ServiceSidType"=dword:00000001
"Start"=dword:00000003
"Type"=dword:00000020

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefsvc\Parameters]
"ServiceDll"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  77,00,65,00,62,00,74,00,68,00,72,00,65,00,61,00,74,00,64,00,65,00,66,00,73,\
  00,76,00,63,00,2e,00,64,00,6c,00,6c,00,00,00
"ServiceDllUnloadOnStop"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefsvc\TriggerInfo]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefsvc\TriggerInfo\0]
"Action"=dword:00000001
"Data0"=hex:75,10,bc,a3,3a,1a,82,41
"DataType0"=dword:00000001
"GUID"=hex:16,28,7a,2d,5e,0c,fc,45,9c,e7,57,0e,5e,cd,e9,c9
"Type"=dword:00000007

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc]
"DependOnService"=hex(7):52,00,70,00,63,00,53,00,73,00,00,00,00,00
"Description"="@%systemroot%\\system32\\webthreatdefusersvc.dll,-101"
"DisplayName"="@%systemroot%\\system32\\webthreatdefusersvc.dll,-100"
"ErrorControl"=dword:00000001
"FailureActions"=hex:80,51,01,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,60,ea,00,00,01,00,00,00,c0,d4,01,00,01,00,00,00,80,a9,03,00
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,73,\
  00,76,00,63,00,68,00,6f,00,73,00,74,00,2e,00,65,00,78,00,65,00,20,00,2d,00,\
  6b,00,20,00,4c,00,6f,00,63,00,61,00,6c,00,53,00,79,00,73,00,74,00,65,00,6d,\
  00,4e,00,65,00,74,00,77,00,6f,00,72,00,6b,00,52,00,65,00,73,00,74,00,72,00,\
  69,00,63,00,74,00,65,00,64,00,20,00,2d,00,70,00,00,00
"ObjectName"="LocalSystem"
"RequiredPrivileges"=hex(7):53,00,65,00,49,00,6d,00,70,00,65,00,72,00,73,00,6f,\
  00,6e,00,61,00,74,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,\
  65,00,00,00,00,00
"ServiceSidType"=dword:00000003
"Start"=dword:00000002
"Type"=dword:00000060

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc\Parameters]
"ServiceDll"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  77,00,65,00,62,00,74,00,68,00,72,00,65,00,61,00,74,00,64,00,65,00,66,00,75,\
  00,73,00,65,00,72,00,73,00,76,00,63,00,2e,00,64,00,6c,00,6c,00,00,00
"ServiceDllUnloadOnStop"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecCore]
"Description"="@%SystemRoot%\\System32\\Drivers\\msseccore.sys,-1002"
"DisplayName"="@%SystemRoot%\\System32\\Drivers\\msseccore.sys,-1001"
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  72,00,69,00,76,00,65,00,72,00,73,00,5c,00,6d,00,73,00,73,00,65,00,63,00,63,\
  00,6f,00,72,00,65,00,2e,00,73,00,79,00,73,00,00,00
"Start"=dword:00000000
"Type"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecCore\Security]
"Security"=hex:01,00,14,80,dc,00,00,00,e8,00,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ac,00,06,00,00,00,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,\
  05,50,00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,\
  00,0b,28,00,00,00,00,10,01,06,00,00,00,00,00,05,50,00,00,00,b5,89,fb,38,19,\
  84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,14,00,fd,01,02,00,01,01,\
  00,00,00,00,00,05,12,00,00,00,00,00,18,00,ff,01,0e,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,20,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  04,00,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,06,00,00,00,01,\
  01,00,00,00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc]
"DelayedAutoStart"=dword:00000001
"DependOnService"=hex(7):52,00,70,00,63,00,53,00,73,00,00,00,00,00
"Description"="@%SystemRoot%\\System32\\wscsvc.dll,-201"
"DisplayName"="@%SystemRoot%\\System32\\wscsvc.dll,-200"
"ErrorControl"=dword:00000001
"FailureActions"=hex:80,51,01,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,c0,d4,01,00,01,00,00,00,e0,93,04,00,00,00,00,00,00,00,00,00
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,73,\
  00,76,00,63,00,68,00,6f,00,73,00,74,00,2e,00,65,00,78,00,65,00,20,00,2d,00,\
  6b,00,20,00,4c,00,6f,00,63,00,61,00,6c,00,53,00,65,00,72,00,76,00,69,00,63,\
  00,65,00,4e,00,65,00,74,00,77,00,6f,00,72,00,6b,00,52,00,65,00,73,00,74,00,\
  72,00,69,00,63,00,74,00,65,00,64,00,20,00,2d,00,70,00,00,00
"LaunchProtected"=dword:00000002
"ObjectName"="NT AUTHORITY\\LocalService"
"RequiredPrivileges"=hex(7):53,00,65,00,43,00,68,00,61,00,6e,00,67,00,65,00,4e,\
  00,6f,00,74,00,69,00,66,00,79,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,\
  67,00,65,00,00,00,53,00,65,00,49,00,6d,00,70,00,65,00,72,00,73,00,6f,00,6e,\
  00,61,00,74,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,65,00,\
  00,00,00,00
"ServiceSidType"=dword:00000001
"Start"=dword:00000002
"Type"=dword:00000020

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc\Parameters]
"ServiceDll"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,\
  00,74,00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,\
  77,00,73,00,63,00,73,00,76,00,63,00,2e,00,64,00,6c,00,6c,00,00,00
"ServiceDllUnloadOnStop"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc\Security]
"Security"=hex:01,00,14,80,1c,01,00,00,28,01,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ec,00,08,00,00,00,00,00,18,00,9d,00,02,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,21,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  12,00,00,00,00,00,18,00,9d,01,02,00,01,02,00,00,00,00,00,05,20,00,00,00,20,\
  02,00,00,00,00,14,00,9d,00,02,00,01,01,00,00,00,00,00,05,04,00,00,00,00,00,\
  14,00,9d,00,02,00,01,01,00,00,00,00,00,05,06,00,00,00,00,00,28,00,fd,01,02,\
  00,01,06,00,00,00,00,00,05,50,00,00,00,e5,fe,79,5f,a0,ae,0d,3b,22,fa,0a,c9,\
  01,5a,41,3a,e5,a6,4a,b7,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,05,50,\
  00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,\
  28,00,ff,01,0f,00,01,06,00,00,00,00,00,05,50,00,00,00,db,8c,74,0f,c2,72,73,\
  f3,2b,26,b9,44,77,1e,4f,02,76,63,b5,21,01,01,00,00,00,00,00,05,12,00,00,00,\
  01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService]
"DependOnService"=hex(7):52,00,70,00,63,00,53,00,73,00,00,00,00,00
"Description"="@%systemroot%\\system32\\SecurityHealthAgent.dll,-1001"
"DisplayName"="@%systemroot%\\system32\\SecurityHealthAgent.dll,-1002"
"ErrorControl"=dword:00000001
"FailureActions"=hex:80,51,01,00,00,00,00,00,00,00,00,00,03,00,00,00,14,00,00,\
  00,01,00,00,00,60,ea,00,00,01,00,00,00,60,ea,00,00,00,00,00,00,00,00,00,00
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,53,\
  00,65,00,63,00,75,00,72,00,69,00,74,00,79,00,48,00,65,00,61,00,6c,00,74,00,\
  68,00,53,00,65,00,72,00,76,00,69,00,63,00,65,00,2e,00,65,00,78,00,65,00,00,\
  00
"LaunchProtected"=dword:00000002
"ObjectName"="LocalSystem"
"RequiredPrivileges"=hex(7):53,00,65,00,49,00,6d,00,70,00,65,00,72,00,73,00,6f,\
  00,6e,00,61,00,74,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,\
  65,00,00,00,53,00,65,00,42,00,61,00,63,00,6b,00,75,00,70,00,50,00,72,00,69,\
  00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,53,00,65,00,52,00,65,00,73,00,\
  74,00,6f,00,72,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,65,\
  00,00,00,53,00,65,00,44,00,65,00,62,00,75,00,67,00,50,00,72,00,69,00,76,00,\
  69,00,6c,00,65,00,67,00,65,00,00,00,53,00,65,00,43,00,68,00,61,00,6e,00,67,\
  00,65,00,4e,00,6f,00,74,00,69,00,66,00,79,00,50,00,72,00,69,00,76,00,69,00,\
  6c,00,65,00,67,00,65,00,00,00,53,00,65,00,53,00,65,00,63,00,75,00,72,00,69,\
  00,74,00,79,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,\
  53,00,65,00,41,00,73,00,73,00,69,00,67,00,6e,00,50,00,72,00,69,00,6d,00,61,\
  00,72,00,79,00,54,00,6f,00,6b,00,65,00,6e,00,50,00,72,00,69,00,76,00,69,00,\
  6c,00,65,00,67,00,65,00,00,00,53,00,65,00,54,00,63,00,62,00,50,00,72,00,69,\
  00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,53,00,65,00,53,00,79,00,73,00,\
  74,00,65,00,6d,00,45,00,6e,00,76,00,69,00,72,00,6f,00,6e,00,6d,00,65,00,6e,\
  00,74,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,65,00,00,00,53,00,\
  65,00,53,00,68,00,75,00,74,00,64,00,6f,00,77,00,6e,00,50,00,72,00,69,00,76,\
  00,69,00,6c,00,65,00,67,00,65,00,00,00,00,00
"ServiceSidType"=dword:00000001
"Start"=dword:00000003
"Type"=dword:00000010

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService\Security]
"Security"=hex:01,00,14,80,1c,01,00,00,28,01,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,00,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ec,00,08,00,00,00,00,00,18,00,9d,00,02,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,21,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  12,00,00,00,00,00,18,00,9d,01,02,00,01,02,00,00,00,00,00,05,20,00,00,00,20,\
  02,00,00,00,00,14,00,9d,00,02,00,01,01,00,00,00,00,00,05,04,00,00,00,00,00,\
  14,00,9d,00,02,00,01,01,00,00,00,00,00,05,06,00,00,00,00,00,28,00,fd,01,02,\
  00,01,06,00,00,00,00,00,05,50,00,00,00,e5,fe,79,5f,a0,ae,0d,3b,22,fa,0a,c9,\
  01,5a,41,3a,e5,a6,4a,b7,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,05,50,\
  00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,\
  28,00,ff,01,0f,00,01,06,00,00,00,00,00,05,50,00,00,00,db,8c,74,0f,c2,72,73,\
  f3,2b,26,b9,44,77,1e,4f,02,76,63,b5,21,01,01,00,00,00,00,00,05,12,00,00,00,\
  01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent]
"Description"="@%SystemRoot%\\System32\\Drivers\\SgrmAgent.sys,-1002"
"DisplayName"="@%SystemRoot%\\System32\\Drivers\\SgrmAgent.sys,-1001"
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  72,00,69,00,76,00,65,00,72,00,73,00,5c,00,53,00,67,00,72,00,6d,00,41,00,67,\
  00,65,00,6e,00,74,00,2e,00,73,00,79,00,73,00,00,00
"Start"=dword:00000004
"Type"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent\Security]
"Security"=hex:01,00,14,80,dc,00,00,00,e8,00,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ac,00,06,00,00,00,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,\
  05,50,00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,\
  00,0b,28,00,00,00,00,10,01,06,00,00,00,00,00,05,50,00,00,00,b5,89,fb,38,19,\
  84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,14,00,fd,01,02,00,01,01,\
  00,00,00,00,00,05,12,00,00,00,00,00,18,00,ff,01,0e,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,20,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  04,00,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,06,00,00,00,01,\
  01,00,00,00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker]
"DependOnService"=hex(7):52,00,70,00,63,00,53,00,73,00,00,00,00,00
"Description"="@%SystemRoot%\\System32\\Sgrm\\SgrmBroker.exe,-101"
"DisplayName"="@%SystemRoot%\\System32\\Sgrm\\SgrmBroker.exe,-100"
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,\
  74,00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,53,\
  00,67,00,72,00,6d,00,5c,00,53,00,67,00,72,00,6d,00,42,00,72,00,6f,00,6b,00,\
  65,00,72,00,2e,00,65,00,78,00,65,00,00,00
"LaunchProtected"=dword:00000001
"ObjectName"="LocalSystem"
"RequiredPrivileges"=hex(7):53,00,65,00,49,00,6d,00,70,00,65,00,72,00,73,00,6f,\
  00,6e,00,61,00,74,00,65,00,50,00,72,00,69,00,76,00,69,00,6c,00,65,00,67,00,\
  65,00,00,00,00,00
"ServiceSidType"=dword:00000001
"Start"=dword:00000004
"Type"=dword:00000010

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker\TriggerInfo]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker\TriggerInfo\0]
"Action"=dword:00000001
"Data0"=hex:37,00,61,00,32,00,30,00,66,00,63,00,65,00,63,00,2d,00,64,00,65,00,\
  63,00,34,00,2d,00,34,00,63,00,35,00,39,00,2d,00,62,00,65,00,35,00,37,00,2d,\
  00,32,00,31,00,32,00,65,00,38,00,66,00,36,00,35,00,64,00,33,00,64,00,65,00,\
  00,00
"DataType0"=dword:00000002
"GUID"=hex:67,d1,90,bc,70,94,39,41,a9,ba,be,0b,bb,f5,b7,4d
"Type"=dword:00000006

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt]
"Description"="@%SystemRoot%\\System32\\Drivers\\mssecflt.sys,-1002"
"DisplayName"="@%SystemRoot%\\System32\\Drivers\\mssecflt.sys,-1001"
"ErrorControl"=dword:00000001
"Group"="Filter"
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  72,00,69,00,76,00,65,00,72,00,73,00,5c,00,6d,00,73,00,73,00,65,00,63,00,66,\
  00,6c,00,74,00,2e,00,73,00,79,00,73,00,00,00
"Start"=dword:00000003
"SupportedFeatures"=dword:0000000f
"Type"=dword:00000001
"DependOnService"=hex(7):66,00,6c,00,74,00,6d,00,67,00,72,00,00,00,00,00

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt\Instances]
"DefaultInstance"="MsSecFlt Instance"

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt\Instances\MsSecFlt Instance]
"Altitude"="385600"
"Flags"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt\Security]
"Security"=hex:01,00,14,80,dc,00,00,00,e8,00,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ac,00,06,00,00,00,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,\
  05,50,00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,\
  00,0b,28,00,00,00,00,10,01,06,00,00,00,00,00,05,50,00,00,00,b5,89,fb,38,19,\
  84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,14,00,fd,01,02,00,01,01,\
  00,00,00,00,00,05,12,00,00,00,00,00,18,00,ff,01,0e,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,20,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  04,00,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,06,00,00,00,01,\
  01,00,00,00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00


[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecWfp]
"DependOnService"=hex(7):54,00,63,00,70,00,69,00,70,00,00,00,00,00
"Description"="@%SystemRoot%\\System32\\Drivers\\mssecwfp.sys,-1002"
"DisplayName"="@%SystemRoot%\\System32\\Drivers\\mssecwfp.sys,-1001"
"ErrorControl"=dword:00000001
"ImagePath"=hex(2):73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  72,00,69,00,76,00,65,00,72,00,73,00,5c,00,6d,00,73,00,73,00,65,00,63,00,77,\
  00,66,00,70,00,2e,00,73,00,79,00,73,00,00,00
"Start"=dword:00000003
"Type"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecWfp\Security]
"Security"=hex:01,00,14,80,dc,00,00,00,e8,00,00,00,14,00,00,00,30,00,00,00,02,\
  00,1c,00,01,00,00,00,02,80,14,00,ff,01,0f,00,01,01,00,00,00,00,00,01,00,00,\
  00,00,02,00,ac,00,06,00,00,00,00,00,28,00,ff,01,0f,00,01,06,00,00,00,00,00,\
  05,50,00,00,00,b5,89,fb,38,19,84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,\
  00,0b,28,00,00,00,00,10,01,06,00,00,00,00,00,05,50,00,00,00,b5,89,fb,38,19,\
  84,c2,cb,5c,6c,23,6d,57,00,77,6e,c0,02,64,87,00,00,14,00,fd,01,02,00,01,01,\
  00,00,00,00,00,05,12,00,00,00,00,00,18,00,ff,01,0e,00,01,02,00,00,00,00,00,\
  05,20,00,00,00,20,02,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,\
  04,00,00,00,00,00,14,00,9d,01,02,00,01,01,00,00,00,00,00,05,06,00,00,00,01,\
  01,00,00,00,00,00,05,12,00,00,00,01,01,00,00,00,00,00,05,12,00,00,00

[-HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection]
'@
    $file7 = @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\windowsdefender]

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppUserModelId\Windows.Defender]
"ShowInSettings"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppUserModelId\Microsoft.Windows.Defender]
"ShowInSettings"=dword:00000000

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0]
@="Windows Defender SmartScreen"

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Application]
"ApplicationName"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}"
"ApplicationCompany"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/PublisherDisplayName}"
"ApplicationIcon"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/Files/Assets/SmallLogo.png}"
"ApplicationDescription"="ms-resource:DisplayName"
"AppUserModelID"="Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy!App"

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\DefaultIcon]
@="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/Files/Assets/SmallLogo.png}"

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell]

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell\open]
"ActivatableClassId"="App.AppXc99k5qnnsvxj5szemm7fp3g7y08we5vm.mca"
"PackageId"="Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy"
"ContractId"="Windows.Protocol"
"DesiredInitialViewState"=dword:00000000

[HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell\open\command]
"DelegateExecute"="{4ED3A719-CEA8-4BD9-910D-E252F997AFC2}"

[HKEY_CURRENT_USER\Software\Classes\ms-cxh]
"URL Protocol"=""
@="URL:ms-cxh"

[HKEY_CLASSES_ROOT\windowsdefender]
@="URL:windowsdefender"
"EditFlags"=dword:00200000
"URL Protocol"=""

[HKEY_CLASSES_ROOT\windowsdefender\DefaultIcon]
@="C:\\Program Files\\Windows Defender\\EppManifest.dll,-100"

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0]
@="Windows Defender SmartScreen"

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Application]
"ApplicationName"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/DisplayName}"
"ApplicationCompany"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/resources/PublisherDisplayName}"
"ApplicationIcon"="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/Files/Assets/SmallLogo.png}"
"ApplicationDescription"="ms-resource:DisplayName"
"AppUserModelID"="Microsoft.Windows.Apprep.ChxApp_cw5n1h2txyewy!App"

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\DefaultIcon]
@="@{Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy?ms-resource://Microsoft.Windows.Apprep.ChxApp/Files/Assets/SmallLogo.png}"

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell]

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell\open]
"ActivatableClassId"="App.AppXc99k5qnnsvxj5szemm7fp3g7y08we5vm.mca"
"PackageId"="Microsoft.Windows.Apprep.ChxApp_1000.22621.1.0_neutral_neutral_cw5n1h2txyewy"
"ContractId"="Windows.Protocol"
"DesiredInitialViewState"=dword:00000000

[HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0\Shell\open\command]
"DelegateExecute"="{4ED3A719-CEA8-4BD9-910D-E252F997AFC2}"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WindowsDefender]
@="URL:Windows Defender"
"EditFlags"=dword:00200000
"URL Protocol"=" "

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WindowsDefender\DefaultIcon]
@="C:\\Program Files\\Windows Defender\\EppManifest.dll,-100"

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Ubpm]
"CriticalMaintenance_DefenderCleanup"="NT Task\\Microsoft\\Windows\\Windows Defender\\Windows Defender Cleanup"
"CriticalMaintenance_DefenderVerification"="NT Task\\Microsoft\\Windows\\Windows Defender\\Windows Defender Verification"

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy"WindowsDefender-1"="v2.0|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|App=%ProgramFiles%\\Windows Defender\\MsMpEng.exe|Svc=WinDefend|Name=Allow Out TCP traffic from WinDefend|"
"WindowsDefender-2"="v2.0|Action=Block|Active=TRUE|Dir=In|App=%ProgramFiles%\\Windows Defender\\MsMpEng.exe|Svc=WinDefend|Name=Block All In traffic to WinDefend|"
"WindowsDefender-3"="v2.0|Action=Block|Active=TRUE|Dir=Out|App=%ProgramFiles%\\Windows Defender\\MsMpEng.exe|Svc=WinDefend|Name=Block All Out traffic from WinDefend|"
'@
    $file8 = @'
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]
@="CLSID_AntiPhishingBrowserSolution"

[HKEY_CLASSES_ROOT\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}\InprocServer32]
@="C:\\Windows\\System32\\ieapfltr.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]
@="CLSID_AntiPhishingBrowserSolution"

[HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}\InprocServer32]
@="C:\\Windows\\SysWOW64\\ieapfltr.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]
@="CLSID_AntiPhishingBrowserSolution"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}\InprocServer32]
@="C:\\Windows\\System32\\ieapfltr.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]
@="CLSID_AntiPhishingBrowserSolution"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}\InprocServer32]
@="C:\\Windows\\SysWOW64\\ieapfltr.dll"
"ThreadingModel"="Both"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Service.UserSessionServiceManager]
"ActivationType"=dword:00000001
"Server"="WebThreatDefSvc"
"TrustLevel"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatExperienceManager.ThreatExperienceManager]
"ActivationType"=dword:00000000
"DllPath"="C:\\Windows\\System32\\ThreatExperienceManager.dll"
"Threading"=dword:00000000
"TrustLevel"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatResponseEngine.ThreatDecisionEngine]
"ActivationType"=dword:00000000
"DllPath"="C:\\Windows\\System32\\ThreatResponseEngine.dll"
"Threading"=dword:00000000
"TrustLevel"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Configuration.WTDUserSettings]
"ActivationType"=dword:00000001
"Server"="WebThreatDefSvc"
"TrustLevel"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\open]
"NoSmartScreen"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runas]
"NoSmartScreen"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\exefile\shell\runasuser]
"NoSmartScreen"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SmartScreen.exe]
"Debugger"=-

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SmartScreen.exe]

'@


    #restore defender reg keys
    Write-Status -Message 'Restoring Defender Registry Keys...' -Type Output
    New-item -Path "$tempDir\enableReg" -ItemType Directory -Force | Out-Null
    New-Item -Path "$tempDir\enableReg\enable1.reg" -Value $file1 -Force | Out-Null
    New-Item -Path "$tempDir\enableReg\enable2.reg" -Value $file2 -Force | Out-Null
    New-Item -Path "$tempDir\enableReg\enable3.reg" -Value $file3 -Force | Out-Null
    New-Item -Path "$tempDir\enableReg\enable5.reg" -Value $file5 -Force | Out-Null
    New-Item -Path "$tempDir\enableReg\enable6.reg" -Value $file6 -Force | Out-Null
    New-Item -Path "$tempDir\enableReg\enable7.reg" -Value $file7 -Force | Out-Null
    New-Item -Path "$tempDir\enableReg\enable8.reg" -Value $file8 -Force | Out-Null

    $files = (Get-ChildItem -Path "$tempDir\enableReg").FullName
    foreach ($file in $files) {
      $command = "Start-Process regedit.exe -ArgumentList `"/s $file`""
      Run-Trusted -command $command
      Start-Sleep 1
    }

    $command = @'
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen"  /f
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /f 
Reg delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /f
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\Microsoft-Antimalware-ShieldProvider" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\WinDefend" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\MsSecFlt" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdBoot" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdFilter" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "3" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "3" /f
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f 
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /f 
Reg delete "HKLM\SYSTEM\ControlSet001\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /f 
Reg delete "HKLM\SOFTWARE\Microsoft\Windows Security Health\State" /v "AppAndBrowser_StoreAppsSmartScreenOff" /f  
Reg delete "HKLM\NTUSER\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /f 
Reg delete "HKLM\DEFAULT\SOFTWARE\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /f
Reg delete "HKLM\DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /f
Reg delete "HKLM\NTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "PreventOverride" /f 
Reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "SmartScreenEnabled" /f 
Reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /f 
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableEnhancedNotifications' /f
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableNotifications' /f
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'SummaryNotificationDisabled' /f
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'NoActionNotificationDisabled' /f
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'FilesBlockedNotificationDisabled' /f
Reg delete 'HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel' /v 'MitigationOptions' /f
Reg add 'HKLM\SOFTWARE\Microsoft\Windows Defender' /v 'PUAProtection' /t REG_DWORD /d '2' /f
Reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'SmartScreenEnabled' /f
'@
    New-Item -Path "$tempDir\EnableDefend.bat" -Value $command -Force | Out-Null

    Run-Trusted -command "Start-process $tempDir\EnableDefend.bat"
    Write-Status -Message 'Enabling MsMpEng Service...' -Type Output

    function enableMsMpEng {
      $id = 'Defender'; $key = 'Registry::HKU\S-1-5-21-*\Volatile Environment'; $code = @'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $U=[uintptr]; $Z=[uintptr]::size 
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += $U; 4..6|% {$D += $D[$_]."MakeByR`efType"()}; $F=@()
 $F+='kernel','CreateProcess',($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), 'advapi','RegOpenKeyEx',($U,$S,$I,$I,$D[9])
 $F+='advapi','RegSetValueEx',($U,$S,$I,$I,[byte[]],$I),'advapi','RegFlushKey',($U),'advapi','RegCloseKey',($U)
 0..4|% {$9=$D[0]."DefinePInvok`eMethod"($F[3*$_+1], $F[3*$_]+"32", 8214,1,$S, $F[3*$_+2], 1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"("f" + $n++, $_, 6)}}; $T=@(); 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 if ([environment]::username -ne "system") { $TI="Trusted`Installer"; start-service $TI -ea 0; $As=get-process -name $TI -ea 0
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $R=@($null, "powershell -nop -c iex(`$env:R); # $id", 0, 0, 0, 0x0E080610, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $R; return}; $env:R=''; rp $key $id -force -ea 0; $e=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$e.Invoke($null,@("$_",2))}
 ## Toggling was unreliable due to multiple windows programs with open handles on these keys
 ## so went with low-level functions instead! do not use them in other scripts without a trip to learn-microsoft-com  
 function RegSetDwords ($hive, $key, [array]$values, [array]$dword, $REG_TYPE=4, $REG_ACCESS=2, $REG_OPTION=0) {
   $rok = ($hive, $key, $REG_OPTION, $REG_ACCESS, ($hive -as $D[9]));  F "RegOpenKeyEx" $rok; $rsv = $rok[4]
   $values |% {$i = 0} { F "RegSetValueEx" ($rsv[0], [string]$_, 0, $REG_TYPE, [byte[]]($dword[$i]), 4); $i++ }
   F "RegFlushKey" @($rsv); F "RegCloseKey" @($rsv); $rok = $null; $rsv = $null;
 }  
 ## The ` sprinkles are used to keep ps event log clean, not quote the whole snippet on every run
 ################################################################################################################################ 
 
 ## get script options
 $toggle = 0; $toggle_rev = 1; 
$ENABLE_TAMPER_PROTECTION = 1

 stop-service "wscsvc" -force -ea 0 >'' 2>''
 kill -name "OFFmeansOFF","MpCmdRun" -force -ea 0 
 
 $HKLM = [uintptr][uint32]2147483650
 $VALUES = "ServiceKeepAlive","PreviousRunningMode","IsServiceRunning","DisableAntiSpyware","DisableAntiVirus","PassiveMode"
 $DWORDS = 0, 0, 0, $toggle, $toggle, $toggle
 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS 
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS
 [GC]::Collect(); sleep 1
 pushd "$env:programfiles\Windows Defender"
 $mpcmdrun=("OFFmeansOFF.exe","MpCmdRun.exe")[(test-path "MpCmdRun.exe")]
 start -wait $mpcmdrun -args "-EnableService -HighPriority"
 $wait=3
 while ((get-process -name "MsMpEng" -ea 0) -and $wait -gt 0) {$wait--; sleep 1;}
 
 ## OFF means OFF
 pushd (split-path $(gp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" ImagePath -ea 0).ImagePath.Trim('"'))
 ren OFFmeansOFF.exe MpCmdRun.exe -force -ea 0

 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS 
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS

  ## when re-enabling Defender, also re-enable Tamper Protection - annoying but safer - set to 0 at top of the script to skip it
 if ($ENABLE_TAMPER_PROTECTION -ne 0) {
   RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender\Features" ("TamperProtection","TamperProtectionSource") (1,5)
 }
 
 start-service "windefend" -ea 0
 start-service "wscsvc" -ea 0 >'' 2>'' 
 
 ################################################################################################################################
'@; $V = ''; 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }; Set-ItemProperty $key $id $V, $code -type 7 -force -ea 0
      Start-Process powershell -args "-nop -c `n$V  `$env:R=(gi `$key -ea 0 |% {`$_.getvalue(`$id)-join''}); iex(`$env:R)" -verb runas -Wait
    }
    enableMsMpEng
    Write-Status -Message 'Enabling Scheduled Tasks...' -Type Output
    
    $defenderTasks = Get-ScheduledTask 
    foreach ($task in $defenderTasks) {
      if ($task.TaskName -like 'Windows Defender*') {
        Enable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue | Out-Null
      }
    }

   
    #rename smartscreen
    $command = 'Rename-item -path C:\Windows\System32\smartscreenOFF.exe -newname smartscreen.exe -force -erroraction silentlycontinue' 
    Run-Trusted -command $command

    Remove-Item "$tempDir\EnableDefend.bat" -Force -ErrorAction SilentlyContinue
    Remove-Item "$tempDir\enableReg" -Recurse -Force -ErrorAction SilentlyContinue

  }
 
  


  if ($checkbox3.Checked) {
    Write-Status -Message 'Enabling Services...' -Type Output
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\BTAGService' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\bthserv' /v 'Start' /t REG_DWORD /d '3' /f
    $usersvcs = (Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\BluetoothUserService*').Name
    foreach ($usersvc in $usersvcs) {
      Reg.exe add $usersvc /v 'Start' /t REG_DWORD /d '3' /f
    }
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\Fax' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\Spooler' /v 'Start' /t REG_DWORD /d '2' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\defragsvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'Start' /t REG_DWORD /d '2' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\RmSvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\wisvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\diagsvc' /v 'Start' /t REG_DWORD /d '3' /f
    $command = "Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DPS' /v 'Start' /t REG_DWORD /d '2' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost' /v 'Start' /t REG_DWORD /d '3' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost' /v 'Start' /t REG_DWORD /d '3' /f"
    Run-Trusted -command $command
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker' /v 'Start' /t REG_DWORD /d '2' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\lfsvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnum' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc' /v 'Start' /t REG_DWORD /d '3' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WalletService' /v 'Start' /t REG_DWORD /d '3' /f

  }


  if ($checkbox4.Checked) {
    if (Test-Path 'C:\Windows\System32\WSReset.exe') {
      Write-Status -Message 'Running Wsreset.exe -i...' -Type Output
      Start-process WSReset.exe -ArgumentList '-i' 
      Start-Sleep 10
      while (get-process -Name BackgroundTransferHost -ErrorAction SilentlyContinue) {
        Start-Sleep 1
      }
    }
    #check if it installed
    if (!(Get-AppxPackage 'Microsoft.WindowsStore')) {
      Write-Status -Message 'Wsreset Did Not Work, Running Zoicware Store Installer...' -Type Output
      $storeDir = Search-Directory '*zWindowsStore'
      $dependencies = @()
      Get-ChildItem $storeDir | ForEach-Object {
        if ($_.FullName -like '*.appxbundle') {
          $Script:storePath = $_.FullName
        }
        else {
          $dependencies += $_.FullName
        }
      }
      Add-AppPackage -Path $storePath -DependencyPath $dependencies 
    }
  


    

  }


  if ($checkbox5.Checked) {
    Write-Status -Message 'Restoring Registry Tweaks...' -Type Output
    Remove-Item "$tempDir\RevertTweaks.reg" -Force -ErrorAction SilentlyContinue
    $file = New-Item -Path "$tempDir\RevertTweaks.reg" -ItemType File -Force

    $regContent = @'
Windows Registry Editor Version 5.00

;enable uac
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"PromptOnSecureDesktop"=dword:00000001
"EnableLUA"=dword:00000001
"ConsentPromptBehaviorAdmin"=dword:00000005

;store 
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore]
"AutoDownload"=-

;taskbar
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"TaskbarMn"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ShowTaskViewButton"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search]
"SearchboxTaskbarMode"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"HideSCAMeetNow"=-

[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer]
"DisableNotificationCenter"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds]
"EnableFeeds"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"EnableAutoTray"=-

;startmenu
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer]
"ShowOrHideMostUsedApps"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer]
"HideRecentlyAddedApps"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"HideRecentlyAddedApps"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Start_TrackDocs"=-

;Explorer
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"LaunchTo"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"ShowFrequent"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings]
"IsDeviceSearchHistoryEnabled"=-

[HKEY_CURRENT_USER\Control Panel\Desktop]
"MenuShowDelay"="400"

;personalization
[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize]
"AppsUseLightTheme"=dword:00000001
"SystemUsesLightTheme"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize]
"AppsUseLightTheme"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent]
"AccentPalette"=hex:a6,d8,ff,00,76,b9,ed,00,42,9c,e3,00,00,78,d7,00,00,5a,9e,\
  00,00,42,75,00,00,26,42,00,f7,63,0c,00
"StartColorMenu"=dword:ff9e5a00
"AccentColorMenu"=dword:ffd77800

[HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM]
"EnableWindowColorization"=dword:00000000
"AccentColor"=dword:ffd77800
"ColorizationColor"=dword:c40078d7
"ColorizationAfterglow"=dword:c40078d7

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh] 
"AllowNewsAndInterests"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize]
"EnableTransparency"=dword:00000001

;sound

[HKEY_CURRENT_USER\Software\Microsoft\Multimedia\Audio]
"UserDuckingPreference"=-

;power
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings]
"ShowLockOption"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings]
"ShowSleepOption"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power]
"HibernateEnabled"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling]
"PowerThrottlingOff"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile]
"NetworkThrottlingIndex"=dword:0000000a
"SystemResponsiveness"=dword:00000014


[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers]
"HwSchMode"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\VideoSettings]
"VideoQualityOnBattery"=-

;system settings
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects]
"VisualFXSetting"=-

[HKEY_CURRENT_USER\Control Panel\Desktop]
"UserPreferencesMask"=-
"DragFullWindows"="1"

[HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics]
"MinAnimate"="1"

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"TaskbarAnimations"=dword:00000001
"ListviewShadow"=dword:00000001
"ListviewAlphaSelect"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM]
"EnableAeroPeek"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance]
"fAllowToGetHelp"=dword:00000001

;xbox
[HKEY_CURRENT_USER\System\GameConfigStore]
"GameDVR_Enabled"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\GameDVR]
"AppCaptureEnabled"=-
"AudioEncodingBitrate"=-
"AudioCaptureEnabled"=-
"CustomVideoEncodingBitrate"=-
"CustomVideoEncodingHeight"=-
"CustomVideoEncodingWidth"=-
"HistoricalBufferLength"=-
"HistoricalBufferLengthUnit"=-
"HistoricalCaptureEnabled"=-
"HistoricalCaptureOnBatteryAllowed"=-
"HistoricalCaptureOnWirelessDisplayAllowed"=-
"MaximumRecordLength"=-
"VideoEncodingBitrateMode"=-
"VideoEncodingResolutionMode"=-
"VideoEncodingFrameRateMode"=-
"EchoCancellationEnabled"=-
"CursorCaptureEnabled"=-
"VKToggleGameBar"=-
"VKMToggleGameBar"=-
"VKSaveHistoricalVideo"=-
"VKMSaveHistoricalVideo"=-
"VKToggleRecording"=-
"VKMToggleRecording"=-
"VKTakeScreenshot"=-
"VKMTakeScreenshot"=-
"VKToggleRecordingIndicator"=-
"VKMToggleRecordingIndicator"=-
"VKToggleMicrophoneCapture"=-
"VKMToggleMicrophoneCapture"=-
"VKToggleCameraCapture"=-
"VKMToggleCameraCapture"=-
"VKToggleBroadcast"=-
"VKMToggleBroadcast"=-
"MicrophoneCaptureEnabled"=-
"SystemAudioGain"=-
"MicrophoneGain"=-

[HKEY_CURRENT_USER\Software\Microsoft\GameBar]
"UseNexusForGameBarEnabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\GameBar]
"GamepadNexusChordEnabled"=-

;privacy
[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam]
"Value"="Allow"
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessLocation"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessCamera"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsActivateWithVoice"=-
"LetAppsActivateWithVoiceAboveLock"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessNotifications"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessAccountInfo"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessContacts"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessCalendar"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessPhone"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessCallHistory"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessEmail"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessTasks"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessMessaging"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessRadios"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessTrustedDevices"=-
"LetAppsSyncWithDevices"=-

; PRIVACY Text and Image Generation Deny
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessSystemAIModels"=-

; PRIVACY Human Presence Deny
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessHumanPresence"=-

; PRIVACY BackgroundSpatialPerception Deny
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessBackgroundSpatialPerception"=-

; PRIVACY Eye Tracker Deny
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessGazeInput"=-

; PRIVACY GetDiagnosticInfo Deny
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsGetDiagnosticInfo"=-

; PRIVACY Motion Deny
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsAccessMotion"=-

; PRIVACY Background Apps Deny
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy]
"LetAppsRunInBackground"=-




[HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps]
"AgentActivationEnabled"=-
"AgentActivationLastUsed"=-

[-HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps]

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios]
"Value"="Allow"

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess]
"Value"="Allow"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder]
"Value"="Allow"

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI]
"DisableMFUTracking"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EdgeUI]
"DisableMFUTracking"=-

[HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization]
"RestrictImplicitInkCollection"=dword:00000000
"RestrictImplicitTextCollection"=dword:00000000

[HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization\TrainedDataStore]
"HarvestContacts"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Personalization\Settings]
"AcceptedPrivacyPolicy"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules]
"NumberOfSIUFInPeriod"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"PublishUserActivities"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings]
"SafeSearchMode"=dword:00000001
"IsAADCloudSearchEnabled"=-
"IsMSACloudSearchEnabled"=-

;notifications
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications]
"ToastEnabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance]
"Enabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel]
"Enabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.CapabilityAccess]
"Enabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp]
"Enabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]
"SubscribedContent-338389Enabled"=dword:00000001


[HKEY_CURRENT_USER\SOFTWARE\Microsoft\ScreenMagnifier]
"FollowCaret"=-
"FollowNarrator"=-
"FollowMouse"=-
"FollowFocus"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Narrator]
"IntonationPause"=-
"ReadHints"=-
"ErrorNotificationType"=-
"EchoChars"=-
"EchoWords"=-
"NarratorCursorHighlight"=-
"CoupleNarratorCursorKeyboard"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Narrator\NarratorHome]
"MinimizeType"=-
"AutoStart"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Narrator\NoRoam]
"EchoToggleKeys"=-
"DuckAudio"=-
"WinEnterLaunchEnabled"=-
"ScriptingEnabled"=-
"OnlineServicesEnabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Ease of Access]
"selfvoice"=-
"selfscan"=-

[HKEY_CURRENT_USER\Control Panel\Accessibility]
"Sound on Activation"=-
"Warning Sounds"=-

[HKEY_CURRENT_USER\Control Panel\Accessibility\HighContrast]
"Flags"="126"

[HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response]
"AutoRepeatDelay"="1000"
"AutoRepeatRate"="500"
"Flags"="126"

[HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys]
"Flags"="62"
"MaximumSpeed"="80"
"TimeToMaximumSpeed"="3000"

[HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys]
"Flags"="510"

[HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys]
"Flags"="62"

[HKEY_CURRENT_USER\Control Panel\Accessibility\SoundSentry]
"Flags"="2"
"FSTextEffect"="0"
"TextEffect"="0"
"WindowsEffect"="1"


[HKEY_CURRENT_USER\Control Panel\Accessibility\SlateLaunch]
"ATapp"="narrator"
"LaunchAT"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching]
"SearchOrderConfig"=dword:00000001

[HKEY_CURRENT_USER\Software\NVIDIA Corporation\NvTray]
"StartOnLogin"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance]
"MaintenanceDisabled"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]
"DisableAutomaticRestartSignOn"=-

[HKEY_LOCAL_MACHINE\SYSTEM\Maps]
"AutoUpdateEnabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"MultiTaskingAltTabFilter"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Hidden"=dword:00000002

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Windows.InputSwitchToastHandler]
"Enabled"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings]
"NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK"=-
"NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK"=-
"NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND"=-

[HKEY_CURRENT_USER\Keyboard Layout\Toggle]
"Language Hotkey"=-
"Hotkey"=-
"Layout Hotkey"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay]
"Enabled"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\CTF\LangBar]
"ShowStatus"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System]
"DisableLogonBackgroundImage"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search]
"BingSearchEnabled"=-

[HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer]
"DisableSearchBoxSuggestions"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers]
"DisableAutoplay"=dword:00000000


[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]
"SystemPaneSuggestionsEnabled"=dword:00000001
"SubscribedContent-338388Enabled"=dword:00000001

[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search]
"ConnectedSearchUseWeb"=-
"DisableWebSearch"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.BackupReminder]
"Enabled"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.LowDisk]
"Enabled"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer]
"DisableCoInstallers"=-

[HKEY_CURRENT_USER\SOFTWARE\Valve\Steam]
"GPUAccelWebViewsV2"=dword:00000001
"H264HWAccel"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell]
"FolderType"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search]
"BackgroundAppGlobalToggle"=dword:00000001
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications]
"GlobalUserDisabled"=dword:00000000

[HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search]
"ConnectedSearchUseWeb"=-
"DisableWebSearch"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DesktopSpotlight\Settings]
"EnabledState"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\FTH]
"Enabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer]
"SettingsPageVisibility"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer]
"EnableAutoTray"=dword:00000001

[HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify]
"SystemTrayChevronVisibility"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MdmCommon\SettingValues]
"LocationSyncEnabled"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy]
"TailoredExperiencesWithDiagnosticDataEnabled"=-

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\Store\TailoredExperiencesWithDiagnosticDataEnabled]
"Value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection]
"AllowTelemetry"=-
"MaxTelemetryAllowed"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\Store\AllowTelemetry]
"Value"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Start_IrisRecommendations"=dword:00000001
"Start_AccountNotifications"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Start]
"HideRecommendedSection"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Education]
"IsEducationEnvironment"=-
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer]
"HideRecommendedSection"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]
"OpenFolderInNewTab"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power]
"SleepStudyDisabled"=-

[-HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32]

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity]
"Enabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard]
"EnableVirtualizationBasedSecurity"=dword:00000001
"RequirePlatformSecurityFeatures"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks]
"Enabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard]
"Enabled"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard]
"Disabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings]
"IsDynamicSearchBoxEnabled"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\StorageSense]
"AllowStorageSenseGlobal"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"TaskbarAl"=dword:00000001

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop]
"Enabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager]
"SubscribedContent-310093Enabled"=-
"SubscribedContent-338393Enabled"=-
"SubscribedContent-353694Enabled"=-
"SubscribedContent-353696Enabled"=-
"OemPreInstalledAppsEnabled"=-
"PreInstalledAppsEnabled"=-
"SilentInstalledAppsEnabled"=-
"SoftLandingEnabled"=-
"ContentDeliveryAllowed"=-
"PreInstalledAppsEverEnabled"=-
"SubscribedContentEnabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"EnableSnapBar"=-
"EnableSnapAssistFlyout"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications]
"EnableAccountNotifications"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer]
"HubMode"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"Start_IrisRecommendations"=-
"Start_Layout"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start]
"ShowRecentList"=-

[HKEY_CURRENT_USER\Software\Microsoft\input\Settings]
"InsightsEnabled"=-

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]
"ShowCopilotButton"=dword:00000001

[HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsCopilot]
"TurnOffWindowsCopilot"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\luafv]
"Start"=dword:00000002

[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP]
"DragTrayEnabled"=dword:00000001

[-HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\14\3895955085]
'@

    Add-Content -Path $file.FullName -Value $regContent -Force
    Start-Sleep 1
    regedit.exe /s $file.FullName

    Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue

  }

  if ($checkbox6.Checked) {
    Write-Status -Message 'Downloading Xbox Game Repair Tool...' -Type Output
    #remove gamebar popup block
    Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' 1 -type dword -force -ea 0
    Set-ItemProperty 'HKCU:\System\GameConfigStore' 'GameDVR_Enabled' 1 -type dword -force -ea 0
    'ms-gamebar', 'ms-gamebarservices', 'ms-gamingoverlay' | ForEach-Object {
      #remove noopenwith and systray.exe to hide popup
      Remove-ItemProperty "Registry::HKCR\$_" 'NoOpenWith' -force -ea 0
      Remove-Item "Registry::HKCR\$_\shell" -rec -force -ea 0 
    }
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri 'https://aka.ms/GamingRepairTool' -UseBasicParsing -OutFile "$tempDir\GamingRepairTool.exe"
    Start-Process "$tempDir\GamingRepairTool.exe" -Wait -WindowStyle Normal
    Remove-Item "$tempDir\GamingRepairTool.exe" -Force -ErrorAction SilentlyContinue
  }


  if ($checkbox7.Checked) {
    Write-Status -Message 'Disabling Qos for Upload and Resetting Network Changes...' -Type Output
    FixUploadBufferBloat -Disable
  }


  if ($checkbox8.Checked) {
    Write-Status -Message 'Removing Razer & Asus Servers from Hosts File...' -Type Output

    $hostsPath = 'C:\Windows\System32\drivers\etc\hosts'
    $content = Get-Content -Path $hostsPath -Raw
    $contentArray = $content -split "`r`n"
    $newContent = @()
    foreach ($line in $contentArray) {
      if ($line -like '*razer*' -or $line -like '*asus*') {
        $newContent += $null
      }
      else {
        $newContent += $line
      }
    }
    Set-Content -Path $hostsPath -Value $newContent -Force

  }

  if ($checkbox9.Checked) {
    Write-Status -Message 'Unpausing Updates...' -Type Output
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -name 'PauseUpdatesExpiryTime' -Force
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -name 'PauseFeatureUpdatesEndTime' -Force
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -name 'PauseFeatureUpdatesStartTime' -Force
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -name 'PauseQualityUpdatesEndTime' -Force
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -name 'PauseQualityUpdatesStartTime' -Force
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -name 'PauseUpdatesStartTime' -Force

    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetAllowOptionalContent' /f >$null
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdates' /f >$null
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdatesPeriodInDays' /f >$null
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdates' /f >$null
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /f >$null 
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /f >$null
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeUpdateClassifications' /f >$null
    Reg.exe delete 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'ExcludeWUDriversInQualityUpdate' /f >$null
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' /v 'PreventDeviceMetadataFromNetwork' /f >$null
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' /v 'DontPromptForWindowsUpdate' /f >$null
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' /v 'DontSearchWindowsUpdate' /f >$null
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DriverSearching' /v 'DriverUpdateWizardWuSearchEnabled' /f >$null
  }
 
  if ($checkbox10.Checked) {
    Write-Status -Message 'Restoring Default Context Menu...' -Type Output

    $regFile = @'
  Windows Registry Editor Version 5.00

  [-HKEY_LOCAL_MACHINE\Software\Classes\.bat\ShellNew]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\.ps1\ShellNew]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\.reg\ShellNew]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\DesktopBackground\Shell\KillNotResponding]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\DesktopBackground\Shell\ShutDown]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\DesktopBackground\Shell\SnippingTool]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\DesktopBackground\Shell\taskmgr]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\Directory\background\shell\OpenElevatedCmd]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\Directory\background\shell\OpenElevatedPS]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\Directory\shell\OpenElevatedCmd]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\Directory\shell\OpenElevatedPS]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\Drive\shell\OpenElevatedCmd]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\Drive\shell\OpenElevatedPS]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\LibraryFolder\Shell\OpenElevatedCmd]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\LibraryFolder\Shell\OpenElevatedPS]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\Microsoft.PowerShellScript.1\Shell\runas]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\Msi.Package\shell\runas]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\SystemFileAssociations\.ps1\Shell\run_edit]
  
  [-HKEY_LOCAL_MACHINE\Software\Classes\VBSFile\Shell\runas]

  [-HKEY_CLASSES_ROOT\*\shell\runas]
 
  [-HKEY_CLASSES_ROOT\*\shell\runas\command]
 
  [-HKEY_CLASSES_ROOT\Directory\shell\runas]
 
  [-HKEY_CLASSES_ROOT\Directory\shell\runas\command]

  [-HKEY_CLASSES_ROOT\*\shell\Delete Permanently]

[-HKEY_CURRENT_USER\SOFTWARE\Classes\*\shellex\Delete Permanently]

[HKEY_CLASSES_ROOT\*\shell\pintohomefile]
"CommandStateHandler"="{b455f46e-e4af-4035-b0a4-cf18d2f6f28e}"
"CommandStateSync"=""
"MUIVerb"="@shell32.dll,-51608"
"NeverDefault"=""
"SkipCloudDownload"=dword:00000000

[HKEY_CLASSES_ROOT\*\shell\pintohomefile\command]
"DelegateExecute"="{b455f46e-e4af-4035-b0a4-cf18d2f6f28e}"

[HKEY_CLASSES_ROOT\Directory\shellex\PropertySheetHandlers\{ef43ecfe-2ab9-4632-bf21-58909dd177f0}]
@=""

[HKEY_CLASSES_ROOT\Drive\shellex\PropertySheetHandlers\{ef43ecfe-2ab9-4632-bf21-58909dd177f0}]
@=""

[HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\Sharing]
@="{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"

[HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers\Sharing]
@="{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"

[HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\Sharing]
@="{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"

[HKEY_CLASSES_ROOT\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing]
@="{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"

[HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing]
@="{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"

[HKEY_CLASSES_ROOT\Drive\shellex\ContextMenuHandlers\Sharing]
@="{f81e9010-6ea4-11ce-a7ff-00aa003ca9f6}"

[HKEY_CLASSES_ROOT\Directory\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}]

[HKEY_CLASSES_ROOT\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}]

[HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}]

[HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}]

[HKEY_CLASSES_ROOT\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}]

[HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}]

[HKEY_CLASSES_ROOT\Drive\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}]

[HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo]
@="{7BA4C740-9E81-11CF-99D3-00AA004AE837}"

[HKEY_CLASSES_ROOT\UserLibraryFolder\shellex\ContextMenuHandlers\SendTo]
@="{7BA4C740-9E81-11CF-99D3-00AA004AE837}"

[HKEY_CLASSES_ROOT\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing]
@="{e2bf9676-5f8f-435c-97eb-11607a5bedf7}"

[HKEY_CLASSES_ROOT\DesktopBackground\Shell\Personalize]
@=hex(2):40,00,25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,74,\
  00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,74,00,\
  68,00,65,00,6d,00,65,00,63,00,70,00,6c,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,\
  00,31,00,30,00,00,00
"HideInSafeMode"=""
"Icon"=hex(2):25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,74,\
  00,25,00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,74,00,\
  68,00,65,00,6d,00,65,00,63,00,70,00,6c,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,\
  00,31,00,00,00
"Position"="Bottom"
"SettingsURI"="ms-settings:personalization"

[HKEY_CLASSES_ROOT\DesktopBackground\Shell\Personalize\command]
"DelegateExecute"="{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}"

[HKEY_CLASSES_ROOT\DesktopBackground\Shell\Display]
@=hex(2):40,00,25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,\
  00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  69,00,73,00,70,00,6c,00,61,00,79,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,34,\
  00,00,00
"Icon"=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,\
  00,25,00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,64,00,\
  69,00,73,00,70,00,6c,00,61,00,79,00,2e,00,64,00,6c,00,6c,00,2c,00,2d,00,31,\
  00,00,00
"Position"="Bottom"
"SettingsUri"="ms-settings:display"

[HKEY_CLASSES_ROOT\DesktopBackground\Shell\Display\command]
"DelegateExecute"="{556FF0D6-A1EE-49E5-9FA4-90AE116AD744}"

[HKEY_CLASSES_ROOT\Folder\ShellEx\ContextMenuHandlers\Library Location]
@="{3dad6c5d-2167-4cae-9914-f99e41c12cfa}"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location]
@="{3dad6c5d-2167-4cae-9914-f99e41c12cfa}"
'@

    Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoCustomizeThisFolder' /f *>$null
    Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{9F156763-7844-4DC4-B2B1-901F640F5155}' /f *>$null
    Reg.exe delete 'HKCR\SystemFileAssociations\image\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null
    Reg.exe delete 'HKCR\batfile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null   
    Reg.exe delete 'HKCR\cmdfile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\docxfile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\fonfile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\htmlfile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\inffile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\inifile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\JSEFile\Shell\Print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\otffile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\pfmfile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\regfile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\rtffile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\ttcfile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\ttffile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\txtfile\shell\print' /v 'ProgrammaticAccessOnly' /f *>$null 
    Reg.exe delete 'HKCR\VBEFile\Shell\Print' /v 'ProgrammaticAccessOnly' /f *>$null
    Reg.exe delete 'HKCR\VBSFile\Shell\Print' /v 'ProgrammaticAccessOnly' /f *>$null
    Reg.exe delete 'HKCR\WSFFile\Shell\Print' /v 'ProgrammaticAccessOnly' /f *>$null
    Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}' /f *>$null 
    Reg.exe delete 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}' /f *>$null
    Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{EE07CEF5-3441-4CFB-870A-4002C724783A}' /f *>$null
    Reg.exe delete 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{EE07CEF5-3441-4CFB-870A-4002C724783A}' /f *>$null
    Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{1d27f844-3a1f-4410-85ac-14651078412d}' /f *>$null

    $path = New-Item -Path "$tempDir\RestoreContext.reg" -Value $regFile -Force 
    Start-Process regedit.exe -ArgumentList "/s $($path.FullName)"
  }

  if ($checkbox11.Checked) {
    Write-Status -Message 'Restoring Default Winver...' -Type Output
    if (Test-Path "$env:USERPROFILE\zBackup\OGwinver.exe") {
      Move-item 'C:\Windows\System32\winver.exe' -Destination "$folder\W11Files"
      if (Test-Path "$folder\W11Files\WinverMono.exe") {
        Rename-Item "$folder\W11Files\winver.exe" -NewName 'WinverStandard.exe'
      }
      else {
        Rename-Item "$folder\W11Files\winver.exe" -NewName 'WinverMono.exe'
      }
      Move-item "$env:USERPROFILE\zBackup\OGwinver.exe" -Destination 'C:\Windows\System32'
      Rename-Item 'C:\Windows\System32\OGwinver.exe' -NewName 'winver.exe' -Force
    }
    else {
      Write-Status -Message "Winver Not Found in $env:USERPROFILE\zBackup" -Type Error
    }
  }

  if ($checkbox12.Checked) {
    Write-Status -Message 'Restoring Win 11 Task Manager...' -type output
    Remove-Item 'C:\Windows\System32\Taskmgr.exe' -Force 
    Rename-Item 'C:\Windows\System32\Taskmgr_WIN11.exe' -NewName 'Taskmgr.exe' -Force | Out-Null
  }

  if ($checkbox13.Checked) {
    Write-Status -Message 'Restoring Win 11 File Explorer Ribbon...' -type output
    Reg.exe delete 'HKCU\Software\Classes\CLSID\{2aa9162e-c906-4dd9-ad0b-3d24a8eef5a0}' /f *>$null
    Reg.exe delete 'HKCU\Software\Classes\CLSID\{6480100b-5a83-4d1e-9f69-8ae5a88e9a33}' /f *>$null
  }

  if ($checkbox14.Checked) {
    Write-Status -Message 'Enabling Windows Backup App...' -type output
    Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount' /v 'DisableUserAuth' /f *>$null
  }

  if ($checkbox15.Checked) {
    Write-Status -Message 'Enabling HVCI/VBS...' -type output
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' /v 'Enabled' /t REG_DWORD /d '1' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'EnableVirtualizationBasedSecurity' /t REG_DWORD /d '1' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard' /v 'RequirePlatformSecurityFeatures' /t REG_DWORD /d '1' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks' /v 'Enabled' /t REG_DWORD /d '1' /f
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' /v 'Enabled' /t REG_DWORD /d '1' /f
    Reg.exe delete 'HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel' /v 'MitigationOptions' /f *>$null
  }


}
