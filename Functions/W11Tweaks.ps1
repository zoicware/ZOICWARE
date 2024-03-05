function W11Tweaks {
  param (
    [Parameter(mandatory=$false)] [bool]$Autorun = $false
    ,[Parameter(mandatory=$false)] [bool]$removeEdges = $false
    ,[Parameter(mandatory=$false)] [bool]$win10taskbar = $false
    ,[Parameter(mandatory=$false)] [bool]$win10explorer = $false
    ,[Parameter(mandatory=$false)] [bool]$servicesManual = $false
    
  )

#dot source update config function
    $path = Get-ChildItem -path C:\ -Filter update-config.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; }
    .$path


  $checkbox2 = new-object System.Windows.Forms.checkbox
  $checkbox4 = new-object System.Windows.Forms.checkbox
  $checkbox6 = new-object System.Windows.Forms.checkbox
  $checkbox3 = new-object System.Windows.Forms.checkbox

  $settings = @{}
  $settings["removeEdges"] = $checkbox2
  $settings["10TaskbarStartmenu"] = $checkbox4
  $settings["10Explorer"] = $checkbox6
  $settings["servicesManual"] = $checkbox3


  if($Autorun){
    $result = [System.Windows.Forms.DialogResult]::OK
    $checkbox2.Checked = $removeEdges
    $checkbox4.Checked = $win10taskbar
    $checkbox6.Checked = $win10explorer
    $checkbox3.Checked = $servicesManual
  }
  else{

# Load the necessary assemblies for Windows Forms
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")


# Create a form
$form = New-Object Windows.Forms.Form
$form.Text = "Windows 11 Tweaks"
$form.Size = New-Object Drawing.Size(450, 450)


$label1 = New-Object System.Windows.Forms.Label
$label1.Location = New-Object System.Drawing.Point(10,10)
$label1.Size = New-Object System.Drawing.Size(200,20)
$label1.Text = 'Patch Explorer:'
$label1.Font = New-Object System.Drawing.Font("Segoe UI", 13)  
$form.Controls.Add($label1)

$label2 = New-Object System.Windows.Forms.Label
$label2.Location = New-Object System.Drawing.Point(10,200)  
$label2.Size = New-Object System.Drawing.Size(200,20)
$label2.Text = 'Misc:'
$label2.Font = New-Object System.Drawing.Font("Segoe UI", 13)  
$form.Controls.Add($label2)

#explorer patcher options
 
 $checkbox2.Location = new-object System.Drawing.Size(20,40)
 $checkbox2.Size = new-object System.Drawing.Size(200,30)
 $checkbox2.Text = "Remove Rounded Edges"
 $checkbox2.Font = New-Object System.Drawing.Font("Segoe UI", 9)
 $checkbox2.Checked = $false
 $Form.Controls.Add($checkbox2) 
 
 
 $checkbox4.Location = new-object System.Drawing.Size(20,80)
 $checkbox4.Size = new-object System.Drawing.Size(300,30)
 $checkbox4.Text = "Enable Windows 10 TaskBar and StartMenu"
 $checkbox4.Font = New-Object System.Drawing.Font("Segoe UI", 9)
 $checkbox4.Checked = $false
 $Form.Controls.Add($checkbox4)
 
 
 $checkbox6.Location = new-object System.Drawing.Size(20,120)
 $checkbox6.Size = new-object System.Drawing.Size(300,30)
 $checkbox6.Text = "Enable Windows 10 File Explorer"
 $checkbox6.Font = New-Object System.Drawing.Font("Segoe UI", 9)
 $checkbox6.Checked = $false
 $Form.Controls.Add($checkbox6)   
 

#misc options

 $checkbox3.Location = new-object System.Drawing.Size(20,230)
 $checkbox3.Size = new-object System.Drawing.Size(200,30)
 $checkbox3.Text = "Set all Services to Manual"
 $checkbox3.Font = New-Object System.Drawing.Font("Segoe UI", 9)
 $checkbox3.Checked = $false
 $Form.Controls.Add($checkbox3) 

 $OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(120,380)
$OKButton.Size = New-Object System.Drawing.Size(100,23)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(210,380)
$CancelButton.Size = New-Object System.Drawing.Size(100,23)
$CancelButton.Text = 'Cancel'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)


  $result = $form.ShowDialog()

  }


if ($result -eq [System.Windows.Forms.DialogResult]::OK){

  if(!($Autorun)){
    #loop through checkbox hashtable to update config
    $settings.GetEnumerator() | ForEach-Object {
      
      $settingName = $_.Key
      $checkbox = $_.Value
  
      if ($checkbox.Checked) {
          update-config -setting $settingName -value 1
      }
  }
  }

if($checkbox2.Checked){
#disable rounded edges
$path = Get-ChildItem -Path C:\ -Filter win11-toggle-rounded-corners.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
Start-Process $path -ArgumentList '--autostart --disable' -WindowStyle Hidden -Wait

}

if($checkbox4.Checked){
#install explorer patcher
if(!(Test-Path -Path 'C:\Program Files\ExplorerPatcher\ep_setup.exe' -ErrorAction SilentlyContinue)){

$path = Get-ChildItem -Path C:\ -Filter ep_setup.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
Start-Process $path -WindowStyle Hidden -Wait
#disable notis
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Windows.Explorer" /v "Enabled" /t REG_DWORD /d "0" /f
}
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowClassicMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\ExplorerPatcher" /v "TaskbarGlomLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\ExplorerPatcher" /v "MMTaskbarGlomLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\ExplorerPatcher" /v "HideControlCenterButton" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f
}


if($checkbox6.Checked){
#check if explorer patcher is installed
if(!(Test-Path -Path 'C:\Program Files\ExplorerPatcher\ep_setup.exe' -ErrorAction SilentlyContinue)){
$path = Get-ChildItem -Path C:\ -Filter ep_setup.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
Start-Process $path -WindowStyle Hidden -Wait
#disable notis
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Windows.Explorer" /v "Enabled" /t REG_DWORD /d "0" /f
}
#windows 10 file explorer config
$path = Get-ChildItem -Path C:\ -Filter ExplorerPatcher10.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
Move-Item $path -Destination "$env:USERPROFILE\Desktop" -Force

[System.Windows.Forms.MessageBox]::Show('Config Exported to Desktop...Import Under "About".', 'Explorer Patcher')
Start-Process "C:\Windows\System32\rundll32.exe" -ArgumentList '"C:\Program Files\ExplorerPatcher\ep_gui.dll",ZZGUI' -Wait   
}






if($checkbox3.Checked){
#set all services to manual (that are allowed)
$services = Get-Service  
$servicesKeep = "AudioEndpointBuilder
Audiosrv
EventLog
SysMain
Themes
WSearch"
foreach ($service in $services) { 
if($service.StartType -like "*Auto*"){
if(!($servicesKeep -match $service.Name)){
        
        Set-Service -Name $service.Name -StartupType Manual -ErrorAction SilentlyContinue
       
        }         
    }
  }
Write-Host "Services Set to Manual..."
}
}




}


