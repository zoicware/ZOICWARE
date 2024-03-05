function OptionalTweaks {
  param (
    [Parameter(mandatory=$false)] [bool]$Autorun = $false
    ,[Parameter(mandatory=$false)] [bool]$opblackTheme = $false
    ,[Parameter(mandatory=$false)] [bool]$opclassicTheme = $false 
    ,[Parameter(mandatory=$false)] [bool]$opROFSW = $false 
    ,[Parameter(mandatory=$false)] [bool]$opremoveSpeech = $false 
    ,[Parameter(mandatory=$false)] [bool]$openableHAGS = $false 
    ,[Parameter(mandatory=$false)] [bool]$optransTaskbar = $false
    ,[Parameter(mandatory=$false)] [bool]$opdoubleClickPS = $false
    ,[Parameter(mandatory=$false)] [bool]$opremoveMouseSoundSchemes = $false 
    ,[Parameter(mandatory=$false)] [bool]$opremoveRecycle = $false
    ,[Parameter(mandatory=$false)] [bool]$opremoveQuickAccess = $false
    ,[Parameter(mandatory=$false)] [bool]$openableGameBar = $false 
    ,[Parameter(mandatory=$false)] [bool]$opblockRazerAsus = $false
    ,[Parameter(mandatory=$false)] [bool]$opremoveNetworkIcon = $false 
    ,[Parameter(mandatory=$false)] [bool]$opapplyPBO = $false
    ,[Parameter(mandatory=$false)] [bool]$opnoDriversInUpdate = $false
    ,[Parameter(mandatory=$false)] [bool]$opremoveBackupApp = $false
    ,[Parameter(mandatory=$false)] [bool]$openable11Sounds = $false
    ,[Parameter(mandatory=$false)] [bool]$connewFiles = $false
    ,[Parameter(mandatory=$false)] [bool]$conmorePS = $false
    ,[Parameter(mandatory=$false)] [bool]$consnipping = $false
    ,[Parameter(mandatory=$false)] [bool]$conshutdown = $false
    ,[Parameter(mandatory=$false)] [bool]$conrunAsAdmin = $false
    ,[Parameter(mandatory=$false)] [bool]$conpsCmd = $false 
    ,[Parameter(mandatory=$false)] [bool]$conkillTasks = $false 
    ,[Parameter(mandatory=$false)] [bool]$conpermDel = $false
    ,[Parameter(mandatory=$false)] [bool]$legacyPhotoViewer = $false
    ,[Parameter(mandatory=$false)] [bool]$legacy7calc = $false
    ,[Parameter(mandatory=$false)] [bool]$legacySnipping = $false
    ,[Parameter(mandatory=$false)] [bool]$legacy7task = $false
    ,[Parameter(mandatory=$false)] [bool]$legacyVolumeFlyout = $false
    ,[Parameter(mandatory=$false)] [bool]$legacyAltTab = $false
  )
  

  #dot source update config function
    $path = Get-ChildItem -path C:\ -Filter update-config.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; }
    .$path



#create checkboxes
$checkbox2 = new-object System.Windows.Forms.checkbox
$classicblackBTN = new-object System.Windows.Forms.RadioButton
$checkbox4 = new-object System.Windows.Forms.checkbox
$checkbox5 = new-object System.Windows.Forms.checkbox
$checkbox6 = new-object System.Windows.Forms.checkbox
$checkbox7 = new-object System.Windows.Forms.checkbox
$checkbox8 = new-object System.Windows.Forms.checkbox
$checkbox9 = new-object System.Windows.Forms.checkbox
$checkbox10 = new-object System.Windows.Forms.checkbox
$checkbox12 = new-object System.Windows.Forms.checkbox
$checkbox13 = new-object System.Windows.Forms.checkbox
$checkbox14 = new-object System.Windows.Forms.checkbox
$checkbox15 = new-object System.Windows.Forms.checkbox
$checkbox16 = new-object System.Windows.Forms.checkbox
$checkbox17 = new-object System.Windows.Forms.checkbox
$checkbox18 = new-object System.Windows.Forms.checkbox
$checkbox19 = new-object System.Windows.Forms.checkbox
$checkbox20 = new-object System.Windows.Forms.checkbox
$checkbox26 = new-object System.Windows.Forms.checkbox
$checkbox21 = new-object System.Windows.Forms.checkbox
$checkbox22 = new-object System.Windows.Forms.checkbox
$checkbox23 = new-object System.Windows.Forms.checkbox
$checkbox24 = new-object System.Windows.Forms.checkbox
$checkbox25 = new-object System.Windows.Forms.checkbox
$checkbox27 = new-object System.Windows.Forms.checkbox
$checkbox28 = new-object System.Windows.Forms.checkbox
$checkbox29 = new-object System.Windows.Forms.checkbox
$checkbox30 = new-object System.Windows.Forms.checkbox
$checkbox31 = new-object System.Windows.Forms.checkbox
$checkbox32 = new-object System.Windows.Forms.checkbox
$checkbox33 = new-object System.Windows.Forms.checkbox


#hashtable for updating config
$settings = @{}
$settings["opblackTheme"] = $checkbox2
$settings["opclassicTheme"] = $classicblackBTN
$settings["opROFSW"] = $checkbox4
$settings["opremoveSpeech"] = $checkbox5
$settings["legacyPhotoViewer"] = $checkbox6
$settings["openableHAGS"] = $checkbox7
$settings["optransTaskbar"] = $checkbox8
$settings["opremoveQuickAccess"] = $checkbox9
$settings["openableGameBar"] = $checkbox10
$settings["legacy7calc"] = $checkbox12
$settings["opblockRazerAsus"] = $checkbox13
$settings["connewFiles"] = $checkbox14
$settings["conmorePS"] = $checkbox15
$settings["consnipping"] = $checkbox16
$settings["conshutdown"] = $checkbox17
$settings["conrunAsAdmin"] = $checkbox18
$settings["conpsCmd"] = $checkbox19
$settings["conkillTasks"] = $checkbox20
$settings["conpermDel"] = $checkbox26
$settings["legacySnipping"] = $checkbox21
$settings["legacy7task"] = $checkBox22
$settings["opremoveNetworkIcon"] = $checkbox23
$settings["opapplyPBO"] = $checkbox24
$settings["legacyVolumeFlyout"] = $checkbox25
$settings["opdoubleClickPS"] = $checkbox27
$settings["legacyAltTab"] = $checkbox28
$settings["opnoDriversInUpdate"] = $checkbox29
$settings["opremoveBackupApp"] = $checkbox30
$settings["opremoveMouseSoundSchemes"] = $checkbox31
$settings["openable11Sounds"] = $checkbox32
$settings["opremoveRecycle"] = $checkbox33


if($AutoRun){
  $result = [System.Windows.Forms.DialogResult]::OK
  #setting options
  $checkbox2.Checked = $opblackTheme 
  $classicblackBTN.Checked = $opclassicTheme  
  $checkbox4.Checked = $opROFSW  
  $checkbox5.Checked = $opremoveSpeech
  $checkbox6.Checked = $legacyPhotoViewer 
  $checkbox7.Checked = $openableHAGS
  $checkbox8.Checked = $optransTaskbar
  $checkbox9.Checked = $opremoveQuickAccess
  $checkbox10.Checked = $openableGameBar
  $checkbox12.Checked = $legacy7calc
  $checkbox13.Checked = $opblockRazerAsus
  $checkbox14.Checked = $connewFiles
  $checkbox15.Checked = $conmorePS
  $checkbox16.Checked = $consnipping
  $checkbox17.Checked = $conshutdown
  $checkbox18.Checked = $conrunAsAdmin
  $checkbox19.Checked = $conpsCmd
  $checkbox20.Checked = $conkillTasks
  $checkbox26.Checked = $conpermDel
  $checkbox21.Checked = $legacySnipping
  $checkbox22.Checked = $legacy7task
  $checkbox23.Checked = $opremoveNetworkIcon
  $checkbox24.Checked = $opapplyPBO
  $checkbox25.Checked = $legacyVolumeFlyout
  $checkbox27.Checked = $opdoubleClickPS
  $checkbox28.Checked = $legacyAltTab
  $checkbox29.Checked = $opnoDriversInUpdate
  $checkbox30.Checked = $opremoveBackupApp
  $checkbox31.Checked = $opremoveMouseSoundSchemes
  $checkbox32.Checked = $openable11Sounds
  $checkbox33.Checked = $opremoveRecycle
}
else{
  [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
  [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
      
      # Set the size of your form
      $form = New-Object System.Windows.Forms.Form
      $form.Text = 'Optional Tweaks'
      $form.Size = New-Object System.Drawing.Size(600,580)
      $form.StartPosition = 'CenterScreen'
      
  $TabControl = New-Object System.Windows.Forms.TabControl
  $TabControl.Location = New-Object System.Drawing.Size(10, 10)
  $TabControl.Size = New-Object System.Drawing.Size(570, 500) 
  $TabControl.BackColor = 'White'
  
  
  $TabPage1 = New-Object System.Windows.Forms.TabPage
  $TabPage1.Text = "General"
  $TabPage1.BackColor = 'White'
  
  $TabPage2 = New-Object System.Windows.Forms.TabPage
  $TabPage2.Text = "Ultimate Context Menu"
  $TabPage2.BackColor = 'White'
  
  $TabPage3 = New-Object System.Windows.Forms.TabPage
  $TabPage3.Text = "Legacy Win Store"
  $TabPage3.BackColor = 'White'
     
     
  $TabControl.Controls.Add($TabPage1)
  $TabControl.Controls.Add($TabPage2)
  $TabControl.Controls.Add($TabPage3)
  
  
  $Form.Controls.Add($TabControl)    
     
      # create your checkbox 
      
      
      
      $checkbox2.Location = new-object System.Drawing.Size(10,20)
      $checkbox2.Size = new-object System.Drawing.Size(150,20)
      $checkbox2.Text = "Black Theme"
      $checkbox2.Checked = $false
      $Form.Controls.Add($checkbox2)  
      $TabPage1.Controls.Add($checkBox2)
  
      
      $classicblackBTN.Location = new-object System.Drawing.Size(15,40)
      $classicblackBTN.Size = new-object System.Drawing.Size(150,20)
      $classicblackBTN.Text = "Classic Black Theme"
      $classicblackBTN.Checked = $false
      $classicblackBTN.Visible = $false
      $Form.Controls.Add($classicblackBTN)  
      $TabPage1.Controls.Add($classicblackBTN)
      
  
      
      $checkbox4.Location = new-object System.Drawing.Size(10,70)
      $checkbox4.Size = new-object System.Drawing.Size(170,30)
      $checkbox4.Text = "Remove Open File Security Warning"
      $checkbox4.Checked = $false
      $Form.Controls.Add($checkbox4)
      $TabPage1.Controls.Add($checkBox4)
  
      
      $checkbox5.Location = new-object System.Drawing.Size(10,110)
      $checkbox5.Size = new-object System.Drawing.Size(200,20)
      $checkbox5.Text = "Remove Speech Recognition App"
      $checkbox5.Checked = $false
      $Form.Controls.Add($checkbox5)
      $TabPage1.Controls.Add($checkBox5)
  
      
      $checkbox6.Location = new-object System.Drawing.Size(10,20)
      $checkbox6.Size = new-object System.Drawing.Size(150,20)
      $checkbox6.Text = "Classic Photo Viewer"
      $checkbox6.Checked = $false
      $Form.Controls.Add($checkbox6)
      $TabPage3.Controls.Add($checkBox6)
  
      
      $checkbox7.Location = new-object System.Drawing.Size(10,150)
      $checkbox7.Size = new-object System.Drawing.Size(200,20)
      $checkbox7.Text = "Enable HAGS"
      $checkbox7.Checked = $false
      $Form.Controls.Add($checkbox7)
      $TabPage1.Controls.Add($checkBox7)
  
      
      $checkbox8.Location = new-object System.Drawing.Size(10,190)
      $checkbox8.Size = new-object System.Drawing.Size(200,20)
      $checkbox8.Text = "Transparent Task Bar"
      $checkbox8.Checked = $false
      $Form.Controls.Add($checkbox8)
      $TabPage1.Controls.Add($checkBox8)
  
      
      $checkbox9.Location = new-object System.Drawing.Size(220,20)
      $checkbox9.Size = new-object System.Drawing.Size(270,30)
      $checkbox9.Text = "Remove Quick Access From File Explorer"
      $checkbox9.Checked = $false
      $Form.Controls.Add($checkbox9)
      $TabPage1.Controls.Add($checkBox9)
  
      
      $checkbox10.Location = new-object System.Drawing.Size(220,60)
      $checkbox10.Size = new-object System.Drawing.Size(270,30)
      $checkbox10.Text = "Enable Xbox Game Bar"
      $checkbox10.Checked = $false
      $Form.Controls.Add($checkbox10)
      $TabPage1.Controls.Add($checkBox10)
  
      
      $checkbox12.Location = new-object System.Drawing.Size(10,40)
      $checkbox12.Size = new-object System.Drawing.Size(150,30)
      $checkbox12.Text = "Win 7 Calculator"
      $checkbox12.Checked = $false
      $Form.Controls.Add($checkbox12)
      $TabPage3.Controls.Add($checkBox12)
  
      
      $checkbox13.Location = new-object System.Drawing.Size(220,100)
      $checkbox13.Size = new-object System.Drawing.Size(270,30)
      $checkbox13.Text = "Block Razer and ASUS Download Servers"
      $checkbox13.Checked = $false
      $Form.Controls.Add($checkbox13)
      $TabPage1.Controls.Add($checkBox13)
  
  
      
      $checkbox14.Location = new-object System.Drawing.Size(10,30)
      $checkbox14.Size = new-object System.Drawing.Size(190,20)
      $checkbox14.Text = "Aditional files to `"New`" Menu"
      $checkbox14.Checked = $false
      $Form.Controls.Add($checkbox14) 
      $TabPage2.Controls.Add($checkBox14)
  
      
      $checkbox15.Location = new-object System.Drawing.Size(10,60)
      $checkbox15.Size = new-object System.Drawing.Size(150,20)
      $checkbox15.Text = "Aditional ps1 options"
      $checkbox15.Checked = $false
      $Form.Controls.Add($checkbox15)
      $TabPage2.Controls.Add($checkBox15)  
  
      
      $checkbox16.Location = new-object System.Drawing.Size(10,90)
      $checkbox16.Size = new-object System.Drawing.Size(190,20)
      $checkbox16.Text = "Snipping Tool"
      $checkbox16.Checked = $false
      $Form.Controls.Add($checkbox16)
      $TabPage2.Controls.Add($checkBox16) 
  
      
      $checkbox17.Location = new-object System.Drawing.Size(10,120)
      $checkbox17.Size = new-object System.Drawing.Size(190,20)
      $checkbox17.Text = "Shutdown"
      $checkbox17.Checked = $false
      $Form.Controls.Add($checkbox17)
      $TabPage2.Controls.Add($checkBox17)
  
      
      $checkbox18.Location = new-object System.Drawing.Size(10,150)
      $checkbox18.Size = new-object System.Drawing.Size(250,20)
      $checkbox18.Text = "Run as Admin for ps1,bat,vbs files"
      $checkbox18.Checked = $false
      $Form.Controls.Add($checkbox18)
      $TabPage2.Controls.Add($checkBox18)
  
      
      $checkbox19.Location = new-object System.Drawing.Size(10,180)
      $checkbox19.Size = new-object System.Drawing.Size(250,20)
      $checkbox19.Text = "Powershell and Cmd"
      $checkbox19.Checked = $false
      $Form.Controls.Add($checkbox19)
      $TabPage2.Controls.Add($checkBox19)
  
      
      $checkbox20.Location = new-object System.Drawing.Size(10,210)
      $checkbox20.Size = new-object System.Drawing.Size(250,20)
      $checkbox20.Text = "Kill not Responding Tasks"
      $checkbox20.Checked = $false
      $Form.Controls.Add($checkbox20)
      $TabPage2.Controls.Add($checkBox20)
  
      
      $checkbox26.Location = new-object System.Drawing.Size(10,240)
      $checkbox26.Size = new-object System.Drawing.Size(250,20)
      $checkbox26.Text = "Delete Permanently"
      $checkbox26.Checked = $false
      $Form.Controls.Add($checkbox26)
      $TabPage2.Controls.Add($checkBox26)
  
      
      $checkbox21.Location = new-object System.Drawing.Size(10,70)
      $checkbox21.Size = new-object System.Drawing.Size(150,20)
      $checkbox21.Text = "Original Snipping Tool"
      $checkbox21.Checked = $false
      $Form.Controls.Add($checkbox21)
      $TabPage3.Controls.Add($checkBox21)
  
      
      $checkbox22.Location = new-object System.Drawing.Size(10,95)
      $checkbox22.Size = new-object System.Drawing.Size(150,20)
      $checkbox22.Text = "Win 7 Task Manager"
      $checkbox22.Checked = $false
      $Form.Controls.Add($checkbox22)
      $TabPage3.Controls.Add($checkBox22)
  
      
      $checkbox23.Location = new-object System.Drawing.Size(220,140)
      $checkbox23.Size = new-object System.Drawing.Size(270,30)
      $checkbox23.Text = "Remove Network Icon From File Explorer"
      $checkbox23.Checked = $false
      $Form.Controls.Add($checkbox23)
      $TabPage1.Controls.Add($checkBox23)
  
      
      $checkbox24.Location = new-object System.Drawing.Size(220,180)
      $checkbox24.Size = new-object System.Drawing.Size(270,30)
      $checkbox24.Text = "Apply PBO Curve on Startup"
      $checkbox24.Checked = $false
      $Form.Controls.Add($checkbox24)
      $TabPage1.Controls.Add($checkBox24)
  
      
      $checkbox25.Location = new-object System.Drawing.Size(180,20)
      $checkbox25.Size = new-object System.Drawing.Size(150,20)
      $checkbox25.Text = "Classic Volume Flyout"
      $checkbox25.Checked = $false
      $Form.Controls.Add($checkbox25)
      $TabPage3.Controls.Add($checkBox25)
  
      
      $checkbox27.Location = new-object System.Drawing.Size(10,220)
      $checkbox27.Size = new-object System.Drawing.Size(210,30)
      $checkbox27.Text = "Add Double Click to Powershell Files"
      $checkbox27.Checked = $false
      $Form.Controls.Add($checkbox27)
      $TabPage1.Controls.Add($checkBox27)
  
      
      $checkbox28.Location = new-object System.Drawing.Size(180,40)
      $checkbox28.Size = new-object System.Drawing.Size(150,20)
      $checkbox28.Text = "Classic Alt-Tab"
      $checkbox28.Checked = $false
      $Form.Controls.Add($checkbox28)
      $TabPage3.Controls.Add($checkBox28)
  
      
      $checkbox29.Location = new-object System.Drawing.Size(220,220)
      $checkbox29.Size = new-object System.Drawing.Size(270,30)
      $checkbox29.Text = "Do not include drivers in Windows Update"
      $checkbox29.Checked = $false
      $Form.Controls.Add($checkbox29)
      $TabPage1.Controls.Add($checkBox29)
  
      
      $checkbox30.Location = new-object System.Drawing.Size(220,260)
      $checkbox30.Size = new-object System.Drawing.Size(270,30)
      $checkbox30.Text = "Remove Windows Backup App"
      $checkbox30.Checked = $false
      $Form.Controls.Add($checkbox30)
      $TabPage1.Controls.Add($checkBox30)
  
      
      $checkbox31.Location = new-object System.Drawing.Size(10,260)
      $checkbox31.Size = new-object System.Drawing.Size(210,30)
      $checkbox31.Text = "Remove Mouse and Sound Schemes"
      $checkbox31.Checked = $false
      $Form.Controls.Add($checkbox31)
      $TabPage1.Controls.Add($checkBox31)
  
      
      $checkbox32.Location = new-object System.Drawing.Size(220,300)
      $checkbox32.Size = new-object System.Drawing.Size(270,30)
      $checkbox32.Text = "Enable Windows 11 Sounds"
      $checkbox32.Checked = $false
      $Form.Controls.Add($checkbox32)
      $TabPage1.Controls.Add($checkBox32)
  
      
      $checkbox33.Location = new-object System.Drawing.Size(10,300)
      $checkbox33.Size = new-object System.Drawing.Size(270,30)
      $checkbox33.Text = "Remove Recycle Bin Name"
      $checkbox33.Checked = $false
      $Form.Controls.Add($checkbox33)
      $TabPage1.Controls.Add($checkBox33)
  
   $OKButton = New-Object System.Windows.Forms.Button
  $OKButton.Location = New-Object System.Drawing.Point(200,510)
  $OKButton.Size = New-Object System.Drawing.Size(100,23)
  $OKButton.Text = 'OK'
  $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $form.AcceptButton = $OKButton
  $form.Controls.Add($OKButton)
  
  $CancelButton = New-Object System.Windows.Forms.Button
  $CancelButton.Location = New-Object System.Drawing.Point(295,510)
  $CancelButton.Size = New-Object System.Drawing.Size(100,23)
  $CancelButton.Text = 'Cancel'
  $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
  $form.CancelButton = $CancelButton
  $form.Controls.Add($CancelButton)
  
  $label = New-Object System.Windows.Forms.Label
  $label.Location = New-Object System.Drawing.Point(10,10)
  $label.Size = New-Object System.Drawing.Size(200,20)
  $label.Text = 'Select Any Optional Tweaks:'
  $form.Controls.Add($label)
  
   $checkbox2.Add_CheckedChanged({ 
   if($checkbox2.Checked){
      $classicblackBTN.Visible = $true
  
      }
      else{
  
      $classicblackBTN.Visible = $false
  
      }
      
  })    
      # Activate the form
      $Form.Add_Shown({$Form.Activate()})
      $result = $form.ShowDialog()
}


    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{

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
       if(test-path "C:\UltimateContextMenu"){
      $path = Get-ChildItem -Path C:\ -Filter BlackTheme.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @("/s",$path)
        }
        else{
    $path = Get-ChildItem -Path C:\ -Filter UltimateContextMenu -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }

    Move-item $path -Destination "C:\"

    $path = Get-ChildItem -Path C:\ -Filter BlackTheme.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @("/s",$path)

        }
        
        #setting lockscreen to black
        
        if($registry){
        reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /f}


        $path = Get-ChildItem -Path C:\ -Filter Black.jpg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        Move-Item $path -Destination "C:\Windows" -Force

      New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Force

        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImagePath" -Value "C:\Windows\Black.jpg" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" -Name "LockScreenImageStatus" -Value 1

        if($classicblackBTN.Checked){
        $path = Get-ChildItem -Path C:\ -Filter ClassicBlack.deskthemepack -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
        &$path
        while($true){

        $settings = Get-Process -Name SystemSettings -ErrorAction SilentlyContinue
        if($settings -ne $null){
        Stop-Process $settings -Force
        break
        }
        }
        }

      }
      
      if($checkbox4.Checked){
      REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Security" /V "DisableSecuritySettingsCheck" /T "REG_DWORD" /D "00000001" /F
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "00000000" /F
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /V "1806" /T "REG_DWORD" /D "00000000" /F

      }
      if($checkbox5.Checked){
      $speech = Get-ChildItem -Path C:\ -Filter RemoveSpeech.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; } 
 $nsudo = Get-ChildItem -Path C:\ -Filter NSudoLG.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
       $arguments = "-U:T -P:E -M:S "+"`"$speech`"" 
        Start-Process -FilePath $nsudo -ArgumentList $arguments -Wait
      
      }
      if($checkbox6.Checked){
      $photo = Get-ChildItem -Path C:\ -Filter PhotoViewer.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$photo) -Wait

      }
      if($checkbox7.Checked){
      Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f

      }

      if($checkbox8.checked){

      $taskbar = Get-ChildItem -Path C:\ -Filter TaskbarX -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }

      Move-Item -Path $taskbar -Destination "C:\Program Files" -Force

      Start-Process -FilePath "C:\Program Files\TaskbarX\TaskbarX.exe" -ArgumentList @("-tbs=1","-dct=1")

    $pathTB = "C:\Program Files\TaskbarX\TaskbarX.exe"
    $WshShell = New-Object -comObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\TaskbarX.lnk")
    $Shortcut.TargetPath = $pathTB
    $Shortcut.Arguments = "-tbs=1 -dct=1"
    $Shortcut.Save()

      }

      if($checkbox9.Checked){

      Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d "1" /f

      }
      if($checkbox10.Checked){

      reg.exe add "HKCU\System\GameConfigStore" /f /v GameDVR_Enabled /t REG_DWORD /d "1"
      reg.exe add "HKCU\System\GameConfigStore" /f /v GameDVR_FSEBehaviorMode /t REG_DWORD /d "2"
      reg.exe add "HKCU\System\GameConfigStore" /f /v GameDVR_FSEBehavior /t REG_DWORD /d "2"
      reg.exe add "HKCU\System\GameConfigStore" /f /v GameDVR_HonorUserInputToggle /t REG_DWORD /d "0"
      reg.exe add "HKCU\System\GameConfigStore" /f /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d "1"

      try{
      $path = Get-ChildItem -Path C:\ -Filter MicrosoftXaml2.7.Appx -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Add-AppxPackage -path ([String]$path) -ErrorAction Stop
      $path = Get-ChildItem -Path C:\ -Filter XboxGameBarVer1271.AppxBundle -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Add-AppxPackage -path ([String]$path) -ErrorAction Stop

      }catch{
      $vclibs = Get-ChildItem -Path C:\ -Filter MicrosoftVCLibs14.Appx -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Add-AppxPackage -path ([String]$vclibs)
      $path = Get-ChildItem -Path C:\ -Filter MicrosoftXaml2.7.Appx -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Add-AppxPackage -path ([String]$path)
      $path = Get-ChildItem -Path C:\ -Filter XboxGameBarVer1271.AppxBundle -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Add-AppxPackage -path ([String]$path)  

      }
      
      }



if($checkbox12.Checked){

$folder = Get-ChildItem -Path C:\ -Filter System322 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Move-Item -Path $folder -Destination "C:\"
    Rename-Item -Path "C:\System322" -NewName "System32"
    $calc = Get-ChildItem -Path C:\ -Filter OldCalc.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    $nsudo = Get-ChildItem -Path C:\ -Filter NSudoLG.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
       $arguments = "-U:T -P:E -M:S "+"`"$calc`"" 
        Start-Process -FilePath $nsudo -ArgumentList $arguments -Wait

        Move-Item -Path "C:\System32\en-US\calc.exe.mui" -Destination "C:\Windows\System32\en-US" -Force 
    Move-Item -Path "C:\System32\calc.exe" -Destination "C:\Windows\System32" -Force
    Remove-Item -Path "C:\System32" -Recurse -Force

$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Calculator.lnk")
$Shortcut.TargetPath = ("C:\Windows\System32\calc.exe")
$Shortcut.Save()

}

if($checkbox13.Checked){

$hosts = "C:\Windows\System32\drivers\etc\hosts"

Add-Content -Path $hosts -Value '0.0.0.0 synapse3ui-common.razerzone.com
0.0.0.0 bespoke-analytics.razerapi.com
0.0.0.0 discovery.razerapi.com
0.0.0.0 manifest.razerapi.com
0.0.0.0 cdn.razersynapse.com
0.0.0.0 assets.razerzone.com
0.0.0.0 assets2.razerzone.com
0.0.0.0 deals-assets-cdn.razerzone.com
0.0.0.0 synapse-3-webservice.razerzone.com
0.0.0.0 albedozero.razerapi.com
0.0.0.0 gms.razersynapse.com
0.0.0.0 fs.razersynapse.com
0.0.0.0 id.razer.com' -Force

Add-Content -Path $hosts -Value '0.0.0.0 liveupdate01s.asus.com
0.0.0.0 asusactivateservice.azurewebsites.net
0.0.0.0 rog-live-service.asus.com
0.0.0.0 dlcdn-rogboxbu1.asus.com
0.0.0.0 dlcdn-rogboxbu2.asus.com
0.0.0.0 mymessage.asus.com
0.0.0.0 gaming-config.asus.com
0.0.0.0 rog-content-platform.asus.com
0.0.0.0 nomos.asus.com
0.0.0.0 dlcdnrog.asus.com
0.0.0.0 account.asus.com' -Force

}

      if($checkbox14.Checked){

      $path = Get-ChildItem -Path C:\ -Filter UltimateContextMenu -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    if($path -ne "C:\UltimateContextMenu"){
    Move-item $path -Destination "C:\"
    }
      $path = Get-ChildItem -Path C:\ -Filter newMenu.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @("/s",$path)

      }
      if($checkbox15.Checked){
      
    if($path -ne "C:\UltimateContextMenu"){
    $path = Get-ChildItem -Path C:\ -Filter UltimateContextMenu -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Move-item $path -Destination "C:\"
    }
     $path = Get-ChildItem -Path C:\ -Filter ps1Options.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @("/s",$path)
      }
      if($checkbox16.Checked){
      if($path -ne "C:\UltimateContextMenu"){
    $path = Get-ChildItem -Path C:\ -Filter UltimateContextMenu -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Move-item $path -Destination "C:\"
    }
      $path = Get-ChildItem -Path C:\ -Filter Snipping.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @("/s",$path)

      }
      if($checkbox17.Checked){
      if($path -ne "C:\UltimateContextMenu"){
    $path = Get-ChildItem -Path C:\ -Filter UltimateContextMenu -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Move-item $path -Destination "C:\"
    }
      $path = Get-ChildItem -Path C:\ -Filter Shutdown.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @("/s",$path)

      }
      if($checkbox18.Checked){
      if($path -ne "C:\UltimateContextMenu"){
    $path = Get-ChildItem -Path C:\ -Filter UltimateContextMenu -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Move-item $path -Destination "C:\"
    }
      $path = Get-ChildItem -Path C:\ -Filter runAsAdmin.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @("/s",$path)
      }
      if($checkbox19.Checked){
      if($path -ne "C:\UltimateContextMenu"){
    $path = Get-ChildItem -Path C:\ -Filter UltimateContextMenu -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Move-item $path -Destination "C:\"
    }
      $path = Get-ChildItem -Path C:\ -Filter powershellCmd.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @("/s",$path)

      }
      if($checkbox20.Checked){
      if($path -ne "C:\UltimateContextMenu"){
    $path = Get-ChildItem -Path C:\ -Filter UltimateContextMenu -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Move-item $path -Destination "C:\"
    }
      $path = Get-ChildItem -Path C:\ -Filter killTasks.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @("/s",$path)

      }

      if($checkbox26.Checked){
      if($path -ne "C:\UltimateContextMenu"){
    $path = Get-ChildItem -Path C:\ -Filter UltimateContextMenu -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Move-item $path -Destination "C:\"
    }
      $path = Get-ChildItem -Path C:\ -Filter superdel.reg -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @("/s",$path)

      }


      if($checkbox21.Checked){

      $folder = Get-ChildItem -Path C:\ -Filter System321 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Move-Item -Path $folder -Destination "C:\"
    Rename-Item -Path "C:\System321" -NewName "System32"
    $snipping = Get-ChildItem -Path C:\ -Filter OldSnipping.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    $nsudo = Get-ChildItem -Path C:\ -Filter NSudoLG.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
       $arguments = "-U:T -P:E -M:S "+"`"$snipping`"" 
        Start-Process -FilePath $nsudo -ArgumentList $arguments -Wait
    
    Move-Item -Path "C:\System32\en-US\SnippingTool.exe.mui" -Destination "C:\Windows\System32\en-US" -Force 
    Move-Item -Path "C:\System32\SnippingTool.exe" -Destination "C:\Windows\System32" -Force
    Remove-Item -Path "C:\System32" -Recurse -Force

      }
      if($checkbox22.Checked){

      $taskmgr = Get-ChildItem -Path C:\ -Filter classictask.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      $dir = Get-ChildItem -Path C:\ -Filter _FOLDERMUSTBEONCDRIVE -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
      Start-Process -FilePath $taskmgr -ArgumentList "/LOADINF=default /VERYSILENT" -WorkingDirectory $dir

      }

      if($checkbox23.Checked){

      Reg.exe add "HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f

      }

      if($checkbox24.Checked){

#limits (in order)
$ppt = "0"
$tdc = "0"
$edc = "0"


Add-Type -AssemblyName System.Windows.Forms

# Retrieve the number of CPU cores
$cpuCores = (Get-WmiObject -Class Win32_Processor).NumberOfCores

$size = 300+($cpuCores*20)

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "PBO2 Tuner"
$form.Size = New-Object System.Drawing.Size(400,$size)
$form.StartPosition = "CenterScreen"

# Create a checkbox
$checkBox = New-Object System.Windows.Forms.CheckBox
$checkBox.Text = "Custom Limits"
$checkBox.Location = New-Object System.Drawing.Point(200, 140)

# Create three textboxes
$limitBox1 = New-Object System.Windows.Forms.TextBox
$limitBox1.Location = New-Object System.Drawing.Point(220, 170)
$limitBox1.Size = New-Object System.Drawing.Size(60, 20)
$limitBox1.Visible = $false
$limitBox1.MaxLength = 3

$limitBox2 = New-Object System.Windows.Forms.TextBox
$limitBox2.Location = New-Object System.Drawing.Point(220, 200)
$limitBox2.Size = New-Object System.Drawing.Size(60, 20)
$limitBox2.Visible = $false
$limitBox2.MaxLength = 3

$limitBox3 = New-Object System.Windows.Forms.TextBox
$limitBox3.Location = New-Object System.Drawing.Point(220, 230)
$limitBox3.Size = New-Object System.Drawing.Size(60, 20)
$limitBox3.Visible = $false
$limitBox3.MaxLength = 3

# Create three labels
$label1 = New-Object System.Windows.Forms.Label
$label1.Text = "PPT"
$label1.Location = New-Object System.Drawing.Point(190, 170)
$label1.Visible = $false

$label2 = New-Object System.Windows.Forms.Label
$label2.Text = "TDC"
$label2.Location = New-Object System.Drawing.Point(190, 200)
$label2.Visible = $false

$label3 = New-Object System.Windows.Forms.Label
$label3.Text = "EDC"
$label3.Location = New-Object System.Drawing.Point(190, 230)
$label3.Visible = $false

# Add event handler for checkbox checked event
$checkBox.add_CheckedChanged({
    if ($checkBox.Checked) {
        $limitBox1.Visible = $true
        $limitBox2.Visible = $true
        $limitBox3.Visible = $true
        $label1.Visible = $true
        $label2.Visible = $true
        $label3.Visible = $true
    } else {
        $limitBox1.Visible = $false
        $limitBox2.Visible = $false
        $limitBox3.Visible = $false
        $label1.Visible = $false
        $label2.Visible = $false
        $label3.Visible = $false
    }
})

# Add controls to the form
$form.Controls.Add($checkBox)
$form.Controls.Add($limitBox1)
$form.Controls.Add($limitBox2)
$form.Controls.Add($limitBox3)
$form.Controls.Add($label1)
$form.Controls.Add($label2)
$form.Controls.Add($label3)

# Create the label
$label = New-Object System.Windows.Forms.Label
$label.Location = [System.Drawing.Point]::new(10, 20)
$label.Size = [System.Drawing.Size]::new(380, 20)
$label.Text = "Enter the Undervolt for each core:"
$form.Controls.Add($label)

# Create the radio buttons
$radioButtons = @()
$values = @(-10, -20, -30)
for ($i = 0; $i -lt $values.Count; $i++) {
    $radioButton = New-Object System.Windows.Forms.RadioButton
    $radioButton.Location = [System.Drawing.Point]::new(200, 40 + $i * 30)
    $radioButton.Size = [System.Drawing.Size]::new(60, 20)
    $radioButton.Text = $values[$i].ToString()

    # Create a closure to capture the correct radio button object
    $eventHandler = {
        $selectedRadioButton = $this
        $selectedValue = $selectedRadioButton.Text
        foreach ($textBox in $textboxes) {
            $textBox.Text = $selectedValue
        }
    }
    $radioButton.Add_Click($eventHandler)

    $form.Controls.Add($radioButton)
    $radioButtons += $radioButton
}

# Create the text boxes with labels
$textBoxes = @()
for ($i = 0; $i -lt $cpuCores; $i++) {
    $coreNumber = $i
    $coreLabel = "Core "+ $coreNumber
    
    # Create the label
    $coreLabelControl = New-Object System.Windows.Forms.Label
    $coreLabelControl.Location = [System.Drawing.Point]::new(10, 40 + $i * 30)
    $coreLabelControl.Size = [System.Drawing.Size]::new(60, 20)
    $coreLabelControl.Text = $coreLabel
    $form.Controls.Add($coreLabelControl)
    
    # Create the text box
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = [System.Drawing.Point]::new(80, 40 + $i * 30)
    $textBox.Size = [System.Drawing.Size]::new(60, 20)
    $textBox.MaxLength = 3
    $form.Controls.Add($textBox)
    $textBoxes += $textBox
}

# Create the button
$button = New-Object System.Windows.Forms.Button
$button.Location = [System.Drawing.Point]::new(150, 40 + $cpuCores * 30)
$button.Size = [System.Drawing.Size]::new(100, 30)
$button.Text = "Apply"
$button.Add_Click({
$exePath = "non"


$pbo = Get-ChildItem -Path C:\ -Filter PBOTuner -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
Move-item -Path $pbo -Destination "C:\Program Files" -Force
$exePath = "C:\Program Files\PBOTuner\PBO2 tuner.exe"


    

#format: (-)num cpu core undervolt ppt tdc edc 0
if($checkBox.Checked){

if($limitBox1.Text -ne ""){
$ppt = $limitBox1.Text
}

if($limitBox2.Text -ne ""){
$tdc = $limitBox2.Text
}

if($limitBox3.Text -ne ""){
$edc = $limitBox3.Text

}

$values = ($textBoxes.ForEach({ $_.Text }) -join " ") +" "+$ppt+" "+$tdc+" "+$edc+" 0"
}
else{
$values = $textBoxes.ForEach({ $_.Text }) -join " "

}
$taskName = "PBO Tuner"


# Create a new scheduled task action to run the executable
$action = New-ScheduledTaskAction -Execute $exePath -Argument $values

# Create a new scheduled task trigger for user logon
$trigger = New-ScheduledTaskTrigger -AtLogOn


# Register the scheduled task using the User Principal Name
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User $env:USERNAME -RunLevel Highest -Force

$form.Close()
})
$form.Controls.Add($button)

# Show the form
$form.ShowDialog() | Out-Null


      }



if($checkbox25.Checked){

Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC" /v "EnableMtcUvc" /t REG_DWORD /d "0" /f


}



if($checkbox27.Checked){
Reg.exe add "HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell\Open\Command" /ve /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noLogo -file `"`"%1`"`"" /f



}



if($checkbox28.Checked){

Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AltTabSettings" /t REG_DWORD /d "1" /f
}


if($checkbox29.Checked){
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f

}


if($checkbox30.Checked){
dism /online /Get-Packages | Select-String "Microsoft-Windows-UserExperience-Desktop-Package~31bf3856ad364e35~amd64~~.*$" | ForEach-Object { $_.Matches[0].Value } | % {dism /online /remove-package /NoRestart /PackageName:$_}

}

if($checkbox31.Checked){
Reg.exe add "HKCU\AppEvents\Schemes" /ve /t REG_SZ /d ".None" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current" /f
Reg.exe delete "HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current" /f
Reg.exe add "HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current" /f
Reg.exe add "HKCU\Control Panel\Cursors" /v "ContactVisualization" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Cursors" /v "GestureVisualization" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Cursors" /v "Scheme Source" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Cursors" /ve /t REG_SZ /d " " /f
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "AppStarting" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "Arrow" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "Crosshair" -Force -ErrorAction SilentlyContinue
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "Hand" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "IBeam" -Force -ErrorAction SilentlyContinue
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "No" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "NWPen" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "SizeAll" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "SizeNESW" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "SizeNS" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "SizeNWSE" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "SizeWE" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "UpArrow" -Force
Clear-ItemProperty -Path "registry::HKCU\Control Panel\Cursors" -Name "Wait" -Force

}


if($checkbox32.Checked){

$soundFolder = New-Item -Path "C:\Users\$env:USERNAME\Desktop" -Name "Windows 10 Sounds" -ItemType Directory
$win10sounds = Get-ChildItem -Path C:\Windows\Media -Recurse -Filter 'Windows*' | % {$_.FullName}
foreach($sound in $win10sounds){

Copy-Item -Path $sound -Destination $soundFolder -Force

}


$path = Get-ChildItem -Path C:\ -Filter win11sounds -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
$sounds = Get-ChildItem -Path $path -Recurse -Force | % { $_.FullName }

$nsudo = Get-ChildItem -Path C:\ -Filter NSudoLG.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }

foreach($sound in $sounds){
$arguments = "-U:T -P:E -M:S Powershell.exe -windowstyle Hidden -command `"Move-item '$sound' -destination C:\Windows\Media -force`""
Start-Process $nsudo -ArgumentList $arguments -WindowStyle Hidden -Wait

}


}

if($checkbox33.Checked){

Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}" /ve /t REG_SZ /d " " /f

}


       if(test-path "C:\UltimateContextMenu"){
    $path = Get-ChildItem -Path C:\ -Filter _FOLDERMUSTBEONCDRIVE -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Move-item "C:\UltimateContextMenu" -Destination $path
    }

    


       

 }
      


}



















