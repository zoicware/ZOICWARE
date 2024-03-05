function gpTweaks {

    param (
      [Parameter(mandatory=$false)] [bool]$Autorun = $false
      ,[Parameter(mandatory=$false)] [bool]$gpDefender = $false
      ,[Parameter(mandatory=$false)] [bool]$gpUpdates = $false
      ,[Parameter(mandatory=$false)] [bool]$gpTel = $false
    )


    function check-depend {
      #check if updates/services are disabled in the config 
      $configContent = Get-Content -Path "$env:TEMP\ZCONFIG.cfg" -Force
      foreach($line in $configContent){
        #split line into settingName and value
        $splitLine = $line -split '='
        $lineName = $splitLine[0]
        $lineValue = $splitLine[1]
        if($lineName.trim() -like "debloatS*" -and $lineValue.trim() -eq "1"){
          #revert updates so that store works properly
          #pause for 1 year
          $pause = (Get-Date).AddDays(365); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause
          return $true
        }

      }
      
    }



    $checkbox1 = New-Object System.Windows.Forms.CheckBox
    $checkbox2 = New-Object System.Windows.Forms.CheckBox
    $checkbox3 = New-Object System.Windows.Forms.CheckBox
  

  #dot source update config function
    $path = Get-ChildItem -path C:\ -Filter update-config.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; }
    .$path

    #hashtable to loop through
    $settings = @{}
    $settings["gpUpdates"] = $checkbox1
    $settings["gpDefender"] = $checkbox2
    $settings["gpTel"] = $checkbox3

  if($Autorun){
    $result = [System.Windows.Forms.DialogResult]::OK
    $checkbox1.Checked = $gpUpdates
    $checkbox2.Checked = $gpDefender
    $checkbox3.Checked = $gpTel
  }
  else{
    Add-Type -AssemblyName System.Windows.Forms
  
    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Group Policy Tweaks"
    $form.Size = New-Object System.Drawing.Size(300, 200)
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    
    # Create the checkboxes
    
    $checkbox1.Text = "Disable Updates"
    $checkbox1.Location = New-Object System.Drawing.Point(20, 20)
    $checkbox1.AutoSize = $true
    $form.Controls.Add($checkbox1)
    
    
    $checkbox2.Text = "Disable Defender"
    $checkbox2.Location = New-Object System.Drawing.Point(20, 50)
    $checkbox2.AutoSize = $true
    $form.Controls.Add($checkbox2)
    
    
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
  }
  
  
  # Check the selected checkboxes
  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    
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

    if($checkbox1.Checked){
      if(check-depend){
        Write-Host "Store enabled...Updates Paused for 1 year"
      }else{
        Write-Host "Disabling Updates..."
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
   
  
  }
  
  
  if($checkbox2.Checked){
  
  function rename-file([String]$path){
  
  $nsudo = Get-ChildItem -Path C:\ -Filter NSudoLG.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  #rename file with trusted installer
  if($path -like "*MsMpEng.exe*"){$newName = "MsMpEngOFF.exe"}
  else{
  $name, $extension = [System.IO.Path]::GetFileNameWithoutExtension($path), [System.IO.Path]::GetExtension($path)
  $newName = "${name}OFF${extension}"
  }
  $arguments = "-U:T -P:E -M:S Powershell.exe -windowstyle Hidden -command `"Rename-Item -Path '$Path' -NewName $newName -Force`""
  
  Start-Process $nsudo -ArgumentList $arguments -WindowStyle Hidden -Wait 
  
  
  }
  
  
  function Run-Nsudo([String]$path){
  
  $nsudo = Get-ChildItem -Path C:\ -Filter NSudoLG.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  
  $arguments = "-U:T -P:E -M:S `"$path`""
  Start-Process $nsudo -ArgumentList $arguments -WindowStyle Hidden -Wait 
  
  
  }
  
  
  
  #disables defender through gp edit
  Write-Host "Disabling Defender with Group Policy" 
  $defenderBat = Get-ChildItem -Path C:\ -Filter DisableDefend.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  Run-Nsudo -path $defenderBat
  
  Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Cache Maintenance'} | Disable-ScheduledTask -ErrorAction SilentlyContinue
  Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Cleanup'} | Disable-ScheduledTask -ErrorAction SilentlyContinue
  Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Scheduled Scan'} | Disable-ScheduledTask -ErrorAction SilentlyContinue
  Get-ScheduledTask | Where-Object {$_.Taskname -match 'Windows Defender Verification'} | Disable-ScheduledTask -ErrorAction SilentlyContinue
      
  gpupdate /force
  
  Write-Host "Disabling Services"
  
  #disables antimalware service + core service
  
  $imagePathValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name "ImagePath"
  $msMpEngPath = $imagePathValue.ImagePath 
  rename-file -path $msMpEngPath
  
  $WDPath = "C:\ProgramData\Microsoft\Windows Defender\Platform"
  $corePaths = Get-ChildItem -Path $WDPath -Recurse -Filter "MpDefenderCoreService.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }
  $netPaths = Get-ChildItem -Path $WDPath -Recurse -Filter "NisSrv.exe" -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName } 
  
  
  foreach($path in $corePaths){rename-file -path $path}
  foreach($path in $netPaths){rename-file -path $path}
  #disable smartscreen service
  $smartScreen = "C:\Windows\System32\smartscreen.exe"
  rename-file -path $smartScreen
  
  
  }
  
    
  if($checkbox3.Checked){
  Write-Host "Disabling Telemetry..."
    #removes telemetry through gp edit
  Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
  Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
  Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "0" /f
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
  Reg.exe add "HKLM\System\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
  Reg.exe add "HKLM\System\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
  Reg.exe add "HKLM\Software\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
  
 
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" -ErrorAction SilentlyContinue
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" -ErrorAction SilentlyContinue
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" -ErrorAction SilentlyContinue
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" -ErrorAction SilentlyContinue
  Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" -ErrorAction SilentlyContinue
  Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" -ErrorAction SilentlyContinue
  
    
  
  }
  
  
  
      #updates group policy so that the previous changes are applied 
      Write-Host "Updating Policy..."
      gpupdate /force
    }
  
    }