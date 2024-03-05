function debloat {

    param (
      [Parameter(mandatory=$false)] [bool]$Autorun = $false
      ,[Parameter(mandatory=$false)] [bool]$debloatAll = $false
      ,[Parameter(mandatory=$false)] [bool]$debloatSXE = $false
      ,[Parameter(mandatory=$false)] [bool]$debloatSX = $false
      ,[Parameter(mandatory=$false)] [bool]$debloatE = $false
      ,[Parameter(mandatory=$false)] [bool]$debloatS = $false
    )
  
    function check-depend {
      #check if updates/services are disabled in the config 
      $configContent = Get-Content -Path "$env:TEMP\ZCONFIG.cfg" -Force
      $settingName1 = "gpUpdates"
      $settingName2 = "disableServices"
      foreach($line in $configContent){
        #split line into settingName and value
        $splitLine = $line -split '='
        $lineName = $splitLine[0]
        $lineValue = $splitLine[1]
        if($lineName.trim() -match $settingName1 -and $lineValue.trim() -eq "1"){
          #revert updates so that store works properly
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
          #pause for 1 year
          $pause = (Get-Date).AddDays(365); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause
          
        }
        elseif($lineName.Trim() -match $settingName2 -and $lineValue.trim() -eq "1"){
          #enable delivery optimization service
          Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "2" /f
          Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "DelayedAutostart" /t REG_DWORD /d "1" /f
        }

      }

    }





    #dot source update config function
    $path = Get-ChildItem -path C:\ -Filter update-config.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; }
    .$path

    $checkbox2 = New-Object System.Windows.Forms.RadioButton
    $checkbox3 = New-Object System.Windows.Forms.RadioButton
    $checkbox4 = New-Object System.Windows.Forms.RadioButton
    $checkbox5 = New-Object System.Windows.Forms.RadioButton
    $checkbox6 = New-Object System.Windows.Forms.RadioButton
    
    #hashtable to loop through later for updating the config
    $settings = @{}
    $settings["debloatAll"] = $checkbox2
    $settings["debloatSXE"] = $checkbox3
    $settings["debloatSX"] = $checkbox4
    $settings["debloatE"] = $checkbox5
    $settings["debloatS"] = $checkbox6

    
    if($AutoRun){
      $result = [System.Windows.Forms.DialogResult]::OK
      $checkbox2.Checked = $debloatAll
      $checkbox3.Checked = $debloatSXE
      $checkbox4.Checked = $debloatSX
      $checkbox5.Checked = $debloatE
      $checkbox6.Checked = $debloatS
    }
    else{
  
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
  
      
      $checkbox2.Location = new-object System.Drawing.Size(10,40)
      $checkbox2.Size = new-object System.Drawing.Size(150,20)
      $checkbox2.Text = "Debloat All"
      $checkbox2.Checked = $false
      $Form.Controls.Add($checkbox2)  
      
  
      
      $checkbox3.Location = new-object System.Drawing.Size(10,70)
      $checkbox3.Size = new-object System.Drawing.Size(170,30)
      $checkbox3.Text = "Keep Store,Xbox and Edge"
      $checkbox3.Checked = $false
      $Form.Controls.Add($checkbox3)
      
  
      
      $checkbox4.Location = new-object System.Drawing.Size(10,110)
      $checkbox4.Size = new-object System.Drawing.Size(170,30)
      $checkbox4.Text = "Keep Store and Xbox"
      $checkbox4.Checked = $false
      $Form.Controls.Add($checkbox4)
     
  
      
      $checkbox5.Location = new-object System.Drawing.Size(10,150)
      $checkbox5.Size = new-object System.Drawing.Size(200,20)
      $checkbox5.Text = "Debloat All Keep Edge"
      $checkbox5.Checked = $false
      $Form.Controls.Add($checkbox5)
      
  
      
      $checkbox6.Location = new-object System.Drawing.Size(10,190)
      $checkbox6.Size = new-object System.Drawing.Size(200,20)
      $checkbox6.Text = "Debloat All Keep Store"
      $checkbox6.Checked = $false
      $Form.Controls.Add($checkbox6)
      
  $form.Topmost = $true
  
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
          Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
          Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" /v "ProgId" /t REG_SZ /d "IE.HTTP" /f
          Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" /v "ProgId" /t REG_SZ /d "IE.HTTPS" /f
      }
      if($checkbox3.Checked)
      {
     
        #check for dependency issues
        check-depend

    $debloat = Get-ChildItem -Path C:\ -Filter debloatKeepStoreXbox.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
          & $debloat
  
  
    $unpin = Get-ChildItem -Path C:\ -Filter unpin.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
          & $unpin
  
          Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
      }
      if($checkbox4.Checked)
      {
  
      #check for dependency issues
      check-depend
  
    $debloat = Get-ChildItem -Path C:\ -Filter debloatKeepStoreXbox.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
          & $debloat
    
  
    $edge = Get-ChildItem -Path C:\ -Filter EdgeRemoval.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    start-process -FilePath ([string]$edge) -Wait
    Remove-item -Path "C:\Scripts" -Force -Recurse
  Reg.exe add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f
    $unpin = Get-ChildItem -Path C:\ -Filter unpin.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
          & $unpin
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
  
          Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
      }
      if($checkbox6.Checked)
      {
          
    
    #check for dependency issues
    check-depend
    
    $debloat = Get-ChildItem -Path C:\ -Filter debloatKeepStore.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
          & $debloat
  
  
    $edge = Get-ChildItem -Path C:\ -Filter EdgeRemoval.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    start-process -FilePath ([string]$edge) -Wait
    Remove-item -Path "C:\Scripts" -Force -Recurse
  Reg.exe add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d "1" /f
    $unpin = Get-ChildItem -Path C:\ -Filter unpin.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
          & $unpin
          Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
          Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice" /v "ProgId" /t REG_SZ /d "IE.HTTP" /f
          Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice" /v "ProgId" /t REG_SZ /d "IE.HTTPS" /f 
  
      }
      if(!($Autorun)){
        [System.Windows.Forms.MessageBox]::Show('Bloat Removed.')
      }
     
  }
  
  }