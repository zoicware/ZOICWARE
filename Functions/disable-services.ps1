function disable-services {
    param (
      [Parameter(mandatory=$false)] [bool]$Autorun = $false
     # ,[Parameter(mandatory=$false)] $setting 
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
          #revert delivery optimization service so that store works properly
          Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "2" /f
          Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DoSvc" /v "DelayedAutostart" /t REG_DWORD /d "1" /f
      }

    }

  }


    #dot source update config function
    $path = Get-ChildItem -path C:\ -Filter update-config.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; }
    .$path

  if($Autorun){
    $msgBoxInput = 'Yes'
  }
  else{
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Do you want to disable Bluetooth, Printing and others?','zoicware','YesNo','Question')
  }
  
  
  switch  ($msgBoxInput) {
  
    'Yes' {
      if(!($Autorun)){
      #update config
      update-config -setting "disableServices" -value 1
      }
      
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

  check-depend
  
  if(!($Autorun)){
    [System.Windows.Forms.MessageBox]::Show('Services have been disabled.')
  }
  
   }
  
  'No'{}
  
  }
  
  }