function import-reg {

    param (
      [Parameter(mandatory=$false)] [bool]$Autorun = $false
    )


    #dot source update config function
    $path = Get-ChildItem -path C:\ -Filter update-config.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; }
    .$path


  if($AutoRun){
    $msgBoxInput = 'Yes'
  }
  else{
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Import Registry Tweaks?','zoicware','YesNo','Question')
  }
  
  
  switch  ($msgBoxInput) {
  
    'Yes' {
      #update config
      if(!($Autorun)){
        update-config -setting "registryTweaks" -value 1
      }
    
    $Global:registry = $true
    $reg = Get-ChildItem -Path C:\ -Filter RegTweak.ps1 -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
         & $reg
    
  Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\luafv" /v "Start" /t REG_DWORD /d "4" /f
  if(!($Autorun)){
    [System.Windows.Forms.MessageBox]::Show('Registry Tweaks Applied.')
  }
    
   }
  
  'No'{}
  
  }
  
  }