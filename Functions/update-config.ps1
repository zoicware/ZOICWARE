function update-config([String]$setting, $value){
    $currentConfig = Get-Content -Path "$env:TEMP\ZCONFIG.cfg" -Force
    $newConfig = @()
    foreach($line in $currentConfig){
      if($line -notmatch '#'){
        $settingName = "\b$setting\b"
        if($line -match $settingName){
          $newConfig += "$setting = $value" 
        }
        else{
          $newConfig += $line
        }
      }
      else{
        $newConfig += $line
      }
      
    }
    $newConfig | Out-File -FilePath "$env:TEMP\ZCONFIG.cfg" -Force
    }