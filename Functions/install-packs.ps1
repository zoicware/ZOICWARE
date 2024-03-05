function install-packs{
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
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Install DX, C++ Packages and NET 3.5?','zoicware','YesNo','Question')
  }
  
  
  switch  ($msgBoxInput) {
  
    'Yes' {
      #update config
    if(!($Autorun)){
      update-config -setting "installPackages" -value 1
    }

    
    Write-host "------------------------------------"
    Write-host "|                                  |"
    Write-host "|       Packages Installing...     |"
    Write-host "|                                  |"
    Write-host "------------------------------------"
  
    $pathDX = Get-ChildItem -Path C:\ -Filter DXSETUP.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    $pathCpp = Get-ChildItem -Path C:\ -Filter VisualCppRedist_AIO_x86_x64.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    if($pathDX -eq $null -or $pathCpp -eq $null){
    Write-Host "Packages Not Found..."
    Write-Host "Attempting to install..."
  
    try{
  
    $installDir = Get-ChildItem -Path C:\ -Filter _FOLDERMUSTBEONCDRIVE -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  
     #install C++
  $ProgressPreference = 'SilentlyContinue'
  $url = "https://api.github.com/repos/abbodi1406/vcredist/releases/latest"
  $response = Invoke-RestMethod -Uri $url -UseBasicParsing
  $version = $response.tag_name
  Invoke-RestMethod -Uri "https://github.com/abbodi1406/vcredist/releases/download/$version/VisualCppRedist_AIO_x86_x64.exe" -UseBasicParsing -OutFile "$installDir\VisualCppRedist_AIO_x86_x64.exe" 
  
  
  #install directx
  $ProgressPreference = 'SilentlyContinue'
  $dir = New-Item -Path "$env:TEMP\DirectXRedist" -ItemType Directory -Force
  $DXPath = New-Item -Path "$env:TEMP\DirectXRedist\DX" -ItemType Directory -Force
  Invoke-RestMethod -Uri 'https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe' -UseBasicParsing -OutFile "$env:TEMP\DirectXRedist\DXinstaller.exe"
  Start-Process -FilePath "$env:TEMP\DirectXRedist\DXinstaller.exe" -ArgumentList "/Q /T:$DXPath /C" -WindowStyle Hidden -Wait
  #put pack path
  Move-Item $DXPath -Destination $installDir -Force 
  Remove-Item -Path $dir -Force -Recurse
  
  Write-Host "Installing..."
  Start-Process "$installDir\DX\DXSETUP.exe" -ArgumentList '/quiet' -WindowStyle Hidden -Wait
  Start-Process "$installDir\VisualCppRedist_AIO_x86_x64.exe" -ArgumentList '/ai /gm2' -WindowStyle Hidden -Wait
  
    }
    catch{
    Write-Host "Unable to install packages...Make sure you are connected to the internet"
  
    }
  
    }
    else{
  
    Start-Process $pathDX -Argumentlist '/quiet' -WindowStyle Hidden -Wait
    Start-Process $pathCpp -Argumentlist '/ai /gm2' -WindowStyle Hidden -Wait
    
    }
  
    $progresspreference = 'silentlycontinue'
    $vclibs = Get-ChildItem -Path C:\ -Filter MicrosoftVCLibs14.Appx -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    Add-AppxPackage -path ([String]$vclibs)
  
    [System.Windows.Forms.MessageBox]::Show('Please make sure your USB Flash Drive is plugged in.', 'Installing Net 3.5')
    #search for drive with installwim
  $driveLetters = @('D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z')
  $driveFound = $false
  foreach($driveLetter in $driveLetters){
    if(Test-Path "$($driveLetter):\sources\install.wim"){
      Write-Host "Installing NET 3.5..."
      Dism /online /enable-feature /featurename:NetFX3 /All /Source:$($driveLetter):\sources\sxs /LimitAccess
      $driveFound = $true
      break
    }
  }
  #search with different method 
  if(!($driveFound)){
    foreach($driveLetter in $driveLetters){
   $installWim = Get-ChildItem -Path "$($driveLetter):\" -Filter install.wim -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
    if($installWim -ne $null){
      Write-Host "Installing NET 3.5..."
      Dism /online /enable-feature /featurename:NetFX3 /All /Source:$($driveLetter):\sources\sxs /LimitAccess
      $driveFound = $true
      break
    }
  
  }
  
  }
  #cant find install wim 
  if(!($driveFound)){
  Write-Host "Drive NOT Found..."
  
  }
  
    Write-Host "Cleaning up...[PLEASE WAIT]"
  
    $ngenPath = [System.IO.Path]::Combine([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory(), "ngen.exe")
    Start-process $ngenPath -ArgumentList 'update /silent /nologo' -WindowStyle Hidden -Wait 
    
    Start-Process dism.exe -ArgumentList '/online /Cleanup-Image /StartComponentCleanup /ResetBase' -WindowStyle Hidden -Wait 
    
    if(!($Autorun)){
      [System.Windows.Forms.MessageBox]::Show('Packages Installed.')
    }
    
   }
  
  'No'{}
  
  }
} 