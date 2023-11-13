#Amoury Crate Remover by zoic

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

function color ($bc,$fc) {
$a = (Get-Host).UI.RawUI
$a.BackgroundColor = $bc
$a.ForegroundColor = $fc ; cls}	

color "black" "white"




Write-host "Running Uninstaller"

#getting folder from github
Invoke-RestMethod 'https://github.com/zoicware/Amoury-Crate-Uninstaller/archive/refs/heads/main.zip' -OutFile "C:\Uninstaller.zip"
Expand-Archive "C:\Uninstaller.zip" -DestinationPath "C:\"
Remove-Item "C:\Uninstaller.zip"
Expand-Archive "C:\Amoury-Crate-Uninstaller-main\Armoury Crate Uninstall Tool V2.1.5.0.zip" -DestinationPath "C:\"
Remove-Item  "C:\Amoury-Crate-Uninstaller-main" -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("C:\Armoury Crate Uninstall Tool V2.1.5.0\ArmouryCrateUninstaller.lnk")
$Shortcut.TargetPath = "C:\Armoury Crate Uninstall Tool V2.1.5.0\ArmouryCrateUninstallTool.exe"
$Shortcut.Arguments = "/?"
$Shortcut.Save()


#getting delete temp bat from github
Invoke-RestMethod 'https://github.com/zoicware/Delete-Temp/raw/main/Delete%20temp.bat' -OutFile "C:\DeleteTemp.bat"



#running uninstaller
$path = Get-ChildItem -Path C:\ -Filter ArmouryCrateUninstaller.lnk -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$path)

  
  [System.Windows.Forms.MessageBox]::Show('Click OK to Finish Clean Up.')
  
  #cleaning up

  Remove-item "C:\Program Files\ASUS" -Force -Recurse
  Remove-item "C:\Program Files (x86)\ASUS" -Force -Recurse
  Remove-item "C:\ProgramData\ASUS" -Force -Recurse 
  Remove-item "$($env:USERPROFILE)\AppData\Local\ASUS" -Force -Recurse
  Remove-item "C:\GetDeviceCap.xml" -Force -Recurse
  Remove-item "C:\GetDeviceStatus.xml" -Force -Recurse
  Remove-item "C:\QueryAllDevice.xml" -Force -Recurse
  Remove-item "C:\SetMatrixLEDScript.xml" -Force -Recurse
  Remove-Item "C:\Windows\System32\Tasks\ASUS" -Force -Recurse
  Remove-Item "C:\ProgramData\Packages\B9ECED6F.ArmouryCrate_qmba6cd70vzyy" -Force -Recurse
  #testing for installer zip
  if(Test-Path "$($env:USERPROFILE)\Downloads\ArmouryCrateInstallTool.zip")
  {
    Remove-Item "$($env:USERPROFILE)\Downloads\ArmouryCrateInstallTool.zip" -Force -Recurse
  }
  #searching for where installer is extracted to and deleting it
  $path = Get-ChildItem -Path C:\ -Filter ArmouryCrateInstallTool -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  Remove-Item ([string]$path) -Force -Recurse
  #removing schd tasks
  Unregister-ScheduledTask -TaskName "AcPowerNotification" -Confirm:$false
  Unregister-ScheduledTask -TaskName "ArmourySocketServer" -Confirm:$false
  Unregister-ScheduledTask -TaskName "Framework Service" -Confirm:$false
  Unregister-ScheduledTask -TaskName "P508PowerAgent_sdk" -Confirm:$false


  #deleting temp files
  $path = Get-ChildItem -Path C:\ -Filter DeleteTemp.bat -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$path)
  #waiting 3 seconds before cleaning up github downloads
  Start-Sleep -Seconds 3

  Remove-Item "C:\Armoury Crate Uninstall Tool V2.1.5.0" -Force -Recurse
  Remove-Item "C:\DeleteTemp.bat" -Force
 