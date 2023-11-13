If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}



$Bloatware = @(
                #Unnecessary Windows 10 AppX Apps
                "3DBuilder"
                "Microsoft3DViewer"
                "AppConnector"
                "BingFinance"
                "BingNews"
                "BingSports"
                "BingTranslator"
                "BingWeather"
                "BingFoodAndDrink"
                "BingHealthAndFitness"
                "BingTravel"
                "MinecraftUWP"
                "GamingServices"
                "GetHelp"
                "Getstarted"
                "Messaging"
                "Microsoft3DViewer"
                "MicrosoftSolitaireCollection"
                "NetworkSpeedTest"
                "News"
                "Lens"
                "Sway"
                "OneNote"
                "OneConnect"
                "People"
                "Paint3D"
                "MicrosoftStickyNotes"
                "SkypeApp"
                "Todos"
                "Wallet"
                "Whiteboard"
                "WindowsAlarms"
                "windowscommunicationsapps"
                "WindowsFeedbackHub"
                "WindowsMaps"
                "WindowsPhone"
                "WindowsSoundRecorder"
                "ConnectivityStore"
                "CommsPhone"
                "ScreenSketch"
                "MixedReality.Portal"
                "ZuneMusic"
                "ZuneVideo"
                "YourPhone"
                "MicrosoftOfficeHub"
                "WindowsStore"
                "WindowsCamera"
                "WindowsCalculator"
                "HEIFImageExtension"
                "StorePurchaseApp"
                "VP9VideoExtensions"
                "WebMediaExtensions"
                "WebpImageExtension"
                "DesktopAppInstaller"
                #Sponsored Windows 10 AppX Apps
                #Add sponsored/featured apps to remove in the "*AppName*" format
                "EclipseManager"
                "ActiproSoftwareLLC"
                "AdobeSystemsIncorporated.AdobePhotoshopExpress"
                "Duolingo-LearnLanguagesforFree"
                "PandoraMediaInc"
                "CandyCrush"
                "BubbleWitch3Saga"
                "Wunderlist"
                "Flipboard"
                "Twitter"
                "Facebook"
                "Royal Revolt"
                "Sway"
                "Speed Test"
                "Dolby"
                "Viber"
                "ACGMediaPlayer"
                "Netflix"
                "OneCalendar"
                "LinkedInforWindows"
                "HiddenCityMysteryofShadows"
                "Hulu"
                "HiddenCity"
                "AdobePhotoshopExpress"
                "HotspotShieldFreeVPN"

               
                "Advertising"
                

                # HPBloatware Packages
                "HPJumpStarts"
                "HPPCHardwareDiagnosticsWindows"
                "HPPowerManager"
                "HPPrivacySettings"
                "HPSupportAssistant"
                "HPSureShieldAI"
                "HPSystemInformation"
                "HPQuickDrop"
                "HPWorkWell"
                "myHP"
                "HPDesktopSupportUtilities"
                "HPQuickTouch"
                "HPEasyClean"
                "HPSystemInformation"
            )
                            #   Description:
# This script will remove and disable OneDrive integration.



Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}


Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

# Thank you Matthew Israelsson
Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.exe"

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting 10 seconds for explorer to complete loading"
Start-Sleep 10


             ## Teams Removal - Source: https://github.com/asheroto/UninstallTeams
            function getUninstallString($match) {
                return (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$match*" }).UninstallString
            }
            
            $TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
            $TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')
            
            Write-Output "Stopping Teams process..."
            Stop-Process -Name "*teams*" -Force -ErrorAction SilentlyContinue
        
            Write-Output "Uninstalling Teams from AppData\Microsoft\Teams"
            if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
                # Uninstall app
                $proc = Start-Process $TeamsUpdateExePath "-uninstall -s" -PassThru
                $proc.WaitForExit()
            }
        
            Write-Output "Removing Teams AppxPackage..."
            Get-AppxPackage "*Teams*" | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage "*Teams*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        
            Write-Output "Deleting Teams directory"
            if ([System.IO.Directory]::Exists($TeamsPath)) {
                Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue
            }
        
            Write-Output "Deleting Teams uninstall registry key"
            # Uninstall from Uninstall registry key UninstallString
            $us = getUninstallString("Teams");
            if ($us.Length -gt 0) {
                $us = ($us.Replace("/I", "/uninstall ") + " /quiet").Replace("  ", " ")
                $FilePath = ($us.Substring(0, $us.IndexOf(".exe") + 4).Trim())
                $ProcessArgs = ($us.Substring($us.IndexOf(".exe") + 5).Trim().replace("  ", " "))
                $proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru
                $proc.WaitForExit()
            }
            
           taskkill.exe /F /IM "SkypeApp.exe"
           taskkill.exe /F /IM "Skype.exe"

            foreach ($Bloat in $Bloatware) {
                Get-AppXPackage "*$Bloat*" -AllUsers | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
                Get-AppxPackage "*$Bloat*" | Remove-AppxPackage -ErrorAction SilentlyContinue
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$Bloat*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
                
                Write-Host "Trying to remove $Bloat."
                
            }
                
                if(Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq “Microsoft Update Health Tools"})
                {
                $MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq “Microsoft Update Health Tools"}
                $MyApp.Uninstall()
                }
                      
                
                Get-AppxPackage Microsoft.XboxApp | Remove-AppxPackage
                Get-AppxPackage Microsoft.Xbox.TCUI | Remove-AppxPackage
                Get-AppxPackage Microsoft.XboxGameOverlay | Remove-AppxPackage
                Get-AppxPackage Microsoft.XboxGamingOverlay | Remove-AppxPackage
                Get-AppxPackage Microsoft.XboxIdentityProvider | Remove-AppxPackage
                Get-AppxPackage Microsoft.XboxSpeechToTextOverlay | Remove-AppxPackage
                Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
                Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart -ErrorAction SilentlyContinue
                Get-AppxPackage -allusers Microsoft.MSPaint | Remove-AppxPackage
                Get-AppxPackage -allusers Microsoft.OneDriveSync | Remove-AppxPackage
                Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage
                Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage 


