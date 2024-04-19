If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}


function Get-InstalledSoftware {
  
    [CmdletBinding()]
    param(
        [ArgumentCompleter( {
                param ($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)

                Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' | ForEach-Object { try { Get-ItemPropertyValue -Path $_.pspath -Name DisplayName -ErrorAction Stop } catch { $null } } | Where-Object { $_ -like "*$WordToComplete*" } | ForEach-Object { "'$_'" }
            })]
        [string[]] $appName,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]] $computerName,

        [switch] $dontIgnoreUpdates,

        [ValidateNotNullOrEmpty()]
        [ValidateSet('AuthorizedCDFPrefix', 'Comments', 'Contact', 'DisplayName', 'DisplayVersion', 'EstimatedSize', 'HelpLink', 'HelpTelephone', 'InstallDate', 'InstallLocation', 'InstallSource', 'Language', 'ModifyPath', 'NoModify', 'NoRepair', 'Publisher', 'QuietUninstallString', 'UninstallString', 'URLInfoAbout', 'URLUpdateInfo', 'Version', 'VersionMajor', 'VersionMinor', 'WindowsInstaller')]
        [string[]] $property = ('DisplayName', 'DisplayVersion', 'UninstallString'),

        [switch] $ogv
    )

    PROCESS {
        $scriptBlock = {
            param ($Property, $DontIgnoreUpdates, $appName)

            # where to search for applications
            $RegistryLocation = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\'

            # define what properties should be outputted
            $SelectProperty = @('DisplayName') # DisplayName will be always outputted
            if ($Property) {
                $SelectProperty += $Property
            }
            $SelectProperty = $SelectProperty | Select-Object -Unique

            $RegBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME)
            if (!$RegBase) {
                Write-Error "Unable to open registry on $env:COMPUTERNAME"
                return
            }

            foreach ($RegKey in $RegistryLocation) {
                Write-Verbose "Checking '$RegKey'"
                foreach ($appKeyName in $RegBase.OpenSubKey($RegKey).GetSubKeyNames()) {
                    Write-Verbose "`t'$appKeyName'"
                    $ObjectProperty = [ordered]@{}
                    foreach ($CurrentProperty in $SelectProperty) {
                        Write-Verbose "`t`tGetting value of '$CurrentProperty' in '$RegKey$appKeyName'"
                        $ObjectProperty.$CurrentProperty = ($RegBase.OpenSubKey("$RegKey$appKeyName")).GetValue($CurrentProperty)
                    }

                    if (!$ObjectProperty.DisplayName) {
                        # Skipping. There are some weird records in registry key that are not related to any app"
                        continue
                    }

                    $ObjectProperty.ComputerName = $env:COMPUTERNAME

                    # create final object
                    $appObj = New-Object -TypeName PSCustomObject -Property $ObjectProperty

                    if ($appName) {
                        $appNameRegex = $appName | ForEach-Object {
                            [regex]::Escape($_)
                        }
                        $appNameRegex = $appNameRegex -join '|'
                        $appObj = $appObj | Where-Object { $_.DisplayName -match $appNameRegex }
                    }

                    if (!$DontIgnoreUpdates) {
                        $appObj = $appObj | Where-Object { $_.DisplayName -notlike '*Update for Microsoft*' -and $_.DisplayName -notlike 'Security Update*' }
                    }

                    $appObj
                }
            }
        }

        $param = @{
            scriptBlock  = $scriptBlock
            ArgumentList = $property, $dontIgnoreUpdates, $appName
        }
        if ($computerName) {
            $param.computerName = $computerName
            $param.HideComputerName = $true
        }

        $result = Invoke-Command @param

        if ($computerName) {
            $result = $result | Select-Object * -ExcludeProperty RunspaceId
        }
    }

    END {
        if ($ogv) {
            $comp = $env:COMPUTERNAME
            if ($computerName) { $comp = $computerName }
            $result | Out-GridView -PassThru -Title "Installed software on $comp"
        }
        else {
            $result
        }
    }
}


function Uninstall-ApplicationViaUninstallString {
  
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('displayName')]
        [ArgumentCompleter( {
                param ($Command, $Parameter, $WordToComplete, $CommandAst, $FakeBoundParams)

                Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' | ForEach-Object { try { Get-ItemPropertyValue -Path $_.pspath -Name DisplayName -ErrorAction Stop } catch { $null } } | Where-Object { $_ -like "*$WordToComplete*" } | ForEach-Object { "'$_'" }
            })]
        [string[]] $name,

        [string] $addArgument
    )

    begin {
        # without admin rights msiexec uninstall fails without any error
        if (! ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
            throw 'Run with administrator rights'
        }

        if (!(Get-Command Get-InstalledSoftware)) {
            throw 'Function Get-InstalledSoftware is missing'
        }
    }

    process {
        $appList = Get-InstalledSoftware -property DisplayName, UninstallString, QuietUninstallString | Where-Object DisplayName -In $name

        if ($appList) {
            foreach ($app in $appList) {
                if ($app.QuietUninstallString) {
                    $uninstallCommand = $app.QuietUninstallString
                }
                else {
                    $uninstallCommand = $app.UninstallString
                }
                $name = $app.DisplayName

                if (!$uninstallCommand) {
                    Write-Warning "Uninstall command is not defined for app '$name'"
                    continue
                }

                if ($uninstallCommand -like 'msiexec.exe*') {
                    # it is MSI
                    $uninstallMSIArgument = $uninstallCommand -replace 'MsiExec.exe'
                    # sometimes there is /I (install) instead of /X (uninstall) parameter
                    $uninstallMSIArgument = $uninstallMSIArgument -replace '/I', '/X'
                    # add silent and norestart switches
                    $uninstallMSIArgument = "$uninstallMSIArgument /QN"
                    if ($addArgument) {
                        $uninstallMSIArgument = $uninstallMSIArgument + ' ' + $addArgument
                    }
                    Write-Warning "Uninstalling app '$name' via: msiexec.exe $uninstallMSIArgument"
                    Start-Process 'msiexec.exe' -ArgumentList $uninstallMSIArgument -Wait
                }
                else {
                    # it is EXE
                    #region extract path to the EXE uninstaller
                    # path to EXE is typically surrounded by double quotes
                    $match = ([regex]'("[^"]+")(.*)').Matches($uninstallCommand)
                    if (!$match.count) {
                        # string doesn't contain ", try search for ' instead
                        $match = ([regex]"('[^']+')(.*)").Matches($uninstallCommand)
                    }
                    if ($match.count) {
                        $uninstallExe = $match.captures.groups[1].value
                    }
                    else {
                        # string doesn't contain even '
                        # before blindly use the whole string as path to an EXE, check whether it doesn't contain common argument prefixes '/', '-' ('-' can be part of the EXE path, but it is more safe to make false positive then fail later because of faulty command)
                        if ($uninstallCommand -notmatch '/|-') {
                            $uninstallExe = $uninstallCommand
                        }
                    }
                    if (!$uninstallExe) {
                        Write-Error "Unable to extract EXE path from '$uninstallCommand'"
                        continue
                    }
                    #endregion extract path to the EXE uninstaller
                    if ($match.count) {
                        $uninstallExeArgument = $match.captures.groups[2].value
                    }
                    else {
                        Write-Verbose "I've used whole uninstall string as EXE path"
                    }
                    if ($addArgument) {
                        $uninstallExeArgument = $uninstallExeArgument + ' ' + $addArgument
                    }
                    # Start-Process param block
                    $param = @{
                        FilePath = $uninstallExe
                        Wait     = $true
                    }
                    if ($uninstallExeArgument) {
                        $param.ArgumentList = $uninstallExeArgument
                    }
                    Write-Warning "Uninstalling app '$name' via: $uninstallExe $uninstallExeArgument"
                    Start-Process @param
                }
            }
        }
        else {
            Write-Warning "No software with name $($name -join ', ') was found. Get the correct name by running 'Get-InstalledSoftware' function."
        }
    }
}


$Bloatware = @(
    #Unnecessary Windows 10 AppX Apps
    '3DBuilder'
    'Microsoft3DViewer'
    'AppConnector'
    'BingFinance'
    'BingNews'
    'BingSports'
    'BingTranslator'
    'BingWeather'
    'BingFoodAndDrink'
    'BingHealthAndFitness'
    'BingTravel'
    'MinecraftUWP'
    'GamingServices'
    'GetHelp'
    'Getstarted'
    'Messaging'
    'Microsoft3DViewer'
    'MicrosoftSolitaireCollection'
    'NetworkSpeedTest'
    'News'
    'Lens'
    'Sway'
    'OneNote'
    'OneConnect'
    'People'
    'Paint3D'
    'MicrosoftStickyNotes'
    'SkypeApp'
    'Todos'
    'Wallet'
    'Whiteboard'
    'WindowsAlarms'
    'WindowsFeedbackHub'
    'WindowsMaps'
    'WindowsPhone'
    'WindowsSoundRecorder'
    'ConnectivityStore'
    'CommsPhone'
    'ScreenSketch'
    'MixedReality.Portal'
    'ZuneMusic'
    'ZuneVideo'
    'YourPhone'
    'MicrosoftOfficeHub'
    'WindowsStore'
    'Microsoft.WindowsStore'
    'WindowsCamera'
    'WindowsCalculator'
    'HEIFImageExtension'
    'StorePurchaseApp'
    'VP9VideoExtensions'
    'WebMediaExtensions'
    'WebpImageExtension'
    'DesktopAppInstaller'
    'Microsoft.Windows.Ai.Copilot.Provider'
    'Clipchamp.Clipchamp'
    'Microsoft.GamingApp'
    'Microsoft.HEVCVideoExtension'
    'Microsoft.RawImageExtension'
    'Microsoft.PowerAutomateDesktop'
    'MicrosoftCorporationII.QuickAssist'
    'Microsoft.XboxApp'
    'Microsoft.Xbox.TCUI'
    'Microsoft.XboxGameOverlay'
    'Microsoft.XboxGamingOverlay'
    'Microsoft.XboxIdentityProvider'
    'Microsoft.XboxSpeechToTextOverlay'
    'Microsoft.MSPaint'
    'Microsoft.OneDriveSync'
    'Microsoft.549981C3F5F10'
    'MicrosoftWindows.NarratorScript.Excel'                                                                                  
    'MicrosoftWindows.NarratorScript.Outlook'
    'windowscommunicationsapps'
    'Microsoft.Paint'
    'Microsoft.WindowsTerminal'
    'Microsoft.OutlookForWindows'
    'MicrosoftCorporationII.MicrosoftFamily'
    'Microsoft.Windows.DevHome'
    'Microsoft.Services.Store.Engagement'
    #Sponsored Windows 10 AppX Apps
    #Add sponsored/featured apps to remove in the "*AppName*" format
    'EclipseManager'
    'ActiproSoftwareLLC'
    'AdobeSystemsIncorporated.AdobePhotoshopExpress'
    'Duolingo-LearnLanguagesforFree'
    'PandoraMediaInc'
    'CandyCrush'
    'BubbleWitch3Saga'
    'Wunderlist'
    'Flipboard'
    'Twitter'
    'Facebook'
    'Royal Revolt'
    'Sway'
    'Speed Test'
    'Dolby'
    'Viber'
    'ACGMediaPlayer'
    'Netflix'
    'OneCalendar'
    'LinkedInforWindows'
    'HiddenCityMysteryofShadows'
    'Hulu'
    'HiddenCity'
    'AdobePhotoshopExpress'
    'HotspotShieldFreeVPN'

               
    'Advertising'
                

    # HPBloatware Packages
    'HPJumpStarts'
    'HPPCHardwareDiagnosticsWindows'
    'HPPowerManager'
    'HPPrivacySettings'
    'HPSupportAssistant'
    'HPSureShieldAI'
    'HPSystemInformation'
    'HPQuickDrop'
    'HPWorkWell'
    'myHP'
    'HPDesktopSupportUtilities'
    'HPQuickTouch'
    'HPEasyClean'
    'HPSystemInformation'
)
#   Description:
# This script will remove and disable OneDrive integration.



Write-Output 'Kill OneDrive process'
taskkill.exe /F /IM 'OneDrive.exe' >$null 2>&1
taskkill.exe /F /IM 'explorer.exe' >$null 2>&1

Write-Output 'Remove OneDrive'
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output 'Removing OneDrive leftovers'
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
# check if directory is empty before removing:
If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}


Write-Output 'Remove Onedrive from explorer sidebar'
New-PSDrive -PSProvider 'Registry' -Root 'HKEY_CLASSES_ROOT' -Name 'HKCR'
mkdir -Force 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
Set-ItemProperty -Path 'HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' 'System.IsPinnedToNameSpaceTree' 0
mkdir -Force 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}'
Set-ItemProperty -Path 'HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' 'System.IsPinnedToNameSpaceTree' 0
Remove-PSDrive 'HKCR'

# Thank you Matthew Israelsson
Write-Output 'Removing run hook for new users'
reg load 'hku\Default' 'C:\Users\Default\NTUSER.DAT'
reg delete 'HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' /v 'OneDriveSetup' /f
reg unload 'hku\Default'

Write-Output 'Removing startmenu entry'
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.exe"

Write-Output 'Restarting explorer'
Start-Process 'explorer.exe'

Write-Output 'Waiting 10 seconds for explorer to complete loading'
Start-Sleep 10


## Teams Removal - Source: https://github.com/asheroto/UninstallTeams
function getUninstallString($match) {
    return (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like "*$match*" }).UninstallString
}
            
$TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
$TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')
            
Write-Output 'Stopping Teams process...'
Stop-Process -Name '*teams*' -Force -ErrorAction SilentlyContinue
        
Write-Output 'Uninstalling Teams from AppData\Microsoft\Teams'
if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
    # Uninstall app
    $proc = Start-Process $TeamsUpdateExePath '-uninstall -s' -PassThru
    $proc.WaitForExit()
}
        
Write-Output 'Removing Teams AppxPackage...'
Get-AppxPackage '*Teams*' | Remove-AppxPackage -ErrorAction SilentlyContinue
Get-AppxPackage '*Teams*' -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        
Write-Output 'Deleting Teams directory'
if ([System.IO.Directory]::Exists($TeamsPath)) {
    Remove-Item $TeamsPath -Force -Recurse -ErrorAction SilentlyContinue
}
        
Write-Output 'Deleting Teams uninstall registry key'
# Uninstall from Uninstall registry key UninstallString
$us = getUninstallString('Teams');
if ($us.Length -gt 0) {
    $us = ($us.Replace('/I', '/uninstall ') + ' /quiet').Replace('  ', ' ')
    $FilePath = ($us.Substring(0, $us.IndexOf('.exe') + 4).Trim())
    $ProcessArgs = ($us.Substring($us.IndexOf('.exe') + 5).Trim().replace('  ', ' '))
    $proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru
    $proc.WaitForExit()
}
            
taskkill.exe /F /IM 'SkypeApp.exe' >$null 2>&1
taskkill.exe /F /IM 'Skype.exe' >$null 2>&1

foreach ($Bloat in $Bloatware) {
            
    Get-AppXPackage "*$Bloat*" -AllUsers -ErrorAction SilentlyContinue | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue }
    Get-AppxPackage "*$Bloat*" -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object DisplayName -like "*$Bloat*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    Write-Host "Trying to remove $Bloat" 
                
                
}
                
   
#uninstall health update tools and installed updates
$apps = Get-InstalledSoftware  
foreach ($app in $apps) {
    if ($app.DisplayName -like '*Update for Windows*' -or $app.DisplayName -like '*Microsoft Update Health Tools*') {
        Uninstall-ApplicationViaUninstallString $app.DisplayName
    }
}
                      
               
#uninstall remote desktop connection
#only works on 23h2/ Windows 10 KB50358+
$ProgressPreference = 'SilentlyContinue'
$win10 = $false
$osInfo = Get-ComputerInfo
if ($osInfo.OsName -like '*Windows 10*') {
    #if os is win 10 check for hotfix
    $hotfixes = Get-HotFix
    foreach ($hotfix in $hotfixes) {
        if ($hotfix.Description -eq 'Security Update' -or $hotfix.Description -eq 'Update') {
            #check KB version
            if ($hotfix.HotFixID -like 'KB503*') {
                $win10 = $true
            }
        }
    }
}
else {
    $buildNum = $osInfo.OSDisplayVersion
}


if ($buildNum -eq '23H2' -or $win10 -eq $true) {
    Start-Process mstsc.exe -ArgumentList '/uninstall' 
    Start-Sleep 1
    $running = $true
    do {
        $openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object MainWindowTitle
        foreach ($window in $openWindows) {
            if ($window.MainWindowTitle -eq 'Remote Desktop Connection') {
                Stop-Process -Name 'mstsc' -Force
                $running = $false
            }
        }
    }while ($running)
}

Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM...'
$packagesToRemove = @('Microsoft-Windows-QuickAssist-Package', 'Microsoft-Windows-Hello-Face-Package', 'Microsoft-Windows-StepsRecorder-Package')
$packages = (Get-WindowsPackage -Online).PackageName
foreach ($package in $packages) {
    foreach ($packageR in $packagesToRemove) {
        #ignore 32 bit packages [wow64]
        if ($package -like "$packageR*" -and $package -notlike '*wow64*') {
            #erroraction silently continue doesnt work since error comes from dism
            #using catch block to ignore error
            try {
                Remove-WindowsPackage -Online -PackageName $package -NoRestart -ErrorAction Stop | Out-Null
            }
            catch {
                #error from outdated package version
                #do nothing
            }
           
        }
    }
    
}
#remove narrator exe and startmenu shortcut
Start-Process cmd.exe -ArgumentList '/c takeown /f C:\Windows\System32\Narrator.exe && icacls C:\Windows\System32\Narrator.exe /grant administrators:F >nul 2>&1'
Remove-Item -Force 'C:\Windows\System32\Narrator.exe' -ErrorAction SilentlyContinue
Remove-Item -Force 'C:\Users\Admin\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessibility\Narrator.lnk' -ErrorAction SilentlyContinue
               

                