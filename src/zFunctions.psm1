using module .\CustomCheckedListBoxModule
function debloat {

  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
    , [Parameter(mandatory = $false)] [bool]$debloatAll = $false
    , [Parameter(mandatory = $false)] [bool]$debloatSXE = $false
    , [Parameter(mandatory = $false)] [bool]$debloatSX = $false
    , [Parameter(mandatory = $false)] [bool]$debloatE = $false
    , [Parameter(mandatory = $false)] [bool]$debloatS = $false
  )
  
  # ----------------------------------------------------------- DEBLOAT FUNCTIONS ---------------------------------------------------


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
            # region extract path to the EXE uninstaller
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


  function debloat-TeamsOneDrive {
    Write-Status -Message 'Uninstalling Teams and OneDrive...' -Type Output
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
  }

  
  function get-dismPackages {
    $packagesToRemove = @(
      'Microsoft-Windows-QuickAssist-Package*' 
      'Microsoft-Windows-Hello-Face-Package*'
      'Microsoft-Windows-StepsRecorder-Package*'
      'Microsoft-Windows-TabletPCMath*' 
      'Microsoft-Windows-Wallpaper-Content-Extended*'
      'Microsoft-OneCore-ApplicationModel-Sync-Desktop*'
      'Microsoft-Windows-MediaPlayer*'
    )
    $packages = Get-WindowsPackage -Online
    $foundPackages = @()
    foreach ($package in $packages) {
      $match = $packagesToRemove | Where-Object { $package.PackageName -like $_ -and $package.PackageName -notlike '*wow64*' -and $package.PackageState -eq 'Installed' }
      if ($match) {
        $foundPackages += $package
      }
    }
    
    return $foundPackages
  }


  function get-dismCapability {
    $capabilitesToRemove = @(
      'Accessibility.Braille~~~~*'
      'App.StepsRecorder~~~~*'
      'App.Support.QuickAssist~~~~*'
      'Hello.Face.20134~~~~*'
      'Hello.Face.18967~~~~*'
      'AzureArcSetup~~~~*'
      'MathRecognizer~~~~*'
      'Microsoft.Wallpapers.Extended~~~~*'
      'OneCoreUAP.OneSync~~~~*'
      'Print.Fax.Scan~~~~*'
      'Print.Management.Console~~~~*'
      'XPS.Viewer~~~~*'
      'Media.WindowsMediaPlayer~~~~*'
    )
    $capabilites = get-windowscapability -online 
    $foundCapabilities = @()
    foreach ($capability in $capabilites) {
      $match = $capabilitesToRemove | Where-Object { $capability.Name -like $_ -and $capability.State -eq 'Installed' }
      if ($match) {
        $foundCapabilities += $capability
      }
    }

    return $foundCapabilities

  }

  function get-dismFeatures {
    $featuresToRemove = @(
      'Printing-XPSServices-Features'
      'WorkFolders-Client'
      'MediaPlayback'
      'WindowsMediaPlayer'
      'Microsoft-RemoteDesktopConnection'
      'Recall'
      'Printing-PrintToPDFServices-Features'
      'Printing-Foundation-Features'
      'Printing-Foundation-InternetPrinting-Client'
      'Printing-Foundation-LPDPrintService'
      'Printing-Foundation-LPRPortMonitor'
      'Windows-Defender-Default-Definitions'
    )
    $features = Get-WindowsOptionalFeature -Online
    $foundFeatures = @()
    foreach ($feature in $features) {
      $match = $featuresToRemove | Where-Object { $feature.FeatureName -eq $_ -and $feature.State -eq 'Enabled' }
      if ($match) {
        $foundFeatures += $feature
      }
    }
    return $foundFeatures

  }

  function debloat-HealthUpdateTools {
    #uninstall health update tools and installed updates
    $apps = Get-InstalledSoftware  
    foreach ($app in $apps) {
      if ($app.DisplayName -like '*Update for Windows*' -or $app.DisplayName -like '*Microsoft Update Health Tools*') {
        Uninstall-ApplicationViaUninstallString $app.DisplayName
      }
    }
  }

  function debloat-remotedesktop {
    #uninstall remote desktop connection
    
    try {
      #get uninstall string 
      $uninstallstr = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\mstsc*' -Name 'UninstallString').UninstallString
      $path, $arg = $uninstallstr -split ' '
      Start-Process -FilePath $path -ArgumentList $arg
      Start-Sleep 1
      $running = $true
      #create stopwatch for 10 secs incase of do while getting stuck
      $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
      do {
        $openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object MainWindowTitle
        foreach ($window in $openWindows) {
          if ($window.MainWindowTitle -eq 'Remote Desktop Connection') {
            Stop-Process -Name 'mstsc' -Force
            $running = $false
          }
        }

        if ($stopwatch.Elapsed.TotalSeconds -ge 10) {
          $running = $false
        }
      }while ($running)

      $stopwatch.Stop()
    }
    catch {
      #remote desktop not found
      Write-Status -Message 'Remote Desktop Not Found' -Type Error
    }
    
    
    
  }


  function debloat-dismPackage {
    param(
      [string]$packageName
    )
    $ProgressPreference = 'SilentlyContinue'
   
    #erroraction silently continue doesnt work since error comes from dism
    #using catch block to ignore error
    Write-Status -Message "Removing Package $packageName..." -Type Output
    try {
      Remove-WindowsPackage -Online -PackageName $package -NoRestart -ErrorAction Stop *>$null
    }
    catch {
      #error from outdated package version
      #do nothing
    }
       

  }

  function debloat-dismCapability {
    param (
      [string]$capabilityName
    )
    Write-Status -Message "Removing Capability $capabilityName..." -Type Output
    $ProgressPreference = 'SilentlyContinue'
    try {
      Remove-WindowsCapability -Online -Name $capabilityName -ErrorAction Stop *>$null
    }
    catch {
      #ignore error
    }
    

  }

  function debloat-dismFeatures {
    param(
      [string]$featureName
    )
    $ProgressPreference = 'SilentlyContinue'
    Write-Status -Message "Removing Feature $featureName..." -Type Output
    try {
      Disable-WindowsOptionalFeature -Online -FeatureName $featureName -Remove -NoRestart -ErrorAction Stop *>$null
    }
    catch {
      #ignore error
    }
    

  }

  function debloat-Win32Apps {
    param(
      [ValidateSet('speech', 'livecaptions', 'magnifier', 'Narrator', 'osk', 'voiceaccess', 'stepsrecorder', 'QuickAssist', 'MathInput')]
      [string]$appName
    )

    $startMenu = "$env:appdata\Microsoft\Windows\Start Menu\Programs\Accessibility"
    $startMenu2 = "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Accessories"
    $startMenu3 = "$env:PROGRAMDATA\Microsoft\Windows\Start Menu\Programs\Accessibility"
    switch ($appName) {
      'speech' { 
        Write-Status -Message 'Removing Speech App...' -Type Output
        $command = 'Remove-item -path C:\Windows\System32\Speech -recurse -force; Remove-item -path C:\Windows\Speech\Common -recurse -force'
        Run-Trusted -command $command
        Start-Sleep 1
        Remove-Item "$startmenu3\Speech Recognition.lnk" -Force -ErrorAction SilentlyContinue
        break
      }
      'livecaptions' {
        Write-Status -Message 'Removing Live Captions...' -Type Output
        $command = "Remove-item -path $env:windir\System32\LiveCaptions.exe -force"
        Run-Trusted -command $command
        Start-Sleep 1
        Remove-Item "$startMenu\LiveCaptions.lnk" -Force -ErrorAction SilentlyContinue
        break
      }
      'magnifier' {
        Write-Status -Message 'Removing Magnifier...' -Type Output
        $command = "Remove-item -path $env:windir\System32\magnify.exe -force"
        Run-Trusted -command $command
        Start-Sleep 1
        Remove-Item "$startMenu\Magnify.lnk" -Force -ErrorAction SilentlyContinue
        break
      }
      'Narrator' {
        Write-Status -Message 'Removing Narrator...' -Type Output
        $command = "Remove-item -path $env:windir\System32\narrator.exe -force"
        Run-Trusted -command $command
        Start-Sleep 1
        Remove-Item "$startMenu\Narrator.lnk" -Force -ErrorAction SilentlyContinue
        break
      }
      'osk' {
        Write-Status -Message 'Removing On Screen Keyboard...' -Type Output
        $command = "Remove-item -path $env:windir\System32\osk.exe -force; Remove-item -path `"$env:programfiles\Common Files\Microsoft Shared\ink`" -force -recurse"
        Run-Trusted -command $command
        Start-Sleep 1
        Remove-Item "$startMenu\On-Screen Keyboard.lnk" -Force -ErrorAction SilentlyContinue
        break
      }
      'voiceaccess' {
        Write-Status -Message 'Removing Voice Access...' -Type Output
        $command = "Remove-item -path $env:windir\System32\voiceaccess.exe -force"
        Run-Trusted -command $command
        Start-Sleep 1
        Remove-Item "$startMenu\VoiceAccess.lnk" -Force -ErrorAction SilentlyContinue
        break
      }
      'stepsrecorder' {
        Write-Status -Message 'Removing Steps Recorder...' -Type Output
        $command = "Remove-item -path $env:windir\System32\psr.exe -force"
        Run-Trusted -command $command
        Start-Sleep 1
        Remove-Item "$startMenu2\Steps Recorder.lnk" -Force -ErrorAction SilentlyContinue
        break
      }
      'QuickAssist' {
        Write-Status -Message 'Removing Quick Assist...' -Type Output
        $command = "Remove-item -path $env:windir\System32\quickassist.exe -force"
        Run-Trusted -command $command
        Start-Sleep 1
        Remove-Item "$startMenu2\Quick Assist.lnk" -Force -ErrorAction SilentlyContinue
        break
      }
      'MathInput' {
        Write-Status -Message 'Removing Math Input Panel...' -Type Output
        $command = "Remove-item -path `"$env:programfiles\Common Files\Microsoft Shared\ink`" -force -recurse" 
        Run-Trusted -command $command
        Start-Sleep 1
        Remove-Item "$startMenu2\Math Input Panel.lnk" -Force -ErrorAction SilentlyContinue
        break
      }
    }
  }
  
  function debloatPreset {
    param (
      [string]$choice
    )

    function debloatAppx {

      param (
        [string]$Bloat
      )
      #silentlycontinue doesnt work sometimes so trycatch block is needed to supress errors
      try {
        Get-AppXPackage "*$Bloat*" -AllUsers -ErrorAction Stop | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue; Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop } | Out-Null
      }
      catch {}
      try {
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$Bloat*" | Remove-AppxProvisionedPackage -AllUsers -Online -ErrorAction Stop | Out-Null
      }
      catch {}  
    }




    $packages = (Get-AppxPackage -AllUsers).name
    #remove dups
    $Bloatware = $packages | Sort-Object | Get-Unique
    $ProgressPreference = 'SilentlyContinue'

    switch ($choice) {
      'debloatAll' {
        foreach ($Bloat in $Bloatware) {
          #using where-obj for wildcards to work
          $isProhibited = $prohibitedPackages | Where-Object { $Bloat -like $_ }
          #skip locked packages to save time
          if ($Bloat -notin $lockedAppxPackages -and !$isProhibited) {
            #dont remove nvcp, photos, notepad(11) and paint on 11 (win10 paint is "MSPaint")
            #using -like because microsoft like to randomly change package names
            if (!($Bloat -like '*NVIDIA*' -or $Bloat -like '*Photos*' -or $Bloat -eq 'Microsoft.Paint' -or $Bloat -like '*Notepad*')) { 
              Write-Status -Message "Trying to remove $Bloat" -Type Output
              debloatAppx -Bloat $Bloat
            }          
          }

        }
      }
      'debloatKeepStore' {
        foreach ($Bloat in $Bloatware) {
          #using where-obj for wildcards to work
          $isProhibited = $prohibitedPackages | Where-Object { $Bloat -like $_ }
          #skip locked packages to save time
          if ($Bloat -notin $lockedAppxPackages -and !$isProhibited) {
            #dont remove nvcp, photos or paint on 11 (win10 paint is "MSPaint")
            #dont remove store
            if (!($Bloat -like '*NVIDIA*' -or $Bloat -like '*Photos*' -or $Bloat -eq 'Microsoft.Paint' -or $Bloat -like '*Store*' -or $Bloat -like '*Notepad*')) { 
              Write-Status -Message "Trying to remove $Bloat" -Type Output
              debloatAppx -Bloat $Bloat
            }          
          }

        }
      }
      'debloatKeepStoreXbox' {
        foreach ($Bloat in $Bloatware) {
          #using where-obj for wildcards to work
          $isProhibited = $prohibitedPackages | Where-Object { $Bloat -like $_ }
          #skip locked packages to save time
          if ($Bloat -notin $lockedAppxPackages -and !$isProhibited) {
            #dont remove nvcp, photos or paint on 11 (win10 paint is "MSPaint")
            #dont remove store and xbox
            if (!($Bloat -like '*NVIDIA*' -or $Bloat -like '*Photos*' -or $Bloat -eq 'Microsoft.Paint' -or $Bloat -like '*Store*' -or $Bloat -like '*Xbox*' -or $Bloat -like '*Gaming*' -or $Bloat -like '*Notepad*')) { 
              Write-Status -Message "Trying to remove $Bloat" -Type Output
              debloatAppx -Bloat $Bloat
            }          
          }

        }
      }
    }


  }



    


  # ----------------------------------------------------------- DEBLOAT FUNCTIONS ---------------------------------------------------



  $comboBoxPresets = New-Object System.Windows.Forms.ComboBox
  $comboBoxPresets.Items.AddRange(@(
      'Debloat All',
      'Keep Store, Xbox and Edge',
      'Keep Store and Xbox',
      'Debloat All Keep Edge',
      'Debloat All Keep Store'
    ))

  #hashtable to loop through later for updating the config
  $settings = @{}
  $settings['debloatAll'] = 'Debloat All'
  $settings['debloatSXE'] = 'Keep Store, Xbox and Edge'
  $settings['debloatSX'] = 'Keep Store and Xbox'
  $settings['debloatE'] = 'Debloat All Keep Edge'
  $settings['debloatS'] = 'Debloat All Keep Store'


  $Global:lockedAppxPackages = @(
    'Microsoft.Windows.NarratorQuickStart' 
    'Microsoft.Windows.ParentalControls'
    'Microsoft.Windows.PeopleExperienceHost'
    'Microsoft.ECApp'
    'Microsoft.LockApp'
    'NcsiUwpApp'
    'Microsoft.XboxGameCallableUI'
    'Microsoft.Windows.XGpuEjectDialog'
    'Microsoft.Windows.SecureAssessmentBrowser'
    'Microsoft.Windows.PinningConfirmationDialog'
    'Microsoft.AsyncTextService'
    'Microsoft.AccountsControl'
    'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE'
    'E2A4F912-2574-4A75-9BB0-0D023378592B'
    'Microsoft.Windows.PrintQueueActionCenter'
    'Microsoft.Windows.CapturePicker'
    'Microsoft.CredDialogHost'
    'Microsoft.Windows.AssignedAccessLockApp'
    'Microsoft.Windows.Apprep.ChxApp'
    'Windows.PrintDialog'
    'Microsoft.Windows.ContentDeliveryManager'
    'Microsoft.BioEnrollment'
    'Microsoft.Windows.CloudExperienceHost'
    'MicrosoftWindows.UndockedDevKit'
    'Microsoft.Windows.OOBENetworkCaptivePortal'
    'Microsoft.Windows.OOBENetworkConnectionFlow'
    'Microsoft.AAD.BrokerPlugin'
    'MicrosoftWindows.Client.CoPilot'
    'MicrosoftWindows.Client.CBS'
    'MicrosoftWindows.Client.Core'
    'MicrosoftWindows.Client.FileExp'
    'Microsoft.SecHealthUI'
    'Microsoft.Windows.SecHealthUI'
    'windows.immersivecontrolpanel'
    'Windows.CBSPreview'
    'MicrosoftWindows.Client.WebExperience'
    'Microsoft.Windows.CallingShellApp'
    'Microsoft.Win32WebViewHost'
    'Microsoft.MicrosoftEdgeDevToolsClient'
    'Microsoft.Advertising.Xaml'
    'Microsoft.Services.Store.Engagement'
    'Microsoft.WidgetsPlatformRuntime'
    'MicrosoftWindows.Client.AIX'
    'MicrosoftWindows.Client.Photon'
    'Microsoft.DekstopAppInstaller'
    'MicrosoftWindows.55182690.Taskbar'
    'MicrosoftWindows.Client.CoreAI'
  )

  $Global:prohibitedPackages = @(
    'Microsoft.NET.Native.Framework.*'
    'Microsoft.NET.Native.Runtime.*'
    'Microsoft.UI.Xaml.*'
    'Microsoft.VCLibs.*'
    'Microsoft.WindowsAppRuntime.*'
    'c5e2524a-ea46-4f67-841f-6a9465d9d515'
    '1527c705-839a-4832-9118-54d4Bd6a0c89'
    'Microsoft.Windows.ShellExperienceHost'
    'Microsoft.Windows.StartMenuExperienceHost'
    'Microsoft.Windows.Search'
    'MicrosoftWindows.LKG*'
    'MicrosoftWindows.Client.LKG'
    'MicrosoftWindows.Client.OOBE'
    'MicrosoftWindows.Client.WebExperience'
    'Microsoft.WidgetsPlatformRuntime'
    'Microsoft.Windows.AppSuggestedFoldersToLibraryDialog'
    'Microsoft.Windows.AppResolverUX'
    'Microsoft.Windows.AugLoop.CBS'
  )

    
  if ($AutoRun) {
    $result = [System.Windows.Forms.DialogResult]::OK
    if ($debloatAll) {
      $comboBoxPresets.SelectedIndex = 0
    }
    elseif ($debloatSXE) {
      $comboBoxPresets.SelectedIndex = 1
    }
    elseif ($debloatSX) {
      $comboBoxPresets.SelectedIndex = 2
    }
    elseif ($debloatE) {
      $comboBoxPresets.SelectedIndex = 3
    }
    elseif ($debloatS) {
      $comboBoxPresets.SelectedIndex = 4
    }
    
  }
  else {
  
    #creating powershell list box 
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

        

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Debloat'
    $form.Size = New-Object System.Drawing.Size(700, 550)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

    # Sidebar Panel
    $sidebarPanel = New-Object System.Windows.Forms.Panel
    $sidebarPanel.Location = New-Object System.Drawing.Point(0, 0)
    $sidebarPanel.Size = New-Object System.Drawing.Size(150, $form.ClientSize.Height)
    $sidebarPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $form.Controls.Add($sidebarPanel)

    $presetsBtn = New-Object System.Windows.Forms.Button
    $presetsBtn.Location = New-Object System.Drawing.Point(10, 10)
    $presetsBtn.Size = New-Object System.Drawing.Size(130, 40)
    $presetsBtn.Text = 'Debloat Presets'
    $presetsBtn.ForeColor = 'White'
    $presetsBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
    $presetsBtn.FlatAppearance.BorderSize = 0
    $presetsBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $presetsBtn.Tag = 'Inactive'
    $presetsBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $presetsBtn.Add_MouseLeave({ if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) } else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) } })
    $sidebarPanel.Controls.Add($presetsBtn)

    $appxBtn = New-Object System.Windows.Forms.Button
    $appxBtn.Location = New-Object System.Drawing.Point(10, 60)
    $appxBtn.Size = New-Object System.Drawing.Size(130, 40)
    $appxBtn.Text = 'Appx Packages'
    $appxBtn.ForeColor = 'White'
    $appxBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
    $appxBtn.FlatAppearance.BorderSize = 0
    $appxBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $appxBtn.Tag = 'Inactive'
    $appxBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $appxBtn.Add_MouseLeave({ if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) } else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) } })
    $sidebarPanel.Controls.Add($appxBtn)

    $featuresBtn = New-Object System.Windows.Forms.Button
    $featuresBtn.Location = New-Object System.Drawing.Point(10, 110)
    $featuresBtn.Size = New-Object System.Drawing.Size(130, 40)
    $featuresBtn.Text = 'Optional Features'
    $featuresBtn.ForeColor = 'White'
    $featuresBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
    $featuresBtn.FlatAppearance.BorderSize = 0
    $featuresBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $featuresBtn.Tag = 'Inactive'
    $featuresBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $featuresBtn.Add_MouseLeave({ if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) } else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) } })
    $sidebarPanel.Controls.Add($featuresBtn)

    $extrasBtn = New-Object System.Windows.Forms.Button
    $extrasBtn.Location = New-Object System.Drawing.Point(10, 160)
    $extrasBtn.Size = New-Object System.Drawing.Size(130, 40)
    $extrasBtn.Text = 'Extras'
    $extrasBtn.ForeColor = 'White'
    $extrasBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
    $extrasBtn.FlatAppearance.BorderSize = 0
    $extrasBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $extrasBtn.Tag = 'Inactive'
    $extrasBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $extrasBtn.Add_MouseLeave({ if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) } else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) } })
    $sidebarPanel.Controls.Add($extrasBtn)

    $url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#debloat'
    $infobutton = New-Object Windows.Forms.Button
    $infobutton.Location = New-Object Drawing.Point(5, 480)
    $infobutton.Size = New-Object Drawing.Size(30, 27)
    $infobutton.Cursor = 'Hand'
    $infobutton.Add_Click({
        try {
          Start-Process $url -ErrorAction Stop
        }
        catch {
          Write-Status -Message 'No Internet Connected...' -Type Error
        }
            
      })
    $infobutton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $image = [System.Drawing.Image]::FromFile('C:\Windows\System32\SecurityAndMaintenance.png')
    $resizedImage = New-Object System.Drawing.Bitmap $image, 24, 25
    $infobutton.Image = $resizedImage
    $infobutton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $infobutton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $infobutton.FlatAppearance.BorderSize = 0
    #$infobutton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$infobutton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $sidebarPanel.Controls.Add($infobutton)

  
    # Main Content Panel
    $contentPanel = New-Object System.Windows.Forms.Panel
    $contentPanel.Location = New-Object System.Drawing.Point(160, 10)
    $contentPanel.Size = New-Object System.Drawing.Size(520, 470) # Adjusted for larger form
    $contentPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $form.Controls.Add($contentPanel)


    # Debloat Presets Panel
    $presetsPanel = New-Object System.Windows.Forms.Panel
    $presetsPanel.Location = New-Object System.Drawing.Point(0, 0)
    $presetsPanel.Size = New-Object System.Drawing.Size(520, 470)
    $presetsPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $presetsPanel.Visible = $true
    $contentPanel.Controls.Add($presetsPanel)

    $label1 = New-Object System.Windows.Forms.Label
    $label1.Location = New-Object System.Drawing.Point(10, 10)
    $label1.Size = New-Object System.Drawing.Size(200, 20)
    $label1.Text = 'Debloat Presets'
    $label1.ForeColor = 'White'
    $label1.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $presetsPanel.Controls.Add($label1)

    $comboBoxPresets = New-Object System.Windows.Forms.ComboBox
    $comboBoxPresets.Location = New-Object System.Drawing.Point(20, 40)
    $comboBoxPresets.Size = New-Object System.Drawing.Size(480, 25)
    $comboBoxPresets.Items.AddRange(@('Debloat All', 'Keep Store, Xbox and Edge', 'Keep Store and Xbox', 'Debloat All Keep Edge', 'Debloat All Keep Store'))
    $comboBoxPresets.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $comboBoxPresets.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $comboBoxPresets.ForeColor = 'White'
    $comboBoxPresets.SelectedIndex = 0
    $presetsPanel.Controls.Add($comboBoxPresets)

    $presetDescriptionLabel = New-Object System.Windows.Forms.Label
    $presetDescriptionLabel.Location = New-Object System.Drawing.Point(20, 70)
    $presetDescriptionLabel.Size = New-Object System.Drawing.Size(480, 60)
    $presetDescriptionLabel.ForeColor = 'White'
    $presetDescriptionLabel.Font = New-Object System.Drawing.Font('Segoe UI', 10) 
    $presetDescriptionLabel.Text = "Removes all non-essential apps, including Store, Xbox, and Edge.`r`nAlso removes Remote Desktop, Health Update Tools, and cleans Start Menu Pinned Icons."
    $presetsPanel.Controls.Add($presetDescriptionLabel)

    $applyPreset = New-Object System.Windows.Forms.Button
    $applyPreset.Location = New-Object System.Drawing.Point(20, 150)
    $applyPreset.Size = New-Object System.Drawing.Size(480, 30)
    $applyPreset.Text = 'Apply Preset'
    $applyPreset.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $applyPreset.ForeColor = [System.Drawing.Color]::White
    $applyPreset.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $applyPreset.Tag = 'false'
    $applyPreset.Add_Click({ $applyPreset.Tag = 'true' })
    $presetsPanel.Controls.Add($applyPreset)

    $comboBoxPresets.Add_SelectedIndexChanged({
        switch ($comboBoxPresets.SelectedIndex) {
          0 { $presetDescriptionLabel.Text = "Removes all non-essential apps, including Store, Xbox, and Edge.`r`nAlso removes Remote Desktop, Health Update Tools, and cleans Start Menu Pinned Icons." }
          1 { $presetDescriptionLabel.Text = "Keeps Microsoft Store, Xbox apps, and Edge browser.`r`nAlong with removing Remote Desktop, Health Update Tools, and cleaning Start Menu Pinned Icons" }
          2 { $presetDescriptionLabel.Text = "Keeps Microsoft Store and Xbox apps, removes Edge.`r`nAlong with removing Remote Desktop, Health Update Tools, and cleaning Start Menu Pinned Icons" }
          3 { $presetDescriptionLabel.Text = "Removes all non-essential apps except Edge browser.`r`nAlong with removing Remote Desktop, Health Update Tools, and cleaning Start Menu Pinned Icons" }
          4 { $presetDescriptionLabel.Text = "Removes all non-essential apps except Microsoft Store.`r`nAlong with removing Remote Desktop, Health Update Tools, and cleaning Start Menu Pinned Icons" }
        }
      })

    # Appx Packages Panel
    $appxPanel = New-Object System.Windows.Forms.Panel
    $appxPanel.Location = New-Object System.Drawing.Point(0, 0)
    $appxPanel.Size = New-Object System.Drawing.Size(520, 470)
    $appxPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $appxPanel.Visible = $false
    $contentPanel.Controls.Add($appxPanel)

    $removeAppxPackages = {
      if ($customCheckedListBox.CheckedItems.Count -eq 0) { Write-Host 'No Packages Selected' }
      else {
        $ProgressPreference = 'SilentlyContinue'
        foreach ($package in $customCheckedListBox.CheckedItems.GetEnumerator()) {
          Write-Status -Message "Trying to Remove $package" -Type Output
          #silentlycontinue doesnt work sometimes so trycatch block is needed to supress errors
          try {
            Get-AppXPackage "*$package*" -AllUsers -ErrorAction Stop | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue; Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction Stop } | Out-Null
          }
          catch {}
          try {
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$package*" | Remove-AppxProvisionedPackage -AllUsers -Online -ErrorAction Stop | Out-Null
          }
          catch {}    
        }
        #refresh list box
        Get-Packages -showLockedPackages $false
      }
    }


    $removeAppx = New-Object System.Windows.Forms.Button
    $removeAppx.Location = New-Object System.Drawing.Point(20, 430)
    $removeAppx.Size = New-Object System.Drawing.Size(230, 30)
    $removeAppx.Text = 'Remove Appx Packages'
    $removeAppx.Font = New-Object System.Drawing.Font('Segoe UI', 9) 
    $removeAppx.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $removeAppx.ForeColor = [System.Drawing.Color]::White
    #$removeAppx.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$removeAppx.FlatAppearance.BorderSize = 0
    #$removeAppx.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$removeAppx.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $removeAppx.Add_Click({
        &$removeAppxPackages
      })
    $appxPanel.Controls.Add($removeAppx)

    
    $removeLockedPackages = {
      if ($customCheckedListBox.CheckedItems.Count -eq 0) { Write-Host 'No Locked Packages Selected' }
      else {
        $selectedLockedPackages = @()
        foreach ($package in $customCheckedListBox.CheckedItems.GetEnumerator()) {
          $selectedLockedPackages += $package
        }

        $removelockedFunc = Search-File '*Remove-Locked.ps1'
        foreach ($packageName in $selectedLockedPackages) {
          Write-Status -Message "Trying to Remove $packageName" -Type Output
          #dot source function 
          Run-Trusted -command ".'$removelockedFunc'; Remove-Locked $packageName"
          Start-Sleep .5
        }
       
      }
      #update list
      Get-Packages -showLockedPackages $true
    }
    
    $removeLocked = New-Object System.Windows.Forms.Button
    $removeLocked.Location = New-Object System.Drawing.Point(270, 430)
    $removeLocked.Size = New-Object System.Drawing.Size(230, 30)
    $removeLocked.Text = 'Remove Locked Packages'
    $removeLocked.Font = New-Object System.Drawing.Font('Segoe UI', 9) 
    $removeLocked.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $removeLocked.ForeColor = [System.Drawing.Color]::White
    #$removeLocked.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$removeLocked.FlatAppearance.BorderSize = 0
    #$removeLocked.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$removeLocked.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $removeLocked.Add_Click({
        &$removeLockedPackages
      })
    $appxPanel.Controls.Add($removeLocked)

 
    $checkAllBoxes = {
      if (!$checkAll.Checked) {
        #uncheck boxes
        for (($i = 0); $i -lt $customCheckedListBox.Items.Count; $i++) {
          $customCheckedListBox.SetItemChecked($i, $false)
        }
      }
      else {
        #check all buttons
        for (($i = 0); $i -lt $customCheckedListBox.Items.Count; $i++) {
          $customCheckedListBox.SetItemChecked($i, $true)
        }

      }

    }

    $checkAll = New-Object System.Windows.Forms.CheckBox
    $checkAll.Location = New-Object System.Drawing.Point(20, 40)
    $checkAll.Size = New-Object System.Drawing.Size(90, 21)
    $checkAll.Text = 'Check All'
    $checkAll.ForeColor = 'White'
    $checkAll.Add_Click({ 
        &$checkAllBoxes
      })
    $appxPanel.Controls.Add($checkAll)

    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(10, 10)
    $label2.Size = New-Object System.Drawing.Size(200, 20)
    $label2.Text = 'Appx Packages'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $appxPanel.Controls.Add($label2)


    function Get-Packages {
      param (
        [bool]$showLockedPackages
      )

      # Clear the logos hashtable and the checked list box items
      $Global:logos.Clear()
      $customCheckedListBox.Items.Clear()
      

      $packageNames = Get-AppxPackage -AllUsers | Select-Object Name, InstallLocation
      #remove dups
      $Global:sortedPackages = $packageNames | Sort-Object Name -Unique
     
      if ($showLockedPackages) {
        $Global:BloatwareLocked = @()
        foreach ($package in $sortedPackages) {
          $isProhibited = $prohibitedPackages | Where-Object { $package.Name -like $_ }
          if ($package.Name -in $lockedAppxPackages -and !$isProhibited) {
            $packageObj = [PSCustomObject]@{
              Name            = $package.name
              InstallLocation = $package.InstallLocation
            }
            if ($package.Name -eq 'E2A4F912-2574-4A75-9BB0-0D023378592B') {
              $packageObj.Name = 'Microsoft.Windows.AppResolverUX'
            }
            elseif ($package.Name -eq 'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE') {
              $packageObj.Name = 'Microsoft.Windows.AppSuggestedFoldersToLibraryDialog'
            }
            $Global:BloatwareLocked += $packageObj
          }
        }

        # Populate logos for locked packages
        foreach ($package in $Global:BloatwareLocked) {
          Add-LogoForPackage -packageName $package.Name -installLocation $package.InstallLocation
        }

      }
      else {
        $Global:Bloatware = @()
        foreach ($package in $sortedPackages) {
          $isProhibited = $prohibitedPackages | Where-Object { $package.Name -like $_ }
          if ($package.Name -notin $lockedAppxPackages -and !$isProhibited) {
            $newObj = [PSCustomObject]@{
              Name            = $package.Name
              InstallLocation = $package.InstallLocation
            }
            $Global:Bloatware += $newObj
          }
        }

        # Populate logos for regular packages
        foreach ($package in $Global:Bloatware) {
          Add-LogoForPackage -packageName $package.Name -installLocation $package.InstallLocation
        }

      }

      # Add items to the checked list box
      foreach ($package in $Global:logos.GetEnumerator()) {
        $customCheckedListBox.Items.Add($package.Key) *>$null
      }

    }

    # Define the function to add logo for a package
    function Add-LogoForPackage {
      param (
        [string]$packageName,
        [string]$installLocation
      )

      $xmlPath = "$installLocation\AppxManifest.xml"
      #read xml and get icon
      try {
        $xmlContent = [xml](Get-Content $xmlPath -ErrorAction Stop)
        $logo = [array]$xmlContent.Package.Applications.Application.VisualElements.Square44x44Logo
   
        #handle multiple logos
        if ($logo.Length -ne 0) {
          $extractedLogo = $logo[0]
        
          $Index = $extractedLogo.LastIndexOf('.')
          $logoPath = $extractedLogo.Substring(0, $Index)
          $logoExt = $extractedLogo.Substring($Index)
          $logoFullPath = (Get-ChildItem "$($package.InstallLocation)\$logoPath.scale*$logoExt" -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
        }
      }
      catch {
        #cant read xml or doesnt exist 
      }
     
   
      if ($logoFullPath) {
        $Global:logos.Add($packageName, $logoFullPath)
      }
      else {
        $Global:logos.Add($packageName, $Global:noLogoPath)
      }
    
      
    }
    
    # Optional Features Panel
    $featuresPanel = New-Object System.Windows.Forms.Panel
    $featuresPanel.Location = New-Object System.Drawing.Point(0, 0)
    $featuresPanel.Size = New-Object System.Drawing.Size(520, 470)
    $featuresPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $featuresPanel.Visible = $false
    $contentPanel.Controls.Add($featuresPanel)

    $label3 = New-Object System.Windows.Forms.Label
    $label3.Location = New-Object System.Drawing.Point(10, 10)
    $label3.Size = New-Object System.Drawing.Size(200, 20)
    $label3.Text = 'Optional Features'
    $label3.ForeColor = 'White'
    $label3.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $featuresPanel.Controls.Add($label3)

    $checkAllCheckbox = New-Object System.Windows.Forms.CheckBox
    $checkAllCheckbox.Location = New-Object System.Drawing.Point(420, 20)
    $checkAllCheckbox.Size = New-Object System.Drawing.Size(100, 20)
    $checkAllCheckbox.Text = 'Check All'
    $checkAllCheckbox.ForeColor = 'White'
    $checkAllCheckbox.Add_CheckedChanged({
        $dataGridView.EndEdit() # Ensure any pending edits are applied
        foreach ($row in $dataGridView.Rows) {
          $row.Cells['Select'].Value = $checkAllCheckbox.Checked
        }
        $dataGridView.Refresh()
      })
    $featuresPanel.Controls.Add($checkAllCheckbox)

    $dataGridView = New-Object System.Windows.Forms.DataGridView
    $dataGridView.Location = New-Object System.Drawing.Point(20, 40)
    $dataGridView.Size = New-Object System.Drawing.Size(480, 350)
    $dataGridView.BackgroundColor = [System.Drawing.Color]::Black
    $dataGridView.ForeColor = 'White'
    $dataGridView.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $dataGridView.ColumnHeadersDefaultCellStyle.ForeColor = 'White'
    $dataGridView.DefaultCellStyle.BackColor = [System.Drawing.Color]::Black
    $dataGridView.DefaultCellStyle.ForeColor = 'White'
    $dataGridView.RowHeadersVisible = $false
    $dataGridView.AllowUserToAddRows = $false
    $dataGridView.ReadOnly = $false
    $dataGridView.SelectionMode = 'FullRowSelect'
    $dataGridView.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::Fill
    $dataGridView.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
    $dataGridView.Columns.Clear()
    $featuresPanel.Controls.Add($dataGridView)
    
    $Global:progressBar1 = New-Object System.Windows.Forms.ProgressBar
    $progressBar1.Location = New-Object System.Drawing.Point(230, 485)
    $progressBar1.Size = New-Object System.Drawing.Size(150, 15)
    $progressBar1.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
    $progressBar1.Minimum = 0
    $progressBar1.Maximum = 100
    $progressBar1.Visible = $false
    $form.Controls.Add($progressBar1)

    $Global:labelLoading = New-Object System.Windows.Forms.Label
    $labelLoading.Text = 'Loading'
    $labelLoading.ForeColor = 'White'
    $labelLoading.Location = New-Object System.Drawing.Point(160, 480)
    $labelLoading.AutoSize = $true
    $labelLoading.Font = New-Object System.Drawing.Font('Segoe UI', 11)
    $labelLoading.Visible = $false
    $form.Controls.Add($labelLoading)
    
    $Global:timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000 # 1 second
    $script:progressValue = 0
    $timer.Add_Tick({
        $script:progressValue++
        if ($script:progressValue -le 100) {
          $progressBar1.Value = $script:progressValue
        }
        else {
          $timer.Stop()
        }
      })


    function Populate-DataGridView {
    
      # Create a DataTable to hold the data
      $dataTable = New-Object System.Data.DataTable
      [void]$dataTable.Columns.Add('Select', [bool])
      [void]$dataTable.Columns.Add('Name', [string])
      [void]$dataTable.Columns.Add('Type', [string])

      $script:progressValue = 0
      $progressBar1.Value = 0
      $timer.Start()
    
      $totalItems = 0
      $processedItems = 0

      $packages = get-dismPackages
      $totalItems += $packages.Count
      foreach ($package in $packages) {
        if ($package.PackageName) {
          $row = $dataTable.NewRow()
          $row['Select'] = $false
          $row['Name'] = $package.PackageName
          $row['Type'] = 'Package'
          $dataTable.Rows.Add($row)
          $processedItems++
          $progressBar1.Value = [math]::Min(100, ($processedItems / $totalItems) * 100)
          $form.Refresh() 
        }
      }
    
      $capabilities = get-dismCapability
      $totalItems += $capabilities.Count
      foreach ($capability in $capabilities) {
        if ($capability.Name) {
          $row = $dataTable.NewRow()
          $row['Select'] = $false
          $row['Name'] = $capability.Name
          $row['Type'] = 'Capability'
          $dataTable.Rows.Add($row)
          $processedItems++
          $progressBar1.Value = [math]::Min(100, ($processedItems / $totalItems) * 100)
          $form.Refresh() 
        }
      }
    
      $features = get-dismFeatures
      $totalItems += $features.Count
      foreach ($feature in $features) {
        if ($feature.FeatureName) {
          $row = $dataTable.NewRow()
          $row['Select'] = $false
          $row['Name'] = $feature.FeatureName
          $row['Type'] = 'Feature'
          $dataTable.Rows.Add($row)
          $processedItems++
          $progressBar1.Value = [math]::Min(100, ($processedItems / $totalItems) * 100)
          $form.Refresh() 
        }
      }
    
        
      $dataGridView.DataSource = $dataTable
    
      $dataGridView.Columns['Select'].ReadOnly = $false
      $dataGridView.Columns['Name'].ReadOnly = $true
      $dataGridView.Columns['Type'].ReadOnly = $true
      $dataGridView.Columns['Select'].Width = 60
      $dataGridView.Columns['Name'].Width = 340
      $dataGridView.Columns['Type'].Width = 80
        

      $progressBar1.Value = 100
      $timer.Stop()
     
      $dataGridView.Refresh()
      $dataGridView.Update()
      $featuresPanel.Refresh()
      $dataGridView.ClearSelection()
      
    }
  

    $removeSelectedButton = New-Object System.Windows.Forms.Button
    $removeSelectedButton.Location = New-Object System.Drawing.Point(20, 400)
    $removeSelectedButton.Size = New-Object System.Drawing.Size(480, 30)
    $removeSelectedButton.Text = 'Remove Selected'
    $removeSelectedButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $removeSelectedButton.ForeColor = [System.Drawing.Color]::White
    $removeSelectedButton.Add_Click({
        $selectedRows = $dataGridView.Rows | Where-Object { $_.Cells['Select'].Value -eq $true }
        if ($selectedRows.Count -eq 0) {
          Write-Status -Message 'No items selected for removal.' -Type Error
          return
        }
    
        foreach ($row in $selectedRows) {
          $name = $row.Cells['Name'].Value
          $type = $row.Cells['Type'].Value
          if ($type -eq 'Package') {
            debloat-dismPackage -packageName $name
          }
          elseif ($type -eq 'Capability') {
            debloat-dismCapability -capabilityName $name
          }
          elseif ($type -eq 'Feature') {
            debloat-dismFeatures -featureName $name
          }
            
        }
        #refresh grid view
        Populate-DataGridView
      })
    $featuresPanel.Controls.Add($removeSelectedButton)

   
        
    $showLockedPackages = New-Object System.Windows.Forms.CheckBox
    $showLockedPackages.Location = New-Object System.Drawing.Point(120, 40)
    $showLockedPackages.Size = New-Object System.Drawing.Size(140, 20)
    $showLockedPackages.Text = 'Show Locked Packages'
    $showLockedPackages.ForeColor = 'White'
    $showLockedPackages.Checked = $false
    $showLockedPackages.Add_CheckedChanged({ Get-Packages -showLockedPackages $showLockedPackages.Checked })
    $appxPanel.Controls.Add($showLockedPackages)
        
    # Extras Panel
    $extrasPanel = New-Object System.Windows.Forms.Panel
    $extrasPanel.Location = New-Object System.Drawing.Point(0, 0)
    $extrasPanel.Size = New-Object System.Drawing.Size(520, 470)
    $extrasPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $extrasPanel.Visible = $false
    $contentPanel.Controls.Add($extrasPanel)

    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text = 'Win 32 Apps'
    $groupBox.Size = New-Object System.Drawing.Size(240, 290)
    $groupBox.Location = New-Object System.Drawing.Point(10, 40)
    $groupBox.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $groupBox.ForeColor = 'White'
    $extrasPanel.Controls.Add($groupBox)

    $extraSpeech = New-Object System.Windows.Forms.CheckBox
    $extraSpeech.Location = New-Object System.Drawing.Point(20, 20)
    $extraSpeech.Size = New-Object System.Drawing.Size(115, 20)
    $extraSpeech.Text = 'Speech App'
    $extraSpeech.ForeColor = 'White'
    $groupBox.Controls.Add($extraSpeech)

    $extraLiveCap = New-Object System.Windows.Forms.CheckBox
    $extraLiveCap.Location = New-Object System.Drawing.Point(20, 50)
    $extraLiveCap.Size = New-Object System.Drawing.Size(115, 20)
    $extraLiveCap.Text = 'Live Captions'
    $extraLiveCap.ForeColor = 'White'
    $groupBox.Controls.Add($extraLiveCap)

    $extraMagnifier = New-Object System.Windows.Forms.CheckBox
    $extraMagnifier.Location = New-Object System.Drawing.Point(20, 80)
    $extraMagnifier.Size = New-Object System.Drawing.Size(115, 20)
    $extraMagnifier.Text = 'Magnifier'
    $extraMagnifier.ForeColor = 'White'
    $groupBox.Controls.Add($extraMagnifier)

    $extraNarrator = New-Object System.Windows.Forms.CheckBox
    $extraNarrator.Location = New-Object System.Drawing.Point(20, 110)
    $extraNarrator.Size = New-Object System.Drawing.Size(115, 20)
    $extraNarrator.Text = 'Narrator'
    $extraNarrator.ForeColor = 'White'
    $groupBox.Controls.Add($extraNarrator)

    $extraOSK = New-Object System.Windows.Forms.CheckBox
    $extraOSK.Location = New-Object System.Drawing.Point(20, 140)
    $extraOSK.Size = New-Object System.Drawing.Size(125, 20)
    $extraOSK.Text = 'On-Screen Keyboard'
    $extraOSK.ForeColor = 'White'
    $groupBox.Controls.Add($extraOSK)

    $extraVoice = New-Object System.Windows.Forms.CheckBox
    $extraVoice.Location = New-Object System.Drawing.Point(20, 170)
    $extraVoice.Size = New-Object System.Drawing.Size(115, 20)
    $extraVoice.Text = 'Voice Access'
    $extraVoice.ForeColor = 'White'
    $groupBox.Controls.Add($extraVoice)

    $extraSteps = New-Object System.Windows.Forms.CheckBox
    $extraSteps.Location = New-Object System.Drawing.Point(20, 200)
    $extraSteps.Size = New-Object System.Drawing.Size(115, 20)
    $extraSteps.Text = 'Steps Recorder'
    $extraSteps.ForeColor = 'White'
    $groupBox.Controls.Add($extraSteps)

    $extraQuickAssist = New-Object System.Windows.Forms.CheckBox
    $extraQuickAssist.Location = New-Object System.Drawing.Point(20, 230)
    $extraQuickAssist.Size = New-Object System.Drawing.Size(115, 20)
    $extraQuickAssist.Text = 'Quick Assist'
    $extraQuickAssist.ForeColor = 'White'
    $groupBox.Controls.Add($extraQuickAssist)

    $extraMathInput = New-Object System.Windows.Forms.CheckBox
    $extraMathInput.Location = New-Object System.Drawing.Point(20, 260)
    $extraMathInput.Size = New-Object System.Drawing.Size(115, 20)
    $extraMathInput.Text = 'Math Input Panel'
    $extraMathInput.ForeColor = 'White'
    $groupBox.Controls.Add($extraMathInput)

    $label4 = New-Object System.Windows.Forms.Label
    $label4.Location = New-Object System.Drawing.Point(10, 10)
    $label4.Size = New-Object System.Drawing.Size(200, 20)
    $label4.Text = 'Extras'
    $label4.ForeColor = 'White'
    $label4.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $extrasPanel.Controls.Add($label4)

    $groupBox2 = New-Object System.Windows.Forms.GroupBox
    $groupBox2.Text = 'Misc'
    $groupBox2.Size = New-Object System.Drawing.Size(240, 230)
    $groupBox2.Location = New-Object System.Drawing.Point(260, 40)
    $groupBox2.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $groupBox2.ForeColor = 'White'
    $extrasPanel.Controls.Add($groupBox2)

    $extraEdge = New-Object System.Windows.Forms.CheckBox
    $extraEdge.Location = New-Object System.Drawing.Point(20, 20)
    $extraEdge.Size = New-Object System.Drawing.Size(115, 20)
    $extraEdge.Text = 'Microsoft Edge'
    $extraEdge.ForeColor = 'White'
    $groupBox2.Controls.Add($extraEdge)

    $extraWebview = New-Object System.Windows.Forms.CheckBox
    $extraWebview.Location = New-Object System.Drawing.Point(135, 20)
    $extraWebview.Size = New-Object System.Drawing.Size(100, 20)
    $extraWebview.Text = 'Edge WebView'
    $extraWebview.ForeColor = 'White'
    $groupBox2.Controls.Add($extraWebview)

    $extraTeamsOneDrive = New-Object System.Windows.Forms.CheckBox
    $extraTeamsOneDrive.Location = New-Object System.Drawing.Point(20, 50)
    $extraTeamsOneDrive.Size = New-Object System.Drawing.Size(150, 20)
    $extraTeamsOneDrive.Text = 'Teams and OneDrive'
    $extraTeamsOneDrive.ForeColor = 'White'
    $groupBox2.Controls.Add($extraTeamsOneDrive)

    $extraUpdateTools = New-Object System.Windows.Forms.CheckBox
    $extraUpdateTools.Location = New-Object System.Drawing.Point(20, 80)
    $extraUpdateTools.Size = New-Object System.Drawing.Size(150, 20)
    $extraUpdateTools.Text = 'Windows Update Tools'
    $extraUpdateTools.ForeColor = 'White'
    $groupBox2.Controls.Add($extraUpdateTools)

    $extraRemoveRemote = New-Object System.Windows.Forms.CheckBox
    $extraRemoveRemote.Location = New-Object System.Drawing.Point(20, 110)
    $extraRemoveRemote.Size = New-Object System.Drawing.Size(170, 20)
    $extraRemoveRemote.Text = 'Remote Desktop Connection'
    $extraRemoveRemote.ForeColor = 'White'
    $groupBox2.Controls.Add($extraRemoveRemote)

    $extraStartMenu = New-Object System.Windows.Forms.CheckBox
    $extraStartMenu.Location = New-Object System.Drawing.Point(20, 140)
    $extraStartMenu.Size = New-Object System.Drawing.Size(200, 20)
    $extraStartMenu.Text = 'Clean Start Menu Icons'
    $extraStartMenu.ForeColor = 'White'
    $groupBox2.Controls.Add($extraStartMenu)

    $applyExtras = New-Object System.Windows.Forms.Button
    $applyExtras.Location = New-Object System.Drawing.Point(20, 350)
    $applyExtras.Size = New-Object System.Drawing.Size(480, 30)
    $applyExtras.Text = 'Apply Extras'
    $applyExtras.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $applyExtras.ForeColor = [System.Drawing.Color]::White
    $applyExtras.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $extrasPanel.Controls.Add($applyExtras)



       
    #GLOBAL VARS
    $Global:logos = [System.Collections.Hashtable]::new()
    # $Global:Bloatware = @()
    $customCheckedListBox = [CustomCheckedListBox]::new()
    $Global:noLogoPath = Search-File '*1X1.png'
    $Global:sortedPackages = @()
  
   
    $customCheckedListBox.Location = New-Object System.Drawing.Point(20, 70)
    $customCheckedListBox.Size = New-Object System.Drawing.Size(480, 350)
    $customCheckedListBox.BackColor = 'Black'
    $customCheckedListBox.ForeColor = 'White'
    $customCheckedListBox.CheckOnClick = $true
    $appxPanel.Controls.Add($customCheckedListBox)
    Get-Packages -showLockedPackages $false
    [CustomCheckedListBox]::logos = $Global:logos


    # Sidebar Button Click Events
    $presetsBtn.Add_Click({
        $presetsPanel.Visible = $true
        $appxPanel.Visible = $false
        $featuresPanel.Visible = $false
        $extrasPanel.Visible = $false
        $presetsBtn.Tag = 'Active'
        $appxBtn.Tag = 'Inactive'
        $featuresBtn.Tag = 'Inactive'
        $extrasBtn.Tag = 'Inactive'
        $presetsBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
        $appxBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $featuresBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $extrasBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
      })

    $appxBtn.Add_Click({
        $presetsPanel.Visible = $false
        $appxPanel.Visible = $true
        $featuresPanel.Visible = $false
        $extrasPanel.Visible = $false
        $presetsBtn.Tag = 'Inactive'
        $appxBtn.Tag = 'Active'
        $featuresBtn.Tag = 'Inactive'
        $extrasBtn.Tag = 'Inactive'
        $presetsBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $appxBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
        $featuresBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $extrasBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        Get-Packages -showLockedPackages $showLockedPackages.Checked
      })

    $featuresBtn.Add_Click({
        $progressBar1.Visible = $true
        $labelLoading.Visible = $true
        $presetsPanel.Visible = $false
        $appxPanel.Visible = $false
        $featuresPanel.Visible = $true
        $extrasPanel.Visible = $false
        $presetsBtn.Tag = 'Inactive'
        $appxBtn.Tag = 'Inactive'
        $featuresBtn.Tag = 'Active'
        $extrasBtn.Tag = 'Inactive'
        $presetsBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $appxBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $featuresBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
        $extrasBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        Populate-DataGridView
        $progressBar1.Visible = $false
        $labelLoading.Visible = $false
      })

    $extrasBtn.Add_Click({
        $presetsPanel.Visible = $false
        $appxPanel.Visible = $false
        $featuresPanel.Visible = $false
        $extrasPanel.Visible = $true
        $presetsBtn.Tag = 'Inactive'
        $appxBtn.Tag = 'Inactive'
        $featuresBtn.Tag = 'Inactive'
        $extrasBtn.Tag = 'Active'
        $presetsBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $appxBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $featuresBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $extrasBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
      })

    # Set initial active state for Debloat Presets
    $presetsBtn.Tag = 'Active'
    $presetsBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
   
    $result = $form.ShowDialog()
  }


  
  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    if (!($Autorun)) {
      #loop through checkbox hashtable to update config
      $settings.GetEnumerator() | ForEach-Object {
      
        $setting = $_.Key
        $settingFullName = $_.Value
  
        if ($comboBoxPresets.SelectedItem -eq $settingFullName) {
          update-config -setting $setting -value 1
        }
      }
    }  
  
    if ($applyPreset.Tag -eq 'True') {
      if ($comboBoxPresets.SelectedIndex -eq 0) {
          
        debloatPreset -choice 'debloatAll'
        Write-Status -Message 'Removing Teams and One Drive' -Type Output
        debloat-TeamsOneDrive
        Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
        debloat-remotedesktop
        debloat-HealthUpdateTools
        Write-Status -Message 'Uninstalling Edge...' -Type Output
        $edge = Search-File '*EdgeRemove.ps1'
        &$edge -Webview
        Write-Status -Message 'Cleaning Start Menu...' -Type Output
        $unpin = Search-File '*unpin.ps1'
        & $unpin
      }
      if ($comboBoxPresets.SelectedIndex -eq 1) {
     
      
        debloatPreset -choice 'debloatKeepStoreXbox'
        Write-Status -Message 'Removing Teams and One Drive' -Type Output
        debloat-TeamsOneDrive
        debloat-HealthUpdateTools
        Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
        debloat-remotedesktop
        Write-Status -Message 'Cleaning Start Menu...' -Type Output
        $unpin = Search-File '*unpin.ps1'
        & $unpin
  
      }
      if ($comboBoxPresets.SelectedIndex -eq 2) {
  
     
        debloatPreset -choice 'debloatKeepStoreXbox'
        Write-Status -Message 'Removing Teams and One Drive' -Type Output
        debloat-TeamsOneDrive
        debloat-HealthUpdateTools
        Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
        debloat-remotedesktop
        Write-Status -Message 'Uninstalling Edge...' -Type Output
        $edge = Search-File '*EdgeRemove.ps1'
        &$edge
        Write-Status -Message 'Cleaning Start Menu...' -Type Output
        $unpin = Search-File '*unpin.ps1'
        & $unpin     
      
      }
      if ($comboBoxPresets.SelectedIndex -eq 3) {
        debloatPreset -choice 'debloatAll'
        Write-Status -Message 'Removing Teams and One Drive' -Type Output
        debloat-TeamsOneDrive
        Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
        debloat-remotedesktop
        debloat-HealthUpdateTools
        Write-Status -Message 'Cleaning Start Menu...' -Type Output
        $unpin = Search-File '*unpin.ps1'
        & $unpin
  
      }
      if ($comboBoxPresets.SelectedIndex -eq 4) { 
    
     
        debloatPreset -choice 'debloatKeepStore'
        Write-Status -Message 'Removing Teams and One Drive' -Type Output
        debloat-TeamsOneDrive
        debloat-HealthUpdateTools
        Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
        debloat-remotedesktop
        Write-Status -Message 'Uninstalling Edge...' -Type Output
        $edge = Search-File '*EdgeRemove.ps1'
        &$edge
        Write-Status -Message 'Cleaning Start Menu...' -Type Output
        $unpin = Search-File '*unpin.ps1'
        & $unpin
  
      }

    }
    


    #------------------------- debloat extras

    if ($extraEdge.Checked) {
      if ($extraWebview.Checked) {
        Write-Status -Message 'Uninstalling Edge && WebView...' -Type Output
        $edge = Search-File '*EdgeRemove.ps1'
        &$edge -Webview
      }
      else {
        Write-Status -Message 'Uninstalling Edge...' -Type Output
        $edge = Search-File '*EdgeRemove.ps1'
        &$edge
      }
    }

    if ($extraTeamsOneDrive.Checked) {
      Write-Status -Message 'Removing Teams and One Drive' -Type Output
      debloat-TeamsOneDrive
    }

    if ($extraUpdateTools.Checked) {
      Write-Status -Message 'Removing Windows Update Tools' -Type Output
      debloat-HealthUpdateTools
    }

    if ($extraRemoveRemote.Checked) {
      Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
      debloat-remotedesktop
    }

    if ($extraStartMenu.Checked) {
      Write-Status -Message 'Cleaning Start Menu...' -Type Output
      $unpin = Search-File '*unpin.ps1'
      & $unpin
    }

    if ($extraSpeech.Checked) {
      debloat-Win32Apps -appName speech
    }

    if ($extraLiveCap.Checked) {
      debloat-Win32Apps -appName livecaptions
    }
    
    if ($extraMagnifier.Checked) {
      debloat-Win32Apps -appName magnifier
    }

    if ($extraNarrator.Checked) {
      debloat-Win32Apps -appName Narrator
    }

    if ($extraOSK.Checked) {
      debloat-Win32Apps -appName osk
    }

    if ($extraVoice.Checked) {
      debloat-Win32Apps -appName voiceaccess
    }

    if ($extraSteps.Checked) {
      debloat-Win32Apps -appName stepsrecorder
    }

    if ($extraQuickAssist.Checked) {
      debloat-Win32Apps -appName QuickAssist
    }

    if ($extraMathInput.Checked) {
      debloat-Win32Apps -appName MathInput
    }

    if (!($Autorun)) {
      #replace message box
      Custom-MsgBox -message 'Bloat Removed!' -type None
    }
     
  }
}
Export-ModuleMember -Function debloat


function disable-services {
  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
    # ,[Parameter(mandatory=$false)] $setting 
  )



  if ($Autorun) {
    $msgBoxInput = 'OK'
  }
  else {
    $msgBoxInput = Custom-MsgBox -message 'Do you want to disable Bluetooth, Printing and others?' -type Question
  }
  
  
  switch ($msgBoxInput) {
  
    'OK' {
      if (!($Autorun)) {
        #update config
        update-config -setting 'disableServices' -value 1
      }
      
      #disables some unecessary services 
      Write-Status -Message 'Disabling Services...' -Type Output
      Write-Host '    BTAGService,
    BthAvctpSvc,
    bthserv,
    BluetoothUserService,
    Fax,
    Spooler,
    PrintWorkflowUserSvc,
    PrintNotify,
    shpamsvc,
    RemoteRegistry,
    PhoneSvc,
    defragsvc,
    DoSvc,
    RmSvc,
    wisvc,
    TabletInputService,
    diagsvc,
    DPS,
    WdiServiceHost,
    WdiSystemHost,
    AssignedAccessManagerSvc,
    MapsBroker,
    lfsvc,
    Netlogon,
    WpcMonSvc,
    SCardSvr,
    ScDeviceEnum,
    SCPolicySvc,
    WbioSrvc,
    WalletService' -ForegroundColor Cyan
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\BTAGService' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\BthAvctpSvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\bthserv' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\Fax' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\Spooler' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\PrintNotify' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\shpamsvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\defragsvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\RmSvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\wisvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\diagsvc' /v 'Start' /t REG_DWORD /d '4' /f
      $command = "Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DPS' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WdiServiceHost' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WdiSystemHost' /v 'Start' /t REG_DWORD /d '4' /f"
      Run-Trusted -command $command
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\AssignedAccessManagerSvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\lfsvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WpcMonSvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\SCardSvr' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\ScDeviceEnum' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\SCPolicySvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\WalletService' /v 'Start' /t REG_DWORD /d '4' /f

  
      if (!($Autorun)) {
        Custom-MsgBox -message 'Services Disabled!' -type None
      }
  
    }
  
    'Cancel' {}
  
  }
  
}
Export-ModuleMember -Function disable-services








function gpTweaks {

  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
    , [Parameter(mandatory = $false)] [bool]$gpDefender = $false
    , [Parameter(mandatory = $false)] [bool]$gpUpdates = $false
    , [Parameter(mandatory = $false)] [bool]$gpTel = $false
  )




  $checkbox1 = New-Object System.Windows.Forms.CheckBox
  $checkbox2 = New-Object System.Windows.Forms.CheckBox
  $checkbox3 = New-Object System.Windows.Forms.CheckBox
  

 
  #hashtable to loop through
  $settings = @{}
  $settings['gpUpdates'] = $checkbox1
  $settings['gpDefender'] = $checkbox2
  $settings['gpTel'] = $checkbox3

  if ($Autorun) {
    $result = [System.Windows.Forms.DialogResult]::OK
    $checkbox1.Checked = $gpUpdates
    $checkbox2.Checked = $gpDefender
    $checkbox3.Checked = $gpTel
  }
  else {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Group Policy Tweaks'
    $form.Size = New-Object System.Drawing.Size(300, 200)
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)
    
    # Create the checkboxes
    
    $checkbox1.Text = 'Disable Updates'
    $checkbox1.Location = New-Object System.Drawing.Point(20, 20)
    $checkbox1.ForeColor = 'White'
    $checkbox1.AutoSize = $true
    $form.Controls.Add($checkbox1)
    
    
    $checkbox2.Text = 'Disable Defender'
    $checkbox2.Location = New-Object System.Drawing.Point(20, 50)
    $checkbox2.ForeColor = 'White'
    $checkbox2.AutoSize = $true
    $form.Controls.Add($checkbox2)
    
    
    $checkbox3.Text = 'Disable Telemetry'
    $checkbox3.Location = New-Object System.Drawing.Point(20, 80)
    $checkbox3.ForeColor = 'White'
    $checkbox3.AutoSize = $true
    $form.Controls.Add($checkbox3)
    
    
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(70, 140)
    $OKButton.Size = New-Object System.Drawing.Size(75, 23)
    $OKButton.Text = 'OK'
    $OKButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $OKButton.ForeColor = [System.Drawing.Color]::White
    #$OKButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$OKButton.FlatAppearance.BorderSize = 0
    #$OKButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$OKButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)
  
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(150, 140)
    $CancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $CancelButton.ForeColor = [System.Drawing.Color]::White
    #$CancelButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$CancelButton.FlatAppearance.BorderSize = 0
    #$CancelButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$CancelButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)
    
    
    # Show the form and wait for user input
    $result = $form.ShowDialog()
  }
  
  
  # Check the selected checkboxes
  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    
    if (!($Autorun)) {
      #loop through checkbox hashtable to update config
      $settings.GetEnumerator() | ForEach-Object {
      
        $settingName = $_.Key
        $checkbox = $_.Value
  
        if ($checkbox.Checked) {
          update-config -setting $settingName -value 1
        }
      }

    }

    if ($checkbox1.Checked) {
      Write-Status -Message 'Disabling Updates...' -Type Output
      #disables updates through gp edit and servives
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetProxyBehaviorForUpdateDetection' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetDisableUXWUAccess' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAutoUpdate' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'UseWUServer' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc' /v 'Start' /t REG_DWORD /d '4' /f 
      Reg.exe add 'HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' /v 'DownloadMode' /t REG_DWORD /d '0' /f
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\WindowsUpdate\Scheduled Start' -Erroraction SilentlyContinue
      
   
  
    }
  
  
    if ($checkbox2.Checked) {
      #reg files
      $file1 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=dword:00000001
"ServiceKeepAlive"=dword:00000000
"AllowFastServiceStartup"=dword:00000000
"DisableLocalAdminMerge"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
"LocalSettingOverrideDisableOnAccessProtection"=dword:00000000
"LocalSettingOverrideRealtimeScanDirection"=dword:00000000
"LocalSettingOverrideDisableIOAVProtection"=dword:00000000
"LocalSettingOverrideDisableBehaviorMonitoring"=dword:00000000
"LocalSettingOverrideDisableIntrusionPreventionSystem"=dword:00000000
"LocalSettingOverrideDisableRealtimeMonitoring"=dword:00000000
"DisableIOAVProtection"=dword:00000001
"DisableRealtimeMonitoring"=dword:00000001
"DisableBehaviorMonitoring"=dword:00000001
"DisableOnAccessProtection"=dword:00000001
"DisableScanOnRealtimeEnable"=dword:00000001
"RealtimeScanDirection"=dword:00000002
"DisableInformationProtectionControl"=dword:00000001
"DisableIntrusionPreventionSystem"=dword:00000001
"DisableRawWriteNotification"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=dword:00000001
'@
      $file2 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIOAVProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender]
"PUAProtection"=dword:00000000
"DisableRoutinelyTakingAction"=dword:00000001
"ServiceKeepAlive"=dword:00000000
"AllowFastServiceStartup"=dword:00000000
"DisableLocalAdminMerge"=dword:00000001
"DisableAntiSpyware"=dword:00000001
"RandomizeScheduleTaskTimes"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowArchiveScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowBehaviorMonitoring]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowCloudProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowEmailScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanOnMappedNetworkDrives]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowFullScanRemovableDriveScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowIntrusionPreventionSystem]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowOnAccessProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowRealtimeMonitoring]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScanningNetworkFiles]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowScriptScanning]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\AllowUserUIAccess]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\CheckForSignaturesBeforeRunningScan]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\CloudBlockLevel]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\CloudExtendedTimeout]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\DaysToRetainCleanedMalware]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupFullScan]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\DisableCatchupQuickScan]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableControlledFolderAccess]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableLowCPUPriority]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\EnableNetworkProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\PUAProtection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\RealTimeScanDirection]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScanParameter]
"value"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScheduleScanDay]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\ScheduleScanTime]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\SignatureUpdateInterval]
"value"=dword:00000018

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Defender\SubmitSamplesConsent]
"value"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions]
"DisableAutoExclusions"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine]
"MpEnablePus"=dword:00000000
"MpCloudBlockLevel"=dword:00000000
"MpBafsExtendedTimeout"=dword:00000000
"EnableFileHashComputation"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS]
"ThrottleDetectionEventsRate"=dword:00000000
"DisableSignatureRetirement"=dword:00000001
"DisableProtocolRecognition"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager]
"DisableScanningNetworkFiles"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection]
"DisableRealtimeMonitoring"=dword:00000001
"DisableBehaviorMonitoring"=dword:00000001
"DisableOnAccessProtection"=dword:00000001
"DisableScanOnRealtimeEnable"=dword:00000001
"DisableIOAVProtection"=dword:00000001
"LocalSettingOverrideDisableOnAccessProtection"=dword:00000000
"LocalSettingOverrideRealtimeScanDirection"=dword:00000000
"LocalSettingOverrideDisableIOAVProtection"=dword:00000000
"LocalSettingOverrideDisableBehaviorMonitoring"=dword:00000000
"LocalSettingOverrideDisableIntrusionPreventionSystem"=dword:00000000
"LocalSettingOverrideDisableRealtimeMonitoring"=dword:00000000
"RealtimeScanDirection"=dword:00000002
"IOAVMaxSize"=dword:00000512
"DisableInformationProtectionControl"=dword:00000001
"DisableIntrusionPreventionSystem"=dword:00000001
"DisableRawWriteNotification"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan]
"LowCpuPriority"=dword:00000001
"DisableRestorePoint"=dword:00000001
"DisableArchiveScanning"=dword:00000000
"DisableScanningNetworkFiles"=dword:00000000
"DisableCatchupFullScan"=dword:00000000
"DisableCatchupQuickScan"=dword:00000001
"DisableEmailScanning"=dword:00000000
"DisableHeuristics"=dword:00000001
"DisableReparsePointScanning"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates]
"SignatureDisableNotification"=dword:00000001
"RealtimeSignatureDelivery"=dword:00000000
"ForceUpdateFromMU"=dword:00000000
"DisableScheduledSignatureUpdateOnBattery"=dword:00000001
"UpdateOnStartUp"=dword:00000000
"SignatureUpdateCatchupInterval"=dword:00000002
"DisableUpdateOnStartupWithoutEngine"=dword:00000001
"ScheduleTime"=dword:00001440
"DisableScanOnUpdate"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet]
"DisableBlockAtFirstSeen"=dword:00000001
"LocalSettingOverrideSpynetReporting"=dword:00000000
"SpynetReporting"=dword:00000000
"SubmitSamplesConsent"=dword:00000002

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\UX Configuration]
"SuppressRebootNotification"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access]
"EnableControlledFolderAccess"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection]
"EnableNetworkProtection"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows Defender]
"DisableRoutinelyTakingAction"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware]
"ServiceKeepAlive"=dword:00000000
"AllowFastServiceStartup"=dword:00000000
"DisableRoutinelyTakingAction"=dword:00000001
"DisableAntiSpyware"=dword:00000001
"DisableAntiVirus"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Microsoft Antimalware\SpyNet]
"SpyNetReporting"=dword:00000000
"LocalSettingOverrideSpyNetReporting"=dword:00000000

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting]
"DisableEnhancedNotifications"=dword:00000001
"DisableGenericRePorts"=dword:00000001
"WppTracingLevel"=dword:00000000
"WppTracingComponents"=dword:00000000

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy]
"VerifiedAndReputablePolicyState"=dword:00000000
'@
      $file3 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableEnhancedNotifications]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\DisableNotifications]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\WindowsDefenderSecurityCenter\HideWindowsSecurityNotificationAreaControl]
"value"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center]
"FirstRunDisabled"=dword:00000001
"AntiVirusOverride"=dword:00000001
"FirewallOverride"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications]
"DisableEnhancedNotifications"=dword:00000001
"DisableNotifications"=dword:00000001

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance]
"Enabled"=dword:00000000
'@
      $file5 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\Software\Classes\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}]

[-HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}]

[-HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_CLASSES_ROOT\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}]

[-HKEY_CLASSES_ROOT\CLSID\{2781761E-28E2-4109-99FE-B9D127C57AFE}]

[-HKEY_CLASSES_ROOT\CLSID\{195B4D07-3DE2-4744-BBF2-D90121AE785B}]

[-HKEY_CLASSES_ROOT\CLSID\{361290c0-cb1b-49ae-9f3e-ba1cbe5dab35}]

[-HKEY_CLASSES_ROOT\CLSID\{45F2C32F-ED16-4C94-8493-D72EF93A051B}]

[-HKEY_CLASSES_ROOT\CLSID\{6CED0DAA-4CDE-49C9-BA3A-AE163DC3D7AF}]

[-HKEY_CLASSES_ROOT\CLSID\{8a696d12-576b-422e-9712-01b9dd84b446}]

[-HKEY_CLASSES_ROOT\CLSID\{8C9C0DB7-2CBA-40F1-AFE0-C55740DD91A0}]

[-HKEY_CLASSES_ROOT\CLSID\{A2D75874-6750-4931-94C1-C99D3BC9D0C7}]

[-HKEY_CLASSES_ROOT\CLSID\{A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}]

[-HKEY_CLASSES_ROOT\CLSID\{DACA056E-216A-4FD1-84A6-C306A017ECEC}]

[-HKEY_CLASSES_ROOT\CLSID\{E3C9166D-1D39-4D4E-A45D-BC7BE9B00578}]

[-HKEY_CLASSES_ROOT\CLSID\{F6976CF5-68A8-436C-975A-40BE53616D59}]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger]
'@
      $file6 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0ACC9108-2000-46C0-8407-5FD9F89521E8}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{1D77BCC8-1D07-42D0-8C89-3A98674DFB6F}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4A9233DB-A7D3-45D6-B476-8C7D8DF73EB5}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{B05F34EE-83F2-413D-BC1D-7D5BD6E98300}]
'@
      $file7 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecCore]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wscsvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdFilter]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdBoot]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefusersvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\webthreatdefsvc]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmAgent]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SgrmBroker]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection]
"DisallowExploitProtectionOverride"=dword:00000001

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecFlt]

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MsSecWfp]
'@
      $file8 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend]

[-HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\windowsdefender]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppUserModelId\Windows.Defender]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\AppUserModelId\Microsoft.Windows.Defender]

[-HKEY_CLASSES_ROOT\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0]

[-HKEY_CURRENT_USER\Software\Classes\ms-cxh]

[-HKEY_CLASSES_ROOT\Local Settings\MrtCache\C:%5CWindows%5CSystemApps%5CMicrosoft.Windows.AppRep.ChxApp_cw5n1h2txyewy%5Cresources.pri]

[-HKEY_CLASSES_ROOT\WindowsDefender]

[-HKEY_CURRENT_USER\Software\Classes\AppX9kvz3rdv8t7twanaezbwfcdgrbg3bck0]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WindowsDefender]

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Ubpm]
"CriticalMaintenance_DefenderCleanup"=-
"CriticalMaintenance_DefenderVerification"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Ubpm]
"CriticalMaintenance_DefenderCleanup"=-
"CriticalMaintenance_DefenderVerification"=-

[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System]
"WindowsDefender-1"=-
"WindowsDefender-2"=-
"WindowsDefender-3"=-

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System]
"WindowsDefender-1"=-
"WindowsDefender-2"=-
"WindowsDefender-3"=-
'@
      $file9 = @'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Signature Updates]
"SignatureDisableNotification"=dword:00000001
"RealtimeSignatureDelivery"=dword:00000000
"ForceUpdateFromMU"=dword:00000000
"DisableScheduledSignatureUpdateOnBattery"=dword:00000001
"UpdateOnStartUp"=dword:00000000
"SignatureUpdateCatchupInterval"=dword:00000002
"DisableUpdateOnStartupWithoutEngine"=dword:00000001
"ScheduleTime"=dword:00001440
"DisableScanOnUpdate"=dword:00000001
'@
      $file10 = @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"Windows Defender"=-
"SecurityHealth"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run]
"Windows Defender"=-
"SecurityHealth"=-

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"WindowsDefender"=-
"SecurityHealth"=-
'@
      $file11 = @'
Windows Registry Editor Version 5.00

[-HKEY_CLASSES_ROOT\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Classes\WOW6432Node\CLSID\{E48B2549-D510-4A76-8A5F-FC126A6215F0}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Service.UserSessionServiceManager]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatExperienceManager.ThreatExperienceManager]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.ThreatResponseEngine.ThreatDecisionEngine]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Microsoft.OneCore.WebThreatDefense.Configuration.WTDUserSettings]
'@
      $file12 = @'
Windows Registry Editor Version 5.00

[-HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{900c0763-5cad-4a34-bc1f-40cd513679d5}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects\{900c0763-5cad-4a34-bc1f-40cd513679d5}]

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender]

[-HKEY_CLASSES_ROOT\Folder\shell\WindowsDefender]

[-HKEY_CLASSES_ROOT\DesktopBackground\Shell\WindowsSecurity]

[-HKEY_CLASSES_ROOT\Folder\shell\WindowsDefender\Command]
'@

      
      #refactor of https://github.com/AveYo/LeanAndMean/blob/main/disableDefender.ps1
      $code = @'
function defeatMsMpEng {
    
$key = 'Registry::HKU\S-1-5-21-*\Volatile Environment'
    
# Define types and modules
$I = [int32]
$M = $I.module.GetType("System.Runtime.InteropServices.Marshal")
$P = $I.module.GetType("System.IntPtr")
$S = [string]
$D = @()
$DM = [AppDomain]::CurrentDomain.DefineDynamicAssembly(1, 1).DefineDynamicModule(1)
$U = [uintptr]
$Z = [uintptr]::Size

# Define dynamic types
0..5 | ForEach-Object { $D += $DM.DefineType("AveYo_$_", 1179913, [ValueType]) }
$D += $U
4..6 | ForEach-Object { $D += $D[$_].MakeByRefType() }

# Define PInvoke methods
$F = @(
    'kernel', 'CreateProcess', ($S, $S, $I, $I, $I, $I, $I, $S, $D[7], $D[8]),
    'advapi', 'RegOpenKeyEx', ($U, $S, $I, $I, $D[9]),
    'advapi', 'RegSetValueEx', ($U, $S, $I, $I, [byte[]], $I),
    'advapi', 'RegFlushKey', ($U),
    'advapi', 'RegCloseKey', ($U)
)
0..4 | ForEach-Object { $9 = $D[0].DefinePInvokeMethod($F[3 * $_ + 1], $F[3 * $_] + "32", 8214, 1, $S, $F[3 * $_ + 2], 1, 4) }

# Define fields
$DF = @(
    ($P, $I, $P),
    ($I, $I, $I, $I, $P, $D[1]),
    ($I, $S, $S, $S, $I, $I, $I, $I, $I, $I, $I, $I, [int16], [int16], $P, $P, $P, $P),
    ($D[3], $P),
    ($P, $P, $I, $I)
)
1..5 | ForEach-Object { $k = $_; $n = 1; $DF[$_ - 1] | ForEach-Object { $9 = $D[$k].DefineField("f" + $n++, $_, 6) } }

# Create types
$T = @()
0..5 | ForEach-Object { $T += $D[$_].CreateType() }

# Create instances
0..5 | ForEach-Object { New-Variable -Name "A$_" -Value ([Activator]::CreateInstance($T[$_])) -Force }

# Define functions
function F ($1, $2) { $T[0].GetMethod($1).Invoke(0, $2) }
function M ($1, $2, $3) { $M.GetMethod($1, [type[]]$2).Invoke(0, $3) }

# Allocate memory
$H = @()
$Z, (4 * $Z + 16) | ForEach-Object { $H += M "AllocHGlobal" $I $_ }

# Check user and start service if necessary
if ([environment]::username -ne "system") {
    $TI = "TrustedInstaller"
    Start-Service $TI -ErrorAction SilentlyContinue
    $As = Get-Process -Name $TI -ErrorAction SilentlyContinue
    M "WriteIntPtr" ($P, $P) ($H[0], $As.Handle)
    $A1.f1 = 131072
    $A1.f2 = $Z
    $A1.f3 = $H[0]
    $A2.f1 = 1
    $A2.f2 = 1
    $A2.f3 = 1
    $A2.f4 = 1
    $A2.f6 = $A1
    $A3.f1 = 10 * $Z + 32
    $A4.f1 = $A3
    $A4.f2 = $H[1]
    M "StructureToPtr" ($D[2], $P, [boolean]) (($A2 -as $D[2]), $A4.f2, $false)
    $R = @($null, "powershell -nop -c iex(`$env:R); # $id", 0, 0, 0, 0x0E080610, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
    F 'CreateProcess' $R
    return
}

# Clear environment variable
$env:R = ''
Remove-ItemProperty -Path $key -Name $id -Force -ErrorAction SilentlyContinue

# Set privileges
$e = [diagnostics.process].GetMember('SetPrivilege', 42)[0]
'SeSecurityPrivilege', 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege' | ForEach-Object { $e.Invoke($null, @("$_", 2)) }

# Define function to set registry DWORD values
function RegSetDwords ($hive, $key, [array]$values, [array]$dword, $REG_TYPE = 4, $REG_ACCESS = 2, $REG_OPTION = 0) {
    $rok = ($hive, $key, $REG_OPTION, $REG_ACCESS, ($hive -as $D[9]))
    F "RegOpenKeyEx" $rok
    $rsv = $rok[4]
    $values | ForEach-Object { $i = 0 } { F "RegSetValueEx" ($rsv[0], [string]$_, 0, $REG_TYPE, [byte[]]($dword[$i]), 4); $i++ }
    F "RegFlushKey" @($rsv)
    F "RegCloseKey" @($rsv)
    $rok = $null
    $rsv = $null
}


 
    $disable = 1
    $disable_rev = 0
    $disable_SMARTSCREENFILTER = 1
    #stop security center and defender commandline exe
    stop-service 'wscsvc' -force -ErrorAction SilentlyContinue *>$null
    Stop-Process -name 'OFFmeansOFF', 'MpCmdRun' -force -ErrorAction SilentlyContinue
 
    $HKLM = [uintptr][uint32]2147483650 
    $VALUES = 'ServiceKeepAlive', 'PreviousRunningMode', 'IsServiceRunning', 'DisableAntiSpyware', 'DisableAntiVirus', 'PassiveMode'
    $DWORDS = 0, 0, 0, $disable, $disable, $disable
    #apply registry values (not all will apply)
    RegSetDwords $HKLM 'SOFTWARE\Policies\Microsoft\Windows Defender' $VALUES $DWORDS 
    RegSetDwords $HKLM 'SOFTWARE\Microsoft\Windows Defender' $VALUES $DWORDS
    [GC]::Collect() 
    Start-Sleep 1
    #run defender command line to disable msmpeng service
    Push-Location "$env:programfiles\Windows Defender"
    $mpcmdrun = ('OFFmeansOFF.exe', 'MpCmdRun.exe')[(test-path 'MpCmdRun.exe')]
    Start-Process -wait $mpcmdrun -args '-DisableService -HighPriority'
    #wait for service to close before continuing
    $wait = 14
    while ((get-process -name 'MsMpEng' -ea 0) -and $wait -gt 0) { 
        $wait--
        Start-Sleep 1
    }
 
    #rename defender commandline exe
    $location = split-path $(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend' ImagePath -ErrorAction SilentlyContinue).ImagePath.Trim('"')
    Push-Location $location
    Rename-Item MpCmdRun.exe -NewName 'OFFmeansOFF.exe' -force -ErrorAction SilentlyContinue
 
    #cleanup scan history
    Remove-Item "$env:ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db" -force -ErrorAction SilentlyContinue
    Remove-Item "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service" -recurse -force -ErrorAction SilentlyContinue

    #apply keys that are blocked when msmpeng is running
    RegSetDwords $HKLM 'SOFTWARE\Policies\Microsoft\Windows Defender' $VALUES $DWORDS 
    RegSetDwords $HKLM 'SOFTWARE\Microsoft\Windows Defender' $VALUES $DWORDS

    #disable smartscreen
    if ($disable_SMARTSCREENFILTER) {
        Set-ItemProperty 'HKLM:\CurrentControlSet\Control\CI\Policy' 'VerifiedAndReputablePolicyState' 0 -type Dword -force -ErrorAction SilentlyContinue
        Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' 'SmartScreenEnabled' 'Off' -force -ErrorAction SilentlyContinue 
        Get-Item Registry::HKEY_Users\S-1-5-21*\Software\Microsoft -ea 0 | ForEach-Object {
            Set-ItemProperty "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'EnableWebContentEvaluation' $disable_rev -type Dword -force -ErrorAction SilentlyContinue
            Set-ItemProperty "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'PreventOverride' $disable_rev -type Dword -force -ErrorAction SilentlyContinue
            New-Item "$($_.PSPath)\Edge\SmartScreenEnabled" -ErrorAction SilentlyContinue *>$null
            Set-ItemProperty "$($_.PSPath)\Edge\SmartScreenEnabled" '(Default)' $disable_rev -ErrorAction SilentlyContinue
        }
        if ($disable_rev -eq 0) { 
            Stop-Process -name smartscreen -force -ErrorAction SilentlyContinue
        }
    }

}
defeatMsMpEng
'@
      $script = New-Item "$env:TEMP\DefeatDefend.ps1" -Value $code -Force
      $run = "Start-Process powershell.exe -ArgumentList `"-executionpolicy bypass -File $($script.FullName) -Verb runas`""

      Write-Status -Message 'Running Initial Stage...' -Type Output

      #disable notifications and others that are allowed while defender is running
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableEnhancedNotifications' /t REG_DWORD /d '1' /f *>$null
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications' /v 'DisableNotifications' /t REG_DWORD /d '1' /f *>$null
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'SummaryNotificationDisabled' /t REG_DWORD /d '1' /f *>$null
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'NoActionNotificationDisabled' /t REG_DWORD /d '1' /f *>$null
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender Security Center\Virus and threat protection' /v 'FilesBlockedNotificationDisabled' /t REG_DWORD /d '1' /f *>$null
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance' /v 'Enabled' /t REG_DWORD /d '0' /f *>$null
      #exploit protection
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel' /v 'MitigationOptions' /t REG_BINARY /d '222222000001000000000000000000000000000000000000' /f *>$null
      Run-Trusted -command "Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows Defender' /v 'PUAProtection' /t REG_DWORD /d '0' /f"
      Run-Trusted -command "Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'SmartScreenEnabled' /t REG_SZ /d 'Off' /f"



      Write-Status -Message 'Disabling Defender with Registry Hacks...'  -Type Output
      $scriptContent = @'
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\Microsoft-Antimalware-ShieldProvider" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\EventLog\System\WinDefend" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\MsSecFlt" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\Sense" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdBoot" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f 
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SOFTWARE\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f 
Reg add "HKLM\SYSTEM\ControlSet001\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d "0" /f 
Reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\State" /v "AppAndBrowser_StoreAppsSmartScreenOff" /t REG_DWORD /d 0 /f 
'@

      New-Item -Path "$env:TEMP\disableScript.ps1" -Value $scriptContent -Force | Out-Null
      $command = "Start-Process powershell.exe -ArgumentList `"-ExecutionPolicy Bypass -file `"$env:TEMP\disableScript.ps1`"`""
      Run-Trusted -command $command

      New-item -Path "$env:TEMP\disableReg" -ItemType Directory -Force | Out-Null
      New-Item -Path "$env:TEMP\disableReg\disable1.reg" -Value $file1 -Force | Out-Null
      New-Item -Path "$env:TEMP\disableReg\disable2.reg" -Value $file2 -Force | Out-Null
      New-Item -Path "$env:TEMP\disableReg\disable3.reg" -Value $file3 -Force | Out-Null
      New-Item -Path "$env:TEMP\disableReg\disable5.reg" -Value $file5 -Force | Out-Null
      New-Item -Path "$env:TEMP\disableReg\disable6.reg" -Value $file6 -Force | Out-Null
      New-Item -Path "$env:TEMP\disableReg\disable7.reg" -Value $file7 -Force | Out-Null
      New-Item -Path "$env:TEMP\disableReg\disable8.reg" -Value $file8 -Force | Out-Null
      New-Item -Path "$env:TEMP\disableReg\disable9.reg" -Value $file9 -Force | Out-Null
      New-Item -Path "$env:TEMP\disableReg\disable10.reg" -Value $file10 -Force | Out-Null
      New-Item -Path "$env:TEMP\disableReg\disable11.reg" -Value $file11 -Force | Out-Null
      $files = (Get-ChildItem -Path "$env:TEMP\disableReg").FullName
      foreach ($file in $files) {
        $command = "Start-Process regedit.exe -ArgumentList `"/s $file`""
        Run-Trusted -command $command
        Start-Sleep 1
      }


      #attempt to kill defender processes and silence notifications from sec center
      $command = 'Stop-Process MpDefenderCoreService -Force; Stop-Process smartscreen -Force; Stop-Process SecurityHealthService -Force; Stop-Process SecurityHealthSystray -Force; Stop-Service -Name wscsvc -Force; Stop-Service -Name Sense -Force'
      Run-Trusted -command $command
      Run-Trusted -command $run

      #disable tasks
      $tasks = Get-ScheduledTask
      foreach ($task in $tasks) {
        if ($task.Taskname -like 'Windows Defender*') {
          Disable-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
        }
      }

      #stop smartscreen from running
      $smartScreen = 'C:\Windows\System32\smartscreen.exe'
      $smartScreenOFF = 'C:\Windows\System32\smartscreenOFF.exe'
      $command = "Remove-item -path $smartscreenOFF -force -erroraction silentlycontinue; Rename-item -path $smartScreen -newname smartscreenOFF.exe -force"
 
      Run-Trusted -command $command

      Write-Status -Message 'Cleaning Up...' -Type Output
      Remove-Item "$env:TEMP\disableReg" -Recurse -Force
      Remove-item "$env:TEMP\disableScript.ps1" -Force
      Remove-Item "$env:TEMP\DefeatDefend.ps1" -Force

    }
      
     
  
    
  
    
    if ($checkbox3.Checked) {
      Write-Status -Message 'Disabling Telemetry...' -Type Output
      #removes telemetry through gp edit
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'AllowTelemetry' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableGraphRecentItems' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'AllowClipboardHistory' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'AllowCrossDeviceClipboard' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'EnableActivityFeed' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'PublishUserActivities' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' /v 'UploadUserActivities' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' /v 'DisabledByGroupPolicy' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' /v 'DontSendAdditionalData' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'AllowDeviceNameInTelemetry' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableCloudOptimizedContent' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableWindowsConsumerFeatures' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'AllowTelemetry' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'MaxTelemetryAllowed' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\System\ControlSet001\Services\dmwappushservice' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\System\ControlSet001\Control\WMI\Autologger\Diagtrack-Listener' /v 'Start' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\Software\Policies\Microsoft\Biometrics' /v 'Enabled' /t REG_DWORD /d '0' /f
  
      #disable all the loggers under diag track
      $subkeys = Get-ChildItem -Path 'HKLM:\System\ControlSet001\Control\WMI\Autologger\Diagtrack-Listener'
      foreach ($subkey in $subkeys) {
        Set-ItemProperty -Path "registry::$($subkey.Name)" -Name 'Enabled' -Value 0 -Force
      }
 
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' -ErrorAction SilentlyContinue
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\ProgramDataUpdater' -ErrorAction SilentlyContinue
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\Autochk\Proxy' -ErrorAction SilentlyContinue
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' -ErrorAction SilentlyContinue
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' -ErrorAction SilentlyContinue
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' -ErrorAction SilentlyContinue
  
    
  
    }
  
  
  
    #updates group policy so that the previous changes are applied 
    Write-Status -Message 'Updating Policy...' -Type Output
    gpupdate /force
  }
  
}
Export-ModuleMember -Function gpTweaks





function import-powerplan {

  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
    , [Parameter(mandatory = $false)] [bool]$importPPlan = $false
    , [Parameter(mandatory = $false)] [bool]$enableUltimate = $false
    , [Parameter(mandatory = $false)] [bool]$enableMaxOverlay = $false 
    , [Parameter(mandatory = $false)] [bool]$enableHighOverlay = $false 
    , [Parameter(mandatory = $false)] [bool]$removeallPlans = $false
    , [Parameter(mandatory = $false)] [bool]$importPPlanAMD = $false
  )
      
  
  $checkbox1 = New-Object System.Windows.Forms.CheckBox
  $checkbox2 = New-Object System.Windows.Forms.CheckBox
  $checkbox3 = New-Object System.Windows.Forms.CheckBox
  $checkboxALL = New-Object System.Windows.Forms.CheckBox
  $checkboxCustomPlan1 = New-Object System.Windows.Forms.CheckBox
  $checkboxCustomPlan2 = New-Object System.Windows.Forms.CheckBox

    
  #hashtable to loop through
  $settings = @{}
  $settings['enableUltimate'] = $checkbox1
  $settings['enableMaxOverlay'] = $checkbox2
  $settings['enableHighOverlay'] = $checkbox3
  $settings['removeallPlans'] = $checkboxALL
    
  if ($Autorun) {
    $checkboxCustomPlan1.Checked = $importPPlan
    $checkboxCustomPlan2.Checked = $importPPlanAMD
    $result = [System.Windows.Forms.DialogResult]::OK
    $checkbox1.Checked = $enableUltimate
    $checkbox2.Checked = $enableMaxOverlay
    $checkbox3.Checked = $enableHighOverlay
    $checkboxALL.Checked = $removeallPlans
  }
  else {
    
    $Global:output = powercfg /l
    $powerplanNames = @()
    foreach ($line in $output) {
      if ($line -match ':') {
        $start = $line.trim().IndexOf('(') + 1
        $end = $line.trim().IndexOf(')')
        $length = $end - $start
        try {
          $powerplanNames += $line.trim().Substring($start, $length)
        }
        catch {}
        
      }
    }
   
    
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Power Tweaks'
    $form.Size = New-Object System.Drawing.Size(750, 550) 
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

    # Sidebar Panel
    $sidebarPanel = New-Object System.Windows.Forms.Panel
    $sidebarPanel.Location = New-Object System.Drawing.Point(0, 0)
    $sidebarPanel.Size = New-Object System.Drawing.Size(150, $form.ClientSize.Height)
    $sidebarPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $form.Controls.Add($sidebarPanel)

    # Sidebar Buttons
    $powerPlanBtn = New-Object System.Windows.Forms.Button
    $powerPlanBtn.Location = New-Object System.Drawing.Point(10, 10)
    $powerPlanBtn.Size = New-Object System.Drawing.Size(130, 40)
    $powerPlanBtn.Text = 'Power Plan'
    $powerPlanBtn.ForeColor = 'White'
    $powerPlanBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
    $powerPlanBtn.FlatAppearance.BorderSize = 0
    $powerPlanBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $powerPlanBtn.Tag = 'Active' 
    $powerPlanBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $powerPlanBtn.Add_MouseLeave({
        if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }
        else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) }
      })
    $sidebarPanel.Controls.Add($powerPlanBtn)

    $usbPowerBtn = New-Object System.Windows.Forms.Button
    $usbPowerBtn.Location = New-Object System.Drawing.Point(10, 60)
    $usbPowerBtn.Size = New-Object System.Drawing.Size(130, 40)
    $usbPowerBtn.Text = 'USB Power'
    $usbPowerBtn.ForeColor = 'White'
    $usbPowerBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
    $usbPowerBtn.FlatAppearance.BorderSize = 0
    $usbPowerBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $usbPowerBtn.Tag = 'Inactive' 
    $usbPowerBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $usbPowerBtn.Add_MouseLeave({
        if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }
        else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) }
      })
    $sidebarPanel.Controls.Add($usbPowerBtn)

    # Info Button in Sidebar
    $url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#import-and-remove-power-plans'
    $infobutton = New-Object System.Windows.Forms.Button
    $infobutton.Location = New-Object System.Drawing.Point(5, 480)  
    $infobutton.Size = New-Object System.Drawing.Size(30, 27)
    $infobutton.Cursor = 'Hand'
    $infobutton.Add_Click({
        try {
          Start-Process $url -ErrorAction Stop
        }
        catch {
          Write-Status -Message 'No Internet Connected...' -Type Error
        }
      })
    $infobutton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $image = [System.Drawing.Image]::FromFile('C:\Windows\System32\SecurityAndMaintenance.png')
    $resizedImage = New-Object System.Drawing.Bitmap $image, 24, 25
    $infobutton.Image = $resizedImage
    $infobutton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $infobutton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $infobutton.FlatAppearance.BorderSize = 0
    $sidebarPanel.Controls.Add($infobutton)

    # Main Content Panel
    $contentPanel = New-Object System.Windows.Forms.Panel
    $contentPanel.Location = New-Object System.Drawing.Point(160, 10)
    $contentPanel.Size = New-Object System.Drawing.Size(570, 450)  
    $contentPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $form.Controls.Add($contentPanel)

    # Power Plan Panel
    $powerPlanPanel = New-Object System.Windows.Forms.Panel
    $powerPlanPanel.Location = New-Object System.Drawing.Point(0, 0)
    $powerPlanPanel.Size = New-Object System.Drawing.Size(570, 450) 
    $powerPlanPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $powerPlanPanel.Visible = $true
    $contentPanel.Controls.Add($powerPlanPanel)

    # USB Power Panel
    $usbPowerPanel = New-Object System.Windows.Forms.Panel
    $usbPowerPanel.Location = New-Object System.Drawing.Point(0, 0)
    $usbPowerPanel.Size = New-Object System.Drawing.Size(570, 450)  
    $usbPowerPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65) 
    $usbPowerPanel.Visible = $false
    $contentPanel.Controls.Add($usbPowerPanel)

    # Labels for Power Plan Panel
    $labelPowerPlan = New-Object System.Windows.Forms.Label
    $labelPowerPlan.Text = 'Power Plan'
    $labelPowerPlan.Location = New-Object System.Drawing.Point(10, 10)
    $labelPowerPlan.Size = New-Object System.Drawing.Size(200, 20)
    $labelPowerPlan.ForeColor = 'White'
    $labelPowerPlan.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $powerPlanPanel.Controls.Add($labelPowerPlan)

    $lineStartPoint = New-Object System.Drawing.Point(5, 35)
    $lineEndPoint = New-Object System.Drawing.Point(250, 35)
    $lineColor = [System.Drawing.Color]::White
    $lineWidth = 1.5

    $powerPlanPanel.Add_Paint({
        $graphics = $powerPlanPanel.CreateGraphics()
        $pen = New-Object System.Drawing.Pen($lineColor, $lineWidth)
        $graphics.DrawLine($pen, $lineStartPoint, $lineEndPoint)
        $pen.Dispose()
        $graphics.Dispose()
      })

    $labelRemovePower = New-Object System.Windows.Forms.Label
    $labelRemovePower.Text = 'Remove Power Plans:'
    $labelRemovePower.Location = New-Object System.Drawing.Point(10, 50)
    $labelRemovePower.Size = New-Object System.Drawing.Size(200, 20)
    $labelRemovePower.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $labelRemovePower.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($labelRemovePower)

    $labelHidden = New-Object System.Windows.Forms.Label
    $labelHidden.Text = 'Enable Hidden Power Plans:'
    $labelHidden.Location = New-Object System.Drawing.Point(260, 50)
    $labelHidden.Size = New-Object System.Drawing.Size(250, 20)
    $labelHidden.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $labelHidden.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($labelHidden)

    $labelCustom = New-Object System.Windows.Forms.Label
    $labelCustom.Text = 'Import Custom Plans:'
    $labelCustom.Location = New-Object System.Drawing.Point(10, 290)
    $labelCustom.Size = New-Object System.Drawing.Size(250, 20)
    $labelCustom.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $labelCustom.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($labelCustom)

  
    $checkboxCustomPlan1.Text = "Zoic's Ultimate Performance"
    $checkboxCustomPlan1.Location = New-Object System.Drawing.Point(10, 320)
    $checkboxCustomPlan1.Size = New-Object System.Drawing.Size(200, 20)
    $checkboxCustomPlan1.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($checkboxCustomPlan1)

    $tooltip1 = New-Object System.Windows.Forms.ToolTip
    $tooltip1.SetToolTip($checkboxCustomPlan1, 'Provides Optimal Performance for All CPUs with All Power Saving Features Disabled')
    
    $checkboxCustomPlan2 = New-Object System.Windows.Forms.CheckBox
    $checkboxCustomPlan2.Text = "Zoic's Ultimate Performance (AMD)"
    $checkboxCustomPlan2.Location = New-Object System.Drawing.Point(10, 350)
    $checkboxCustomPlan2.Size = New-Object System.Drawing.Size(200, 20)
    $checkboxCustomPlan2.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($checkboxCustomPlan2)

    $tooltip2 = New-Object System.Windows.Forms.ToolTip
    $tooltip2.SetToolTip($checkboxCustomPlan2, 'Helps to Stabilize PBO When Idling for AMD CPUs')
   
    $labelCustom2 = New-Object System.Windows.Forms.Label
    $labelCustom2.Text = 'Import Your Own Plan:'
    $labelCustom2.Location = New-Object System.Drawing.Point(260, 290)
    $labelCustom2.Size = New-Object System.Drawing.Size(250, 20)
    $labelCustom2.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $labelCustom2.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($labelCustom2)

    $powerTextbox = New-Object System.Windows.Forms.TextBox
    $powerTextbox.Location = New-Object System.Drawing.Point(260, 320)
    $powerTextbox.Size = New-Object System.Drawing.Size(250, 20)
    $powerTextbox.Text = $null
    $powerPlanPanel.Controls.Add($powerTextbox)

    $filebrowsebttn = New-Object System.Windows.Forms.Button
    $filebrowsebttn.Location = New-Object System.Drawing.Point(515, 320)
    $filebrowsebttn.Size = New-Object System.Drawing.Size(40, 20)
    $filebrowsebttn.Text = '...'
    $filebrowsebttn.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $filebrowsebttn.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $filebrowsebttn.ForeColor = [System.Drawing.Color]::White
    $filebrowsebttn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $filebrowsebttn.FlatAppearance.BorderSize = 1
    #$filebrowsebttn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$filebrowsebttn.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $filebrowsebttn.Add_Click({    
        $selectedPowFile = Show-ModernFilePicker -Mode File -fileType pow
        if ($selectedPowFile) {
          $powerTextbox.Text = $selectedPowFile 
        }
        
      })
    $powerPlanPanel.Controls.Add($filebrowsebttn)

    # Labels for USB Power Panel
    $labelUSBPower = New-Object System.Windows.Forms.Label
    $labelUSBPower.Text = 'USB Power'
    $labelUSBPower.Location = New-Object System.Drawing.Point(10, 10)
    $labelUSBPower.Size = New-Object System.Drawing.Size(200, 20)
    $labelUSBPower.ForeColor = 'White'
    $labelUSBPower.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $usbPowerPanel.Controls.Add($labelUSBPower)

    $lineStartPoint = New-Object System.Drawing.Point(5, 35)
    $lineEndPoint = New-Object System.Drawing.Point(250, 35)
    $lineColor = [System.Drawing.Color]::White
    $lineWidth = 1.5

    $usbPowerPanel.Add_Paint({
        $graphics = $usbPowerPanel.CreateGraphics()
        $pen = New-Object System.Drawing.Pen($lineColor, $lineWidth)
        $graphics.DrawLine($pen, $lineStartPoint, $lineEndPoint)
        $pen.Dispose()
        $graphics.Dispose()
      })

    $labelDisablePowerSaving = New-Object System.Windows.Forms.Label
    $labelDisablePowerSaving.Text = 'Disable Power Saving:'
    $labelDisablePowerSaving.Location = New-Object System.Drawing.Point(10, 50)
    $labelDisablePowerSaving.Size = New-Object System.Drawing.Size(200, 20)
    $labelDisablePowerSaving.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $labelDisablePowerSaving.ForeColor = 'White'
    $usbPowerPanel.Controls.Add($labelDisablePowerSaving)

    $checkedListBox = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox.Size = New-Object System.Drawing.Size(230, 150)  
    $checkedListBox.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $checkedListBox.ForeColor = 'White'
    $checkedListBox.CheckOnClick = $true
    $checkedListBox.Location = New-Object System.Drawing.Point(10, 70)
    $powerPlanPanel.Controls.Add($checkedListBox)
    
    foreach ($name in $powerplanNames) {
      [void]$checkedListBox.Items.Add($name)
    }

    $checkboxALL.Text = 'Check All'
    $checkboxALL.Location = New-Object System.Drawing.Point(10, 220)  
    $checkboxALL.Size = New-Object System.Drawing.Size(100, 20)
    $checkboxALL.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($checkboxALL)

    $checkboxALL.Add_CheckedChanged({
        $total = $checkedListBox.Items.Count
        $index = 0
        if ($checkboxALL.Checked) {
          for ($index = 0; $index -lt $total; $index++) {
            $checkedListBox.SetItemChecked($index, $true)
          }
        }
        else {
          for ($index = 0; $index -lt $total; $index++) {
            $checkedListBox.SetItemChecked($index, $false)
          }
        }
      })

    $checkboxRestore = New-Object System.Windows.Forms.CheckBox
    $checkboxRestore.Text = 'Restore Default'
    $checkboxRestore.Location = New-Object System.Drawing.Point(120, 220)  
    $checkboxRestore.Size = New-Object System.Drawing.Size(125, 20)
    $checkboxRestore.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($checkboxRestore)

    # Enable Hidden Power Plans Checkboxes
    $checkbox1.Text = 'Ultimate Performance'
    $checkbox1.Location = New-Object System.Drawing.Point(260, 80)
    $checkbox1.Size = New-Object System.Drawing.Size(200, 20)
    $checkbox1.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($checkbox1)

    $checkbox2.Text = 'Max Performance Overlay'
    $checkbox2.Location = New-Object System.Drawing.Point(260, 110)
    $checkbox2.Size = New-Object System.Drawing.Size(200, 20)
    $checkbox2.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($checkbox2)

    $checkbox3.Text = 'High Performance Overlay'
    $checkbox3.Location = New-Object System.Drawing.Point(260, 140)
    $checkbox3.Size = New-Object System.Drawing.Size(200, 20)
    $checkbox3.ForeColor = 'White'
    $powerPlanPanel.Controls.Add($checkbox3)

    $treeView = New-Object System.Windows.Forms.TreeView
    $treeView.CheckBoxes = $true
    $treeView.Location = New-Object System.Drawing.Point(10, 70)
    $treeView.Size = New-Object System.Drawing.Size(540, 350)  
    $treeView.Scrollable = $true
    $treeView.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $treeView.ForeColor = [System.Drawing.Color]::White
    $usbPowerPanel.Controls.Add($treeView)

    # Populate TreeView with USB Devices
    Write-Status -Message 'Getting USB Devices...' -Type Output
    $usbDevices = Get-PnpDevice -Class USB | Where-Object { $_.Status -ne 'Unknown' } | ForEach-Object {
      [PSCustomObject]@{
        Name       = $_.FriendlyName
        InstanceId = $_.InstanceId
        Parent     = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_Parent).Data
      }
    }

    $controllers = $usbDevices | Where-Object { $_.Name -like '*Host Controller*' } | Group-Object -Property InstanceId -AsHashTable -AsString
    $genhubs = $usbDevices | Where-Object { $_.Name -like '*USB Hub*' } | Group-Object -Property Parent -AsHashTable -AsString
    $restOfDevices = $usbDevices | Where-Object { 
      $_.Name -notlike '*Host Controller*' -and 
      $_.Name -notlike '*USB Hub*' 
    } | Group-Object -Property Parent -AsHashTable -AsString

    foreach ($controller in $controllers.Values) {
      $controllerNode = New-Object System.Windows.Forms.TreeNode
      $controllerNode.Text = $controller.Name
      $controllerNode.Tag = $controller.InstanceId
      $controllerNode.ImageIndex = 0

      $childDevices = $usbDevices | Where-Object { $_.Parent -eq $controller.InstanceId }

      foreach ($device in $childDevices) {
        $deviceNode = New-Object System.Windows.Forms.TreeNode
        $deviceNode.Text = $device.Name
        $deviceNode.Tag = $device.InstanceId

        if ($genhubs.ContainsKey($device.InstanceId)) {
          $hubNode = New-Object System.Windows.Forms.TreeNode
          $hubNode.Text = $genhubs[$device.InstanceId].Name
          $hubNode.Tag = $genhubs[$device.InstanceId].InstanceId

          $hubChildren = $usbDevices | Where-Object { $_.Parent -eq $device.InstanceId }
          foreach ($hubChild in $hubChildren) {
            $hubChildNode = New-Object System.Windows.Forms.TreeNode
            $hubChildNode.Text = $hubChild.Name
            $hubChildNode.Tag = $hubChild.InstanceId

            if ($restOfDevices.ContainsKey($hubChild.InstanceId)) {
              $childDevices = $restOfDevices[$hubChild.InstanceId]
              foreach ($childDevice in $childDevices) {
                $childNode = New-Object System.Windows.Forms.TreeNode
                $childNode.Text = $childDevice.Name
                $childNode.Tag = $childDevice.InstanceId
                $hubChildNode.Nodes.Add($childNode)
              }
            }

            $hubNode.Nodes.Add($hubChildNode)
          }
          $deviceNode.Nodes.Add($hubNode)
        }
        elseif ($restOfDevices.ContainsKey($device.InstanceId)) {
          $childDevices = $restOfDevices[$device.InstanceId]
          foreach ($childDevice in $childDevices) {
            $childNode = New-Object System.Windows.Forms.TreeNode
            $childNode.Text = $childDevice.Name
            $childNode.Tag = $childDevice.InstanceId
            $deviceNode.Nodes.Add($childNode)
          }
        }

        $controllerNode.Nodes.Add($deviceNode)
      }

      $treeView.Nodes.Add($controllerNode)
    }

    $treeView.ExpandAll()

    $treeView.add_AfterCheck({
        param($sender, $e)
        if ($e.Node.Nodes.Count -gt 0 -and $e.Node.Checked) {
          foreach ($childNode in $e.Node.Nodes) {
            $childNode.Checked = $true
          }
        }
        elseif ($e.Node.Nodes.Count -gt 0 -and -not $e.Node.Checked) {
          foreach ($childNode in $e.Node.Nodes) {
            $childNode.Checked = $false
          }
        }
      })

    # Check All Checkbox for USB Power
    $checkboxALLUSB = New-Object System.Windows.Forms.CheckBox
    $checkboxALLUSB.Text = 'Check All'
    $checkboxALLUSB.Location = New-Object System.Drawing.Point(460, 50) 
    $checkboxALLUSB.Size = New-Object System.Drawing.Size(100, 20)
    $checkboxALLUSB.ForeColor = 'White'
    $usbPowerPanel.Controls.Add($checkboxALLUSB)

    $checkboxALLUSB.Add_CheckedChanged({
        if ($checkboxALLUSB.Checked) {
          foreach ($treeNode in $treeView.Nodes) {
            $treeNode.Checked = $true
          }
        }
        else {
          foreach ($treeNode in $treeView.Nodes) {
            $treeNode.Checked = $false
          }
        }
      })

    # OK and Cancel Buttons
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(315, 470)  
    $OKButton.Size = New-Object System.Drawing.Size(100, 23)
    $OKButton.Text = 'Apply'
    $OKButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $OKButton.ForeColor = [System.Drawing.Color]::White
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(425, 470) 
    $CancelButton.Size = New-Object System.Drawing.Size(100, 23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $CancelButton.ForeColor = [System.Drawing.Color]::White
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    $powerPlanBtn.Add_Click({
        $powerPlanPanel.Visible = $true
        $usbPowerPanel.Visible = $false
        $powerPlanBtn.Tag = 'Active'
        $usbPowerBtn.Tag = 'Inactive'
        $powerPlanBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
        $usbPowerBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
      })

    $usbPowerBtn.Add_Click({
        $powerPlanPanel.Visible = $false
        $usbPowerPanel.Visible = $true
        $usbPowerBtn.Tag = 'Active'
        $powerPlanBtn.Tag = 'Inactive'
        $usbPowerBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
        $powerPlanBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
      })

    # Activate the form
    $form.Add_Shown({ $form.Activate() })
    $result = $form.ShowDialog()
      
  }
      
      
      

              
   
   
      
      
      
  # Check the selected checkboxes
  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    

    if ($checkboxCustomPlan1.Checked) {
      if (!($Autorun)) {
        #update config
        update-config -setting 'usePowerPlan' -value 1
      }
              
      #imports power plan
      $p = Search-File '*zoicsultimateperformance.pow'
      
      #generate new guid
      $guid = New-Guid 
      powercfg -import ([string]$p) $guid     
      powercfg /setactive $guid 
      powercfg -h off  
      if (!($Autorun)) {
        Custom-MsgBox -message 'Custom Power Plan Active!' -type None
      }
    }
   
          
    if ($checkboxCustomPlan2.Checked) {
      if (!($Autorun)) {
        #update config
        update-config -setting 'usePowerPlanAMD' -value 1
      }
              
      #imports power plan
      $p = Search-File '*zoicsultimateperformanceAMD.pow'
      
      #generate new guid
      $guid = New-Guid 
      powercfg -import ([string]$p) $guid     
      powercfg /setactive $guid 
      powercfg -h off 
      if (!($Autorun)) {
        Custom-MsgBox -message 'Custom AMD Power Plan Active!' -type None
      }
    }
   
    if (!$Autorun) {
      if ($powerTextbox.Text -ne '') {

        $planPath = $powerTextbox.Text
        #generate new guid
        $guid = New-Guid 
        powercfg -import ([string]$planPath) $guid     
        powercfg /setactive $guid 
        powercfg -h off 

        Custom-MsgBox -message 'Imported Power Plan Active!' -type None
      
      }
    }
    


    if (!($Autorun)) {
      #loop through checkbox hashtable to update config
      $settings.GetEnumerator() | ForEach-Object {
          
        $settingName = $_.Key
        $checkbox = $_.Value
      
        if ($checkbox.Checked) {
          update-config -setting $settingName -value 1
        }
      }
    }
    
    $removed = $false
    if ($removeallPlans -or $checkboxALL.Checked) {
      $removed = $true
      $output = powercfg /L
      $powerPlans = @{}
      foreach ($line in $output) {
        # extract guid manually to avoid lang issues
        if ($line -match ':') {
          $parse = $line -split ':'
          $index = $parse[1].Trim().indexof('(')
          $guid = $parse[1].Trim().Substring(0, $index)
          #get name
          $start = $parse[1].IndexOf('(')
          $name = $parse[1].Substring($start).Trim('()*')
          $name = $name -replace '\)' , ''
          $powerPlans.Add($name, $guid)
        }
      }
      # delete all powerplans
      foreach ($plan in $powerPlans.GetEnumerator()) {
        Write-Status -Message "Removing $($plan.Key)..." -Type Output
        cmd /c "powercfg /delete $($plan.Value)" | Out-Null
      }
    }


    if ($checkedListBox.CheckedItems -and $removed -eq $false) {
      $powerPlans = @{}
      foreach ($line in $output) {
        foreach ($name in $checkedListBox.CheckedItems.GetEnumerator()) {
          if ($line -like "*$name*") {
            $parse = $line -split ':'
            $index = $parse[1].Trim().indexof('(')
            $guid = $parse[1].Trim().Substring(0, $index)
            #get name
            $start = $parse[1].IndexOf('(')
            $name = $parse[1].Substring($start).Trim('()*')
            $name = $name -replace '\)' , ''
            $powerPlans.Add($name, $guid)
          }
        }
      }
      foreach ($plan in $powerPlans.GetEnumerator()) {
        Write-Status -Message "Removing $($plan.Key)..." -Type Output
        cmd /c "powercfg /delete $($plan.Value)" | Out-Null
      }
    }
    if ($checkbox1.Checked) {
      #duplicate ultimate performance
      powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
     
    }
    if ($checkbox2.Checked) {
      #duplicate max performance overlay
      powercfg -duplicatescheme ded574b5-45a0-4f42-8737-46345c09c238 | Out-Null  
    }    
    if ($checkbox3.Checked) {
      #duplicate high performance overlay
      powercfg -duplicatescheme 3af9b8d9-7c97-431d-ad78-34a8bfea439f | Out-Null

    }    
   

    function Disable-PowerSaving {
      param (
        [string]$name,
        [string]$instanceID
      )

      $key = 'HKLM\SYSTEM\ControlSet001\Enum'

      Write-Status -Message "Disabling Power Saving For $name" -Type Output
       
      Reg.exe add "$($key)\$instanceID\Device Parameters\WDF" /v 'IdleInWorkingState' /t REG_DWORD /d '0' /f
      #uncheck device manager ui
      try {
        $powerMgmt = Get-CimInstance MSPower_DeviceEnable -Namespace root\wmi | Where-Object { $_.InstanceName -like "*$instanceID*" }
        $powerMgmt.Enable = $false 
        Set-CimInstance -InputObject $powerMgmt -ErrorAction Stop
      }
      catch {
        Write-Status -Message 'No Power Saving For This Device, Reg Key Still Applied...' -Type Warning
      }

    }

    
    foreach ($rootNode in $treeView.Nodes) {
      if ($rootNode.Checked) {
        Disable-PowerSaving -name $rootNode.Text -instanceId $rootNode.Tag
      }

      #check child nodes
      foreach ($childNode in $rootNode.Nodes) {
        if ($childNode.Checked) {
          Disable-PowerSaving -name $childNode.Text -instanceId $childNode.Tag
        }
        foreach ($genUsbNode in $childNode.Nodes) {
          if ($genUsbNode.Checked) {
            Disable-PowerSaving -name $genUsbNode.Text -instanceId $genUsbNode.Tag
          }

          foreach ($deviceNode in $genUsbNode.Nodes) {
            if ($deviceNode.Checked) {
              Disable-PowerSaving -name $deviceNode.Text -instanceId $deviceNode.Tag
            }
          }
        }
      }
    }
       

    if ($checkboxRestore.Checked) {
      Write-Status -Message 'Restoring Default Power Plans...' -Type Output
      powercfg -restoredefaultschemes | Out-Null
    }
          
  }
      
}
Export-ModuleMember -Function import-powerplan






function import-reg {

  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
  )
    
    
    
    
  if ($AutoRun) {
    $result = [System.Windows.Forms.DialogResult]::OK
  }
  else {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form3 = New-Object System.Windows.Forms.Form
    $form3.Text = 'Registry Tweaks'
    $form3.Size = New-Object System.Drawing.Size(790, 700)
    $form3.StartPosition = 'CenterScreen'
    $form3.BackColor = 'Black'
    $form3.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $form3.Icon = New-Object System.Drawing.Icon($Global:customIcon)

    #info button
    $url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#registry-tweaks'
    $infobutton = New-Object Windows.Forms.Button
    $infobutton.Location = New-Object Drawing.Point(740, 10)
    $infobutton.Size = New-Object Drawing.Size(30, 30)
    $infobutton.Cursor = 'Hand'
    $infobutton.Add_Click({
        try {
          Start-Process $url -ErrorAction Stop
        }
        catch {
          Write-Status -Message 'No Internet Connected...' -Type Error
        }
            
      })
    $infobutton.BackColor = 'Black'
    $image = [System.Drawing.Image]::FromFile('C:\Windows\System32\SecurityAndMaintenance.png')
    $resizedImage = New-Object System.Drawing.Bitmap $image, 24, 25
    $infobutton.Image = $resizedImage
    $infobutton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $infobutton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $infobutton.FlatAppearance.BorderSize = 1
    #$infobutton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$infobutton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form3.Controls.Add($infobutton)


    $searchBox10 = New-Object System.Windows.Forms.TextBox
    $searchBox10.Location = New-Object System.Drawing.Point(10, 190)
    $searchBox10.Size = New-Object System.Drawing.Size(150, 20)
    $form3.Controls.Add($searchBox10)

    $searchBox11 = New-Object System.Windows.Forms.TextBox
    $searchBox11.Location = New-Object System.Drawing.Point(405, 190)
    $searchBox11.Size = New-Object System.Drawing.Size(150, 20)
    $form3.Controls.Add($searchBox11)


    $pictureBox = New-Object System.Windows.Forms.PictureBox
    $pictureBox.Location = New-Object System.Drawing.Point(165, 190) 
    $pictureBox.Size = New-Object System.Drawing.Size(30, 20) 
    $pictureBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
    $imagePath = "$iconDir\zSearchIcon.png"
    try {
      $image = [System.Drawing.Image]::FromFile($imagePath)
    }
    catch {
      Write-Status -Message 'Missing Asset (Search Icon)' -Type Warning
    }
    $pictureBox.Image = $image
    $form3.Controls.Add($pictureBox)


    $pictureBox2 = New-Object System.Windows.Forms.PictureBox
    $pictureBox2.Location = New-Object System.Drawing.Point(560, 190) 
    $pictureBox2.Size = New-Object System.Drawing.Size(30, 20) 
    $pictureBox2.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
    # $imagePath = Search-File '*zSearchIcon.png'
    # try {
    #   $image = [System.Drawing.Image]::FromFile($imagePath)
    # }
    # catch {
    #   Write-Status -Message 'Missing Asset (Search Icon)' -Type Warning
    # }
    $pictureBox2.Image = $image
    $form3.Controls.Add($pictureBox2)

    
    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(10, 10)
    $label2.Size = New-Object System.Drawing.Size(300, 20)
    $label2.Text = 'Mode: Exclude Selected Tweaks'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font('Segoe UI', 12) 
    $form3.Controls.Add($label2)
    

    <#
    $lineStartPoint = New-Object System.Drawing.Point(0, 43)
    $lineEndPoint = New-Object System.Drawing.Point(280, 43)
    $lineColor = [System.Drawing.Color]::Gray
    $lineWidth = 1.5

    $form3.Add_Paint({
        $graphics = $form3.CreateGraphics()
        $pen = New-Object System.Drawing.Pen($lineColor, $lineWidth)
        $graphics.DrawLine($pen, $lineStartPoint, $lineEndPoint)
        $pen.Dispose()
        $graphics.Dispose()
      })
#>

    $label3 = New-Object System.Windows.Forms.Label
    $label3.Location = New-Object System.Drawing.Point(10, 165)
    $label3.Size = New-Object System.Drawing.Size(150, 20)
    $label3.Text = 'Windows 10'
    $label3.ForeColor = 'White'
    $label3.Font = New-Object System.Drawing.Font('Segoe UI', 10) 
    $form3.Controls.Add($label3)

    $label4 = New-Object System.Windows.Forms.Label
    $label4.Location = New-Object System.Drawing.Point(405, 165)
    $label4.Size = New-Object System.Drawing.Size(150, 20)
    $label4.Text = 'Windows 11'
    $label4.ForeColor = 'White'
    $label4.Font = New-Object System.Drawing.Font('Segoe UI', 10) 
    $form3.Controls.Add($label4)

    $checkedListBox10 = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox10.Location = New-Object System.Drawing.Point(10, 215)
    $checkedListBox10.Size = New-Object System.Drawing.Size(350, 435)
    $checkedListBox10.BackColor = 'Black'
    $checkedListBox10.ForeColor = 'White'
    $checkedListBox10.CheckOnClick = $true
    $checkedListBox10.ScrollAlwaysVisible = $true
    $Form3.Controls.Add($checkedListBox10)

    $checkedListBox11 = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox11.Location = New-Object System.Drawing.Point(405, 215)
    $checkedListBox11.Size = New-Object System.Drawing.Size(350, 435)
    $checkedListBox11.BackColor = 'Black'
    $checkedListBox11.ForeColor = 'White'
    $checkedListBox11.CheckOnClick = $true
    $checkedListBox11.ScrollAlwaysVisible = $true
    $Form3.Controls.Add($checkedListBox11)

    $r10 = Search-File '*RegistryTweaks10.txt'
    $r11 = Search-File '*RegistryTweaks11.txt'
   
    #add to reg tweaks 10
    $content = Get-Content $r10
    $Global:regOptions10 = $content -split "`n"
    $options10 = @()
    foreach ($line in $regOptions10) {
      if ($line -like ';*') {
        $name = $line -split ';'
        $checkedListBox10.Items.Add($name[1].Trim(), $false) | Out-Null
        $options10 += $name[1].Trim()
      }
    }
    #add to reg tweaks 11
    $content = Get-Content $r11
    $Global:regOptions11 = $content -split "`n"
    $options11 = @()
    $archiveAppsTweak = $false
    foreach ($line in $regOptions11) {
      if ($line -like ';*') {
        $name = $line -split ';'
        $checkedListBox11.Items.Add($name[1].Trim(), $false) | Out-Null
        $options11 += $name[1].Trim()
        if ($name[1].Trim() -eq 'Disable Archive Apps') {
          $archiveAppsTweak = $true
        }
      }
      
    }
  
    if (!$archiveAppsTweak) {
      #add archive apps to win11 tweaks
      $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
      $items = (Get-ChildItem $regPath).Name
      foreach ($item in $items) {
        if ($item -like '*S-1-5-21*') {
          #extract sid
          $sid = ($item -split '\\')[-1]
        }
      }
      #create reg content 
      $disableArchiveApps = @"

; Disable Archive Apps
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\InstallService\Stubification\$sid]
"EnableAppOffloading"=dword:00000000
"@
      Add-Content -Path $r11 -Value $disableArchiveApps -Force | Out-Null

      #add to checkedlistbox
      $checkedListBox11.Items.Add('Disable Archive Apps', $false) | Out-Null
      $options11 += 'Disable Archive Apps'
    }
   

    # Add the listbox for selected items
    $selectedItemsBox = New-Object System.Windows.Forms.ListBox
    $selectedItemsBox.Location = New-Object System.Drawing.Point(10, 30)
    $selectedItemsBox.Size = New-Object System.Drawing.Size(420, 115)
    $selectedItemsBox.BackColor = 'Black'
    $selectedItemsBox.ForeColor = 'Red'
    $selectedItemsBox.ScrollAlwaysVisible = $true
    $form3.Controls.Add($selectedItemsBox)


    $originalItems10 = $options10.Clone()
    $originalItems11 = $options11.Clone()
 
    # store checked states
    $checkedStates10 = @{}
    $checkedStates11 = @{}

    foreach ($item in $originalItems10) {
      $checkedStates10[$item] = $false
    }

    foreach ($item in $originalItems11) {
      $checkedStates11[$item] = $false
    }

   

    # Modify the ItemCheck events to update the selected items listbox
    $checkedListBox10.Add_ItemCheck({
        param($sender, $e)
        $item = $checkedListBox10.Items[$e.Index]
        $checkedStates10[$item] = $e.NewValue -eq 'Checked'
    
        # Update selected items listbox
        $selectedItemsBox.Items.Clear()
    
        foreach ($checkedItem in $checkedListBox10.CheckedItems) {
          #skip current item because the state hasnt changed yet
          if ($checkedItem -ne $item) {
            $selectedItemsBox.Items.Add("Win10: $checkedItem")
          }
        }

        # Add the item that triggered this event if it's being checked
        if ($e.NewValue -eq 'Checked') {
          $selectedItemsBox.Items.Add("Win10: $item")
        }
        
        # Add items from Windows 11 checklist
        foreach ($checkedItem in $checkedListBox11.CheckedItems) {
          $selectedItemsBox.Items.Add("Win11: $checkedItem")
        }
      })

    $checkedListBox11.Add_ItemCheck({
        param($sender, $e)
        $item = $checkedListBox11.Items[$e.Index]
        $checkedStates11[$item] = $e.NewValue -eq 'Checked'
    
        # Update selected items listbox
        $selectedItemsBox.Items.Clear()
    
        foreach ($checkedItem in $checkedListBox11.CheckedItems) {
          #skip current item because the state hasnt changed yet
          if ($checkedItem -ne $item) {
            $selectedItemsBox.Items.Add("Win11: $checkedItem")
          }
        }

        # Add the item that triggered this event if it's being checked
        if ($e.NewValue -eq 'Checked') {
          $selectedItemsBox.Items.Add("Win11: $item")
        }

        # Add items from Windows 10 checklist
        foreach ($checkedItem in $checkedListBox10.CheckedItems) {
          $selectedItemsBox.Items.Add("Win10: $checkedItem")
        }

      })

    $searchBox10.Add_TextChanged({
        $searchText = $searchBox10.Text.ToLower()
        $checkedListBox10.Items.Clear()

        $sortedItems = $originalItems10 | Sort-Object {
          # return to original order when not searching
          if ([string]::IsNullOrWhiteSpace($searchText)) {
            return [array]::IndexOf($originalItems10, $_)
          }
          #starts with top priority
          if ($_.ToLower().StartsWith($searchText)) {
            return 0
          }
          #contains second priority
          if ($_.ToLower().Contains($searchText)) {
            return 1
          }
          #no match
          return 2
        }

        # keep checked state the same when adding back to list
        foreach ($item in $sortedItems) {
          $index = $checkedListBox10.Items.Add($item)
          $checkedListBox10.SetItemChecked($index, $checkedStates10[$item])
        }
      })

   
    $searchBox11.Add_TextChanged({
        $searchText = $searchBox11.Text.ToLower()
        $checkedListBox11.Items.Clear()

        $sortedItems = $originalItems11 | Sort-Object {
          # return to original order when not searching
          if ([string]::IsNullOrWhiteSpace($searchText)) {
            return [array]::IndexOf($originalItems11, $_)
          }
          #starts with top priority
          if ($_.ToLower().StartsWith($searchText)) {
            return 0
          }
          #contains second priority
          if ($_.ToLower().Contains($searchText)) {
            return 1
          }
          #no match
          return 2
        }

        # keep checked state the same when adding back to list
        foreach ($item in $sortedItems) {
          $index = $checkedListBox11.Items.Add($item)
          $checkedListBox11.SetItemChecked($index, $checkedStates11[$item])
        }
      })


    $default = New-Object System.Windows.Forms.Button
    $default.Location = New-Object System.Drawing.Point(595, 95)
    $default.Size = New-Object System.Drawing.Size(130, 35)
    $default.Text = 'Run All Tweaks'
    $default.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $default.ForeColor = [System.Drawing.Color]::White
    $default.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form3.Controls.Add($default)

    $Global:blackWallpaper = $false
    $Global:taskMgrOnTop = $false

    $custom = New-Object System.Windows.Forms.Button
    $custom.Location = New-Object System.Drawing.Point(435, 95)
    $custom.Size = New-Object System.Drawing.Size(130, 35)
    $custom.Text = 'Run Custom Tweaks'
    $custom.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $custom.ForeColor = [System.Drawing.Color]::White
    $custom.Visible = $true
    $custom.Add_Click({

        #build custom regtweak in temp dir

        #remove any previous custom reg file (just in case)
        Remove-Item "$env:temp\CustomTweaks.reg" -Force -ErrorAction SilentlyContinue | Out-Null

        $removeTweaks10 = @()
        foreach ($item in $checkedListBox10.CheckedItems.GetEnumerator()) {
          $removeTweaks10 += $item
        }
        #get tweaks 10
        $editedRegContent10 = @()
        $removeTweak = $false
        
        foreach ($line in $regOptions10) {
          #if line has comment check it 
          if ($line -like ';*') {
            #reset remove tweak
            $removeTweak = $false
            $name = $line -split ';'
            #if the name is in removeitems list then exclude the following lines till the next ";"
            if ($name[1].trim() -in $removeTweaks10) {
              $removeTweak = $true
            }
            else {
              #tweak not in list
              $editedRegContent10 += $line
              #keep track of some options for later
              if ($name[1].trim() -eq 'Set background black') {
                $Global:blackWallpaper = $true
              }

              if ($name[1].trim() -eq 'Task Manager Always On Top') {
                $Global:taskMgrOnTop = $true
              }

            }
          }
          else {
            if (!$removeTweak) {
              #tweak not in list
              $editedRegContent10 += $line
            }
          }
        }
        #get 11 tweaaks
        $removeTweaks11 = @()
        foreach ($item in $checkedListBox11.CheckedItems.GetEnumerator()) {
          $removeTweaks11 += $item
        }
        #get tweaks 11
        $editedRegContent11 = @()
        $removeTweak = $false
        
        foreach ($line in $regOptions11) {
          #if line has comment check it 
          if ($line -like ';*') {
            #reset remove tweak
            $removeTweak = $false
            $name = $line -split ';'
            #if the name is in removeitems list then exclude the following lines till the next ";"
            if ($name[1].trim() -in $removeTweaks11) {
              $removeTweak = $true
            }
            else {
              #tweak not in list
              $editedRegContent11 += $line
            }
          }
          else {
            if (!$removeTweak) {
              #tweak not in list
              $editedRegContent11 += $line
            }
          }
        }

        Add-Content "$env:temp\CustomTweaks.reg" -Value $editedRegContent10 -Force
        Add-Content "$env:temp\CustomTweaks.reg" -Value $editedRegContent11 -Force

      })
    $custom.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form3.Controls.Add($custom)

    $selectedbttn = New-Object System.Windows.Forms.Button
    $selectedbttn.Location = New-Object System.Drawing.Point(435, 95)
    $selectedbttn.Size = New-Object System.Drawing.Size(130, 35)
    $selectedbttn.Text = 'Run Selected Tweaks'
    $selectedbttn.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $selectedbttn.ForeColor = [System.Drawing.Color]::White
    $selectedbttn.Visible = $false
    $selectedbttn.Add_Click({

        #REVERSE LOGIC OF REMOVE TWEAKS

        #remove any previous custom reg file (just in case)
        Remove-Item "$env:temp\CustomTweaks.reg" -Force -ErrorAction SilentlyContinue | Out-Null

        $selectedTweaks10 = @()
        foreach ($item in $checkedListBox10.CheckedItems.GetEnumerator()) {
          $selectedTweaks10 += $item
        }
        #get tweaks 10
        $editedRegContent10 = @()
        $addTweak = $false
        
        foreach ($line in $regOptions10) {
          #if line has comment check it 
          if ($line -like ';*') {
            $name = $line -split ';'
            #if name is in addtweaks add the line and tweak until next ;
            if ($name[1].trim() -in $selectedTweaks10) {
              #add name
              $editedRegContent10 += $line
              $addTweak = $true

              #keep track of some options for later
              if ($name[1].trim() -eq 'Set background black') {
                Write-host 'black'
                $Global:blackWallpaper = $true
              }

              if ($name[1].trim() -eq 'Task Manager Always On Top') {
                Write-host 'task'
                $Global:taskMgrOnTop = $true
              }
            }
            else {
              #tweak is not in list
              $addTweak = $false
            }
          }
          else {
            if ($addTweak) {
              #add tweak
              $editedRegContent10 += $line
            }
          }
        }
        #get 11 tweaaks
        $selectedTweaks11 = @()
        foreach ($item in $checkedListBox11.CheckedItems.GetEnumerator()) {
          $selectedTweaks11 += $item
        }
        #get tweaks 11
        $editedRegContent11 = @()
        $addTweak = $false
        
        foreach ($line in $regOptions11) {
          #if line has comment check it 
          if ($line -like ';*') {
            $name = $line -split ';'
            #if name is in addtweaks add the line and tweak until next ;
            if ($name[1].trim() -in $selectedTweaks11) {
              #add name
              $editedRegContent11 += $line
              $addTweak = $true
            }
            else {
              #tweak is not in list
              $addTweak = $false
            }
          }
          else {
            if ($addTweak) {
              #add tweak
              $editedRegContent11 += $line
            }
          }
        }

        Add-Content "$env:temp\CustomTweaks.reg" -Value "Windows Registry Editor Version 5.00`r`n" -Force
        Add-Content "$env:temp\CustomTweaks.reg" -Value $editedRegContent10 -Force
        Add-Content "$env:temp\CustomTweaks.reg" -Value $editedRegContent11 -Force

      })
    $selectedbttn.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form3.Controls.Add($selectedbttn)

    $changeModebttn = New-Object System.Windows.Forms.Button
    $changeModebttn.Location = New-Object System.Drawing.Point(435, 30)
    $changeModebttn.Size = New-Object System.Drawing.Size(90, 25)
    $changeModebttn.Text = 'Change Mode'
    $changeModebttn.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
    $changeModebttn.ForeColor = [System.Drawing.Color]::White
    $changeModebttn.Tag = $false
    $changeModebttn.add_Click({
        if ($changeModebttn.Tag -eq $false) {
          $label2.Text = 'Mode: Run Selected Tweaks'
          $selectedItemsBox.ForeColor = [System.Drawing.Color]::FromArgb(66, 245, 93) #light green
          $selectedbttn.Visible = $true
          $custom.Visible = $false
          $changeModebttn.Tag = $true
          $changeModebttn.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 20)
        }
        else {
          $label2.Text = 'Mode: Remove Selected Tweaks'
          $selectedItemsBox.ForeColor = 'Red'
          $selectedbttn.Visible = $false
          $custom.Visible = $true
          $changeModebttn.Tag = $false
          $changeModebttn.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
        }
      
      })
    $form3.Controls.Add($changeModebttn)

    $result = $form3.ShowDialog() 
  }
      
      
  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    #update config
    if (!($Autorun)) {
      update-config -setting 'registryTweaks' -value 1
    }

    function WallpaperRefresh {
      #refresh wallpaper to apply black color on 24h2 using winapi
      Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class WallpaperRefresh {
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool InvalidateRect(IntPtr hWnd, IntPtr lpRect, bool bErase);
    
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
'@

      $SPI_SETDESKWALLPAPER = 0x0014
      $SPIF_UPDATEINIFILE = 0x01
      $SPIF_SENDCHANGE = 0x02

      # set wallpaper blank
      $blankWallpaper = ''
      [WallpaperRefresh]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $blankWallpaper, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)

      #refresh wallpaper
      [WallpaperRefresh]::InvalidateRect(0, [IntPtr]::Zero, $true)
    }


    function UpdateVisuals {
      #update any visual other visual changes
      #run 5 times as multiple visual changes will be applied
      1..5 | ForEach-Object { 
        & RUNDLL32.EXE user32.dll, UpdatePerUserSystemParameters , 1 , True 
        Start-Sleep -Milliseconds 5
      } 
    }

    function MSIMode {
      #set gpu msi mode
      $instanceID = (Get-PnpDevice -Class Display).InstanceId
      Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\$instanceID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v 'MSISupported' /t REG_DWORD /d '1' /f *>$null
    }

    function PassExpire {
      $OS = Get-CimInstance Win32_OperatingSystem
      if ($OS.BuildNumber -gt 19045) {
        #disable password expire for 11
        net accounts /maxpwage:unlimited *>$null
      }
    }

    function TaskOnTopW11 {
      $OS = Get-CimInstance Win32_OperatingSystem
      if ($OS.BuildNumber -gt 19045) {
        #apply taskmanager always on top for win11
        $settingsFile = "$env:LOCALAPPDATA\Microsoft\Windows\TaskManager\settings.json"

        #kill taskmanager if its open
        Stop-Process -Name Taskmgr -Force -ErrorAction SilentlyContinue

        $jsonContent = Get-Content -Path $settingsFile -Raw | ConvertFrom-Json
        #add always ontop property
        $jsonContent | Add-Member -NotePropertyName 'AlwaysOnTop' -NotePropertyValue $true -Force

        $jsonContent | ConvertTo-Json -Depth 10 | Set-Content -Path $settingsFile
      }

    
    }

    if (Test-Path "$env:temp\CustomTweaks.reg") {
      #custom reg tweaks selected
      $regContent = Get-Content "$env:temp\CustomTweaks.reg" -Force

      Set-Content "$env:USERPROFILE\Desktop\RegTweaks.reg" -Value $regContent -Force

      Write-Status -Message 'Applying Registry Tweaks...' -Type Output
      #run tweaks
      regedit.exe /s "$env:USERPROFILE\Desktop\RegTweaks.reg"
      Start-Sleep 2

      if ($Global:blackWallpaper) {
        WallpaperRefresh
      }

      if ($Global:taskMgrOnTop) {
        TaskOnTopW11
      }

      PassExpire
      MSIMode
      UpdateVisuals

      #prevent event log error from disabling uac
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\luafv' /v 'Start' /t REG_DWORD /d '4' /f
      
      Write-Status -Message 'Restarting Explorer...' -Type Output
      #final refresh 
      Stop-Process -name 'sihost' -force

      #cleanup
      Remove-Item "$env:temp\CustomTweaks.reg" -Force -ErrorAction SilentlyContinue
    }
    else {

      $reg10 = Search-File '*RegistryTweaks10.txt'
      $regContent10 = Get-Content $reg10 -Force
      Set-Content "$env:TEMP\RegTweaks10.reg" -Value $regContent10 -Force | Out-Null
      $regContentTotal = $regContent10
      $OS = Get-CimInstance Win32_OperatingSystem
      if ($OS.BuildNumber -gt 19045) {
        #add win 11 tweaks
        $reg11 = Search-File '*RegistryTweaks11.txt'
        $regContent11 = Get-Content $reg11 -Force
        New-Item "$env:TEMP\RegTweaks11.reg" -Value "Windows Registry Editor Version 5.00`r`n" -Force | Out-Null
        Add-Content "$env:TEMP\RegTweaks11.reg" -Value $regContent11 -Force | Out-Null
        $regContentTotal += $regContent11
      }

      #create full reg tweaks on desktop but run win10 and 11 seperate to avoid some keys not applying
      Set-Content "$env:USERPROFILE\Desktop\RegTweaks.reg" -Value $regContentTotal -Force

      Write-Status -Message 'Applying Registry Tweaks...' -Type Output
      #run tweaks
      regedit.exe /s "$env:TEMP\RegTweaks10.reg"
      Start-Sleep 2
      if (Test-Path "$env:TEMP\RegTweaks11.reg") {
        regedit.exe /s "$env:TEMP\RegTweaks11.reg"
      }
      Start-Sleep 2

      WallpaperRefresh
      TaskOnTopW11
      PassExpire
      MSIMode
      UpdateVisuals

      #prevent event log error from disabling uac
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\luafv' /v 'Start' /t REG_DWORD /d '4' /f
      
      Remove-Item "$env:TEMP\RegTweaks10.reg" -Force -ErrorAction SilentlyContinue
      Remove-Item "$env:TEMP\RegTweaks11.reg" -Force -ErrorAction SilentlyContinue
      
      Write-Status -Message 'Restarting Explorer...' -Type Output
      #final refresh 
      Stop-Process -name 'sihost' -force
    }

    
  
    if (!($Autorun)) {
      Custom-MsgBox -message 'Registry Tweaks Applied!' -type None
    }
        
  }
  
}
Export-ModuleMember -Function import-reg






function install-packs {
  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
  )
      
         
      
  if ($AutoRun) {
    $msgBoxInput = 'OK'
  }
  else {
    $msgBoxInput = Custom-MsgBox -message 'Install DX, C++ Packages and NET 3.5?' -type Question
  }
        
        
  switch ($msgBoxInput) {
        
    'OK' {
      #update config
      if (!($Autorun)) {
        update-config -setting 'installPackages' -value 1
      }
      
      Write-Status -Message 'Attempting to install...' -Type Output
     
      try {
        
        $installDir = $PSScriptRoot 
        #install C++
        $ProgressPreference = 'SilentlyContinue'
        $url = 'https://api.github.com/repos/abbodi1406/vcredist/releases/latest'
        $response = Invoke-RestMethod -Uri $url -UseBasicParsing -ErrorAction Stop
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
        Write-Status -Message 'Installing...' -Type Output
    
        #dirty fix for dxinstaller bug
        Start-Process "$installDir\DX\DXSETUP.exe" -ArgumentList '/silent'
        $wshell = New-Object -ComObject wscript.shell
        Start-Sleep 1
        #get title of all open windows
        $openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object MainWindowTitle
        foreach ($window in $openWindows) {
          #if the dxinstaller is open press enter to close it and run with other command
          if ($window -like '*DirectX*') {
            $wshell.SendKeys('~')
            Start-Process "$installDir\DX\DXSETUP.exe" -ArgumentList '/quiet' -Wait
          }

        }
        #run Cpp installer
        Start-Process "$installDir\VisualCppRedist_AIO_x86_x64.exe" -ArgumentList '/ai /gm2' -WindowStyle Hidden -Wait
        
      }
      catch {
        Write-Status -Message 'Unable to install packages...Make sure you are connected to the internet' -Type Error
        
      }
        
      
      $result = Custom-MsgBox -message 'Please make sure your Windows Installation Flash Drive is plugged in' -type Warning
      if ($result -eq 'OK') {
        #search for drive with installwim
        #$driveLetters = @('D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z')
        #get current drive letters
        $drives = Get-PSDrive
        $driveLetters = @()
        foreach ($drive in $drives) {
          if ($drive.Provider -match 'FileSystem' -and $drive.Name -notmatch 'C') {
            $driveLetters += $drive.Name
          }
        }
      
        $driveFound = $false
        foreach ($driveLetter in $driveLetters) {
          if (Test-Path "$($driveLetter):\sources\install.wim") {
            Write-Status -Message 'Installing NET 3.5...' -Type Output
        
            Dism /online /enable-feature /featurename:NetFX3 /All /Source:$($driveLetter):\sources\sxs /LimitAccess
            $driveFound = $true
            break
          }
        }
    
        
      
        #cant find install wim 
        if (!($driveFound)) {
          Write-Status -Message 'Drive NOT Found...' -Type Error
        
        }
      }
      
      Write-Status -Message 'Cleaning up...[Running Background Tasks]' -Type Output
   
      $burntToast = Search-Directory -filter '*BurntToast'
      #steal icon from startmenu resources
      $exeImage = 'C:\Windows\SystemApps\MicrosoftWindows.Client.Core_cw5n1h2txyewy\StartMenu\Assets\FileIcons\32\exe.scale-400.png'
      $ngenPath = [System.IO.Path]::Combine([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory(), 'ngen.exe')
      $command = "Import-Module -name $burntToast; New-BurntToastNotification  -Text 'Ngen Process' , 'Running' -applogo $exeImage; Start-process $ngenPath -ArgumentList 'update /silent /nologo' -WindowStyle Hidden -Wait; New-BurntToastNotification  -Text 'Ngen Process' , 'Complete' -applogo $exeImage" 
      Start-Process powershell -ArgumentList "-noprofile -windowstyle hidden -c $command"   

      $command = "Import-Module -name $burntToast; New-BurntToastNotification  -Text 'DISM Process' , 'Running' -applogo $exeImage; Start-Process dism.exe -ArgumentList '/online /Cleanup-Image /StartComponentCleanup /ResetBase' -WindowStyle Hidden -Wait; New-BurntToastNotification  -Text 'DISM Process' , 'Complete' -applogo $exeImage"
      Start-Process powershell -ArgumentList "-noprofile -windowstyle hidden -c $command" 
          
      if (!($Autorun)) {
        Custom-MsgBox -message 'Packages Installed!' -type None
      }
          
    }
        
    'Cancel' {}
        
  }
}
Export-ModuleMember -Function install-packs

function OptionalTweaks {
  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
    , [Parameter(mandatory = $false)] [bool]$opblackTheme = $false
    , [Parameter(mandatory = $false)] [bool]$opclassicTheme = $false 
    , [Parameter(mandatory = $false)] [bool]$opROFSW = $false 
    , [Parameter(mandatory = $false)] [bool]$openableHAGS = $false 
    , [Parameter(mandatory = $false)] [bool]$optransTaskbar = $false
    , [Parameter(mandatory = $false)] [bool]$opremoveMouseSoundSchemes = $false 
    , [Parameter(mandatory = $false)] [bool]$opremoveRecycle = $false
    , [Parameter(mandatory = $false)] [bool]$opremoveQuickAccess = $false
    , [Parameter(mandatory = $false)] [bool]$opblockRazerAsus = $false
    , [Parameter(mandatory = $false)] [bool]$opremoveNetworkIcon = $false 
    , [Parameter(mandatory = $false)] [bool]$opapplyPBO = $false
    , [Parameter(mandatory = $false)] [bool]$opnoDriversInUpdate = $false
    , [Parameter(mandatory = $false)] [bool]$openable11Sounds = $false
    , [Parameter(mandatory = $false)] [bool]$connewFiles = $false
    , [Parameter(mandatory = $false)] [bool]$conmorePS = $false
    , [Parameter(mandatory = $false)] [bool]$consnipping = $false
    , [Parameter(mandatory = $false)] [bool]$conshutdown = $false
    , [Parameter(mandatory = $false)] [bool]$conrunAsAdmin = $false
    , [Parameter(mandatory = $false)] [bool]$conpsCmd = $false 
    , [Parameter(mandatory = $false)] [bool]$conkillTasks = $false 
    , [Parameter(mandatory = $false)] [bool]$conpermDel = $false
    , [Parameter(mandatory = $false)] [bool]$conTakeOwn = $false
    , [Parameter(mandatory = $false)] [bool]$conFavorites = $false
    , [Parameter(mandatory = $false)] [bool]$conCustomizeFolder = $false
    , [Parameter(mandatory = $false)] [bool]$conGiveAccess = $false
    , [Parameter(mandatory = $false)] [bool]$conOpenTerm = $false
    , [Parameter(mandatory = $false)] [bool]$conRestorePrev = $false
    , [Parameter(mandatory = $false)] [bool]$conPrint = $false
    , [Parameter(mandatory = $false)] [bool]$conSend = $false
    , [Parameter(mandatory = $false)] [bool]$conShare = $false
    , [Parameter(mandatory = $false)] [bool]$conPersonalize = $false
    , [Parameter(mandatory = $false)] [bool]$conDisplay = $false
    , [Parameter(mandatory = $false)] [bool]$opSecUpdatesOnly = $false
    , [Parameter(mandatory = $false)] [bool]$conExtractAll = $false
    , [Parameter(mandatory = $false)] [bool]$oppauseUpdates = $false
    , [Parameter(mandatory = $false)] [bool]$conTroubleshootComp = $false
    , [Parameter(mandatory = $false)] [bool]$conIncludeLibrary = $false
    , [Parameter(mandatory = $false)] [bool]$opStopOSUpgrade = $false
    , [Parameter(mandatory = $false)] [bool]$opDisablePowerShellLogs = $false
    , [Parameter(mandatory = $false)] [bool]$opNoGUIBoot = $false
    , [Parameter(mandatory = $false)] [bool]$opDisablePlatBinTable = $false
    , [Parameter(mandatory = $false)] [bool]$opGameBarPopup = $false
    , [Parameter(mandatory = $false)] [bool]$opFastShutdownRestart = $false
    , [Parameter(mandatory = $false)] [bool]$opRemoveBackupApp = $false
  )
        
      
      
      
  #create checkboxes
  $checkbox2 = new-object System.Windows.Forms.checkbox
  $classicblackBTN = new-object System.Windows.Forms.checkbox
  $checkbox4 = new-object System.Windows.Forms.checkbox
  $checkbox7 = new-object System.Windows.Forms.checkbox
  $checkbox8 = new-object System.Windows.Forms.checkbox
  $checkbox9 = new-object System.Windows.Forms.checkbox
  $checkbox13 = new-object System.Windows.Forms.checkbox
  $checkbox14 = new-object System.Windows.Forms.checkbox
  $checkbox15 = new-object System.Windows.Forms.checkbox
  $checkbox16 = new-object System.Windows.Forms.checkbox
  $checkbox17 = new-object System.Windows.Forms.checkbox
  $checkbox18 = new-object System.Windows.Forms.checkbox
  $checkbox19 = new-object System.Windows.Forms.checkbox
  $checkbox20 = new-object System.Windows.Forms.checkbox
  $checkbox26 = new-object System.Windows.Forms.checkbox
  $checkbox23 = new-object System.Windows.Forms.checkbox
  $checkbox24 = new-object System.Windows.Forms.checkbox
  $checkbox29 = new-object System.Windows.Forms.checkbox
  $checkbox31 = new-object System.Windows.Forms.checkbox
  $checkbox32 = new-object System.Windows.Forms.checkbox
  $checkbox33 = new-object System.Windows.Forms.checkbox
  $checkbox34 = new-object System.Windows.Forms.checkbox
  $checkbox35 = new-object System.Windows.Forms.checkbox
  $checkbox36 = new-object System.Windows.Forms.checkbox
  $checkbox37 = new-object System.Windows.Forms.checkbox    
  $checkbox38 = new-object System.Windows.Forms.checkbox 
  $checkbox39 = new-object System.Windows.Forms.checkbox
  $checkbox40 = new-object System.Windows.Forms.checkbox
  $checkbox41 = new-object System.Windows.Forms.checkbox
  $checkbox42 = new-object System.Windows.Forms.checkbox
  $checkbox43 = new-object System.Windows.Forms.checkbox
  $checkbox44 = new-object System.Windows.Forms.checkbox
  $checkbox45 = new-object System.Windows.Forms.checkbox
  $checkbox46 = new-object System.Windows.Forms.checkbox
  $checkbox47 = new-object System.Windows.Forms.checkbox
  $checkbox48 = new-object System.Windows.Forms.checkbox
  $checkbox49 = new-object System.Windows.Forms.checkbox
  $checkbox50 = new-object System.Windows.Forms.checkbox
  $checkbox51 = new-object System.Windows.Forms.checkbox
  $checkbox52 = new-object System.Windows.Forms.checkbox
  $checkbox53 = new-object System.Windows.Forms.checkbox
  $checkbox54 = new-object System.Windows.Forms.checkbox
  $checkbox55 = new-object System.Windows.Forms.checkbox
  $checkbox56 = new-object System.Windows.Forms.checkbox

  #hashtable for updating config
  $settings = @{}
  $settings['opblackTheme'] = $checkbox2
  $settings['opclassicTheme'] = $classicblackBTN
  $settings['opROFSW'] = $checkbox4
  $settings['openableHAGS'] = $checkbox7
  $settings['optransTaskbar'] = $checkbox8
  $settings['opremoveQuickAccess'] = $checkbox9
  $settings['opblockRazerAsus'] = $checkbox13
  $settings['connewFiles'] = $checkbox14
  $settings['conmorePS'] = $checkbox15
  $settings['consnipping'] = $checkbox16
  $settings['conshutdown'] = $checkbox17
  $settings['conrunAsAdmin'] = $checkbox18
  $settings['conpsCmd'] = $checkbox19
  $settings['conkillTasks'] = $checkbox20
  $settings['conpermDel'] = $checkbox26
  $settings['opremoveNetworkIcon'] = $checkbox23
  $settings['opapplyPBO'] = $checkbox24
  $settings['opnoDriversInUpdate'] = $checkbox29
  $settings['opremoveMouseSoundSchemes'] = $checkbox31
  $settings['openable11Sounds'] = $checkbox32
  $settings['opremoveRecycle'] = $checkbox33
  $settings['conTakeOwn'] = $checkbox34
  $settings['conFavorites'] = $checkbox35
  $settings['conCustomizeFolder'] = $checkbox36
  $settings['conGiveAccess'] = $checkbox37
  $settings['conOpenTerm'] = $checkbox38
  $settings['conRestorePrev'] = $checkbox39
  $settings['conPrint'] = $checkbox40
  $settings['conSend'] = $checkbox41
  $settings['conShare'] = $checkbox42
  $settings['conPersonalize'] = $checkbox43
  $settings['conDisplay'] = $checkbox44
  $settings['opSecUpdatesOnly'] = $checkbox45
  $settings['conExtractAll'] = $checkbox46
  $settings['oppauseUpdates'] = $checkbox47
  $settings['conTroubleshootComp'] = $checkbox48
  $settings['conIncludeLibrary'] = $checkbox49
  $settings['opStopOSUpgrade'] = $checkbox50
  $settings['opDisablePowerShellLogs'] = $checkbox51
  $settings['opNoGUIBoot'] = $checkbox52
  $settings['opDisablePlatBinTable'] = $checkbox53
  $settings['opGameBarPopup'] = $checkbox54
  $settings['opFastShutdownRestart'] = $checkbox55
  $settings['opRemoveBackupApp'] = $checkbox56
      
  if ($AutoRun) {
    $result = [System.Windows.Forms.DialogResult]::OK
    #setting options
    $checkbox2.Checked = $opblackTheme 
    $classicblackBTN.Checked = $opclassicTheme  
    $checkbox4.Checked = $opROFSW  
    $checkbox7.Checked = $openableHAGS
    $checkbox8.Checked = $optransTaskbar
    $checkbox9.Checked = $opremoveQuickAccess
    $checkbox13.Checked = $opblockRazerAsus
    $checkbox14.Checked = $connewFiles
    $checkbox15.Checked = $conmorePS
    $checkbox16.Checked = $consnipping
    $checkbox17.Checked = $conshutdown
    $checkbox18.Checked = $conrunAsAdmin
    $checkbox19.Checked = $conpsCmd
    $checkbox20.Checked = $conkillTasks
    $checkbox26.Checked = $conpermDel
    $checkbox23.Checked = $opremoveNetworkIcon
    $checkbox24.Checked = $opapplyPBO
    $checkbox29.Checked = $opnoDriversInUpdate
    $checkbox31.Checked = $opremoveMouseSoundSchemes
    $checkbox32.Checked = $openable11Sounds
    $checkbox33.Checked = $opremoveRecycle
    $checkbox34.Checked = $conTakeOwn
    $checkbox35.Checked = $conFavorites
    $checkbox36.Checked = $conCustomizeFolder
    $checkbox37.Checked = $conGiveAccess
    $checkbox38.Checked = $conOpenTerm
    $checkbox39.Checked = $conRestorePrev
    $checkbox40.Checked = $conPrint
    $checkbox41.Checked = $conSend
    $checkbox42.Checked = $conShare
    $checkbox43.Checked = $conPersonalize
    $checkbox44.Checked = $conDisplay
    $checkbox45.Checked = $opSecUpdatesOnly
    $checkbox46.Checked = $conExtractAll
    $checkbox47.Checked = $oppauseUpdates
    $checkbox48.Checked = $conTroubleshootComp
    $checkbox49.Checked = $conIncludeLibrary
    $checkbox50.Checked = $opStopOSUpgrade
    $checkbox51.Checked = $opDisablePowerShellLogs
    $checkbox52.Checked = $opNoGUIBoot
    $checkbox53.Checked = $opDisablePlatBinTable
    $checkbox54.Checked = $opGameBarPopup
    $checkbox55.Checked = $opFastShutdownRestart
    $checkbox56.Checked = $opRemoveBackupApp
  }
  else {
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # Set the size of your form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Optional Tweaks'
    $form.Size = New-Object System.Drawing.Size(800, 600)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

    
    # Sidebar Panel
    $sidebarPanel = New-Object System.Windows.Forms.Panel
    $sidebarPanel.Location = New-Object System.Drawing.Point(0, 0)
    $sidebarPanel.Size = New-Object System.Drawing.Size(150, $form.ClientSize.Height)
    $sidebarPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

    # Sidebar Buttons
    $generalBtn = New-Object System.Windows.Forms.Button
    $generalBtn.Location = New-Object System.Drawing.Point(10, 10)
    $generalBtn.Size = New-Object System.Drawing.Size(130, 40)
    $generalBtn.Text = 'General'
    $generalBtn.ForeColor = 'White'
    $generalBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
    $generalBtn.FlatAppearance.BorderSize = 0
    $generalBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $generalBtn.Tag = 'Inactive' # Initial state
    $generalBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $generalBtn.Add_MouseLeave({
        if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }
        else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) }
      })
    $sidebarPanel.Controls.Add($generalBtn)

    $contextMenuBtn = New-Object System.Windows.Forms.Button
    $contextMenuBtn.Location = New-Object System.Drawing.Point(10, 60)
    $contextMenuBtn.Size = New-Object System.Drawing.Size(130, 40)
    $contextMenuBtn.Text = 'Ultimate Context Menu'
    $contextMenuBtn.ForeColor = 'White'
    $contextMenuBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
    $contextMenuBtn.FlatAppearance.BorderSize = 0
    $contextMenuBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $contextMenuBtn.Tag = 'Inactive' # Initial state
    $contextMenuBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $contextMenuBtn.Add_MouseLeave({
        if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }
        else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) }
      })
    $sidebarPanel.Controls.Add($contextMenuBtn)

    $form.Controls.Add($sidebarPanel)


    $url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#optional-tweaks'
    $infobutton = New-Object Windows.Forms.Button
    $infobutton.Location = New-Object Drawing.Point(5, 530) # Adjusted to bottom-left of sidebar
    $infobutton.Size = New-Object Drawing.Size(30, 27)
    $infobutton.Cursor = 'Hand'
    $infobutton.Add_Click({
        try {
          Start-Process $url -ErrorAction Stop
        }
        catch {
          Write-Status -Message 'No Internet Connected...' -Type Error
        }
      })
    $infobutton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $image = [System.Drawing.Image]::FromFile('C:\Windows\System32\SecurityAndMaintenance.png')
    $resizedImage = New-Object System.Drawing.Bitmap $image, 24, 25
    $infobutton.Image = $resizedImage
    $infobutton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $infobutton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $infobutton.FlatAppearance.BorderSize = 0
    $sidebarPanel.Controls.Add($infobutton)

    # Main Content Panel
    $contentPanel = New-Object System.Windows.Forms.Panel
    $contentPanel.Location = New-Object System.Drawing.Point(160, 10)
    $contentPanel.Size = New-Object System.Drawing.Size(620, 500)
    $contentPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $form.Controls.Add($contentPanel)

    # General Panel
    $generalPanel = New-Object System.Windows.Forms.Panel
    $generalPanel.Location = New-Object System.Drawing.Point(0, 0)
    $generalPanel.Size = New-Object System.Drawing.Size(620, 500)
    $generalPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $generalPanel.Visible = $true
    $contentPanel.Controls.Add($generalPanel)

    # Context Menu Panel
    $contextMenuPanel = New-Object System.Windows.Forms.Panel
    $contextMenuPanel.Location = New-Object System.Drawing.Point(0, 0)
    $contextMenuPanel.Size = New-Object System.Drawing.Size(620, 500)
    $contextMenuPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $contextMenuPanel.Visible = $false
    $contentPanel.Controls.Add($contextMenuPanel)

    # Labels
    $label1 = New-Object System.Windows.Forms.Label
    $label1.Location = New-Object System.Drawing.Point(10, 10)
    $label1.Size = New-Object System.Drawing.Size(200, 20)
    $label1.Text = 'General'
    $label1.ForeColor = 'White'
    $label1.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $generalPanel.Controls.Add($label1)

    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(20, 10)
    $label2.Size = New-Object System.Drawing.Size(200, 20)
    $label2.Text = 'Add to Menu'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $contextMenuPanel.Controls.Add($label2)

    $label3 = New-Object System.Windows.Forms.Label
    $label3.Location = New-Object System.Drawing.Point(270, 10)
    $label3.Size = New-Object System.Drawing.Size(200, 20)
    $label3.Text = 'Remove From Menu'
    $label3.ForeColor = 'White'
    $label3.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $contextMenuPanel.Controls.Add($label3)

    # Checkbox Code (keeping the original structure)
    $checkbox2.Location = New-Object System.Drawing.Size(10, 40)
    $checkbox2.Size = New-Object System.Drawing.Size(150, 20)
    $checkbox2.Text = 'Black Theme'
    $checkbox2.ForeColor = 'White'
    $checkbox2.Checked = $false
    $form.Controls.Add($checkbox2)
    $generalPanel.Controls.Add($checkbox2)

    $classicblackBTN.Location = New-Object System.Drawing.Size(20, 70)
    $classicblackBTN.Size = New-Object System.Drawing.Size(150, 20)
    $classicblackBTN.Text = 'Classic Black Theme'
    $classicblackBTN.ForeColor = 'White'
    $classicblackBTN.Checked = $false
    $classicblackBTN.Visible = $true
    $form.Controls.Add($classicblackBTN)
    $generalPanel.Controls.Add($classicblackBTN)

    $checkbox4.Location = New-Object System.Drawing.Size(10, 100)
    $checkbox4.Size = New-Object System.Drawing.Size(210, 30)
    $checkbox4.Text = 'Remove Open File Security Warning'
    $checkbox4.ForeColor = 'White'
    $checkbox4.Checked = $false
    $form.Controls.Add($checkbox4)
    $generalPanel.Controls.Add($checkbox4)

    $checkbox7.Location = New-Object System.Drawing.Size(10, 140)
    $checkbox7.Size = New-Object System.Drawing.Size(200, 20)
    $checkbox7.Text = 'Enable HAGS'
    $checkbox7.ForeColor = 'White'
    $checkbox7.Checked = $false
    $form.Controls.Add($checkbox7)
    $generalPanel.Controls.Add($checkbox7)

    $checkbox8.Location = New-Object System.Drawing.Size(10, 180)
    $checkbox8.Size = New-Object System.Drawing.Size(200, 20)
    $checkbox8.Text = 'Transparent Task Bar'
    $checkbox8.ForeColor = 'White'
    $checkbox8.Checked = $false
    $form.Controls.Add($checkbox8)
    $generalPanel.Controls.Add($checkbox8)

    $checkbox9.Location = New-Object System.Drawing.Size(260, 40)
    $checkbox9.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox9.Text = 'Remove Quick Access From File Explorer'
    $checkbox9.ForeColor = 'White'
    $checkbox9.Checked = $false
    $form.Controls.Add($checkbox9)
    $generalPanel.Controls.Add($checkbox9)

    $checkbox13.Location = New-Object System.Drawing.Size(260, 80)
    $checkbox13.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox13.Text = 'Block Razer and ASUS Download Servers'
    $checkbox13.ForeColor = 'White'
    $checkbox13.Checked = $false
    $form.Controls.Add($checkbox13)
    $generalPanel.Controls.Add($checkbox13)

    $checkbox23.Location = New-Object System.Drawing.Size(260, 120)
    $checkbox23.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox23.Text = 'Remove Network Icon From File Explorer'
    $checkbox23.ForeColor = 'White'
    $checkbox23.Checked = $false
    $form.Controls.Add($checkbox23)
    $generalPanel.Controls.Add($checkbox23)

    $checkbox24.Location = New-Object System.Drawing.Size(260, 160)
    $checkbox24.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox24.Text = 'Apply PBO Curve on Startup'
    $checkbox24.ForeColor = 'White'
    $checkbox24.Checked = $false
    $form.Controls.Add($checkbox24)
    $generalPanel.Controls.Add($checkbox24)

    $checkbox29.Location = New-Object System.Drawing.Size(260, 200)
    $checkbox29.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox29.Text = 'Do not include drivers in Windows Update'
    $checkbox29.ForeColor = 'White'
    $checkbox29.Checked = $false
    $form.Controls.Add($checkbox29)
    $generalPanel.Controls.Add($checkbox29)

    $checkbox31.Location = New-Object System.Drawing.Size(10, 220)
    $checkbox31.Size = New-Object System.Drawing.Size(210, 30)
    $checkbox31.Text = 'Remove Mouse and Sound Schemes'
    $checkbox31.ForeColor = 'White'
    $checkbox31.Checked = $false
    $form.Controls.Add($checkbox31)
    $generalPanel.Controls.Add($checkbox31)

    $checkbox32.Location = New-Object System.Drawing.Size(260, 240)
    $checkbox32.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox32.Text = 'Enable Windows 11 Sounds'
    $checkbox32.ForeColor = 'White'
    $checkbox32.Checked = $false
    $form.Controls.Add($checkbox32)
    $generalPanel.Controls.Add($checkbox32)

    $checkbox33.Location = New-Object System.Drawing.Size(260, 280)
    $checkbox33.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox33.Text = 'Remove Recycle Bin Name'
    $checkbox33.ForeColor = 'White'
    $checkbox33.Checked = $false
    $form.Controls.Add($checkbox33)
    $generalPanel.Controls.Add($checkbox33)

    $checkbox45.Location = New-Object System.Drawing.Size(10, 260)
    $checkbox45.Size = New-Object System.Drawing.Size(210, 30)
    $checkbox45.Text = 'Security Updates Only'
    $checkbox45.ForeColor = 'White'
    $checkbox45.Checked = $false
    $form.Controls.Add($checkbox45)
    $generalPanel.Controls.Add($checkbox45)

    $checkbox47.Location = New-Object System.Drawing.Size(260, 320)
    $checkbox47.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox47.Text = 'Pause Updates for 1 Year'
    $checkbox47.ForeColor = 'White'
    $checkbox47.Checked = $false
    $form.Controls.Add($checkbox47)
    $generalPanel.Controls.Add($checkbox47)

    $checkbox50.Location = New-Object System.Drawing.Size(10, 300)
    $checkbox50.Size = New-Object System.Drawing.Size(210, 30)
    $checkbox50.Text = 'Prevent OS Upgrade'
    $checkbox50.ForeColor = 'White'
    $checkbox50.Checked = $false
    $form.Controls.Add($checkbox50)
    $generalPanel.Controls.Add($checkbox50)

    $checkbox51.Location = New-Object System.Drawing.Size(260, 360)
    $checkbox51.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox51.Text = 'Disable PowerShell Logging'
    $checkbox51.ForeColor = 'White'
    $checkbox51.Checked = $false
    $form.Controls.Add($checkbox51)
    $generalPanel.Controls.Add($checkbox51)

    $checkbox52.Location = New-Object System.Drawing.Size(10, 340)
    $checkbox52.Size = New-Object System.Drawing.Size(210, 30)
    $checkbox52.Text = 'Enable No GUI Boot'
    $checkbox52.ForeColor = 'White'
    $checkbox52.Checked = $false
    $form.Controls.Add($checkbox52)
    $generalPanel.Controls.Add($checkbox52)

    $checkbox53.Location = New-Object System.Drawing.Size(260, 400)
    $checkbox53.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox53.Text = 'Disable Windows Platform Binary Table'
    $checkbox53.ForeColor = 'White'
    $checkbox53.Checked = $false
    $form.Controls.Add($checkbox53)
    $generalPanel.Controls.Add($checkbox53)

    $checkbox54.Location = New-Object System.Drawing.Size(10, 380)
    $checkbox54.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox54.Text = 'Disable Game Bar Popup'
    $checkbox54.ForeColor = 'White'
    $checkbox54.Checked = $false
    $form.Controls.Add($checkbox54)
    $generalPanel.Controls.Add($checkbox54)

    $checkbox55.Location = New-Object System.Drawing.Size(10, 420)
    $checkbox55.Size = New-Object System.Drawing.Size(220, 30)
    $checkbox55.Text = 'Enable Fast Shutdown/Restart'
    $checkbox55.ForeColor = 'White'
    $checkbox55.Checked = $false
    $form.Controls.Add($checkbox55)
    $generalPanel.Controls.Add($checkbox55)

    $checkbox56.Location = New-Object System.Drawing.Size(260, 440)
    $checkbox56.Size = New-Object System.Drawing.Size(270, 30)
    $checkbox56.Text = 'Remove Backup App'
    $checkbox56.ForeColor = 'White'
    $checkbox56.Checked = $false
    $form.Controls.Add($checkbox56)
    $generalPanel.Controls.Add($checkbox56)


    # Context Menu Checkboxes
    $checkbox14.Location = New-Object System.Drawing.Size(20, 40)
    $checkbox14.Size = New-Object System.Drawing.Size(225, 20)
    $checkbox14.Text = "Additional files to `New` Menu"
    $checkbox14.ForeColor = 'White'
    $checkbox14.Checked = $false
    $form.Controls.Add($checkbox14)
    $contextMenuPanel.Controls.Add($checkbox14)

    $checkbox15.Location = New-Object System.Drawing.Size(20, 70)
    $checkbox15.Size = New-Object System.Drawing.Size(190, 20)
    $checkbox15.Text = 'Additional ps1 options'
    $checkbox15.ForeColor = 'White'
    $checkbox15.Checked = $false
    $form.Controls.Add($checkbox15)
    $contextMenuPanel.Controls.Add($checkbox15)

    $checkbox16.Location = New-Object System.Drawing.Size(20, 100)
    $checkbox16.Size = New-Object System.Drawing.Size(190, 20)
    $checkbox16.Text = 'Snipping Tool'
    $checkbox16.ForeColor = 'White'
    $checkbox16.Checked = $false
    $form.Controls.Add($checkbox16)
    $contextMenuPanel.Controls.Add($checkbox16)

    $checkbox17.Location = New-Object System.Drawing.Size(20, 130)
    $checkbox17.Size = New-Object System.Drawing.Size(190, 20)
    $checkbox17.Text = 'Shutdown'
    $checkbox17.ForeColor = 'White'
    $checkbox17.Checked = $false
    $form.Controls.Add($checkbox17)
    $contextMenuPanel.Controls.Add($checkbox17)

    $checkbox18.Location = New-Object System.Drawing.Size(20, 160)
    $checkbox18.Size = New-Object System.Drawing.Size(250, 20)
    $checkbox18.Text = 'Run as Admin for ps1,bat,vbs files'
    $checkbox18.ForeColor = 'White'
    $checkbox18.Checked = $false
    $form.Controls.Add($checkbox18)
    $contextMenuPanel.Controls.Add($checkbox18)

    $checkbox19.Location = New-Object System.Drawing.Size(20, 190)
    $checkbox19.Size = New-Object System.Drawing.Size(250, 20)
    $checkbox19.Text = 'Powershell and Cmd'
    $checkbox19.ForeColor = 'White'
    $checkbox19.Checked = $false
    $form.Controls.Add($checkbox19)
    $contextMenuPanel.Controls.Add($checkbox19)

    $checkbox20.Location = New-Object System.Drawing.Size(20, 220)
    $checkbox20.Size = New-Object System.Drawing.Size(250, 20)
    $checkbox20.Text = 'Kill not Responding Tasks'
    $checkbox20.ForeColor = 'White'
    $checkbox20.Checked = $false
    $form.Controls.Add($checkbox20)
    $contextMenuPanel.Controls.Add($checkbox20)

    $checkbox26.Location = New-Object System.Drawing.Size(20, 250)
    $checkbox26.Size = New-Object System.Drawing.Size(250, 20)
    $checkbox26.Text = 'Delete Permanently'
    $checkbox26.ForeColor = 'White'
    $checkbox26.Checked = $false
    $form.Controls.Add($checkbox26)
    $contextMenuPanel.Controls.Add($checkbox26)

    $checkbox34.Location = New-Object System.Drawing.Size(20, 280)
    $checkbox34.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox34.Text = 'Take Ownership'
    $checkbox34.ForeColor = 'White'
    $checkbox34.Checked = $false
    $form.Controls.Add($checkbox34)
    $contextMenuPanel.Controls.Add($checkbox34)

    $checkbox35.Location = New-Object System.Drawing.Size(270, 40)
    $checkbox35.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox35.Text = 'Add to Favorites'
    $checkbox35.ForeColor = 'White'
    $checkbox35.Checked = $false
    $form.Controls.Add($checkbox35)
    $contextMenuPanel.Controls.Add($checkbox35)

    $checkbox36.Location = New-Object System.Drawing.Size(270, 70)
    $checkbox36.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox36.Text = 'Customize this Folder'
    $checkbox36.ForeColor = 'White'
    $checkbox36.Checked = $false
    $form.Controls.Add($checkbox36)
    $contextMenuPanel.Controls.Add($checkbox36)

    $checkbox37.Location = New-Object System.Drawing.Size(270, 100)
    $checkbox37.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox37.Text = 'Give Access to'
    $checkbox37.ForeColor = 'White'
    $checkbox37.Checked = $false
    $form.Controls.Add($checkbox37)
    $contextMenuPanel.Controls.Add($checkbox37)

    $checkbox38.Location = New-Object System.Drawing.Size(270, 130)
    $checkbox38.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox38.Text = 'Open in Terminal (Win 11)'
    $checkbox38.ForeColor = 'White'
    $checkbox38.Checked = $false
    $form.Controls.Add($checkbox38)
    $contextMenuPanel.Controls.Add($checkbox38)

    $checkbox39.Location = New-Object System.Drawing.Size(270, 160)
    $checkbox39.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox39.Text = 'Restore Previous Versions'
    $checkbox39.ForeColor = 'White'
    $checkbox39.Checked = $false
    $form.Controls.Add($checkbox39)
    $contextMenuPanel.Controls.Add($checkbox39)

    $checkbox40.Location = New-Object System.Drawing.Size(270, 190)
    $checkbox40.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox40.Text = 'Print'
    $checkbox40.ForeColor = 'White'
    $checkbox40.Checked = $false
    $form.Controls.Add($checkbox40)
    $contextMenuPanel.Controls.Add($checkbox40)

    $checkbox41.Location = New-Object System.Drawing.Size(270, 220)
    $checkbox41.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox41.Text = 'Send to'
    $checkbox41.ForeColor = 'White'
    $checkbox41.Checked = $false
    $form.Controls.Add($checkbox41)
    $contextMenuPanel.Controls.Add($checkbox41)

    $checkbox42.Location = New-Object System.Drawing.Size(270, 250)
    $checkbox42.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox42.Text = 'Share'
    $checkbox42.ForeColor = 'White'
    $checkbox42.Checked = $false
    $form.Controls.Add($checkbox42)
    $contextMenuPanel.Controls.Add($checkbox42)

    $checkbox43.Location = New-Object System.Drawing.Size(270, 280)
    $checkbox43.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox43.Text = 'Personalize (Desktop)'
    $checkbox43.ForeColor = 'White'
    $checkbox43.Checked = $false
    $form.Controls.Add($checkbox43)
    $contextMenuPanel.Controls.Add($checkbox43)

    $checkbox44.Location = New-Object System.Drawing.Size(270, 310)
    $checkbox44.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox44.Text = 'Display (Desktop)'
    $checkbox44.ForeColor = 'White'
    $checkbox44.Checked = $false
    $form.Controls.Add($checkbox44)
    $contextMenuPanel.Controls.Add($checkbox44)

    $checkbox46.Location = New-Object System.Drawing.Size(270, 340)
    $checkbox46.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox46.Text = 'Extract All for Archive Files'
    $checkbox46.ForeColor = 'White'
    $checkbox46.Checked = $false
    $form.Controls.Add($checkbox46)
    $contextMenuPanel.Controls.Add($checkbox46)

    $checkbox48.Location = New-Object System.Drawing.Size(270, 370)
    $checkbox48.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox48.Text = 'Troubleshoot Compatibility'
    $checkbox48.ForeColor = 'White'
    $checkbox48.Checked = $false
    $form.Controls.Add($checkbox48)
    $contextMenuPanel.Controls.Add($checkbox48)

    $checkbox49.Location = New-Object System.Drawing.Size(270, 400)
    $checkbox49.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox49.Text = 'Include in Library'
    $checkbox49.ForeColor = 'White'
    $checkbox49.Checked = $false
    $form.Controls.Add($checkbox49)
    $contextMenuPanel.Controls.Add($checkbox49)

    # OK and Cancel Buttons
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(340, 520)
    $OKButton.Size = New-Object System.Drawing.Size(100, 23)
    $OKButton.Text = 'OK'
    $OKButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $OKButton.ForeColor = [System.Drawing.Color]::White
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(450, 520)
    $CancelButton.Size = New-Object System.Drawing.Size(100, 23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $CancelButton.ForeColor = [System.Drawing.Color]::White
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    # Sidebar Button Click Events
    $generalBtn.Add_Click({
        $generalPanel.Visible = $true
        $contextMenuPanel.Visible = $false
        $generalBtn.Tag = 'Active'
        $contextMenuBtn.Tag = 'Inactive'
        $generalBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
        $contextMenuBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
      })

    $contextMenuBtn.Add_Click({
        $generalPanel.Visible = $false
        $contextMenuPanel.Visible = $true
        $contextMenuBtn.Tag = 'Active'
        $generalBtn.Tag = 'Inactive'
        $contextMenuBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
        $generalBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
      })

    # Activate the form
    $form.Add_Shown({ $form.Activate() })
    $result = $form.ShowDialog()
  }
      
      
  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
      
    if (!($Autorun)) {
      #loop through checkbox hashtable to update config
      $settings.GetEnumerator() | ForEach-Object {
            
        $settingName = $_.Key
        $checkbox = $_.Value
        
        if ($checkbox.Checked) {
          update-config -setting $settingName -value 1
        }
      }
    }  
      
    if ($checkbox2.Checked) {
      Write-Status -Message 'Applying Black Theme...' -Type Output
     
      if (test-path 'C:\UltimateContextMenu') {
        $path = 'C:\UltimateContextMenu\BlackTheme.reg'
        Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
      }
      else {
        $path = Search-Directory '*UltimateContextMenu'
        Move-item $path -Destination 'C:\'
      
        $path = 'C:\UltimateContextMenu\BlackTheme.reg'      
        Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
      
      }
              
      #setting lockscreen to black
      reg.exe delete 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' /v 'DisableLogonBackgroundImage' /f *>$null
      
      $path = Search-File '*Black.jpg'
      Move-Item $path -Destination 'C:\Windows' -Force
      
      New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP' -Force
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP' -Name 'LockScreenImagePath' -Value 'C:\Windows\Black.jpg' -Force
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP' -Name 'LockScreenImageStatus' -Value 1

      #change user pfp to black themed
      $userPfps = Search-Directory '*blackUserPics'
      $pfps = (Get-ChildItem -Path $userPfps).FullName
      #backup default pics
      if (!(Test-Path "$env:USERPROFILE\zBackup")) {
        New-Item "$env:USERPROFILE\zBackup" -ItemType Directory | Out-Null
      }
      $backup = New-Item "$env:USERPROFILE\zBackup\defaultUserPics" -ItemType Directory 
      $defaultUserPics = (Get-ChildItem -Path "$env:ProgramData\Microsoft\User Account Pictures" -Exclude '*.dat').FullName
      foreach ($pfp in $defaultUserPics) {
        Move-Item -Path $pfp -Destination $backup.FullName -Force 
      }
      #add black pics to multiple locations so that it updates all
      foreach ($blackPfp in $pfps) {
        Copy-Item $blackPfp -Destination "$env:ProgramData\Microsoft\User Account Pictures" -Force
      }
      
      $publicFolder = New-Item -Path "C:\Users\Public\AccountPictures\$env:USERNAME" -ItemType Directory -Force
      $userSID = Get-CimInstance Win32_UserAccount | Select-Object SID -First 1
      $regPath = New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users' -Name $userSID.SID -Force
      foreach ($blackPfp in $pfps) {
        $file = Copy-Item $blackPfp -Destination $publicFolder.FullName -Force -PassThru
        if ($file.FullName -match '\d+\.*') {
          $junk, $size = $file.FullName -split '-'
          $size = $size -replace '.png' , ''
        }
        else {
          $size = '448'
        }
        New-ItemProperty -Path "registry::$($regPath.Name)" -Name "Image$size" -Value $file.FullName -Force
      }
      
      if ($classicblackBTN.Checked) {
        Write-Status -Message 'Applying Classic Theme...' -Type Output
        $path = Search-File '*ClassicBlack.deskthemepack'
        &$path
        while ($true) {
      
          $settings = Get-Process -Name SystemSettings -ErrorAction SilentlyContinue
          if ($settings -ne $null) {
            Stop-Process $settings -Force
            break
          }
        }
      }
      
    }
            
    if ($checkbox4.Checked) {
      Write-Status -Message 'Disabling Blocked Files...' -Type Output
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Security' /V 'DisableSecuritySettingsCheck' /T 'REG_DWORD' /D '00000001' /F
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' /V '1806' /T 'REG_DWORD' /D '00000000' /F
      Reg.exe add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' /V '1806' /T 'REG_DWORD' /D '00000000' /F
      
    }
   
    if ($checkbox7.Checked) {
      Write-Status -Message 'Enabling HAGS...' -Type Output
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' /v 'HwSchMode' /t REG_DWORD /d '2' /f
      
    }
      
    if ($checkbox8.checked) {
      Write-Status -Message 'Applying Transparent Taskbar...' -Type Output
      $transTB = Search-File '*bundle.msixbundle'
      Add-AppxPackage $transTB
      #fix not working on startup
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableFullTrustStartupTasks' /t REG_DWORD /d '2' /f
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableUwpStartupTasks' /t REG_DWORD /d '2' /f
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'SupportFullTrustStartupTasks' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'SupportUwpStartupTasks' /t REG_DWORD /d '1' /f
      #clear explorer and shell temp cache to run ttb.exe from admin context
      taskkill /f /im explorer.exe *>$null
      taskkill /f /im shellexperiencehost.exe *>$null
      Remove-Item "$env:LOCALAPPDATA\Packages\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\TempState*" -Force -ErrorAction SilentlyContinue
      Start-Process explorer.exe
      Start-Process ttb.exe
      
    }
      
    if ($checkbox9.Checked) {
      Write-Status -Message 'Removing Quick Access...' -Type Output
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'HubMode' /t REG_DWORD /d '1' /f
      
    }
            
      
   
    if ($checkbox13.Checked) {
      Write-Status -Message 'Blocking Razer and ASUS Downloads via Hosts File...' -Type Output
      
      $hosts = 'C:\Windows\System32\drivers\etc\hosts'
      
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
      
    if ($checkbox14.Checked) {
      Write-Status -Message 'Adding bat,ps1, and reg to New File Menu...' -Type Output
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
        Start-Sleep 1
      }
      #fix for win 11
      $OS = Get-CimInstance Win32_OperatingSystem
      if ($OS.BuildNumber -gt 19045) {
        #run both to fix 24h2
        $path = 'C:\UltimateContextMenu\newMenu11.reg'
        Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist "/s $path" -Wait
        $path = 'C:\UltimateContextMenu\newMenu.reg'
        Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist "/s $path" -Wait

      }
      else {
        $path = 'C:\UltimateContextMenu\newMenu.reg'
      }
      
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist "/s $path" -Wait
      
    }
    if ($checkbox15.Checked) {
      Write-Status -Message 'Adding Additional Options to ps1 Files...' -Type Output  
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
        Start-Sleep 1
      }
      $path = 'C:\UltimateContextMenu\ps1Options.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist "/s $path" -Wait
    }
    if ($checkbox16.Checked) {
      Write-Status -Message 'Adding Snipping Tool to Context Menu...' -Type Output  
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
        Start-Sleep 1
      }
      #fix for win 11
      $OS = Get-CimInstance Win32_OperatingSystem
      if ($OS.BuildNumber -gt 19045) {
        $path = 'C:\UltimateContextMenu\Snipping11.reg'
      }
      else {
        $path = 'C:\UltimateContextMenu\Snipping.reg'
      }
      
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist "/s $path" -Wait
      
     
    }
    if ($checkbox17.Checked) {
      Write-Status -Message 'Adding Shutdown and Restart to Context Menu...' -Type Output  
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
        Start-Sleep 1
      }
      $path = 'C:\UltimateContextMenu\Shutdown.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist "/s $path" -Wait
      
    }
    if ($checkbox18.Checked) {
      Write-Status -Message 'Adding Run as Admin for ps1, bat, vbs files to Context Menu...' -Type Output  
      
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
        Start-Sleep 1
      }
      $path = 'C:\UltimateContextMenu\runAsAdmin.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist "/s $path" -Wait
    }
    if ($checkbox19.Checked) {
      Write-Status -Message 'Adding PowerShell and CMD to Context Menu...' -Type Output  
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
        Start-Sleep 1
      }
      $path = 'C:\UltimateContextMenu\powershellCmd.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist "/s $path" -Wait
      
    }
    if ($checkbox20.Checked) {
      Write-Status -Message 'Adding Kill Not Responding Tasks to Context Menu...' -Type Output  
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
        Start-Sleep 1
      }
      $path = 'C:\UltimateContextMenu\killTasks.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist "/s $path" -Wait
      
    }
      
    if ($checkbox26.Checked) {
      Write-Status -Message 'Adding Delete Permanently to Context Menu...' -Type Output  
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
        Start-Sleep 1
      }
      $path = 'C:\UltimateContextMenu\superdel.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist "/s $path"
      
    }
      
      
      
    if ($checkbox23.Checked) {
      Write-Status -Message 'Removing Network Icon From File Explorer...' -Type Output
      Reg.exe add 'HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' /v 'System.IsPinnedToNameSpaceTree' /t REG_DWORD /d '0' /f
      
    }
      
    if ($checkbox24.Checked) {
      
      #limits (in order)
      $ppt = '0'
      $tdc = '0'
      $edc = '0'
      
      
      Add-Type -AssemblyName System.Windows.Forms
      [System.Windows.Forms.Application]::EnableVisualStyles()

      # Retrieve the number of CPU cores
      $cpuCores = (Get-WmiObject -Class Win32_Processor).NumberOfCores
      
      $size = 300 + ($cpuCores * 20)
      
      # Create the form
      $form = New-Object System.Windows.Forms.Form
      $form.Text = 'PBO2 Tuner'
      $form.Size = New-Object System.Drawing.Size(400, $size)
      $form.StartPosition = 'CenterScreen'
      $form.BackColor = 'Black'
      $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
      $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)
      
      # Create a checkbox
      $checkBox = New-Object System.Windows.Forms.CheckBox
      $checkBox.Text = 'Custom Limits'
      $checkBox.ForeColor = 'White'
      $checkbox.Size = New-Object System.Drawing.Size(150, 15)
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
      $label1.Text = 'PPT'
      $label1.Location = New-Object System.Drawing.Point(190, 170)
      $label1.ForeColor = 'White'
      $label1.Visible = $false
      
      $label2 = New-Object System.Windows.Forms.Label
      $label2.Text = 'TDC'
      $label2.Location = New-Object System.Drawing.Point(190, 200)
      $label2.ForeColor = 'White'
      $label2.Visible = $false
      
      $label3 = New-Object System.Windows.Forms.Label
      $label3.Text = 'EDC'
      $label3.Location = New-Object System.Drawing.Point(190, 230)
      $label3.ForeColor = 'White'
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
          }
          else {
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
      $label.Text = 'Enter the Undervolt for each core:'
      $label.ForeColor = 'White'
      $form.Controls.Add($label)
      
      # Create the radio buttons
      $radioButtons = @()
      $values = @(-10, -20, -30)
      for ($i = 0; $i -lt $values.Count; $i++) {
        $radioButton = New-Object System.Windows.Forms.RadioButton
        $radioButton.Location = [System.Drawing.Point]::new(200, 40 + $i * 30)
        $radioButton.Size = [System.Drawing.Size]::new(60, 20)
        $radioButton.ForeColor = 'White'
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
        $coreLabel = 'Core ' + $coreNumber
          
        # Create the label
        $coreLabelControl = New-Object System.Windows.Forms.Label
        $coreLabelControl.Location = [System.Drawing.Point]::new(10, 40 + $i * 30)
        $coreLabelControl.Size = [System.Drawing.Size]::new(60, 20)
        $coreLabelControl.Text = $coreLabel
        $coreLabelControl.ForeColor = 'White'
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
      $button.ForeColor = 'White'
      $button.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
      $button.Text = 'Apply'
      $button.Add_Click({
  
          $pbo = Search-Directory '*PBOTuner'
          Move-item -Path $pbo -Destination 'C:\Program Files' -Force
          $exePath = 'C:\Program Files\PBOTuner\PBO2 tuner.exe'
      
          #format: (-)num cpu core undervolt ppt tdc edc 0
          if ($checkBox.Checked) {
      
            if ($limitBox1.Text -ne '') {
              $ppt = $limitBox1.Text
            }
      
            if ($limitBox2.Text -ne '') {
              $tdc = $limitBox2.Text
            }
      
            if ($limitBox3.Text -ne '') {
              $edc = $limitBox3.Text
      
            }
      
            $values = ($textBoxes.ForEach({ $_.Text }) -join ' ') + ' ' + $ppt + ' ' + $tdc + ' ' + $edc + ' 0'
          }
          else {
            $values = $textBoxes.ForEach({ $_.Text }) -join ' '
      
          }
          $taskName = 'PBO Tuner'
      
      
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
      
      
      
    if ($checkbox29.Checked) {
      Write-Status -Message 'Excluding Drivers From Windows Update...' -Type Output
   
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' /v 'SearchOrderConfig' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\PolicyState' /v 'ExcludeWUDrivers' /t REG_DWORD /d '1' /f
      Write-Status -Message 'Updating Policy...' -Type Output
    
      gpupdate /force
    }
      
      
      
    if ($checkbox31.Checked) {
      Write-Status -Message 'Removing Mouse and Sound Schemes...' -Type Output
    
      Reg.exe add 'HKCU\AppEvents\Schemes' /ve /t REG_SZ /d '.None' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\.Default\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\MailBeep\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\SystemHand\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current' /f
      Reg.exe delete 'HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current' /f
      Reg.exe add 'HKCU\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current' /f
      Reg.exe add 'HKCU\Control Panel\Cursors' /v 'ContactVisualization' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKCU\Control Panel\Cursors' /v 'GestureVisualization' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKCU\Control Panel\Cursors' /v 'Scheme Source' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKCU\Control Panel\Cursors' /ve /t REG_SZ /d ' ' /f
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'AppStarting' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'Arrow' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'Crosshair' -Force -ErrorAction SilentlyContinue
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'Hand' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'IBeam' -Force -ErrorAction SilentlyContinue
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'No' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'NWPen' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'SizeAll' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'SizeNESW' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'SizeNS' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'SizeNWSE' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'SizeWE' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'UpArrow' -Force
      Clear-ItemProperty -Path 'registry::HKCU\Control Panel\Cursors' -Name 'Wait' -Force
      
    }
      
      
    if ($checkbox32.Checked) {
      Write-Status -Message 'Backing Up Windows 10 Sounds and Replacing with Windows 11...' -Type Output
      if (!(Test-Path "$env:USERPROFILE\zBackup")) {
        New-Item "$env:USERPROFILE\zBackup" -ItemType Directory | Out-Null
      }
      $soundBackup = "$env:USERPROFILE\zBackup\Windows10Sounds"
      New-Item $soundBackup -ItemType Directory | Out-Null
      $win10sounds = Get-ChildItem -Path C:\Windows\Media -Recurse -Filter 'Windows*' | ForEach-Object { $_.FullName }
      foreach ($sound in $win10sounds) {
      
        Copy-Item -Path $sound -Destination $soundBackup -Force
      
      }
      
      
      $path = Search-Directory '*win11sounds'
      $command = "`$sounds = Get-ChildItem -Path $path -Recurse -Force | ForEach-Object { `$_.FullName }; foreach(`$sound in `$sounds){Move-item `$sound -destination C:\Windows\Media -force}"

      Run-Trusted -command $command
      
      
      
      
    }
      
    if ($checkbox33.Checked) {
      Write-Status -Message 'Removing Recycle Bin Icon Text...' -Type Output
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}' /ve /t REG_SZ /d ' ' /f
      
    }
      
   
    if ($checkbox34.Checked) {
      Write-Status -Message 'Adding Take Ownership to Context Menu...' -Type Output
      Reg.exe add 'HKCR\*\shell\runas' /ve /t REG_SZ /d 'Take Ownership' /f
      Reg.exe add 'HKCR\*\shell\runas\command' /ve /t REG_SZ /d 'cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F' /f
      Reg.exe add 'HKCR\*\shell\runas\command' /v 'IsolatedCommand' /t REG_SZ /d 'cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F' /f
      Reg.exe add 'HKCR\Directory\shell\runas' /ve /t REG_SZ /d 'Take Ownership' /f
      Reg.exe add 'HKCR\Directory\shell\runas\command' /ve /t REG_SZ /d 'cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t' /f
      Reg.exe add 'HKCR\Directory\shell\runas\command' /v 'IsolatedCommand' /t REG_SZ /d 'cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t' /f

     


    }

    if ($checkbox35.Checked) {
      Write-Status -Message 'Removing Add to Favorites from Context Menu...' -Type Output
      Reg.exe delete 'HKCR\*\shell\pintohomefile' /f

    }

    if ($checkbox36.Checked) {
      Write-Status -Message 'Removing Customize this Folder from Context Menu...' -Type Output
      Reg.exe delete 'HKCR\Directory\shellex\PropertySheetHandlers\{ef43ecfe-2ab9-4632-bf21-58909dd177f0}' /f
      Reg.exe delete 'HKCR\Drive\shellex\PropertySheetHandlers\{ef43ecfe-2ab9-4632-bf21-58909dd177f0}' /f
      #policies
      Reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoCustomizeThisFolder' /f >$null 2>&1
      Reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoCustomizeWebView' /f >$null 2>&1
      Reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'ClassicShell' /f >$null 2>&1
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoCustomizeThisFolder' /t REG_DWORD /d '1' /f
      Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'NoCustomizeWebView' /f >$null 2>&1
      Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'ClassicShell' /f >$null 2>&1
    }

    if ($checkbox37.Checked) {
      Write-Status -Message 'Removing Give Access To from Context Menu...' -Type Output
      Reg.exe delete 'HKCR\*\shellex\ContextMenuHandlers\Sharing' /f
      Reg.exe delete 'HKCR\Directory\Background\shellex\ContextMenuHandlers\Sharing' /f
      Reg.exe delete 'HKCR\Directory\shellex\ContextMenuHandlers\Sharing' /f
      Reg.exe delete 'HKCR\Drive\shellex\ContextMenuHandlers\Sharing' /f
      Reg.exe delete 'HKCR\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing' /f
      Reg.exe delete 'HKCR\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing' /f
    }

    if ($checkbox38.Checked) {
      Write-Status -Message 'Removing Open Terminal from Context Menu...' -Type Output
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{9F156763-7844-4DC4-B2B1-901F640F5155}' /t REG_SZ /d `"`" /f
    }

    if ($checkbox39.Checked) {
      Write-Status -Message 'Removing Restore Previous Versions from Context Menu...' -Type Output
      Reg.exe delete 'HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}' /f
      Reg.exe delete 'HKCR\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}' /f
      Reg.exe delete 'HKCR\Directory\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}' /f
      Reg.exe delete 'HKCR\Drive\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}' /f
      Reg.exe delete 'HKCR\AllFilesystemObjects\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}' /f
      Reg.exe delete 'HKCR\CLSID\{450D8FBA-AD25-11D0-98A8-0800361B1103}\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}' /f
      Reg.exe delete 'HKCR\Directory\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}' /f
      Reg.exe delete 'HKCR\Drive\shellex\PropertySheetHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}' /f
      #policies
      Reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v 'NoPreviousVersionsPage' /f >$null 2>&1
      Reg.exe delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'NoPreviousVersionsPage' /f >$null 2>&1
      Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\PreviousVersions' /v 'DisableLocalPage' /f >$null 2>&1
      Reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v 'NoPreviousVersionsPage' /f >$null 2>&1
      Reg.exe delete 'HKCU\Software\Policies\Microsoft\PreviousVersions' /v 'DisableLocalPage' /f >$null 2>&1
     
    }

    if ($checkbox40.Checked) {
      Write-Status -Message 'Removing Print from Context Menu...' -Type Output
      Reg.exe add 'HKCR\SystemFileAssociations\image\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\batfile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\cmdfile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\docxfile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\fonfile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\htmlfile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\inffile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\inifile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\JSEFile\Shell\Print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\otffile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\pfmfile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\regfile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\rtffile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\ttcfile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\ttffile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\txtfile\shell\print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\VBEFile\Shell\Print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\VBSFile\Shell\Print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
      Reg.exe add 'HKCR\WSFFile\Shell\Print' /v 'ProgrammaticAccessOnly' /t REG_SZ /d `"`" /f
    }

    if ($checkbox41.Checked) {
      Write-Status -Message 'Removing Send To from Context Menu...' -Type Output
      Reg.exe delete 'HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo' /f
      Reg.exe delete 'HKCR\UserLibraryFolder\shellex\ContextMenuHandlers\SendTo' /f
    }

    if ($checkbox42.Checked) {
      Write-Status -Message 'Removing Share from Context Menu...' -Type Output
      Reg.exe delete 'HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing' /f
      Reg.exe delete 'HKCR\*\shellex\ContextMenuHandlers\ModernSharing' /f
    }

    if ($checkbox43.Checked) {
      Write-Status -Message 'Removing Personalize from Context Menu...' -Type Output
      $command = "Remove-Item -Path 'registry::HKCR\DesktopBackground\Shell\Personalize' -Recurse -Force"
      Run-Trusted -command $command
      Start-Sleep 2
    }

    if ($checkbox44.Checked) {
      Write-Status -Message 'Removing Display from Context Menu...' -Type Output
      $command = "Remove-Item -Path 'registry::HKCR\DesktopBackground\Shell\Display' -Recurse -Force"
      Run-Trusted -command $command
      Start-Sleep 2
    }

    if ($checkbox46.Checked) {
      Write-Status -Message 'Removing Extract All from Context Menu...' -Type Output
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}' /t REG_SZ /f
      Reg.exe add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{b8cdcb65-b1bf-4b42-9428-1dfdb7ee92af}' /t REG_SZ /f
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{EE07CEF5-3441-4CFB-870A-4002C724783A}' /t REG_SZ /f
      Reg.exe add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{EE07CEF5-3441-4CFB-870A-4002C724783A}' /t REG_SZ /f
    }

    if ($checkbox45.Checked) {
      Write-Status -Message 'Defering Feature Updates for 730 days(MAX)' -Type Output
      Write-Status -Message 'Defering Optional Updates for 730 days(MAX)' -Type Output
     
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetAllowOptionalContent' /t REG_DWORD /d '0' /f >$null
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdates' /t REG_DWORD /d '1' /f >$null
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdatesPeriodInDays' /t REG_DWORD /d '730' /f >$null
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdates' /t REG_DWORD /d '1' /f >$null
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /t REG_DWORD /d '730' /f >$null
      Write-Status -Message 'Updating Policy...' -Type Output
      gpupdate /force
    }

    if ($checkbox47.Checked) {
      Write-Status -Message 'Pausing Updates for 1 Year...' -Type Output
      #pause for 1 year
      $pause = (Get-Date).AddDays(365) 
      $today = Get-Date
      $today = $today.ToUniversalTime().ToString( 'yyyy-MM-ddTHH:mm:ssZ' )
      $pause = $pause.ToUniversalTime().ToString( 'yyyy-MM-ddTHH:mm:ssZ' ) 
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause -Force
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesEndTime' -Value $pause -Force
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseFeatureUpdatesStartTime' -Value $today -Force
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesEndTime' -Value $pause -Force
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseQualityUpdatesStartTime' -Value $today -Force
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesStartTime' -Value $today -Force
    }


    if ($checkbox48.Checked) {
      Write-Status -Message 'Removing Troubleshoot Compatibility from Context Menu...' -Type Output
      #remove troubleshoot comp
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{1d27f844-3a1f-4410-85ac-14651078412d}' /t REG_SZ /d ' ' /f *>$null
    }

    if ($checkbox49.Checked) {
      Write-Status -Message 'Removing Include in Library from Context Menu...' -Type Output
      #remove include in library
      Reg.exe delete 'HKCR\Folder\ShellEx\ContextMenuHandlers\Library Location' /f *>$null
      Reg.exe delete 'HKLM\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location' /f *>$null
    }


    if ($checkbox50.Checked) {
      Write-Status -Message 'Preventing Windows Update from Upgrading Versions...' -Type Output
      #get current os and build
      $buildVer = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
      $winName = ((Get-CimInstance Win32_OperatingSystem).Caption).Substring(10, 10)

      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ProductVersion' /t REG_SZ /d $winName /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'TargetReleaseVersion' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'TargetReleaseVersionInfo' /t REG_SZ /d $buildVer /f
      gpupdate /force *>$null
    }

    if ($checkbox51.Checked) {
      Write-Status -Message 'Disabling PowerShell Logging...' -Type Output
      Set-PSReadlineOption -HistorySaveStyle SaveNothing
      (Get-PSReadLineOption).HistorySavePath | Remove-Item -Force -ErrorAction SilentlyContinue
    }

    if ($checkbox52.Checked) {
      Write-Status -Message 'Enabling No GUI Boot...' -Type Output
      bcdedit /set '{globalsettings}' bootuxdisabled on
    }

    if ($checkbox53.Checked) {
      Write-Status -Message 'Disabling Windows Platform Binary Table...' -Type Output
      reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\Session Manager' /v 'DisableWpbtExecution' /t REG_DWORD /d 1 /f
      reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager' /v 'DisableWpbtExecution' /t REG_DWORD /d 1 /f
    }

    if ($checkbox54.Checked) {
      Write-Status -Message 'Disabling Game Bar Popup when Xbox App is Uninstalled...' -Type Output
      #hide gamebar popup credits aveyo

      Set-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' 0 -type dword -force -ea 0
      Set-ItemProperty 'HKCU:\System\GameConfigStore' 'GameDVR_Enabled' 0 -type dword -force -ea 0

      'ms-gamebar', 'ms-gamebarservices', 'ms-gamingoverlay' | ForEach-Object {
        #create new reg keys for each handler
        if (!(test-path "Registry::HKCR\$_\shell")) { 
          New-Item "Registry::HKCR\$_\shell" -force >'' 
        }
        if (!(test-path "Registry::HKCR\$_\shell\open")) { 
          New-Item "Registry::HKCR\$_\shell\open" -force >'' 
        }
        if (!(test-path "Registry::HKCR\$_\shell\open\command")) { 
          New-Item "Registry::HKCR\$_\shell\open\command" -force >'' 
        }

        Set-ItemProperty "Registry::HKCR\$_" '(Default)' "URL:$_" -force
        Set-ItemProperty "Registry::HKCR\$_" 'URL Protocol' '' -force
        #add noopenwith and systray.exe to hide popup
        Set-ItemProperty "Registry::HKCR\$_" 'NoOpenWith' '' -force
        Set-ItemProperty "Registry::HKCR\$_\shell\open\command" '(Default)' "`"$env:SystemRoot\System32\systray.exe`"" -force
      }
    }

    if ($checkbox55.Checked) {
      Write-Status -Message 'Enabling Faster Shutdowns and Restarts By Ending Services Sooner...' -Type Output
      Reg.exe add 'HKCU\Control Panel\Desktop' /v 'WaitToKillAppTimeout' /t REG_SZ /d '1500' /f *>$null
      Reg.exe add 'HKCU\Control Panel\Desktop' /v 'AutoEndTasks' /t REG_SZ /d '1' /f *>$null
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control' /v 'WaitToKillServiceTimeout' /t REG_SZ /d '1500' /f *>$null
    }

    if ($checkbox56.Checked) {
      Write-Status -Message 'Removing Backup App...' -Type Output
      Write-Status -Message 'USING A MICROSOFT ACCOUNT TO SIGN INTO APPS WILL NO LONGER WORK...' -Type Warning
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\MicrosoftAccount' /v 'DisableUserAuth' /t REG_DWORD /d '1' /f
    }

    if (test-path 'C:\UltimateContextMenu') {
      $ogLocation = $Global:folder
      Move-item 'C:\UltimateContextMenu' -Destination $ogLocation
    }
                         
  }
            
      
      
}
Export-ModuleMember -Function OptionalTweaks








function remove-tasks {

  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
    # ,[Parameter(mandatory=$false)] $setting 
  )
      
     
    
  if ($Autorun) {
    $msgBoxInput = 'OK'
  }
  else {
    $msgBoxInput = Custom-MsgBox -message 'Remove ALL Scheduled Tasks?' -type Question
  }
      
      
  switch ($msgBoxInput) {
      
    'OK' {
        
      if (!($Autorun)) {
        update-config -setting 'scheduledTasks' -value 1
      }
      Write-Status -Message 'Removing Scheduled Tasks...' -Type Output
      
      Get-ScheduledTask -TaskPath '*' | 
      Where-Object { $_.TaskName -notin @('SvcRestartTask', 'MsCtfMonitor') } | 
      Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
      
    }
      
    'Cancel' {}
      
  }
      
      
      
}
Export-ModuleMember -Function remove-tasks







function update-config([String]$setting, $value) {
  $currentConfig = Get-Content -Path "$env:USERPROFILE\ZCONFIG.cfg" -Force
  $newConfig = @()
  foreach ($line in $currentConfig) {
    if ($line -notmatch '#') {
      $settingName = "\b$setting\b"
      if ($line -match $settingName) {
        $newConfig += "$setting = $value" 
      }
      else {
        $newConfig += $line
      }
    }
    else {
      $newConfig += $line
    }
      
  }
  $newConfig | Out-File -FilePath "$env:USERPROFILE\ZCONFIG.cfg" -Force
}
Export-ModuleMember -Function update-config




function W11Tweaks {
  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
    , [Parameter(mandatory = $false)] [bool]$removeEdges = $false
    , [Parameter(mandatory = $false)] [bool]$win10TaskbarStartmenu = $false
    , [Parameter(mandatory = $false)] [bool]$win10explorer = $false
    , [Parameter(mandatory = $false)] [bool]$servicesManual = $false
    , [Parameter(mandatory = $false)] [bool]$showTrayIcons = $false
    , [Parameter(mandatory = $false)] [bool]$enableOpenShell = $false 
    , [Parameter(mandatory = $false)] [bool]$win10Recycle = $false
    , [Parameter(mandatory = $false)] [bool]$disableBellIcon = $false
    , [Parameter(mandatory = $false)] [bool]$win10Snipping = $false
    , [Parameter(mandatory = $false)] [bool]$win10TaskMgr = $false
    , [Parameter(mandatory = $false)] [bool]$win10Notepad = $false
    , [Parameter(mandatory = $false)] [bool]$hideRecommended = $false
    , [Parameter(mandatory = $false)] [bool]$win10Icons = $false
    , [Parameter(mandatory = $false)] [bool]$darkWinver = $false
    , [Parameter(mandatory = $false)] [bool]$removeQuickSettingTiles = $false
    , [Parameter(mandatory = $false)] [bool]$removeSystemLabel = $false
    , [Parameter(mandatory = $false)] [bool]$disableNotepadTabs = $false
    , [Parameter(mandatory = $false)] [bool]$hideHome = $false
    , [Parameter(mandatory = $false)] [bool]$hideSettingsAds = $false
  )
      
   
      
  $checkbox2 = new-object System.Windows.Forms.checkbox
  $checkbox4 = new-object System.Windows.Forms.checkbox
  $checkbox6 = new-object System.Windows.Forms.checkbox
  $checkbox3 = new-object System.Windows.Forms.checkbox
  $checkbox5 = new-object System.Windows.Forms.checkbox
  $checkbox7 = new-object System.Windows.Forms.checkbox
  $checkbox8 = new-object System.Windows.Forms.checkbox
  $checkbox9 = new-object System.Windows.Forms.checkbox
  $checkbox11 = new-object System.Windows.Forms.checkbox
  $checkbox13 = new-object System.Windows.Forms.checkbox
  $checkbox15 = new-object System.Windows.Forms.checkbox
  $checkbox17 = new-object System.Windows.Forms.checkbox
  $checkbox19 = new-object System.Windows.Forms.checkbox
  $checkbox21 = new-object System.Windows.Forms.checkbox
  $checkbox22 = new-object System.Windows.Forms.checkbox
  $checkbox23 = new-object System.Windows.Forms.checkbox
  $checkbox24 = new-object System.Windows.Forms.checkbox
  $checkbox25 = new-object System.Windows.Forms.checkbox
  $checkbox26 = new-object System.Windows.Forms.checkbox
      
  $settings = @{}
    
  $settings['removeEdges'] = $checkbox2
  $settings['win10TaskbarStartmenu'] = $checkbox4
  $settings['win10Explorer'] = $checkbox6
  $settings['servicesManual'] = $checkbox3
  $settings['showTrayIcons'] = $checkbox5
  $settings['enableOpenShell'] = $checkbox7 
  $settings['hideRecommended'] = $checkbox8
  $settings['win10Recycle'] = $checkbox9
  $settings['disableBellIcon'] = $checkbox11
  $settings['win10Snipping'] = $checkbox13
  $settings['win10TaskMgr'] = $checkbox15
  $settings['win10Notepad'] = $checkbox17
  $settings['win10Icons'] = $checkbox19
  $settings['darkWinver'] = $checkbox21
  $settings['removeQuickSettingTiles'] = $checkbox22
  $settings['removeSystemLabel'] = $checkbox23
  $settings['disableNotepadTabs'] = $checkbox24
  $settings['hideHome'] = $checkbox25
  $settings['hideSettingsAds'] = $checkbox26
      
  if ($Autorun) {
    $result = [System.Windows.Forms.DialogResult]::OK
    $checkbox2.Checked = $removeEdges
    $checkbox4.Checked = $win10taskbar
    $checkbox6.Checked = $win10explorer
    $checkbox3.Checked = $servicesManual
    $checkbox5.Checked = $showTrayIcons
    $checkbox7.Checked = $enableOpenShell
    $checkbox9.Checked = $win10Recycle
    $checkbox11.Checked = $disableBellIcon
    $checkbox13.Checked = $win10Snipping
    $checkbox15.Checked = $win10TaskMgr
    $checkbox17.Checked = $win10Notepad
    $checkbox8.Checked = $hideRecommended
    $checkbox19.Checked = $win10Icons
    $checkbox21.Checked = $darkWinver
    $checkbox22.Checked = $removeQuickSettingTiles
    $checkbox23.Checked = $removeSystemLabel
    $checkbox24.Checked = $disableNotepadTabs
    $checkbox25.Checked = $hideHome
    $checkbox26.Checked = $hideSettingsAds
  }
  else {
      
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # Create a form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Windows 11 Tweaks'
    $form.Size = New-Object System.Drawing.Size(550, 430)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

    # Sidebar Panel
    $sidebarPanel = New-Object System.Windows.Forms.Panel
    $sidebarPanel.Location = New-Object System.Drawing.Point(0, 0)
    $sidebarPanel.Size = New-Object System.Drawing.Size(150, $form.ClientSize.Height)
    $sidebarPanel.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)

    # Sidebar Buttons with Rounded Corners and Mouse-Over Effect
    $patchExplorerBtn = New-Object System.Windows.Forms.Button
    $patchExplorerBtn.Location = New-Object System.Drawing.Point(10, 10)
    $patchExplorerBtn.Size = New-Object System.Drawing.Size(130, 40)
    $patchExplorerBtn.Text = 'Patch Explorer'
    $patchExplorerBtn.ForeColor = 'White'
    $patchExplorerBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) # Initial inactive color
    $patchExplorerBtn.FlatAppearance.BorderSize = 0
    $patchExplorerBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $patchExplorerBtn.Tag = 'Inactive' # Initial state
    $patchExplorerBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $patchExplorerBtn.Add_MouseLeave({
        if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }
        else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) }
      })
    $sidebarPanel.Controls.Add($patchExplorerBtn)

    $win10Btn = New-Object System.Windows.Forms.Button
    $win10Btn.Location = New-Object System.Drawing.Point(10, 60)
    $win10Btn.Size = New-Object System.Drawing.Size(130, 40)
    $win10Btn.Text = 'Windows 10'
    $win10Btn.ForeColor = 'White'
    $win10Btn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) # Initial inactive color
    $win10Btn.FlatAppearance.BorderSize = 0
    $win10Btn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $win10Btn.Tag = 'Inactive' # Initial state
    $win10Btn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $win10Btn.Add_MouseLeave({
        if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }
        else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) }
      })
    $sidebarPanel.Controls.Add($win10Btn)

    $miscBtn = New-Object System.Windows.Forms.Button
    $miscBtn.Location = New-Object System.Drawing.Point(10, 110)
    $miscBtn.Size = New-Object System.Drawing.Size(130, 40)
    $miscBtn.Text = 'Misc'
    $miscBtn.ForeColor = 'White'
    $miscBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) # Initial inactive color
    $miscBtn.FlatAppearance.BorderSize = 0
    $miscBtn.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $miscBtn.Tag = 'Inactive' # Initial state
    $miscBtn.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $miscBtn.Add_MouseLeave({
        if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }
        else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) }
      })
    $sidebarPanel.Controls.Add($miscBtn)

    # Info Button (Moved to Bottom-Left of Sidebar)
    $url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#windows-11-tweaks'
    $infobutton = New-Object Windows.Forms.Button
    $infobutton.Location = New-Object Drawing.Point(5, 330)    
    $infobutton.Size = New-Object Drawing.Size(30, 27)
    $infobutton.Cursor = 'Hand'
    $infobutton.Add_Click({
        try {
          Start-Process $url -ErrorAction Stop
        }
        catch {
          Write-Status -Message 'No Internet Connected...' -Type Error
        }
      })
    $infobutton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $image = [System.Drawing.Image]::FromFile('C:\Windows\System32\SecurityAndMaintenance.png')
    $resizedImage = New-Object System.Drawing.Bitmap $image, 24, 25
    $infobutton.Image = $resizedImage
    $infobutton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $infobutton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $infobutton.FlatAppearance.BorderSize = 0
    $sidebarPanel.Controls.Add($infobutton)

    $form.Controls.Add($sidebarPanel)

    # Main Content Panel
    $contentPanel = New-Object System.Windows.Forms.Panel
    $contentPanel.Location = New-Object System.Drawing.Point(160, 10)
    $contentPanel.Size = New-Object System.Drawing.Size(370, 330)     
    $contentPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $form.Controls.Add($contentPanel)

    # Patch Explorer Panel
    $patchExplorerPanel = New-Object System.Windows.Forms.Panel
    $patchExplorerPanel.Location = New-Object System.Drawing.Point(0, 0)
    $patchExplorerPanel.Size = New-Object System.Drawing.Size(370, 330)   
    $patchExplorerPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $patchExplorerPanel.Visible = $true
    $contentPanel.Controls.Add($patchExplorerPanel)

    # Windows 10 Panel
    $win10Panel = New-Object System.Windows.Forms.Panel
    $win10Panel.Location = New-Object System.Drawing.Point(0, 0)
    $win10Panel.Size = New-Object System.Drawing.Size(370, 330)     
    $win10Panel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $win10Panel.Visible = $false
    $contentPanel.Controls.Add($win10Panel)

    # Misc Panel
    $miscPanel = New-Object System.Windows.Forms.Panel
    $miscPanel.Location = New-Object System.Drawing.Point(0, 0)
    $miscPanel.Size = New-Object System.Drawing.Size(370, 330)   
    $miscPanel.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $miscPanel.Visible = $false
    $contentPanel.Controls.Add($miscPanel)

    # Labels
    $label1 = New-Object System.Windows.Forms.Label
    $label1.Location = New-Object System.Drawing.Point(10, 10)
    $label1.Size = New-Object System.Drawing.Size(200, 20)
    $label1.Text = 'Patch Explorer'
    $label1.ForeColor = 'White'
    $label1.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $patchExplorerPanel.Controls.Add($label1)

    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(10, 10)
    $label2.Size = New-Object System.Drawing.Size(200, 20)
    $label2.Text = 'Windows 10'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $win10Panel.Controls.Add($label2)

    $label3 = New-Object System.Windows.Forms.Label
    $label3.Location = New-Object System.Drawing.Point(10, 10)
    $label3.Size = New-Object System.Drawing.Size(200, 20)
    $label3.Text = 'Misc'
    $label3.ForeColor = 'White'
    $label3.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $miscPanel.Controls.Add($label3)

    # Patch Explorer Checkboxes

    $checkbox2.Location = New-Object System.Drawing.Point(20, 40)
    $checkbox2.Size = New-Object System.Drawing.Size(200, 30)
    $checkbox2.Text = 'Remove Rounded Edges'
    $checkbox2.ForeColor = 'White'
    $checkbox2.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox2.Checked = $false
    $form.Controls.Add($checkbox2)
    $patchExplorerPanel.Controls.Add($checkbox2)


    $checkbox4.Location = New-Object System.Drawing.Point(20, 70)
    $checkbox4.Size = New-Object System.Drawing.Size(330, 30)
    $checkbox4.Text = 'Enable Windows 10 TaskBar and StartMenu'
    $checkbox4.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox4.ForeColor = 'White'
    $checkbox4.Checked = $false
    $form.Controls.Add($checkbox4)
    $patchExplorerPanel.Controls.Add($checkbox4)


    $checkbox6.Location = New-Object System.Drawing.Point(20, 100)
    $checkbox6.Size = New-Object System.Drawing.Size(300, 30)
    $checkbox6.Text = 'Enable Windows 10 File Explorer'
    $checkbox6.ForeColor = 'White'
    $checkbox6.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox6.Checked = $false
    $form.Controls.Add($checkbox6)
    $patchExplorerPanel.Controls.Add($checkbox6)

    $checkbox8.Location = New-Object System.Drawing.Point(20, 130)
    $checkbox8.Size = New-Object System.Drawing.Size(300, 30)
    $checkbox8.Text = 'Hide Startmenu Recommended'
    $checkbox8.ForeColor = 'White'
    $checkbox8.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox8.Checked = $false
    $form.Controls.Add($checkbox8)
    $patchExplorerPanel.Controls.Add($checkbox8)

 
    $checkbox7.Location = New-Object System.Drawing.Point(20, 160)
    $checkbox7.Size = New-Object System.Drawing.Size(350, 30)
    $checkbox7.Text = 'Replace Start Menu and Search with OpenShell'
    $checkbox7.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox7.ForeColor = 'White'
    $checkbox7.Checked = $false
    $form.Controls.Add($checkbox7)
    $patchExplorerPanel.Controls.Add($checkbox7)

    # Windows 10 Checkboxes

    $checkbox9.Location = New-Object System.Drawing.Point(20, 40)
    $checkbox9.Size = New-Object System.Drawing.Size(300, 30)
    $checkbox9.Text = 'Restore Windows 10 Recycle Bin Icon'
    $checkbox9.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox9.ForeColor = 'White'
    $checkbox9.Checked = $false
    $form.Controls.Add($checkbox9)
    $win10Panel.Controls.Add($checkbox9)

 
    $checkbox13.Location = New-Object System.Drawing.Point(20, 70)
    $checkbox13.Size = New-Object System.Drawing.Size(300, 30)
    $checkbox13.Text = 'Restore Windows 10 Snipping Tool'
    $checkbox13.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox13.ForeColor = 'White'
    $checkbox13.Checked = $false
    $form.Controls.Add($checkbox13)
    $win10Panel.Controls.Add($checkbox13)

    $checkbox15.Location = New-Object System.Drawing.Point(20, 100)
    $checkbox15.Size = New-Object System.Drawing.Size(300, 30)
    $checkbox15.Text = 'Restore Windows 10 Task Manager'
    $checkbox15.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox15.ForeColor = 'White'
    $checkbox15.Checked = $false
    $form.Controls.Add($checkbox15)
    $win10Panel.Controls.Add($checkbox15)


    $checkbox17.Location = New-Object System.Drawing.Point(20, 130)
    $checkbox17.Size = New-Object System.Drawing.Size(300, 30)
    $checkbox17.Text = 'Restore Windows 10 Notepad'
    $checkbox17.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox17.ForeColor = 'White'
    $checkbox17.Checked = $false
    $form.Controls.Add($checkbox17)
    $win10Panel.Controls.Add($checkbox17)

    $checkbox19.Location = New-Object System.Drawing.Point(20, 160)
    $checkbox19.Size = New-Object System.Drawing.Size(300, 30)
    $checkbox19.Text = 'Restore Windows 10 Icons'
    $checkbox19.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox19.ForeColor = 'White'
    $checkbox19.Checked = $false
    $form.Controls.Add($checkbox19)
    $win10Panel.Controls.Add($checkbox19)

    # Misc Checkboxes

    $checkbox3.Location = New-Object System.Drawing.Point(20, 40)
    $checkbox3.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox3.Text = 'Set all Services to Manual'
    $checkbox3.ForeColor = 'White'
    $checkbox3.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox3.Checked = $false
    $form.Controls.Add($checkbox3)
    $miscPanel.Controls.Add($checkbox3)

    $checkbox5.Location = New-Object System.Drawing.Point(20, 70)
    $checkbox5.Size = New-Object System.Drawing.Size(250, 30)
    $checkbox5.Text = 'Show all Taskbar Tray Icons'
    $checkbox5.ForeColor = 'White'
    $checkbox5.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox5.Checked = $false
    $form.Controls.Add($checkbox5)
    $miscPanel.Controls.Add($checkbox5)

    $checkbox11.Location = New-Object System.Drawing.Point(20, 100)
    $checkbox11.Size = New-Object System.Drawing.Size(300, 30)
    $checkbox11.Text = 'Disable Bell Icon on Taskbar'
    $checkbox11.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox11.ForeColor = 'White'
    $checkbox11.Checked = $false
    $form.Controls.Add($checkbox11)
    $miscPanel.Controls.Add($checkbox11)

    $checkbox21.Location = New-Object System.Drawing.Point(20, 130)
    $checkbox21.Size = New-Object System.Drawing.Size(300, 30)
    $checkbox21.Text = 'Dark Winver'
    $checkbox21.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox21.ForeColor = 'White'
    $checkbox21.Checked = $false
    $form.Controls.Add($checkbox21)
    $miscPanel.Controls.Add($checkbox21)

    $checkbox22.Location = New-Object System.Drawing.Point(20, 160)
    $checkbox22.Size = New-Object System.Drawing.Size(300, 30)
    $checkbox22.Text = 'Remove Quick Setting Tiles (24H2+)'
    $checkbox22.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox22.ForeColor = 'White'
    $checkbox22.Checked = $false
    $form.Controls.Add($checkbox22)
    $miscPanel.Controls.Add($checkbox22)

    $checkbox23.Location = New-Object System.Drawing.Point(20, 190)
    $checkbox23.Size = New-Object System.Drawing.Size(360, 30)
    $checkbox23.Text = 'Remove System Label From StartMenu Apps'
    $checkbox23.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox23.ForeColor = 'White'
    $checkbox23.Checked = $false
    $form.Controls.Add($checkbox23)
    $miscPanel.Controls.Add($checkbox23)

    $checkbox24.Location = New-Object System.Drawing.Point(20, 220)
    $checkbox24.Size = New-Object System.Drawing.Size(360, 30)
    $checkbox24.Text = 'Disable Notepad Tabs and Rewrite'
    $checkbox24.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox24.ForeColor = 'White'
    $checkbox24.Checked = $false
    $form.Controls.Add($checkbox24)
    $miscPanel.Controls.Add($checkbox24)

    $checkbox25.Location = New-Object System.Drawing.Point(20, 250)
    $checkbox25.Size = New-Object System.Drawing.Size(360, 30)
    $checkbox25.Text = 'Hide Home Page in Settings'
    $checkbox25.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox25.ForeColor = 'White'
    $checkbox25.Checked = $false
    $form.Controls.Add($checkbox25)
    $miscPanel.Controls.Add($checkbox25)

    $checkbox26.Location = New-Object System.Drawing.Point(20, 280)
    $checkbox26.Size = New-Object System.Drawing.Size(360, 30)
    $checkbox26.Text = 'Hide Ads In Settings'
    $checkbox26.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox26.ForeColor = 'White'
    $checkbox26.Checked = $false
    $form.Controls.Add($checkbox26)
    $miscPanel.Controls.Add($checkbox26)

    # OK and Cancel Buttons
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(220, 350) 
    $OKButton.Text = 'OK'
    $OKButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $OKButton.ForeColor = [System.Drawing.Color]::White
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(330, 350) 
    $CancelButton.Text = 'Cancel'
    $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $CancelButton.ForeColor = [System.Drawing.Color]::White
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    # Sidebar Button Click Events with Active State
    $patchExplorerBtn.Add_Click({
        $patchExplorerPanel.Visible = $true
        $win10Panel.Visible = $false
        $miscPanel.Visible = $false
        $patchExplorerBtn.Tag = 'Active'
        $win10Btn.Tag = 'Inactive'
        $miscBtn.Tag = 'Inactive'
        $patchExplorerBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
        $win10Btn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $miscBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
      })

    $win10Btn.Add_Click({
        $patchExplorerPanel.Visible = $false
        $win10Panel.Visible = $true
        $miscPanel.Visible = $false
        $patchExplorerBtn.Tag = 'Inactive'
        $win10Btn.Tag = 'Active'
        $miscBtn.Tag = 'Inactive'
        $patchExplorerBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $win10Btn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
        $miscBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
      })

    $miscBtn.Add_Click({
        $patchExplorerPanel.Visible = $false
        $win10Panel.Visible = $false
        $miscPanel.Visible = $true
        $patchExplorerBtn.Tag = 'Inactive'
        $win10Btn.Tag = 'Inactive'
        $miscBtn.Tag = 'Active'
        $patchExplorerBtn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $win10Btn.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
        $miscBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
      })

    # Set initial active state for Patch Explorer
    $patchExplorerBtn.Tag = 'Active'
    $patchExplorerBtn.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)

    # Activate the form
    $form.Add_Shown({ $form.Activate() })
    $result = $form.ShowDialog()
      
  }
      
      
  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
      
    if (!($Autorun)) {
      #loop through checkbox hashtable to update config
      $settings.GetEnumerator() | ForEach-Object {
            
        $settingName = $_.Key
        $checkbox = $_.Value
        
        if ($checkbox.Checked) {
          update-config -setting $settingName -value 1
        }
      }
    }
      
    if ($checkbox2.Checked) {
      Write-Status -Message 'Disabling Rounded Edges...' -Type Output
      #disable rounded edges
      $path = Search-File '*win11-toggle-rounded-corners.exe'
      Start-Process $path -ArgumentList '--autostart --disable' -WindowStyle Hidden -Wait

      #apply on startup
      $newDir = New-Item -Path 'C:\Program Files\DisableRoundedEdges' -ItemType Directory -Force
      Move-Item -Path $path -Destination $newDir.FullName -Force
      
      #create shortcut
      $WshShell = New-Object -comObject WScript.Shell
      $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\win11-toggle-rounded-corners.lnk')
      $Shortcut.TargetPath = 'C:\Program Files\DisableRoundedEdges\win11-toggle-rounded-corners.exe'
      $Shortcut.Arguments = '--autostart --disable'
      $Shortcut.Save()
      
    }
      
    if ($checkbox4.Checked) {
      if (!(Test-Path -Path "$systemDrive\Program Files\ExplorerPatcher\ep_setup.exe" -ErrorAction SilentlyContinue)) {
        #install explorer patcher
        try {
          # get latest release
          $releasesUrl = 'https://api.github.com/repos/valinet/ExplorerPatcher/releases/latest'
          $release = Invoke-RestMethod -Uri $releasesUrl 
          # create download url
          $downloadUrl = $release.assets | Where-Object { $_.name -eq 'ep_setup.exe' } | Select-Object -ExpandProperty browser_download_url

          # download setup
          Remove-Item -Path "$env:TEMP\setup.exe" -Force -ErrorAction SilentlyContinue
          Invoke-WebRequest -Uri $downloadUrl -OutFile "$env:TEMP\setup.exe" 

        }
        catch {
          Write-Status -Message 'This tweak requires Internet Connection' -Type Error
        }
        #disable notis
        Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Windows.Explorer' /v 'Enabled' /t REG_DWORD /d '0' /f
        #install explorer patcher 
        Write-Status -Message 'Installing Explorer Patcher...' -Type Output
        Start-Process "$env:TEMP\setup.exe" -WindowStyle Hidden -Wait 
      }
      
      Write-Status -Message 'Applying Explorer Patcher Settings...' -Type Output
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Start_ShowClassicMode' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarAl' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKCU\Software\ExplorerPatcher' /v 'TaskbarGlomLevel' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKCU\Software\ExplorerPatcher' /v 'MMTaskbarGlomLevel' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKCU\Software\ExplorerPatcher' /v 'HideControlCenterButton' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableNotificationCenter' /t REG_DWORD /d '1' /f
    }
      
      
    if ($checkbox6.Checked) {
      Write-Status -Message 'Enabling Windows 10 File Explorer Ribbon...' -Type Output
      Reg.exe add 'HKCU\Software\Classes\CLSID\{2aa9162e-c906-4dd9-ad0b-3d24a8eef5a0}' /ve /t REG_SZ /d 'CLSID_ItemsViewAdapter' /f >$null
      Reg.exe add 'HKCU\Software\Classes\CLSID\{2aa9162e-c906-4dd9-ad0b-3d24a8eef5a0}\InProcServer32' /ve /t REG_SZ /d 'C:\Windows\System32\Windows.UI.FileExplorer.dll_' /f >$null
      Reg.exe add 'HKCU\Software\Classes\CLSID\{2aa9162e-c906-4dd9-ad0b-3d24a8eef5a0}\InProcServer32' /v 'ThreadingModel' /t REG_SZ /d 'Apartment' /f >$null
      Reg.exe add 'HKCU\Software\Classes\CLSID\{6480100b-5a83-4d1e-9f69-8ae5a88e9a33}' /ve /t REG_SZ /d 'File Explorer Xaml Island View Adapter' /f >$null
      Reg.exe add 'HKCU\Software\Classes\CLSID\{6480100b-5a83-4d1e-9f69-8ae5a88e9a33}\InProcServer32' /ve /t REG_SZ /d 'C:\Windows\System32\Windows.UI.FileExplorer.dll_' /f >$null
      Reg.exe add 'HKCU\Software\Classes\CLSID\{6480100b-5a83-4d1e-9f69-8ae5a88e9a33}\InProcServer32' /v 'ThreadingModel' /t REG_SZ /d 'Apartment' /f >$null
      Reg.exe add 'HKCU\Software\Microsoft\Internet Explorer\Toolbar\ShellBrowser' /v 'ITBar7Layout' /t REG_BINARY /d '13000000000000000000000020000000100001000000000001000000010700005e01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' /f >$null
      #stop explorer and then open to apply minimized ribbon reg keys
      Stop-Process -Name explorer -Force
      while (!(Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
        Start-Sleep 1
      }
      Start-process explorer.exe -args 'shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}'
      Start-Sleep 1
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon' /v 'MinimizedStateTabletModeOn' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon' /v 'MinimizedStateTabletModeOff' /t REG_DWORD /d '1' /f
      Stop-Process -Name explorer -Force
    }

      
      
      
    if ($checkbox3.Checked) {
      #set all services to manual (that are allowed)
      $services = Get-Service
      $servicesKeep = @(
        'AudioEndpointBuilder',
        'Audiosrv',
        'EventLog',
        'SysMain',
        'Themes',
        'WSearch',
        'NVDisplay.ContainerLocalSystem',
        'WlanSvc',
        'BFE', 
        'BrokerInfrastructure', 
        'CoreMessagingRegistrar', 
        'Dnscache', 
        'LSM', 
        'mpssvc', 
        'RpcEptMapper', 
        'Schedule', 
        'SystemEventsBroker', 
        'StateRepository', 
        'TextInputManagementService', 
        'sppsvc'
      )
      foreach ($service in $services) { 
        if ($service.StartType -like '*Auto*') {
          if ($servicesKeep -notcontains $service.Name) {
            try {
              Set-Service -Name $service.Name -StartupType Manual -ErrorAction Stop
            }
            catch {
              $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
              Set-ItemProperty -Path $regPath -Name 'Start' -Value 3 -ErrorAction SilentlyContinue
            }
              
          }         
        }
      }
      Write-Status -Message 'Services Set to Manual...' -Type Output
    }
    
    
    
    if ($checkbox5.Checked) {
      #show all current tray icons
      Write-Status -Message 'Showing All Apps on Taskbar' -Type Output
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v 'EnableAutoTray' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify' /v 'SystemTrayChevronVisibility' /t REG_DWORD /d '0' /f
      $keys = Get-ChildItem -Path 'registry::HKEY_CURRENT_USER\Control Panel\NotifyIconSettings' -Recurse -Force
      foreach ($key in $keys) {
        Set-ItemProperty -Path "registry::$key" -Name 'IsPromoted' -Value 1 -Force

      }
      #create task to update task tray on log on

      #create updater script
      $scriptContent = @"
`$keys = Get-ChildItem -Path 'registry::HKEY_CURRENT_USER\Control Panel\NotifyIconSettings' -Recurse -Force

foreach (`$key in `$keys) {
    #if the value is set to 0 do not set it to 1
    #set 1 when no reg key is there (new apps)
    if ((Get-ItemProperty -Path "registry::`$key").IsPromoted -eq 0) {
    }
    else {
        Set-ItemProperty -Path "registry::`$key" -Name 'IsPromoted' -Value 1 -Force
    }
}
"@

      $scriptPath = "$env:ProgramData\UpdateTaskTrayIcons.ps1"
      Set-Content -Path $scriptPath -Value $scriptContent -Force

      $vbsScriptContent = @"
Dim shell,command
command = "powershell.exe -ep bypass -c ""$env:ProgramData\UpdateTaskTrayIcons.ps1"""
Set shell = CreateObject("WScript.Shell")
shell.Run command,0
"@
      $vbsPath = "$env:ProgramData\UpdateTaskTraySilent.vbs"
      Set-Content -Path $vbsPath -Value $vbsScriptContent -Force

      #get username and sid
      $currentUserName = $env:COMPUTERNAME + '\' + $env:USERNAME
      $username = Get-LocalUser -Name $env:USERNAME | Select-Object -ExpandProperty sid

      $content = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-05-20T12:59:50.8741407</Date>
    <Author>$currentUserName</Author>
    <URI>\UpdateTaskTray</URI>
  </RegistrationInfo>
   <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$username</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>wscript.exe</Command>
      <Arguments>C:\ProgramData\UpdateTaskTraySilent.vbs</Arguments>
    </Exec>
  </Actions>
</Task>
"@
      Set-Content -Path "$env:TEMP\UpdateTaskTray" -Value $content -Force

      schtasks /Create /XML "$env:TEMP\UpdateTaskTray" /TN '\UpdateTaskTray' /F | Out-Null 

      Remove-Item -Path "$env:TEMP\UpdateTaskTray" -Force -ErrorAction SilentlyContinue
      Write-Status -Message 'Update Task Tray Created...New Apps Will Be Shown Upon Restarting' -Type Output
     
    }
    
    
    if ($checkbox7.Checked) {
      Write-Status -Message 'Installing Open Shell...' -Type Output
      #install openshell startmenu only
      $setup = Search-File '*OpenShellSetup.exe'
      Start-Process $setup -ArgumentList '/qn ADDLOCAL=StartMenu'
      Write-Status -Message 'Disabling Windows Indexing...' -Type Output
     
      Get-Service -Name WSearch | Set-Service -StartupType Disabled
    
      #import custom settings
      $regContent = @'
Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\OpenShell\StartMenu\Settings]
"MenuStyle"="Win7"
"ShiftWin"="Nothing"
"ControlPanelCategories"=dword:00000000
"ProgramsStyle"="Inline"
"AllProgramsMetro"=dword:00000000
"FoldersFirst"=dword:00000000
"OpenPrograms"=dword:00000000
"ProgramsMenuDelay"=dword:000000c8
"HideProgramsMetro"=dword:00000001
"PinnedPrograms"="PinnedItems"
"RecentPrograms"="None"
"EnableJumplists"=dword:00000000
"JumplistKeys"="Open"
"ShutdownCommand"="CommandRestart"
"HybridShutdown"=dword:00000000
"StartScreenShortcut"=dword:00000000
"MainSortZA"=dword:00000000
"MainSortOnce"=dword:00000000
"HighlightNew"=dword:00000000
"CheckWinUpdates"=dword:00000000
"MenuDelay"=dword:000000c8
"SplitMenuDelay"=dword:000000c8
"EnableDragDrop"=dword:00000000
"ScrollType"="NoScroll"
"SameSizeColumns"=dword:00000001
"SingleClickFolders"=dword:00000001
"OpenTruePath"=dword:00000001
"EnableAccessibility"=dword:00000001
"ShowNextToTaskbar"=dword:00000001
"DelayIcons"=dword:00000000
"BoldSettings"=dword:00000000
"EnableAccelerators"=dword:00000000
"SearchBox"="Normal"
"SearchPrograms"=dword:00000001
"SearchInternet"=dword:00000000
"MoreResults"=dword:00000000
"InvertMetroIcons"=dword:00000000
"AlignToWorkArea"=dword:00000000
"MainMenuAnimate"=dword:00000000
"MainMenuAnimation"="None"
"SubMenuAnimation"="None"
"NumericSort"=dword:00000001
"FontSmoothing"="Default"
"MenuShadow"=dword:00000000
"EnableGlass"=dword:00000000
"GlassOverride"=dword:00000001
"GlassColor"=dword:00191919
"GlassOpacity"=dword:00000000
"SkinC1"="Full Glass"
"SkinVariationC1"=""
"SkinOptionsC1"=hex(7):43,00,41,00,50,00,54,00,49,00,4f,00,4e,00,3d,00,31,00,\
  00,00,55,00,53,00,45,00,52,00,5f,00,49,00,4d,00,41,00,47,00,45,00,3d,00,30,\
  00,00,00,55,00,53,00,45,00,52,00,5f,00,4e,00,41,00,4d,00,45,00,3d,00,30,00,\
  00,00,43,00,45,00,4e,00,54,00,45,00,52,00,5f,00,4e,00,41,00,4d,00,45,00,3d,\
  00,30,00,00,00,53,00,4d,00,41,00,4c,00,4c,00,5f,00,49,00,43,00,4f,00,4e,00,\
  53,00,3d,00,30,00,00,00,4c,00,41,00,52,00,47,00,45,00,5f,00,46,00,4f,00,4e,\
  00,54,00,3d,00,30,00,00,00,49,00,43,00,4f,00,4e,00,5f,00,46,00,52,00,41,00,\
  4d,00,45,00,53,00,3d,00,31,00,00,00,4f,00,50,00,41,00,51,00,55,00,45,00,3d,\
  00,30,00,00,00,00,00
"SkinW7"="Immersive"
"SkinVariationW7"=""
"SkinOptionsW7"=hex(7):4c,00,49,00,47,00,48,00,54,00,3d,00,30,00,00,00,44,00,\
  41,00,52,00,4b,00,3d,00,31,00,00,00,41,00,55,00,54,00,4f,00,3d,00,30,00,00,\
  00,55,00,53,00,45,00,52,00,5f,00,49,00,4d,00,41,00,47,00,45,00,3d,00,30,00,\
  00,00,55,00,53,00,45,00,52,00,5f,00,4e,00,41,00,4d,00,45,00,3d,00,30,00,00,\
  00,43,00,45,00,4e,00,54,00,45,00,52,00,5f,00,4e,00,41,00,4d,00,45,00,3d,00,\
  30,00,00,00,53,00,4d,00,41,00,4c,00,4c,00,5f,00,49,00,43,00,4f,00,4e,00,53,\
  00,3d,00,31,00,00,00,4f,00,50,00,41,00,51,00,55,00,45,00,3d,00,31,00,00,00,\
  44,00,49,00,53,00,41,00,42,00,4c,00,45,00,5f,00,4d,00,41,00,53,00,4b,00,3d,\
  00,30,00,00,00,42,00,4c,00,41,00,43,00,4b,00,5f,00,54,00,45,00,58,00,54,00,\
  3d,00,30,00,00,00,42,00,4c,00,41,00,43,00,4b,00,5f,00,46,00,52,00,41,00,4d,\
  00,45,00,53,00,3d,00,30,00,00,00,54,00,52,00,41,00,4e,00,53,00,50,00,41,00,\
  52,00,45,00,4e,00,54,00,5f,00,4c,00,45,00,53,00,53,00,3d,00,30,00,00,00,54,\
  00,52,00,41,00,4e,00,53,00,50,00,41,00,52,00,45,00,4e,00,54,00,5f,00,4d,00,\
  4f,00,52,00,45,00,3d,00,31,00,00,00,00,00
"EnableStartButton"=dword:00000000
"StartButtonType"="AeroButton"
"CustomTaskbar"=dword:00000000
"TaskbarLook"="Opaque"
"TaskbarColor"=dword:000000ff
"TaskbarTextColor"=dword:000000ff
"SkipMetro"=dword:00000001
"OpenMouseMonitor"=dword:00000000
"MenuItems7"=hex(7):49,00,74,00,65,00,6d,00,31,00,2e,00,43,00,6f,00,6d,00,6d,\
  00,61,00,6e,00,64,00,3d,00,63,00,6f,00,6d,00,70,00,75,00,74,00,65,00,72,00,\
  00,00,49,00,74,00,65,00,6d,00,31,00,2e,00,53,00,65,00,74,00,74,00,69,00,6e,\
  00,67,00,73,00,3d,00,4e,00,4f,00,45,00,58,00,50,00,41,00,4e,00,44,00,00,00,\
  49,00,74,00,65,00,6d,00,32,00,2e,00,43,00,6f,00,6d,00,6d,00,61,00,6e,00,64,\
  00,3d,00,64,00,6f,00,77,00,6e,00,6c,00,6f,00,61,00,64,00,73,00,00,00,49,00,\
  74,00,65,00,6d,00,32,00,2e,00,54,00,69,00,70,00,3d,00,24,00,4d,00,65,00,6e,\
  00,75,00,2e,00,44,00,6f,00,77,00,6e,00,6c,00,6f,00,61,00,64,00,54,00,69,00,\
  70,00,00,00,49,00,74,00,65,00,6d,00,32,00,2e,00,53,00,65,00,74,00,74,00,69,\
  00,6e,00,67,00,73,00,3d,00,4e,00,4f,00,45,00,58,00,50,00,41,00,4e,00,44,00,\
  00,00,49,00,74,00,65,00,6d,00,33,00,2e,00,43,00,6f,00,6d,00,6d,00,61,00,6e,\
  00,64,00,3d,00,75,00,73,00,65,00,72,00,5f,00,64,00,6f,00,63,00,75,00,6d,00,\
  65,00,6e,00,74,00,73,00,00,00,49,00,74,00,65,00,6d,00,33,00,2e,00,54,00,69,\
  00,70,00,3d,00,24,00,4d,00,65,00,6e,00,75,00,2e,00,55,00,73,00,65,00,72,00,\
  44,00,6f,00,63,00,75,00,6d,00,65,00,6e,00,74,00,73,00,54,00,69,00,70,00,00,\
  00,49,00,74,00,65,00,6d,00,33,00,2e,00,53,00,65,00,74,00,74,00,69,00,6e,00,\
  67,00,73,00,3d,00,4e,00,4f,00,45,00,58,00,50,00,41,00,4e,00,44,00,00,00,49,\
  00,74,00,65,00,6d,00,34,00,2e,00,43,00,6f,00,6d,00,6d,00,61,00,6e,00,64,00,\
  3d,00,73,00,65,00,70,00,61,00,72,00,61,00,74,00,6f,00,72,00,00,00,49,00,74,\
  00,65,00,6d,00,35,00,2e,00,43,00,6f,00,6d,00,6d,00,61,00,6e,00,64,00,3d,00,\
  70,00,63,00,5f,00,73,00,65,00,74,00,74,00,69,00,6e,00,67,00,73,00,00,00,49,\
  00,74,00,65,00,6d,00,35,00,2e,00,53,00,65,00,74,00,74,00,69,00,6e,00,67,00,\
  73,00,3d,00,54,00,52,00,41,00,43,00,4b,00,5f,00,52,00,45,00,43,00,45,00,4e,\
  00,54,00,00,00,49,00,74,00,65,00,6d,00,36,00,2e,00,43,00,6f,00,6d,00,6d,00,\
  61,00,6e,00,64,00,3d,00,63,00,6f,00,6e,00,74,00,72,00,6f,00,6c,00,5f,00,70,\
  00,61,00,6e,00,65,00,6c,00,00,00,49,00,74,00,65,00,6d,00,36,00,2e,00,4c,00,\
  61,00,62,00,65,00,6c,00,3d,00,24,00,4d,00,65,00,6e,00,75,00,2e,00,43,00,6f,\
  00,6e,00,74,00,72,00,6f,00,6c,00,50,00,61,00,6e,00,65,00,6c,00,00,00,49,00,\
  74,00,65,00,6d,00,36,00,2e,00,54,00,69,00,70,00,3d,00,24,00,4d,00,65,00,6e,\
  00,75,00,2e,00,43,00,6f,00,6e,00,74,00,72,00,6f,00,6c,00,50,00,61,00,6e,00,\
  65,00,6c,00,54,00,69,00,70,00,00,00,49,00,74,00,65,00,6d,00,36,00,2e,00,53,\
  00,65,00,74,00,74,00,69,00,6e,00,67,00,73,00,3d,00,54,00,52,00,41,00,43,00,\
  4b,00,5f,00,52,00,45,00,43,00,45,00,4e,00,54,00,7c,00,4e,00,4f,00,45,00,58,\
  00,50,00,41,00,4e,00,44,00,00,00,49,00,74,00,65,00,6d,00,37,00,2e,00,43,00,\
  6f,00,6d,00,6d,00,61,00,6e,00,64,00,3d,00,72,00,75,00,6e,00,00,00,00,00
"CascadingMenu"=dword:00000000
"ShowNewFolder"=dword:00000000
"EnableExit"=dword:00000000
"EnableExplorer"=dword:00000000
"DisablePinExt"=dword:00000000
'@
      New-Item -Path 'C:\OpenShellSettings.reg' -ItemType File -Force
      Add-Content -Path 'C:\OpenShellSettings.reg' -Value $regContent -Force
      Start-Process regedit.exe -ArgumentList '/s C:\OpenShellSettings.reg' 

      #move all current shortcuts in windows start menu dir to openshell pinned dir
      Write-Status -Message 'Moving Shortcuts...' -Type Output
  
      if (!(Test-Path "$env:USERPROFILE\AppData\Roaming\OpenShell\Pinned")) {
        New-Item -Path "$env:USERPROFILE\AppData\Roaming\OpenShell\Pinned" -ItemType Directory -Force | Out-Null

      }
      $startShortcuts = Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"  -Filter *.lnk -Force
      $startShortcuts += Get-ChildItem -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'  -Filter *.lnk -Force 
      foreach ($shortcut in $startShortcuts) {
        #dont move Administrative Tools shortcut
        if ($shortcut.FullName -notlike '*Administrative Tools*') {
          Move-Item -Path $shortcut.FullName -Destination "$env:USERPROFILE\AppData\Roaming\OpenShell\Pinned" -Force
        }

      }

      #restart explorer to apply changes
      Write-Status -Message 'Explorer Restarting to Apply Changes...' -Type Output
    
      Stop-Process -name 'sihost' -force

      Remove-Item -Path 'C:\OpenShellSettings.reg' -Force -ErrorAction SilentlyContinue

    }
    
    
    if ($checkbox9.Checked) {
      Write-Status -Message 'Replacing Recycle Bin Icon with Windows 10...' -Type Output
      #get recycle bin icons (win 10)
      $iconEmpty = Search-File '*RB_Empty.ico'
      $iconFull = Search-File '*RB_Full.ico'
      #move icons to appdata
      New-Item -Path "$env:USERPROFILE\AppData\Local" -Name 'RecycleBinIcons' -ItemType Directory -Force
      Move-Item -Path $iconEmpty -Destination "$env:USERPROFILE\AppData\Local\RecycleBinIcons" -Force
      Move-Item -Path $iconFull -Destination "$env:USERPROFILE\AppData\Local\RecycleBinIcons" -Force
      #update icon paths
      $iconEmpty = "$env:USERPROFILE\AppData\Local\RecycleBinIcons\RB_Empty.ico"
      $iconFull = "$env:USERPROFILE\AppData\Local\RecycleBinIcons\RB_Full.ico"

      $names = @('(Default)', 'full', 'empty')

      #set each regkey to win 10 icon paths
      foreach ($name in $names) {
        if ($name -eq 'full') {
          $value = "$iconFull,0"
        }
        else {
          $value = "$iconEmpty,0"
        }

        Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\DefaultIcon' -Name $name -Value $value -Force
      }

    }

    if ($checkbox11.Checked) {
      Write-Status -Message 'Hiding Bell Icon from Taskbar...' -Type Output
      Write-Status -Message 'This tweak will break the calendar flyout' -Type Warning
      Reg.exe add 'HKCU\Software\Policies\Microsoft\Windows\Explorer' /v 'DisableNotificationCenter' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableNotificationCenter' /t REG_DWORD /d '1' /f
    }

    if ($checkbox13.Checked) {
      Write-Status -Message 'Restoring Windows 10 Snipping Tool...' -Type Output
      #old snipping
      #uninstall uwp snipping
      $ProgressPreference = 'SilentlyContinue'
      Get-AppXPackage '*ScreenSketch*' -AllUsers -ErrorAction SilentlyContinue | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction SilentlyContinue }
      Get-AppxPackage '*ScreenSketch*' -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue
      Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object DisplayName -like '*ScreenSketch*' | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue

      #takeown and remove
      takeown /f C:\Windows\System32\en-US /r /d Y >$null
      icacls C:\Windows\System32\en-US /grant administrators:F /t >$null
      Remove-Item -Path 'C:\Windows\System32\SnippingTool.exe' -Force -ErrorAction SilentlyContinue
      Remove-Item -Path 'C:\Windows\System32\en-US\SnippingTool.exe.mui' -Force -ErrorAction SilentlyContinue

      $snippingexe = Search-File '*SnippingTool.exe'
      $snippingmui = Search-File '*SnippingTool.exe.mui'
      Move-Item $snippingexe -Destination 'C:\Windows\System32' -Force
      Move-Item $snippingmui -Destination 'C:\Windows\System32\en-US' -Force
      #create startmenu shortcut
      $WshShell = New-Object -comObject WScript.Shell
      $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\SnippingTool.lnk')
      $Shortcut.TargetPath = ('C:\Windows\System32\SnippingTool.exe')
      $Shortcut.Save()
    }

    if ($checkbox15.Checked) {
      Write-Status -Message 'Replacing Windows 11 Taskmanager with Windows 10...' -Type Output
      
      #replace task manager with wrapper to run taskmgr -d
      $wrapper = Search-File '*zTaskmgr.exe'

      takeown /f C:\Windows\System32\Taskmgr.exe *>$null
      icacls C:\Windows\System32\Taskmgr.exe /grant administrators:F /t *>$null

      Rename-Item C:\Windows\System32\Taskmgr.exe -NewName 'Taskmgr_WIN11.exe' -Force | Out-Null
      Copy-Item $wrapper -Destination 'C:\Windows\System32' -Force
      Start-Sleep 1
      Rename-Item 'C:\Windows\System32\zTaskmgr.exe' -NewName 'Taskmgr.exe' -Force

      #copy syswow64 taskmanager and replace system32
      # takeown /f C:\Windows\System32\Taskmgr.exe *>$null
      # icacls C:\Windows\System32\Taskmgr.exe /grant administrators:F /t *>$null
      # Copy-Item -Path 'C:\Windows\SysWOW64\Taskmgr.exe' -Destination 'C:\Windows\System32' -Force

    
      
    }

    if ($checkbox17.Checked) {

      Write-Status -Message 'Enabling Windows 10 Notepad...' -Type Output

      try {
        Get-AppXPackage '*notepad*' -AllUsers -ErrorAction Stop | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction Stop }
      }
      catch {}
      try {
        Remove-AppxPackage -Package '*notepad*' -AllUsers -ErrorAction Stop
      }
      catch {}
      try {
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like '*notepad*' | Remove-AppxProvisionedPackage -AllUsers -Online -ErrorAction Stop | Out-Null
      }
      catch {} 
      

      Add-WindowsCapability -Online -Name Microsoft.Windows.Notepad.System~~~~0.0.1.0 

      Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\notepad.exe' -Force -ErrorAction SilentlyContinue
      Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Classes\Applications\notepad.exe' -Name NoOpenWith -Force -ErrorAction SilentlyContinue

      # Reg.exe add 'HKLM\SOFTWARE\Classes\txtfilelegacy\shell\Open\command' /ve /t REG_SZ /d 'C:\Windows\System32\Notepad.exe "%1"' /f
      #Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.txt\UserChoice' /v 'ProgId' /t REG_SZ /d 'txtfilelegacy' /f
      
      $newtxt = Search-File '*newtxt.reg'
      $txtfile = Search-File '*txtfile.reg'
      regedit.exe /s $newtxt
      regedit.exe /s $txtfile
      
      $WshShell = New-Object -comObject WScript.Shell
      $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk')
      $Shortcut.TargetPath = 'C:\Windows\System32\Notepad.exe'
      $Shortcut.Save()

      
    }

    if ($checkbox8.Checked) {
      Write-Status -Message 'Hiding Recommended Section...' -Type Output
      #set education enviroment
      reg add 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start' /v HideRecommendedSection /t REG_DWORD /d 1 /f
      reg add 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education' /v IsEducationEnvironment /t REG_DWORD /d 1 /f
      reg add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v HideRecommendedSection /t REG_DWORD /d 1 /f

      #restart explorer to apply
      Stop-Process -Name sihost
    }

    if ($checkbox19.Checked) {
      #enable windows 10 icons
      $ogIcons = 'C:\Windows\SystemResources\imageres.dll.mun'
      Write-Status -Message 'Making Backup of C:\Windows\SystemResources\imageres.dll.mun > zBackup' -Type Output
      if (!(Test-Path "$env:USERPROFILE\zBackup")) {
        New-Item "$env:USERPROFILE\zBackup" -ItemType Directory | Out-Null
      }

      #takeownership and move win10 imageres
      takeown.exe /f 'C:\Windows\SystemResources' *>$null
      icacls.exe 'C:\Windows\SystemResources' /grant Administrators:F /T /C *>$null
      takeown.exe /f $ogIcons *>$null
      icacls.exe $ogIcons /grant Administrators:F /T /C *>$null
      Copy-item $ogIcons -Destination "$env:USERPROFILE\zBackup" -Force
      Write-Status -Message 'Replacing With Windows 10 Icons...' -Type Output
      Remove-Item $ogIcons -Force
      $win10imageres = Search-File '*imageres10.dll.mun'
      Move-Item $win10imageres -Destination 'C:\Windows\SystemResources' -Force
      Rename-Item 'C:\Windows\SystemResources\imageres10.dll.mun' -NewName 'imageres.dll.mun' -Force
      #clear icon cache and restart explorer to apply
      taskkill /f /im explorer.exe
      Remove-Item -Path "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Explorer\*iconcache_*" -Force
      Remove-Item -Path "$env:USERPROFILE\AppData\Local\Microsoft\Windows\Explorer\*thumbcache_*" -Force
      #restart explorer
      Start-Process explorer.exe

    }

    if ($checkbox21.Checked) {
      Write-Status -Message "Backing up Original Winver.exe > [$env:USERPROFILE\zBackup]" -Type Output
     
      takeown.exe /f 'C:\Windows\System32\winver.exe' *>$null
      icacls.exe 'C:\Windows\System32\winver.exe' /grant Administrators:F /T /C *>$null
      if (!(Test-Path "$env:USERPROFILE\zBackup")) {
        New-Item "$env:USERPROFILE\zBackup" -ItemType Directory | Out-Null
      }
      Copy-item 'C:\Windows\System32\winver.exe' -Destination "$env:USERPROFILE\zBackup" -Force
      Rename-Item "$env:USERPROFILE\zBackup\winver.exe" -NewName 'OGwinver.exe' -Force
      $Menu = $true
      do {
        $input = Read-Host "Choose 1 For Standard `nChoose 2 for Mono Theme" 
        if ($input -eq 1) {
          Write-Status -Message 'Replacing Winver...' -Type Output
        
          $stdpath = Search-file '*WinverStandard.exe'
          Remove-Item 'C:\Windows\System32\winver.exe' -Force
          Move-Item $stdpath -Destination 'C:\Windows\System32' -Force
          Rename-Item 'C:\Windows\System32\WinverStandard.exe' -NewName 'winver.exe' -Force
          $Menu = $false
        }
        elseif ($input -eq 2) {
          Write-Status -Message 'Replacing Winver...' -Type Output
       
          $monopath = Search-file '*WinverMono.exe'
          Remove-Item 'C:\Windows\System32\winver.exe' -Force
          Move-Item $monopath -Destination 'C:\Windows\System32' -Force
          Rename-Item 'C:\Windows\System32\WinverMono.exe' -NewName 'winver.exe' -Force
          $Menu = $false
        }
        else {
          Write-Host 'Invalid Input!' -ForegroundColor Red
        }
      }while ($Menu)
      
    }


    if ($checkbox22.Checked) {
      Write-Status -Message 'Removing Quick Settings Tiles...' -Type Output
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'SimplifyQuickSettings' /t REG_DWORD /d '1' /f
      gpupdate /force >$null
    }


    if ($checkbox23.Checked) {
      Write-Status -Message 'Removing System Labels from Start Menu Apps...' -Type Output
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1009102476' /v 'EnabledState' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1009102476' /v 'EnabledStateOptions' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1009102476' /v 'Variant' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1009102476' /v 'VariantPayload' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1009102476' /v 'VariantPayloadKind' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1280814733' /v 'EnabledState' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1280814733' /v 'EnabledStateOptions' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1280814733' /v 'Variant' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1280814733' /v 'VariantPayload' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1280814733' /v 'VariantPayloadKind' /t REG_DWORD /d '0' /f
    }

    if ($checkbox24.Checked) {
      Write-Status -Message 'Disabling Notepad Tabs and Rewrite...' -Type Output
      $regContent = @'
Windows Registry Editor Version 5.00

[HKEY_USERS\TEMP\LocalState]
"OpenFile"=hex(5f5e104):01,00,00,00,d1,55,24,57,d1,84,db,01
"GhostFile"=hex(5f5e10b):00,42,60,f1,5a,d1,84,db,01
"RewriteEnabled"=hex(5f5e10b):00,12,4a,7f,5f,d1,84,db,01
'@

      #load notepad settings to registry
      reg load HKU\TEMP "$env:LOCALAPPDATA\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\Settings\settings.dat" >$null
      New-Item "$env:TEMP\DisableTabs.reg" -Value $regContent -Force | Out-Null
      regedit.exe /s "$env:TEMP\DisableTabs.reg"
      Start-Sleep 1
      reg unload HKU\TEMP >$null
      Remove-Item "$env:TEMP\DisableTabs.reg" -Force -ErrorAction SilentlyContinue


    }
      
          
    if ($checkbox25.Checked) {
      Write-Status -Message 'Hiding Home Page in Settings...' -Type Output
      $regKey = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
      $keyPropString = 'hide:home;'
      Reg.exe add $regKey /v 'SettingsPageVisibility' /t REG_SZ /d $keyPropString /f >$null
    }

    if ($checkbox26.Checked) {
      Write-Status -Message 'Hiding Ads and Useless Cards in Settings...' -Type Output
      #disable account ads by setting the default state for velocity ids

      $settingsJSON = (Get-ChildItem -Path "$env:windir\SystemApps" -Recurse).FullName | Where-Object { $_ -like '*wsxpacks\Account\SettingsExtensions.json' }

      #takeownership
      takeown /f $settingsJSON *>$null
      icacls $settingsJSON /grant administrators:F /t *>$null

      $jsonContent = Get-Content $settingsJSON | ConvertFrom-Json
      $list = 'SubscriptionCard', 'SubscriptionCard_Enterprise', 'CopilotSubscriptionCard', 
      'CopilotSubscriptionCard_Enterprise', 'XboxSubscriptionCard', 'XboxSubscriptionCard_Enterprise',
      'SignedOutCard', 'SignedOutCard_SecondPlace', 'SignedOutCard_Enterprise_Local', 
      'SignedOutCard_Enterprise_AAD', 'SettingsPageGroupAccounts'

      $jsonContent.addedHomeCards = $jsonContent.addedHomeCards | Where-Object { $list -notcontains $_.cardId }
      $jsonContent.hiddenPages = $jsonContent.hiddenPages | ForEach-Object { 
        if ($_.pageGroupId -eq 'SettingsPageGroupAccounts' -and $_.conditions -and $_.conditions.velocityKey) { 
          $_.conditions.velocityKey.default = 'disabled'
        }
        $_ 
      }
      $jsonContent.addedPages = $jsonContent.addedPages | ForEach-Object { 
        if ($_.pageId -eq 'SettingsPageGroupAccounts_Home' -and $_.conditions -and $_.conditions.velocityKey) { 
          $_.conditions.velocityKey.default = 'disabled'
        }
        $_ 
      }

      $newContent = $jsonContent | ConvertTo-Json -Depth 100
      Set-Content -Path $settingsJSON -Value $newContent -Force

      #disable annoying "charms" in settings banner 
      $command = "Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\ValueBanner.IdealStateFeatureControlProvider' /v ActivationType /t REG_DWORD /d 0 /f"
      Run-Trusted -command $command
    }

  }
}
Export-ModuleMember -Function W11Tweaks  
      
  
function install-key {

  #check for internet connection
  if (!(Check-Internet)) {
    Write-Status -Message 'Activating Windows with Generic Pro Key via KMS...' -Type Output
   
    #try a few servers incase one is down or is blocked
    $command = {
      takeown.exe /f 'C:\Windows\System32\slmgr.vbs' 
      icacls.exe 'C:\Windows\System32\slmgr.vbs' /grant Administrators:F
      cscript //nologo 'C:\Windows\System32\slmgr.vbs' /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX
      cscript //nologo 'C:\Windows\System32\slmgr.vbs' /skms kms.03k.org:1688
      cscript //nologo 'C:\Windows\System32\slmgr.vbs' /skms kms8.msguides.com
      cscript //nologo 'C:\Windows\System32\slmgr.vbs' /skms kms789.com 
      cscript //nologo 'C:\Windows\System32\slmgr.vbs' /skms kms.digiboy.ir
      cscript //nologo 'C:\Windows\System32\slmgr.vbs' /ato
    }
    Invoke-Command $command | Out-Null
  }

    
  Custom-MsgBox -message 'Windows Activated!' -type None

    
}  
Export-ModuleMember -Function install-key 


function UltimateCleanup {

  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  [System.Windows.Forms.Application]::EnableVisualStyles()

  # Create the form
  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'Ultimate Cleanup'
  $form.Size = New-Object System.Drawing.Size(530, 420)
  $form.StartPosition = 'CenterScreen'
  $form.BackColor = 'Black'
  $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
  $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

  $label = New-Object System.Windows.Forms.Label
  $label.Location = New-Object System.Drawing.Point(10, 10)
  $label.Size = New-Object System.Drawing.Size(250, 24)
  $label.Text = 'Disk Cleanup Options:'
  $label.ForeColor = 'White'
  $label.Font = New-Object System.Drawing.Font('Segoe UI', 10) 
  $form.Controls.Add($label)


  $label = New-Object System.Windows.Forms.Label
  $label.Location = New-Object System.Drawing.Point(270, 10)
  $label.Size = New-Object System.Drawing.Size(250, 24)
  $label.Text = 'Additional Options:'
  $label.ForeColor = 'White'
  $label.Font = New-Object System.Drawing.Font('Segoe UI', 10) 
  $form.Controls.Add($label)

  $lineStartPoint = New-Object System.Drawing.Point(10, 34)
  $lineEndPoint = New-Object System.Drawing.Point(250, 34)
  $lineColor = [System.Drawing.Color]::Gray
  $lineWidth = 1.5

  $form.Add_Paint({
      $graphics = $form.CreateGraphics()
      $pen = New-Object System.Drawing.Pen($lineColor, $lineWidth)
      $graphics.DrawLine($pen, $lineStartPoint, $lineEndPoint)
      $pen.Dispose()
      $graphics.Dispose()
    })


  $lineStartPoint2 = New-Object System.Drawing.Point(270, 34)
  $lineEndPoint2 = New-Object System.Drawing.Point(450, 34)
  $lineColor2 = [System.Drawing.Color]::Gray
  $lineWidth2 = 1.5

  $form.Add_Paint({
      $graphics = $form.CreateGraphics()
      $pen = New-Object System.Drawing.Pen($lineColor2, $lineWidth2)
      $graphics.DrawLine($pen, $lineStartPoint2, $lineEndPoint2)
      $pen.Dispose()
      $graphics.Dispose()
    })

  # Create the CheckedListBox
  $checkedListBox = New-Object System.Windows.Forms.CheckedListBox
  $checkedListBox.Location = New-Object System.Drawing.Point(10, 50)
  $checkedListBox.Size = New-Object System.Drawing.Size(250, 300)
  $checkedListBox.CheckOnClick = $true
  $checkedListBox.BackColor = 'Black'
  $checkedListBox.ForeColor = 'White'
  $options = @(
    'Active Setup Temp Folders'
    'Thumbnail Cache'
    'Delivery Optimization Files'
    'D3D Shader Cache'
    'Downloaded Program Files'
    'Internet Cache Files'
    'Setup Log Files'
    'Temporary Files'
    'Windows Error Reporting Files'
    'Offline Pages Files'
    'Recycle Bin'
    'Temporary Setup Files'
    'Update Cleanup'
    'Upgrade Discarded Files'
    'Windows Defender'
    'Windows ESD installation files'
    'Windows Reset Log Files'
    'Windows Upgrade Log Files'
    'Previous Installations'
    'Old ChkDsk Files'
    'Feedback Hub Archive log files'
    'Diagnostic Data Viewer database files'
    'Device Driver Packages'
  )
  foreach ($option in $options) {
    $checkedListBox.Items.Add($option, $false) | Out-Null
  }

  # Create the checkboxes
  $checkBox1 = New-Object System.Windows.Forms.CheckBox
  $checkBox1.Text = 'Clear Event Viewer Logs'
  $checkBox1.Location = New-Object System.Drawing.Point(270, 50)
  $checkBox1.ForeColor = 'White'
  $checkBox1.AutoSize = $true

  $checkBox2 = New-Object System.Windows.Forms.CheckBox
  $checkBox2.Text = 'Clear Windows Logs'
  $checkBox2.Location = New-Object System.Drawing.Point(270, 80)
  $checkBox2.ForeColor = 'White'
  $checkBox2.AutoSize = $true

  $checkBox3 = New-Object System.Windows.Forms.CheckBox
  $checkBox3.Text = 'Clear TEMP Cache'
  $checkBox3.Location = New-Object System.Drawing.Point(270, 110)
  $checkBox3.ForeColor = 'White'
  $checkBox3.AutoSize = $true

  $checkBox4 = New-Object System.Windows.Forms.CheckBox
  $checkBox4.Text = 'Clean Nvidia Driver Shader Cache'
  $checkBox4.Location = New-Object System.Drawing.Point(270, 140)
  $checkBox4.ForeColor = 'White'
  $checkBox4.AutoSize = $true
  $form.Controls.Add($checkBox4)

  $checkBox5 = New-Object System.Windows.Forms.CheckBox
  $checkBox5.Text = 'Remove Windows.old Folder'
  $checkBox5.Location = New-Object System.Drawing.Point(270, 170)
  $checkBox5.ForeColor = 'White'
  $checkBox5.AutoSize = $true
  $form.Controls.Add($checkBox5)

  $checkBox6 = New-Object System.Windows.Forms.CheckBox
  $checkBox6.Text = 'Remove Old Duplicate Drivers'
  $checkBox6.Location = New-Object System.Drawing.Point(270, 200)
  $checkBox6.ForeColor = 'White'
  $checkBox6.AutoSize = $true
  $form.Controls.Add($checkBox6)

  # Create the Clean button
  $buttonClean = New-Object System.Windows.Forms.Button
  $buttonClean.Text = 'Clean'
  $buttonClean.Location = New-Object System.Drawing.Point(330, 310)
  $buttonClean.Size = New-Object System.Drawing.Size(100, 30)
  $buttonClean.ForeColor = 'White'
  $buttonClean.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
  $buttonClean.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $buttonClean.Add_MouseEnter({
      $buttonClean.BackColor = [System.Drawing.Color]::FromArgb(64, 64, 64)
    })

  $buttonClean.Add_MouseLeave({
      $buttonClean.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    })
  
  $checkALL = New-Object System.Windows.Forms.CheckBox
  $checkALL.Text = 'Check All'
  $checkALL.Location = New-Object System.Drawing.Point(10, 345)
  $checkALL.ForeColor = 'White'
  $checkALL.AutoSize = $true
  $checkALL.add_CheckedChanged({
      if ($checkALL.Checked) {
        $i = 0
        foreach ($option in $options) {
          $checkedListBox.SetItemChecked($i, $true)
          $i++
        }
      }
      else {
        $i = 0
        foreach ($option in $options) {
          $checkedListBox.SetItemChecked($i, $false)
          $i++
        }
      }
    })
  $form.Controls.Add($checkALL)
  
  # Add controls to the form
  $form.Controls.Add($checkedListBox)
  $form.Controls.Add($checkBox1)
  $form.Controls.Add($checkBox2)
  $form.Controls.Add($checkBox3)
  $form.Controls.Add($buttonClean)

  # Show the form
  $result = $form.ShowDialog()


  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $driveletter = $env:SystemDrive -replace ':', ''
    $drive = Get-PSDrive $driveletter
    $usedInGB = [math]::Round($drive.Used / 1GB, 4)
    Write-Host 'BEFORE CLEANING' -ForegroundColor Red 
    Write-Host "Used space on $($drive.Name):\ $usedInGB GB" -ForegroundColor Red
    


    if ($checkBox1.Checked) {
      Write-Status -Message 'Clearing Event Viewer Logs...' -Type Output
      
      wevtutil el | Foreach-Object { wevtutil cl "$_" >$null 2>&1 } 
    }
    if ($checkBox2.Checked) {
      #CLEAR LOGS
      Write-Status -Message 'Clearing Windows Log Files...' -Type Output
      
      #Clear Distributed Transaction Coordinator logs
      Remove-Item -Path $env:SystemRoot\DtcInstall.log -Force -ErrorAction SilentlyContinue 
      #Clear Optional Component Manager and COM+ components logs
      Remove-Item -Path $env:SystemRoot\comsetup.log -Force -ErrorAction SilentlyContinue 
      #Clear Pending File Rename Operations logs
      Remove-Item -Path $env:SystemRoot\PFRO.log -Force -ErrorAction SilentlyContinue 
      #Clear Windows Deployment Upgrade Process Logs
      Remove-Item -Path $env:SystemRoot\setupact.log -Force -ErrorAction SilentlyContinue 
      Remove-Item -Path $env:SystemRoot\setuperr.log -Force -ErrorAction SilentlyContinue 
      #Clear Windows Setup Logs
      Remove-Item -Path $env:SystemRoot\setupapi.log -Force -ErrorAction SilentlyContinue 
      Remove-Item -Path $env:SystemRoot\Panther\* -Force -Recurse -ErrorAction SilentlyContinue 
      Remove-Item -Path $env:SystemRoot\inf\setupapi.app.log -Force -ErrorAction SilentlyContinue 
      Remove-Item -Path $env:SystemRoot\inf\setupapi.dev.log -Force -ErrorAction SilentlyContinue 
      Remove-Item -Path $env:SystemRoot\inf\setupapi.offline.log -Force -ErrorAction SilentlyContinue 
      #Clear Windows System Assessment Tool logs
      Remove-Item -Path $env:SystemRoot\Performance\WinSAT\winsat.log -Force -ErrorAction SilentlyContinue 
      #Clear Password change events
      Remove-Item -Path $env:SystemRoot\debug\PASSWD.LOG -Force -ErrorAction SilentlyContinue 
      #Clear DISM (Deployment Image Servicing and Management) Logs
      Remove-Item -Path $env:SystemRoot\Logs\CBS\CBS.log -Force -ErrorAction SilentlyContinue  
      Remove-Item -Path $env:SystemRoot\Logs\DISM\DISM.log -Force -ErrorAction SilentlyContinue  
      #Clear Server-initiated Healing Events Logs
      Remove-Item -Path "$env:SystemRoot\Logs\SIH\*" -Force -ErrorAction SilentlyContinue 
      #Common Language Runtime Logs
      Remove-Item -Path "$env:LocalAppData\Microsoft\CLR_v4.0\UsageTraces\*" -Force -ErrorAction SilentlyContinue 
      Remove-Item -Path "$env:LocalAppData\Microsoft\CLR_v4.0_32\UsageTraces\*" -Force -ErrorAction SilentlyContinue 
      #Network Setup Service Events Logs
      Remove-Item -Path "$env:SystemRoot\Logs\NetSetup\*" -Force -ErrorAction SilentlyContinue 
      #Disk Cleanup tool (Cleanmgr.exe) Logs
      Remove-Item -Path "$env:SystemRoot\System32\LogFiles\setupcln\*" -Force -ErrorAction SilentlyContinue 
      #Clear Windows update and SFC scan logs
      Remove-Item -Path $env:SystemRoot\Temp\CBS\* -Force -ErrorAction SilentlyContinue 
      #Clear Windows Update Medic Service logs
      takeown /f $env:SystemRoot\Logs\waasmedic /r -Value y *>$null
      icacls $env:SystemRoot\Logs\waasmedic /grant administrators:F /t *>$null
      Remove-Item -Path $env:SystemRoot\Logs\waasmedic -Recurse -ErrorAction SilentlyContinue 
      #Clear Cryptographic Services Traces
      Remove-Item -Path $env:SystemRoot\System32\catroot2\dberr.txt -Force -ErrorAction SilentlyContinue 
      Remove-Item -Path $env:SystemRoot\System32\catroot2.log -Force -ErrorAction SilentlyContinue 
      Remove-Item -Path $env:SystemRoot\System32\catroot2.jrs -Force -ErrorAction SilentlyContinue 
      Remove-Item -Path $env:SystemRoot\System32\catroot2.edb -Force -ErrorAction SilentlyContinue 
      Remove-Item -Path $env:SystemRoot\System32\catroot2.chk -Force -ErrorAction SilentlyContinue 
      #Windows Update Logs
      Remove-Item -Path "$env:SystemRoot\Traces\WindowsUpdate\*" -Force -ErrorAction SilentlyContinue 
    }
    if ($checkBox3.Checked) {
      Write-Status -Message 'Clearing TEMP Files...' -Type Output
   
      #cleanup temp files
      $temp1 = 'C:\Windows\Temp'
      $temp2 = $env:TEMP
      $tempFiles = (Get-ChildItem -Path $temp1 , $temp2 -Recurse -Force).FullName
      foreach ($file in $tempFiles) {
        Remove-Item -Path $file -Recurse -Force -ErrorAction SilentlyContinue
      }
    }

    if ($checkBox4.Checked) {
      Write-Status -Message 'Cleaning DX and GL Cache...' -Type Output
      Remove-Item -Path "$env:LocalAppData\NVIDIA\GLCache" -Recurse -Force -ErrorAction SilentlyContinue
      Remove-Item -Path "$env:USERPROFILE\AppData\LocalLow\NVIDIA\PerDriverVersion\DXCache" -Recurse -Force -ErrorAction SilentlyContinue
      
    }

    if ($checkBox5.Checked) {
      Write-Status -Message 'Removing Windows.old Folder...' -Type Output
      #use multiple methods to remove folder
      $command = "Get-ChildItem `"$env:SystemDrive\Windows.old`" -Recurse | Remove-Item -Force -Recurse"
      Run-Trusted -command $command
      Start-Sleep 1
      $command = "Remove-Item `"$env:SystemDrive\Windows.old`" -Recurse -Force"
      Run-Trusted -command $command
      Write-Status -Message 'Taking Ownership...This may take a moment' -Type Output
      takeown /f "$env:SystemDrive\Windows.old" /r /d Y *>$null
      icacls "$env:SystemDrive\Windows.old" /grant administrators:F /t *>$null
      cmd.exe /c rmdir /S /Q "$env:SystemDrive\Windows.old" *>$null
    }

    if ($checkBox6.Checked) {
      Write-Status -Message 'Searching For Old Duplicate Drivers...' -Type Output
      # Use this PowerShell script to find and remove old and unused device drivers from the Windows Driver Store
      # Explanation: http://woshub.com/how-to-remove-unused-drivers-from-driver-store/

      $dismOut = dism /online /get-drivers
      $Lines = $dismOut | Select-Object -Skip 10
      $Operation = 'theName'
      $Drivers = @()
      foreach ( $Line in $Lines ) {
        $tmp = $Line
        $txt = $($tmp.Split( ':' ))[1]
        switch ($Operation) {
          'theName' {
            $Name = $txt
            $Operation = 'theFileName'
            break
          }
          'theFileName' {
            $FileName = $txt.Trim()
            $Operation = 'theEntr'
            break
          }
          'theEntr' {
            $Entr = $txt.Trim()
            $Operation = 'theClassName'
            break
          }
          'theClassName' {
            $ClassName = $txt.Trim()
            $Operation = 'theVendor'
            break
          }
          'theVendor' {
            $Vendor = $txt.Trim()
            $Operation = 'theDate'
            break
          }
          'theDate' {
            # we'll change the default date format for easy sorting
            $tmp = $txt.split( '.' )
            $txt = "$($tmp[2]).$($tmp[1]).$($tmp[0].Trim())"
            $Date = $txt
            $Operation = 'theVersion'
            break
          }
          'theVersion' {
            $Version = $txt.Trim()
            $Operation = 'theNull'
            $params = [ordered]@{ 'FileName' = $FileName
              'Vendor'                       = $Vendor
              'Date'                         = $Date
              'Name'                         = $Name
              'ClassName'                    = $ClassName
              'Version'                      = $Version
              'Entr'                         = $Entr
            }
            $obj = New-Object -TypeName PSObject -Property $params
            $Drivers += $obj
            break
          }
          'theNull' {
            $Operation = 'theName'
            break
          }
        }
      }
      $last = ''
      $NotUnique = @()
      foreach ( $Dr in $($Drivers | Sort-Object Filename) ) {
        if ($Dr.FileName -eq $last  ) { $NotUnique += $Dr }
        $last = $Dr.FileName
      }
      $NotUnique | Sort-Object FileName | Format-Table
      # search for duplicate drivers 
      $list = $NotUnique | Select-Object -ExpandProperty FileName -Unique
      $ToDel = @()
      foreach ( $Dr in $list ) {
        #  Write-Host 'duplicate driver found' -ForegroundColor Yellow
        $sel = $Drivers | Where-Object { $_.FileName -eq $Dr } | Sort-Object date -Descending | Select-Object -Skip 1
        #  $sel | Format-Table
        $ToDel += $sel
      }
      # Write-Host 'List of driver version  to remove' -ForegroundColor Red
      #  $ToDel | Format-Table
      # Removing old driver versions
      if ($ToDel.Count -gt 0) {
        Write-Status -Message "Removing $($ToDel.Count) Duplicate Drivers..." -Type Output
        foreach ( $item in $ToDel ) {
          $Name = $($item.Name).Trim()
          # Write-Host "deleting $Name" -ForegroundColor Yellow
          # Write-Host "pnputil.exe /remove-device  $Name" -ForegroundColor Yellow
          Invoke-Expression -Command "pnputil.exe /remove-device $Name"
        }
      }
      else {
        Write-Status -Message 'No Duplicate Drivers Found!' -Type Output
      }
    }

    if ($checkedListBox.CheckedItems) {
      $key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
      foreach ($item in $checkedListBox.CheckedItems) {
        reg.exe add "$key\$item" /v StateFlags0069 /t REG_DWORD /d 00000002 /f >$nul 2>&1
      }
      Write-Status -Message 'Running Disk Cleanup...' -Type Output
    
      #credits to @instead1337 for monitoring logic
      $timeout = 300
      $cleanupProcess = Start-Process cleanmgr.exe -ArgumentList '/sagerun:69' -Wait:$false -PassThru
      $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
      $lastCpuUsage = 0
      $lastMemoryUsage = 0

      while ($cleanupProcess -and !$cleanupProcess.HasExited -and $stopwatch.Elapsed.TotalSeconds -lt $timeout) {
        Start-Sleep -Seconds 10
        $process = Get-Process -Id $cleanupProcess.Id -EA SilentlyContinue
        if ($process) {
          $cpuUsage = $process.CPU
          $memoryUsage = $process.WS
          if ($cpuUsage -eq $lastCpuUsage -and $memoryUsage -eq $lastMemoryUsage) {
            Write-Status -Message 'Disk Cleanup Is Most Likely Frozen...' -Type Output
            Write-Status -Message 'Closing Disk Cleanup Window...' -Type Output
            if ($cleanupProcess.MainWindowHandle) {
              $cleanupProcess.CloseMainWindow() | Out-Null
              Start-Sleep -Seconds 5
              if (!$cleanupProcess.HasExited) { $cleanupProcess | Stop-Process -EA SilentlyContinue }
            }
            else {
              $cleanupProcess | Stop-Process -EA SilentlyContinue
            }
          }
          $lastCpuUsage = $cpuUsage
          $lastMemoryUsage = $memoryUsage
        }
        
      }

      
    }

    $drive = Get-PSDrive $driveletter
    $usedInGB = [math]::Round($drive.Used / 1GB, 4)
    Write-Host 'AFTER CLEANING' -ForegroundColor Green
    Write-Host "Used space on $($drive.Name):\ $usedInGB GB" -ForegroundColor Green
    
  }

  
}
Export-ModuleMember -Function UltimateCleanup



function Run-Trusted([String]$command) {

  Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue
  #get bin path to revert later
  $service = Get-WmiObject -Class Win32_Service -Filter "Name='TrustedInstaller'"
  $DefaultBinPath = $service.PathName
  #convert command to base64 to avoid errors with spaces
  $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
  $base64Command = [Convert]::ToBase64String($bytes)
  #change bin to command
  sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
  #run the command
  sc.exe start TrustedInstaller | Out-Null
  #set bin back to default
  sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
  Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue

}
Export-ModuleMember -Function Run-Trusted





# -------------- splitting up get-childitem to search for files and folders individually turns out to be the fastest way to search for files 
# -------------- removed dotnet file searching too slow in most cases because of recursion required
      
function Search-File($filter) {
  #search in _FOLDERMUSTBEONCDRIVE first 

  #search c drive for only files to speed up searching
  return (Get-ChildItem -Path $folder, $sysDrive -Filter $filter -Recurse -File -ErrorAction SilentlyContinue -Force | Where-Object Name -NotIn '$Recycle.Bin' | Select-Object -First 1).FullName
}
Export-ModuleMember -Function Search-File
      
      

function Search-Directory($filter) {
  #search c drive for only directories
  return (Get-ChildItem -Path $folder, $sysDrive -Filter $filter -Recurse -Directory -ErrorAction SilentlyContinue -Force | Where-Object Name -NotIn '$Recycle.Bin' | Select-Object -First 1).FullName
}
Export-ModuleMember -Function Search-Directory   


 

function Custom-MsgBox {
  param(
    [string]$message,
    [ValidateSet('Question', 'Warning', 'None')]
    [string]$type
  )
  Add-Type -AssemblyName System.Windows.Forms

  # Enable visual styles
  [System.Windows.Forms.Application]::EnableVisualStyles()

  # Create the form
  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'ZOICWARE'
  if ($type -eq 'None') {
    $form.Size = New-Object System.Drawing.Size(280, 180)
  }
  else {
    $form.Size = New-Object System.Drawing.Size(370, 200)
  }
  $form.StartPosition = 'CenterScreen'
  $form.BackColor = [System.Drawing.Color]::Black
  $form.ForeColor = [System.Drawing.Color]::White
  $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
  $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

  # Add Icon
  $pictureBox = New-Object System.Windows.Forms.PictureBox
  $pictureBox.Location = New-Object System.Drawing.Point(20, 30) 
  $pictureBox.Size = New-Object System.Drawing.Size(50, 50) 
  $pictureBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
  if ($type -eq 'Warning') {
    $imagePath = 'C:\Windows\System32\SecurityAndMaintenance_Alert.png'
  }
  if ($type -eq 'Question') {
    $imagePath = "$iconDir\questionIcon.png"
  }
  if ($type -eq 'None') {
    $imagePath = "$iconDir\greencheckIcon.png"
  }
    
  try {
    $image = [System.Drawing.Image]::FromFile($imagePath)
  }
  catch {
    Write-Status -Message 'Unable to Load Icon' -Type Error
  }
  $pictureBox.Image = $image
  $form.Controls.Add($pictureBox)

  # Create the label
  $label = New-Object System.Windows.Forms.Label
  $label.Text = $message
  if ($type -eq 'None') {
    $label.Size = New-Object System.Drawing.Size(200, 60)
  }
  else {
    $label.Size = New-Object System.Drawing.Size(250, 80)
  }
  $label.Location = New-Object System.Drawing.Point(90, 40)
  if ($message -like '*Restart PC?') {
    $label.Font = New-Object System.Drawing.Font('Segoe UI', 10)
  }
  $label.ForeColor = [System.Drawing.Color]::White
  $form.Controls.Add($label)

  $ribbonPanel = New-Object System.Windows.Forms.Panel
  $ribbonPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
  $ribbonPanel.Height = 40
  $ribbonPanel.BackColor = [System.Drawing.Color]::FromArgb(35, 35, 35)  
  $form.Controls.Add($ribbonPanel)


  # Create the OK button
  $okButton = New-Object System.Windows.Forms.Button
  if ($type -eq 'Question') {
    $okButton.Text = 'Yes'
  }
  else {
    $okButton.Text = 'OK'
  }
  if ($type -eq 'None') {
    $okButton.Location = New-Object System.Drawing.Point((($ribbonPanel.Width / 2) + 40), 8)
  }
  else {
    $okButton.Location = New-Object System.Drawing.Point(($ribbonPanel.Width / 2), 8)
  }
  $okButton.BackColor = 'Black'
  $okButton.Size = New-Object System.Drawing.Size(75, 25)
  $okButton.ForeColor = [System.Drawing.Color]::White
  $oKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $ribbonPanel.Controls.Add($okButton)

  if (!($type -eq 'None')) {
    # Create the Cancel button
    $cancelButton = New-Object System.Windows.Forms.Button
    if ($type -eq 'Question') {
      $cancelButton.Text = 'No'
    }
    else {
      $cancelButton.Text = 'Cancel'
    }
    $cancelButton.Location = New-Object System.Drawing.Point((($ribbonPanel.Width / 2) + 85), 8)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 25)
    $cancelButton.BackColor = 'Black'
    $cancelButton.ForeColor = [System.Drawing.Color]::White
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $ribbonPanel.Controls.Add($cancelButton)

  }
   
  # Show the form
  $result = $form.ShowDialog()

  return $result
}
Export-ModuleMember -Function Custom-MsgBox


function Check-Internet {
  $noInternet = $false
  try {
    Invoke-WebRequest -Uri 'https://www.google.com' -Method Head -DisableKeepAlive -UseBasicParsing | Out-Null
  }
  catch [System.Net.WebException] {
    $noInternet = $true
  }

  if ($noInternet) {
    Write-Status -Message 'This Tweak Requires Internet Connection...' -Type Error
    return 1
  }
  else {
    return 0
  }

}
Export-ModuleMember -Function Check-Internet


function Install-Browsers {
  
  function Get-FileFromWeb {
    param (
      # Parameter help description
      [Parameter(Mandatory)]
      [string]$URL,
  
      # Parameter help description
      [Parameter(Mandatory)]
      [string]$File 
    )
    Begin {
      function Show-Progress {
        param (
          # Enter total value
          [Parameter(Mandatory)]
          [Single]$TotalValue,
        
          # Enter current value
          [Parameter(Mandatory)]
          [Single]$CurrentValue,
        
          # Enter custom progresstext
          [Parameter(Mandatory)]
          [string]$ProgressText,
        
          # Enter value suffix
          [Parameter()]
          [string]$ValueSuffix,
        
          # Enter bar lengh suffix
          [Parameter()]
          [int]$BarSize = 40,

          # show complete bar
          [Parameter()]
          [switch]$Complete
        )
            
        # calc %
        $percent = $CurrentValue / $TotalValue
        $percentComplete = $percent * 100
        if ($ValueSuffix) {
          $ValueSuffix = " $ValueSuffix" # add space in front
        }
        if ($psISE) {
          Write-Progress "$ProgressText $CurrentValue$ValueSuffix of $TotalValue$ValueSuffix" -id 0 -percentComplete $percentComplete            
        }
        else {
          # build progressbar with string function
          $curBarSize = $BarSize * $percent
          $progbar = ''
          $progbar = $progbar.PadRight($curBarSize, [char]9608)
          $progbar = $progbar.PadRight($BarSize, [char]9617)
        
          if (!$Complete.IsPresent) {
            Write-Host -NoNewLine "`r$ProgressText $progbar [ $($CurrentValue.ToString('#.###').PadLeft($TotalValue.ToString('#.###').Length))$ValueSuffix / $($TotalValue.ToString('#.###'))$ValueSuffix ] $($percentComplete.ToString('##0.00').PadLeft(6)) % complete"
          }
          else {
            Write-Host -NoNewLine "`r$ProgressText $progbar [ $($TotalValue.ToString('#.###').PadLeft($TotalValue.ToString('#.###').Length))$ValueSuffix / $($TotalValue.ToString('#.###'))$ValueSuffix ] $($percentComplete.ToString('##0.00').PadLeft(6)) % complete"                    
          }                
        }   
      }
    }
    Process {
      try {
        $storeEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        
        # invoke request
        $request = [System.Net.HttpWebRequest]::Create($URL)
        $response = $request.GetResponse()
  
        if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $response.StatusCode -eq 404) {
          throw "Remote file either doesn't exist, is unauthorized, or is forbidden for '$URL'."
        }
  
        if ($File -match '^\.\\') {
          $File = Join-Path (Get-Location -PSProvider 'FileSystem') ($File -Split '^\.')[1]
        }
            
        if ($File -and !(Split-Path $File)) {
          $File = Join-Path (Get-Location -PSProvider 'FileSystem') $File
        }

        if ($File) {
          $fileDirectory = $([System.IO.Path]::GetDirectoryName($File))
          if (!(Test-Path($fileDirectory))) {
            [System.IO.Directory]::CreateDirectory($fileDirectory) | Out-Null
          }
        }

        [long]$fullSize = $response.ContentLength
        $fullSizeMB = $fullSize / 1024 / 1024
  
        # define buffer
        [byte[]]$buffer = new-object byte[] 1048576
        [long]$total = [long]$count = 0
  
        # create reader / writer
        $reader = $response.GetResponseStream()
        $writer = new-object System.IO.FileStream $File, 'Create'
  
        # start download
        $finalBarCount = 0 #show final bar only one time
        do {
          
          $count = $reader.Read($buffer, 0, $buffer.Length)
          
          $writer.Write($buffer, 0, $count)
              
          $total += $count
          $totalMB = $total / 1024 / 1024
          
          if ($fullSize -gt 0) {
            Show-Progress -TotalValue $fullSizeMB -CurrentValue $totalMB -ProgressText "Downloading $($File.Name)" -ValueSuffix 'MB'
          }

          if ($total -eq $fullSize -and $count -eq 0 -and $finalBarCount -eq 0) {
            Show-Progress -TotalValue $fullSizeMB -CurrentValue $totalMB -ProgressText "Downloading $($File.Name)" -ValueSuffix 'MB' -Complete
            $finalBarCount++
          }

        } while ($count -gt 0)
      }
  
      catch {
        
        $ExeptionMsg = $_.Exception.Message
        Write-Host "Download breaks with error : $ExeptionMsg"
      }
  
      finally {
        # cleanup
        if ($reader) { $reader.Close() }
        if ($writer) { $writer.Flush(); $writer.Close() }
        
        $ErrorActionPreference = $storeEAP
        [GC]::Collect()
      }    
    }
  }

  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.Application]::EnableVisualStyles()

  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'Browser Installer'
  $form.Size = New-Object System.Drawing.Size(300, 200)
  $form.StartPosition = 'CenterScreen'
  $form.BackColor = [System.Drawing.Color]::Black
  $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

  $chromeRadio = New-Object System.Windows.Forms.RadioButton
  $chromeRadio.Location = New-Object System.Drawing.Point(20, 20)
  $chromeRadio.Size = New-Object System.Drawing.Size(150, 20)
  $chromeRadio.Text = 'Chrome'
  $chromeRadio.ForeColor = [System.Drawing.Color]::White
  $form.Controls.Add($chromeRadio)

  $firefoxRadio = New-Object System.Windows.Forms.RadioButton
  $firefoxRadio.Location = New-Object System.Drawing.Point(20, 50)
  $firefoxRadio.Size = New-Object System.Drawing.Size(150, 20)
  $firefoxRadio.Text = 'Firefox'
  $firefoxRadio.ForeColor = [System.Drawing.Color]::White
  $form.Controls.Add($firefoxRadio)

  $braveRadio = New-Object System.Windows.Forms.RadioButton
  $braveRadio.Location = New-Object System.Drawing.Point(20, 80)
  $braveRadio.Size = New-Object System.Drawing.Size(150, 20)
  $braveRadio.Text = 'Brave'
  $braveRadio.ForeColor = [System.Drawing.Color]::White
  $form.Controls.Add($braveRadio)

  $installButton = New-Object System.Windows.Forms.Button
  $installButton.Location = New-Object System.Drawing.Point(100, 120)
  $installButton.Size = New-Object System.Drawing.Size(100, 30)
  $installButton.Text = 'Install'
  $installButton.ForeColor = [System.Drawing.Color]::White
  $installButton.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45)
  $installButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $form.Controls.Add($installButton)


  $result = $form.ShowDialog()


  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    if ($chromeRadio.Checked) {
      $uri = 'https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B297129A1-A25F-2799-7699-95238E0A3F50%7D%26lang%3Den%26browser%3D3%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Dempty/update2/installers/ChromeSetup.exe'
      Get-FileFromWeb -URL $uri -File "$env:TEMP\ChromeInstaller.exe"
      Write-Host 
      Write-Status -Message 'Installing Chrome...' -Type Output
      Start-Process "$env:TEMP\ChromeInstaller.exe" -ArgumentList '/silent /install' -Wait 
      Remove-Item "$env:TEMP\ChromeInstaller.exe" -Force -ErrorAction SilentlyContinue
    }
    elseif ($firefoxRadio.Checked) {
      $uri = 'https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US'
      Get-FileFromWeb -URL $uri -File "$env:TEMP\FireFoxInstaller.exe" 
      Write-Host
      Write-Status -Message 'Installing Firefox...' -Type Output
      Start-Process "$env:TEMP\FireFoxInstaller.exe" -ArgumentList '-ms' -Wait 
      Remove-Item "$env:TEMP\FireFoxInstaller.exe" -Force -ErrorAction SilentlyContinue
    }
    elseif ($braveRadio.Checked) {
      $headers = @{
        'User-Agent' = 'PowerShell'
      }
      $apiUrl = 'https://api.github.com/repos/brave/brave-browser/releases/latest'
      $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -UseBasicParsing -ErrorAction Stop
      $downloadUrl = $response.assets | Where-Object { $_.name -eq 'BraveBrowserStandaloneSilentSetup.exe' } | Select-Object -ExpandProperty browser_download_url
    
      Get-FileFromWeb -URL $downloadUrl -File "$env:TEMP\BraveInstaller.exe"
      Write-Host
      Write-Status -Message 'Installing Brave...' -Type Output 
      Start-Process "$env:TEMP\BraveInstaller.exe" -Wait
      Remove-Item "$env:TEMP\BraveInstaller.exe" -Force -ErrorAction SilentlyContinue
       
    }

    Custom-MsgBox -message 'Browser Installed!' -type None
  }

}
Export-ModuleMember -Function Install-Browsers


function FixUploadBufferBloat {
  param (
    [switch]$Enable,
    [switch]$Disable
  )

  #-------------------------- CREDITS AVEYO FOR CHANGES -----------------------------

  if ($Enable) {
    Write-Status -Message 'Applying Network Settings to Limit Upload Bandwidth and Improve Latency Under Load...' -Type Output
   
    #get all network adapters
    $NIC = @()
    foreach ($a in Get-NetAdapter -Physical | Select-Object DeviceID, Name) { 
      $NIC += @{ $($a | Select-Object Name -ExpandProperty Name) = $($a | Select-Object DeviceID -ExpandProperty DeviceID) }
    }
    

    $enableQos = {    
      New-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' 1 -type string -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableUserTOSSetting 0 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' NonBestEffortLimit 80 -type dword -force -ea 0 
      Get-NetQosPolicy | Remove-NetQosPolicy -Confirm:$False -ea 0
      Remove-NetQosPolicy 'Bufferbloat' -Confirm:$False -ea 0
      New-NetQosPolicy 'Bufferbloat' -Precedence 254 -DSCPAction 46 -NetworkProfile Public -Default -MinBandwidthWeightAction 25
    }
    &$enableQos *>$null

    $tcpTweaks = {
      $NIC.Values | ForEach-Object {
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpAckFrequency 2 -type dword -force -ea 0  
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpNoDelay 1 -type dword -force -ea 0
      }
      if (Get-Item 'HKLM:\SOFTWARE\Microsoft\MSMQ') { Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters' TCPNoDelay 1 -type dword -force -ea 0 }
      Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' NetworkThrottlingIndex 0xffffffff -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' SystemResponsiveness 10 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' NonBestEffortLimit 80 -type dword -force -ea 0 
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' LargeSystemCache 0 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' Size 3 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DefaultTTL 64 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaxUserPort 65534 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' TcpTimedWaitDelay 30 -type dword -force -ea 0
      New-Item 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' 1 -type string -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' DnsPriority 6 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' HostsPriority 5 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' LocalPriority 4 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' NetbtPriority 7 -type dword -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableTaskOffload -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaximumReassemblyHeaders 0xffff -type dword -force -ea 0 
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' FastSendDatagramThreshold 1500 -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' DefaultReceiveWindow $(2048 * 4096) -type dword -force -ea 0
      Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' DefaultSendWindow $(2048 * 4096) -type dword -force -ea 0
    }
    &$tcpTweaks *>$null


    #disable adapters while applying 
    $NIC.Keys | ForEach-Object { Disable-NetAdapter -InterfaceAlias "$_" -Confirm:$False }

    $netAdaptTweaks = {
      foreach ($key in $NIC.Keys) {
        # reset advanced 
        $netProperty = Get-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword 'NetworkAddress' -ErrorAction SilentlyContinue
        if ($null -ne $netProperty.RegistryValue -and $netProperty.RegistryValue -ne ' ') {
          $mac = $netProperty.RegistryValue 
        }
        Get-NetAdapter -Name "$key" | Reset-NetAdapterAdvancedProperty -DisplayName '*'
        # restore custom mac
        if ($null -ne $mac) { 
          Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword 'NetworkAddress' -RegistryValue $mac 
        }
        # set receive and transmit buffers - less is better for latency, worst for throughput; too less and packet loss increases
        $rx = (Get-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*ReceiveBuffers').NumericParameterMaxValue  
        $tx = (Get-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*TransmitBuffers').NumericParameterMaxValue
        if ($null -ne $rx -and $null -ne $tx) {
          Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*ReceiveBuffers' -RegistryValue $rx # $rx 1024 320
          Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*TransmitBuffers' -RegistryValue $tx # $tx 2048 160
        }
        # pci-e adapters in msi-x mode from intel are generally fine with ITR Adaptive - others? not so much
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*InterruptModeration' -RegistryValue 0 # Off 0 On 1
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword 'ITR' -RegistryValue 0 # Off 0 Adaptive 65535
        # recieve side scaling is always worth it, some adapters feature more queues = cpu threads; not available for wireless   
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*RSS' -RegistryValue 1
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*NumRssQueues' -RegistryValue 2
        # priority tag
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*PriorityVLANTag' -RegistryValue 1
        # undesirable stuff 
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*FlowControl' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*JumboPacket' -RegistryValue 1514
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*HeaderDataSplit' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword 'TcpSegmentation' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword 'RxOptimizeThreshold' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword 'WaitAutoNegComplete' -RegistryValue 1
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword 'PowerSavingMode' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*SelectiveSuspend' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword 'EnableGreenEthernet' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword 'AdvancedEEE' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword 'EEE' -RegistryValue 0
        Set-NetAdapterAdvancedProperty -Name "$key" -RegistryKeyword '*EEE' -RegistryValue 0
      }

    }
    &$netAdaptTweaks *>$null


    $netAdaptTweaks2 = { $NIC.Keys | ForEach-Object {
        Set-NetAdapterRss -Name "$_" -NumberOfReceiveQueues 2 -MaxProcessorNumber 4 -Profile 'NUMAStatic' -Enabled $true -ea 0
        Enable-NetAdapterQos -Name "$_" -ea 0
        Enable-NetAdapterChecksumOffload -Name "$_" -ea 0
        Disable-NetAdapterRsc -Name "$_" -ea 0
        Disable-NetAdapterUso -Name "$_" -ea 0
        Disable-NetAdapterLso -Name "$_" -ea 0
        Disable-NetAdapterIPsecOffload -Name "$_" -ea 0
        Disable-NetAdapterEncapsulatedPacketTaskOffload -Name "$_" -ea 0
      }
        
      Set-NetOffloadGlobalSetting -TaskOffload Enabled
      Set-NetOffloadGlobalSetting -Chimney Disabled
      Set-NetOffloadGlobalSetting -PacketCoalescingFilter Disabled
      Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Disabled
      Set-NetOffloadGlobalSetting -ReceiveSideScaling Enabled
      Set-NetOffloadGlobalSetting -NetworkDirect Enabled
      Set-NetOffloadGlobalSetting -NetworkDirectAcrossIPSubnets Allowed -ea 0
    }
    &$netAdaptTweaks2 *>$null

    #enable adapters
    $NIC.Keys | ForEach-Object { Enable-NetAdapter -InterfaceAlias "$_" -Confirm:$False }

    $netShTweaks = {
      netsh winsock set autotuning on                                    # Winsock send autotuning
      netsh int udp set global uro=disabled                              # UDP Receive Segment Coalescing Offload - 11 24H2
      netsh int tcp set heuristics wsh=disabled forcews=enabled          # Window Scaling heuristics
      netsh int tcp set supplemental internet minrto=300                 # Controls TCP retransmission timeout. 20 to 300 msec.
      netsh int tcp set supplemental internet icw=10                     # Controls initial congestion window. 2 to 64 MSS
      netsh int tcp set supplemental internet congestionprovider=newreno # Controls the congestion provider. Default: cubic
      netsh int tcp set supplemental internet enablecwndrestart=disabled # Controls whether congestion window is restarted.
      netsh int tcp set supplemental internet delayedacktimeout=40       # Controls TCP delayed ack timeout. 10 to 600 msec.
      netsh int tcp set supplemental internet delayedackfrequency=2      # Controls TCP delayed ack frequency. 1 to 255.
      netsh int tcp set supplemental internet rack=enabled               # Controls whether RACK time based recovery is enabled.
      netsh int tcp set supplemental internet taillossprobe=enabled      # Controls whether Tail Loss Probe is enabled.
      netsh int tcp set security mpp=disabled                            # Memory pressure protection (SYN flood drop)
      netsh int tcp set security profiles=disabled                       # Profiles protection (private vs domain)

      netsh int tcp set global rss=enabled                    # Enable receive-side scaling.
      netsh int tcp set global autotuninglevel=Normal         # Fix the receive window at its default value
      netsh int tcp set global ecncapability=enabled          # Enable/disable ECN Capability.
      netsh int tcp set global timestamps=enabled             # Enable/disable RFC 1323 timestamps.
      netsh int tcp set global initialrto=1000                # Connect (SYN) retransmit time (in ms).
      netsh int tcp set global rsc=disabled                   # Enable/disable receive segment coalescing.
      netsh int tcp set global nonsackrttresiliency=disabled  # Enable/disable rtt resiliency for non sack clients.
      netsh int tcp set global maxsynretransmissions=4        # Connect retry attempts using SYN packets.
      netsh int tcp set global fastopen=enabled               # Enable/disable TCP Fast Open.
      netsh int tcp set global fastopenfallback=enabled       # Enable/disable TCP Fast Open fallback.
      netsh int tcp set global hystart=enabled                # Enable/disable the HyStart slow start algorithm.
      netsh int tcp set global prr=enabled                    # Enable/disable the Proportional Rate Reduction algorithm.
      netsh int tcp set global pacingprofile=off              # Set the periods during which pacing is enabled. off: Never pace.

      netsh int ip set global loopbacklargemtu=enable         # Loopback Large Mtu
      netsh int ip set global loopbackworkercount=4           # Loopback Worker Count 1 2 4
      netsh int ip set global loopbackexecutionmode=inline    # Loopback Execution Mode adaptive|inline|worker
      netsh int ip set global reassemblylimit=267748640       # Reassembly Limit 267748640|0
      netsh int ip set global reassemblyoutoforderlimit=48    # Reassembly Out Of Order Limit 32
      netsh int ip set global sourceroutingbehavior=drop      # Source Routing Behavior drop|dontforward
      netsh int ip set dynamicport tcp start=32769 num=32766  # DynamicPortRange tcp
      netsh int ip set dynamicport udp start=32769 num=32766  # DynamicPortRange udp
    }
    &$netShTweaks *>$null

  }
  elseif ($Disable) {
    Write-Status -Message 'Reverting Network Tweaks...' -Type Output
   
    #get all network adapters
    $NIC = @()
    foreach ($a in Get-NetAdapter -Physical | Select-Object DeviceID, Name) { 
      $NIC += @{ $($a | Select-Object Name -ExpandProperty Name) = $($a | Select-Object DeviceID -ExpandProperty DeviceID) }
    }

    $revertTcpTweaks = {
      $NIC.Values | ForEach-Object {
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpAckFrequency -force -ea 0
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpDelAckTicks -force -ea 0
        Remove-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$_" TcpNoDelay -force -ea 0
      }
      if (Get-Item 'HKLM:\SOFTWARE\Microsoft\MSMQ') { Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters' TCPNoDelay -force -ea 0 }
      Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' NetworkThrottlingIndex -force -ea 0
      Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' SystemResponsiveness -force -ea 0
      Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' NonBestEffortLimit -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' LargeSystemCache -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' Size -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DefaultTTL -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaxUserPort -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' TcpTimedWaitDelay -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' DnsPriority -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' HostsPriority -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' LocalPriority -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' NetbtPriority -force -ea 0
    }
    &$revertTcpTweaks *>$null

    $resetRegtweaks = {
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' FastSendDatagramThreshold -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' DefaultSendWindow -force -ea 0 
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters' DefaultReceiveWindow -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' IRPStackSize -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableTaskOffload -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' MaximumReassemblyHeaders -force -ea 0  
    }
    &$resetRegtweaks *>$null

    $resetNetAdaptTweaks = {
      $NIC.Keys | ForEach-Object { Disable-NetAdapter -InterfaceAlias "$_" -Confirm:$False }

      $NIC.Keys | ForEach-Object {
        $mac = $(Get-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword 'NetworkAddress' -ea 0).RegistryValue
        Get-NetAdapter -Name "$_" | Reset-NetAdapterAdvancedProperty -DisplayName '*'
        if ($mac) { Set-NetAdapterAdvancedProperty -Name "$_" -RegistryKeyword 'NetworkAddress' -RegistryValue $mac }
      }

      $NIC.Keys | ForEach-Object { Enable-NetAdapter -InterfaceAlias "$_" -Confirm:$False }
    }
    &$resetNetAdaptTweaks *>$null

    $resetNetshTweaks = {
      netsh int ip set dynamicport tcp start=49152 num=16384
      netsh int ip set dynamicport udp start=49152 num=16384
      netsh int ip set global reassemblyoutoforderlimit=32
      netsh int ip set global reassemblylimit=267748640
      netsh int ip set global loopbackexecutionmode=adaptive 
      netsh int ip set global sourceroutingbehavior=dontforward
      netsh int ip reset; 
      netsh int ipv6 reset 
      netsh int ipv4 reset 
      netsh int tcp reset 
      netsh int udp reset 
      netsh winsock reset
    }
    &$resetNetshTweaks *>$null

    $resetQos = {
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\QoS' 'Do not use NLA' -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DefaultTOSValue -force -ea 0
      Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' DisableUserTOSSetting -force -ea 0
      Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS' 'Tcp Autotuning Level' -force -ea 0
      Get-NetQosPolicy | Remove-NetQosPolicy -Confirm:$False -ea 0
    }
    &$resetQos *>$null


  }


}
Export-ModuleMember -Function FixUploadBufferBloat


function Write-Status {
  param(
    [ValidateSet('Warning', 'Output', 'Error')]
    $Type,
    [string]$Message
  )


  if ($Type -eq 'Warning') {
    Write-Host "[WARNING] $Message" -ForegroundColor DarkYellow
  }
  elseif ($Type -eq 'Output') {
    Write-Host "[+] $Message" -ForegroundColor Cyan
  }
  else {
    Write-Host "[ERROR] $Message" -ForegroundColor Red
  }

}
Export-ModuleMember -Function Write-Status



function Display-Settings {

  #check if settings file is made
  $settingsContent = @'
  #ZOICWARE SCRIPT SETTINGS
  dontCheckUpdates = 0
'@
 
  
  $settingsLocation = "$env:USERPROFILE\zSettings.cfg"
  if (!(Test-Path $settingsLocation)) {
    Write-Status -Message 'Creating Settings File...' -Type Output
    New-Item $settingsLocation -Force | Out-Null
    Set-Content $settingsLocation -Value $settingsContent -Force | Out-Null
  }

  #read settings file
  $dontCheck4Updates = $false
  $readContent = (Get-Content -Path $settingsLocation -Raw -Force) -split "`r`n"
  foreach ($line in $readContent) {
    if ($line -like '*dontCheckUpdates*') {
      $sLine = $line -split '='
      if ($sLine[1].Trim() -eq '1') {
        $dontCheck4Updates = $true
      }
    }
  }

  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.Application]::EnableVisualStyles()

  # Create the form
  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'Zoicware Settings'
  $form.Size = New-Object System.Drawing.Size(300, 230)
  $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
  $form.MaximizeBox = $false
  $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
  $form.BackColor = 'Black'
  $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
  $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)
    
  # Create the checkboxes
  $checkbox1 = New-Object System.Windows.Forms.CheckBox
  $checkbox1.Text = "Don't Check For Updates"
  $checkbox1.Location = New-Object System.Drawing.Point(20, 20)
  $checkbox1.ForeColor = 'White'
  $checkbox1.AutoSize = $true
  if ($dontCheck4Updates) {
    $checkbox1.Checked = $true
  }
  $form.Controls.Add($checkbox1)
    
  $checkbox2 = New-Object System.Windows.Forms.CheckBox
  $checkbox2.Text = 'Clear Script Location Cache'
  $checkbox2.Location = New-Object System.Drawing.Point(20, 50)
  $checkbox2.ForeColor = 'White'
  $checkbox2.AutoSize = $true
  $form.Controls.Add($checkbox2)
    
  $checkbox3 = New-Object System.Windows.Forms.CheckBox
  $checkbox3.Text = 'Reset Config'
  $checkbox3.Location = New-Object System.Drawing.Point(20, 80)
  $checkbox3.ForeColor = 'White'
  $checkbox3.AutoSize = $true
  $form.Controls.Add($checkbox3)
  
  $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
  $Global:asSystem = $false
  if ($currentUser.User -eq 'S-1-5-18') {
    $Global:asSystem = $true
  }
  $checkbox4 = New-Object System.Windows.Forms.CheckBox
  $checkbox4.Text = 'Run as TrustedInstaller'
  $checkbox4.Location = New-Object System.Drawing.Point(20, 110)
  $checkbox4.ForeColor = 'White'
  if ($Global:asSystem) {
    $checkbox4.Checked = $true
  }
  $checkbox4.AutoSize = $true
  $form.Controls.Add($checkbox4)
    
  $OKButton = New-Object System.Windows.Forms.Button
  $OKButton.Location = New-Object System.Drawing.Point(70, 150)
  $OKButton.Size = New-Object System.Drawing.Size(75, 23)
  $OKButton.Text = 'OK'
  $OKButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
  $OKButton.ForeColor = [System.Drawing.Color]::White
  $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $form.AcceptButton = $OKButton
  $form.Controls.Add($OKButton)
  
  $CancelButton = New-Object System.Windows.Forms.Button
  $CancelButton.Location = New-Object System.Drawing.Point(150, 150)
  $CancelButton.Size = New-Object System.Drawing.Size(75, 23)
  $CancelButton.Text = 'Cancel'
  $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
  $CancelButton.ForeColor = [System.Drawing.Color]::White
  $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
  $form.CancelButton = $CancelButton
  $form.Controls.Add($CancelButton)
    
    
  # Show the form and wait for user input
  $result = $form.ShowDialog()

  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {

    if ($dontCheck4Updates -and $checkbox1.Checked -eq $false) {
      Write-Status -Message 'Enabling Check For Updates...' -Type Output
      $newContent = $()
      foreach ($line in $readContent) {
        if ($line -like '*dontCheckUpdates*') {
          $sLine = $line -split '='
          $newLine = "$($sLine[0].Trim()) = 0"
          $newContent += "$newLine`n"
        }
        else {
          $newContent += "$line`n"
        }
      }
      Set-Content -Path $settingsLocation -Value $newContent -Force 
    }
    elseif (!$dontCheck4Updates -and $checkbox1.Checked -eq $true) {
      Write-Status -Message 'Disabling Check For Updates...' -Type Output
      $newContent = $()
      foreach ($line in $readContent) {
        if ($line -like '*dontCheckUpdates*') {
          $sLine = $line -split '='
          $newLine = "$($sLine[0].Trim()) = 1"
          $newContent += "$newLine`n"
        }
        else {
          $newContent += "$line`n"
        }
      }
      Set-Content -Path $settingsLocation -Value $newContent -Force 
    }



    if ($checkbox2.Checked) {
      Write-Status -Message 'Removing Location File...' -Type Output
      Remove-Item "$env:USERPROFILE\zLocation.tmp" -Force -ErrorAction SilentlyContinue
    }


    if ($checkbox3.Checked) {
      Write-Status -Message 'Resetting Config...' -Type Output
      #set all config settings back to 0
      $currentConfig = Get-Content -Path "$env:USERPROFILE\ZCONFIG.cfg" -Force
      $newConfig = @()
      foreach ($line in $currentConfig) {
        if ($line -notmatch '#') {
          $splitLine = $line -split '='
          $settingName = $splitLine[0]
          $newConfig += "$($settingName.trim()) = 0"
        }
        else {
          $newConfig += $line
        }
      
      }
      $newConfig | Out-File -FilePath "$env:USERPROFILE\ZCONFIG.cfg" -Force
    }

    if ($checkbox4.Checked -and !$Global:asSystem) {
      Write-Status -Message 'Re-Launching Zoicware with Trusted Installer Priv...' -Type Output
      $exe = Get-Process -Name '*ZOICWARE'
      
      RunAsTI "$($exe.Path)"
      Stop-Process -Id $PID
      
    }

  }
}
Export-ModuleMember -Function Display-Settings



function RunAsTI ($cmd, $arg) {
  #create key for current user
  $id = 'RunAsTI'
  $key = "Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"
  # .NET reflection and win32 api to run process with system priv
  $code = @'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@

  #create variables for reg key code
  $V = ''
  'cmd', 'arg', 'id', 'key' | ForEach-Object { 
    $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" 
  }
  #set reg key to above code and run
  Set-ItemProperty $key $id $($V, $code) -Type 7 -Force -ErrorAction SilentlyContinue
  Start-Process powershell -ArgumentList "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas -WindowStyle Hidden
} # lean & mean snippet by AveYo, 2022.01.28
Export-ModuleMember -Function RunAsTI



function Show-ModernFilePicker {
  param(
    [ValidateSet('Folder', 'File')]
    $Mode,
    [string]$fileType

  )

  if ($Mode -eq 'Folder') {
    $Title = 'Select Folder'
    $modeOption = $false
    $Filter = "Folders|`n"
  }
  else {
    $Title = 'Select File'
    $modeOption = $true
    if ($fileType) {
      $Filter = "$fileType Files (*.$fileType) | *.$fileType|All files (*.*)|*.*"
    }
    else {
      $Filter = 'All Files (*.*)|*.*'
    }
  }
  #modern file dialog
  #modified code from: https://gist.github.com/IMJLA/1d570aa2bb5c30215c222e7a5e5078fd
  $AssemblyFullName = 'System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
  $Assembly = [System.Reflection.Assembly]::Load($AssemblyFullName)
  $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
  $OpenFileDialog.AddExtension = $modeOption
  $OpenFileDialog.CheckFileExists = $modeOption
  $OpenFileDialog.DereferenceLinks = $true
  $OpenFileDialog.Filter = $Filter
  $OpenFileDialog.Multiselect = $false
  $OpenFileDialog.Title = $Title
  $OpenFileDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')

  $OpenFileDialogType = $OpenFileDialog.GetType()
  $FileDialogInterfaceType = $Assembly.GetType('System.Windows.Forms.FileDialogNative+IFileDialog')
  $IFileDialog = $OpenFileDialogType.GetMethod('CreateVistaDialog', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($OpenFileDialog, $null)
  $null = $OpenFileDialogType.GetMethod('OnBeforeVistaDialog', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($OpenFileDialog, $IFileDialog)
  if ($Mode -eq 'Folder') {
    [uint32]$PickFoldersOption = $Assembly.GetType('System.Windows.Forms.FileDialogNative+FOS').GetField('FOS_PICKFOLDERS').GetValue($null)
    $FolderOptions = $OpenFileDialogType.GetMethod('get_Options', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($OpenFileDialog, $null) -bor $PickFoldersOption
    $null = $FileDialogInterfaceType.GetMethod('SetOptions', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($IFileDialog, $FolderOptions)
  }
  
  

  $VistaDialogEvent = [System.Activator]::CreateInstance($AssemblyFullName, 'System.Windows.Forms.FileDialog+VistaDialogEvents', $false, 0, $null, $OpenFileDialog, $null, $null).Unwrap()
  [uint32]$AdviceCookie = 0
  $AdvisoryParameters = @($VistaDialogEvent, $AdviceCookie)
  $AdviseResult = $FileDialogInterfaceType.GetMethod('Advise', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($IFileDialog, $AdvisoryParameters)
  $AdviceCookie = $AdvisoryParameters[1]
  $Result = $FileDialogInterfaceType.GetMethod('Show', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($IFileDialog, [System.IntPtr]::Zero)
  $null = $FileDialogInterfaceType.GetMethod('Unadvise', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($IFileDialog, $AdviceCookie)
  if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
    $FileDialogInterfaceType.GetMethod('GetResult', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($IFileDialog, $null)
  }

  return $OpenFileDialog.FileName
}
Export-ModuleMember -Function Show-ModernFilePicker


function Repair-Windows {
  Write-Status -Message 'Running SFC Scannow...' -Type Output
  Start-Process sfc.exe -ArgumentList '/scannow' -NoNewWindow -Wait
  
  Write-Status -Message 'Running DISM Repair Commands...' -Type Output
  Start-Process DISM.exe -ArgumentList '/Online /Cleanup-Image /ScanHealth' -NoNewWindow -Wait
  Start-Process DISM.exe -ArgumentList '/Online /Cleanup-Image /CheckHealth' -NoNewWindow -Wait
  Start-Process DISM.exe -ArgumentList '/Online /Cleanup-Image /RestoreHealth' -NoNewWindow -Wait
 

  $choice = Read-Host -Prompt 'Repair Windows Update? [Y/N]'
  if ($choice.ToUpper() -eq 'Y') {
    Write-Status -Message 'Repairing Windows Update...' -Type Output
    Stop-Service wuauserv -NoWait -Force -ErrorAction SilentlyContinue
    Stop-Service BITS -NoWait -Force -ErrorAction SilentlyContinue
    Remove-Item -Path 'C:\Windows\SoftwareDistribution' -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path 'C:\Windows\Logs\WindowsUpdate' -Recurse -Force -ErrorAction SilentlyContinue
    Set-Service BITS -StartupType Automatic -ErrorAction SilentlyContinue
    Set-Service wuauserv -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service DoSvc -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service wuauserv *>$null
    Start-Service BITS *>$null
    Start-Service DoSvc *>$null
  }

  $choice2 = Read-Host -Prompt 'Reset Network Settings? [Y/N]'
  if ($choice2.ToUpper() -eq 'Y') {
    Write-Status -Message 'Resetting Network Settings and Flushing DNS...' -Type Output
    ipconfig /release >$null                         
    ipconfig /renew >$null                        
    ipconfig /flushdns >$null                       
    netsh winsock reset >$null                      
    netsh int ip reset >$null
  }

  $choice5 = Read-Host -Prompt 'Clear Icon Cache? [Y/N]'
  if ($choice5.ToUpper() -eq 'Y') {
    Write-Status -Message 'Clearing Icon Cache...' -Type Output
    $cacheDir = "$env:LocalAppData\Microsoft\Windows\Explorer"
    Get-ChildItem -Path $cacheDir -Filter 'iconcache_*.db' | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path $cacheDir -Filter 'thumbcache_*.db' | Remove-Item -Force -ErrorAction SilentlyContinue
    Stop-Process -Name explorer
  }
  
  $choice3 = Read-Host -Prompt 'Run Check Disk Scan? [Y/N]'
  if ($choice3.ToUpper() -eq 'Y') {
    Write-Status -Message 'Running Check Disk Scan...' -Type Output
    Start-Process chkdsk.exe -ArgumentList '/scan' -NoNewWindow -Wait
    $choice4 = Read-Host -Prompt 'Schedule Check Disk Repair On Next Restart? [Y/N]'
    if ($choice4.ToUpper() -eq 'Y') {
      Start-Process chkdsk.exe -ArgumentList '/f' -NoNewWindow -Wait
    }
  }

}
Export-ModuleMember -Function Repair-Windows


function Restart-Explorer {
  Write-Status -Message 'Restarting Explorer...' -Type Output
  try {
    Stop-Process -name explorer -Force -ErrorAction Stop
  }
  catch {
    #try taskkill instead if stop process doesnt work for some reason
    taskkill.exe /F /IM 'explorer.exe'
  }
  #sleep for 10 seconds and start explorer if not auto starting
  $time = 10
  do {
    $time--
    Start-Sleep 1
  }while (!(Get-Process explorer -ErrorAction SilentlyContinue) -and $time -ne 0)
  if ($time -eq 0) {
    Write-Status -Message 'Explorer Did Not Restart Automatically...' -Type Output
    Write-Status -Message 'Starting Explorer...' -Type Output
    Start-Process explorer
  }
  
  
}
Export-ModuleMember -Function Restart-Explorer


function Restart-Bios {
  $result = Custom-MsgBox -message 'Are You Sure You Want to Restart to BIOS?' -type Question
  if ($result -eq 'OK') {
    #double command to fix enviroment error
    shutdown /r /fw /t 0
    shutdown /r /fw /t 0
  }
}
Export-ModuleMember -Function Restart-Bios