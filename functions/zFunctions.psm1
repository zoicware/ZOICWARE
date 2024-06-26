
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


  function check-depend {
    #check if updates/services are disabled in the config 
    $configContent = Get-Content -Path "$env:USERPROFILE\ZCONFIG.cfg" -Force
    $settingName1 = 'gpUpdates'
    $settingName2 = 'disableServices'
    foreach ($line in $configContent) {
      #split line into settingName and value
      $splitLine = $line -split '='
      $lineName = $splitLine[0]
      $lineValue = $splitLine[1]
      if ($lineName.trim() -match $settingName1 -and $lineValue.trim() -eq '1') {
        #revert updates so that store works properly
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetProxyBehaviorForUpdateDetection' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetDisableUXWUAccess' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAutoUpdate' /f
        Reg.exe delete 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'UseWUServer' /f
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc' /v 'Start' /t REG_DWORD /d '2' /f
        Reg.exe add 'HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' /v 'DownloadMode' /t REG_DWORD /d '1' /f
        Get-ScheduledTask | Where-Object { $_.Taskname -match 'Scheduled Start' } | Enable-ScheduledTask
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
      elseif ($lineName.Trim() -match $settingName2 -and $lineValue.trim() -eq '1') {
        #enable delivery optimization service
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'Start' /t REG_DWORD /d '2' /f
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'DelayedAutostart' /t REG_DWORD /d '1' /f
      }

    }

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


  function debloat-TeamsOneDrive {
    Write-Host 'Uninstalling Teams and OneDrive...'
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



  function debloat-LockedPackages {
    #vars
    $OS = Get-CimInstance Win32_OperatingSystem
    $lockedPackages = @(
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
    )
    if ($OS.Caption -like '*Windows 10*') {
      $lockedPackages += 'Client.CBS'
    }


    Write-Host 'Removing Locked Appx Packages...'

    $provisioned = get-appxprovisionedpackage -online 
    $appxpackage = get-appxpackage -allusers
    $eol = @()
    $store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
    $users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }


    #uninstall packages
    foreach ($choice in $lockedPackages) {
      if ('' -eq $choice.Trim()) { continue }
      foreach ($appx in $($provisioned | Where-Object { $_.PackageName -like "*$choice*" })) {
        $next = !1; foreach ($no in $skip) { if ($appx.PackageName -like "*$no*") { $next = !0 } } ; if ($next) { continue }
        $PackageName = $appx.PackageName; $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName
        New-Item "$store\Deprovisioned\$PackageFamilyName" -force >''; 
        foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageName" -force >'' } ; $eol += $PackageName
        dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >''
        remove-appxprovisionedpackage -packagename $PackageName -online -allusers >''
      }
      foreach ($appx in $($appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" })) {
        $next = !1; foreach ($no in $skip) { if ($appx.PackageFullName -like "*$no*") { $next = !0 } } ; if ($next) { continue }
        $PackageFullName = $appx.PackageFullName;
        New-Item "$store\Deprovisioned\$appx.PackageFamilyName" -force >''; 
        foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageFullName" -force >'' } ; $eol += $PackageFullName
        dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >''
        remove-appxpackage -package $PackageFullName -allusers >''
      }
    }

    ## undo eol unblock trick to prevent latest cumulative update (LCU) failing 
    foreach ($sid in $users) { foreach ($PackageName in $eol) { Remove-Item "$store\EndOfLife\$sid\$PackageName" -force -ErrorAction SilentlyContinue >'' } }

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
    #only works on 23h2/ Windows 10 KB50358+
    $ProgressPreference = 'SilentlyContinue'
    $version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo('C:\Windows\System32\mstsc.exe').FileVersion

    if ($version -like '*3636*' -or $version -like '*2506*') {
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
  }


  function debloat-dism {
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
        Get-AppXPackage $Bloat -AllUsers -ErrorAction Stop | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction Stop }
      }
      catch {}
      try {
        Remove-AppxPackage -Package $Bloat -AllUsers -ErrorAction Stop
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
              Write-Host "Trying to remove $Bloat"
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
              Write-Host "Trying to remove $Bloat"
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
              Write-Host "Trying to remove $Bloat"
              debloatAppx -Bloat $Bloat
            }          
          }

        }
      }
    }


  }



  # ----------------------------------------------------------- DEBLOAT FUNCTIONS ---------------------------------------------------

  $checkbox2 = New-Object System.Windows.Forms.RadioButton
  $checkbox3 = New-Object System.Windows.Forms.RadioButton
  $checkbox4 = New-Object System.Windows.Forms.RadioButton
  $checkbox5 = New-Object System.Windows.Forms.RadioButton
  $checkbox6 = New-Object System.Windows.Forms.RadioButton
 
    
  #hashtable to loop through later for updating the config
  $settings = @{}
  $settings['debloatAll'] = $checkbox2
  $settings['debloatSXE'] = $checkbox3
  $settings['debloatSX'] = $checkbox4
  $settings['debloatE'] = $checkbox5
  $settings['debloatS'] = $checkbox6

    
  if ($AutoRun) {
    $result = [System.Windows.Forms.DialogResult]::OK
    $checkbox2.Checked = $debloatAll
    $checkbox3.Checked = $debloatSXE
    $checkbox4.Checked = $debloatSX
    $checkbox5.Checked = $debloatE
    $checkbox6.Checked = $debloatS
  }
  else {
  
    #creating powershell list box 
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Debloat'
    $form.Size = New-Object System.Drawing.Size(570, 580)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = 'Black'
  
    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text = 'Debloat Presets'
    $groupBox.Size = New-Object System.Drawing.Size(240, 215)
    $groupBox.Location = New-Object System.Drawing.Point(10, 10)
    $groupBox.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 75)
    $groupBox.ForeColor = 'White'
    $form.Controls.Add($groupBox)

    $groupBox2 = New-Object System.Windows.Forms.GroupBox
    $groupBox2.Text = 'Custom Debloat Extras'
    $groupBox2.Size = New-Object System.Drawing.Size(240, 235)
    $groupBox2.Location = New-Object System.Drawing.Point(10, 280)
    $groupBox2.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 75)
    $groupBox2.ForeColor = 'White'
    $form.Controls.Add($groupBox2)

    $applyPreset = New-Object System.Windows.Forms.Button
    $applyPreset.Location = New-Object System.Drawing.Point(18, 190)
    $applyPreset.Size = New-Object System.Drawing.Size(200, 25)
    $applyPreset.Text = 'Apply Preset'
    $applyPreset.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $applyPreset.ForeColor = [System.Drawing.Color]::White
    #$applyPreset.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$applyPreset.FlatAppearance.BorderSize = 0
    #$applyPreset.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$applyPreset.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $applyPreset.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $groupBox.Controls.Add($applyPreset)
    #$form.Controls.Add($applyPreset)

    $removeAppxPackages = {
      if ($checkedListBox.CheckedItems.Count -eq 0) { Write-Host 'No Packages Selected' }
      else {
        foreach ($package in $checkedListBox.CheckedItems.GetEnumerator()) {
          Write-Host "Trying to remove $package"
          #silentlycontinue doesnt work sometimes so trycatch block is needed to supress errors
          try {
            Get-AppXPackage $package -AllUsers -ErrorAction Stop | ForEach-Object { Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" -ErrorAction Stop }
          }
          catch {}
          try {
            Remove-AppxPackage -Package $package -AllUsers -ErrorAction Stop
          }
          catch {}
          try {
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$package*" | Remove-AppxProvisionedPackage -AllUsers -Online -ErrorAction Stop | Out-Null
          }
          catch {}    
        }
        #refresh list box
        &$getPackages
      }
    }


    $removeAppx = New-Object System.Windows.Forms.Button
    $removeAppx.Location = New-Object System.Drawing.Point(423, 465)
    $removeAppx.Size = New-Object System.Drawing.Size(120, 35)
    $removeAppx.Text = 'Remove Appx Packages'
    $removeAppx.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $removeAppx.ForeColor = [System.Drawing.Color]::White
    #$removeAppx.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$removeAppx.FlatAppearance.BorderSize = 0
    #$removeAppx.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$removeAppx.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $removeAppx.Add_Click({
        &$removeAppxPackages
      })
    $form.Controls.Add($removeAppx)

    
    $removeLockedPackages = {
      if ($checkedListBox.CheckedItems.Count -eq 0) { Write-Host 'No Locked Packages Selected' }
      else {
        $selectedLockedPackages = @()
        foreach ($package in $checkedListBox.CheckedItems.GetEnumerator()) {
          $selectedLockedPackages += $package
        }

        $provisioned = get-appxprovisionedpackage -online 
        $appxpackage = get-appxpackage -allusers
        $eol = @()
        $store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
        $users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }

        #uninstall packages
        foreach ($choice in $selectedLockedPackages) {
          Write-Host "Trying to remove $choice"
          if ('' -eq $choice.Trim()) { continue }
          foreach ($appx in $($provisioned | Where-Object { $_.PackageName -like "*$choice*" })) {
            $next = !1; foreach ($no in $skip) { if ($appx.PackageName -like "*$no*") { $next = !0 } } ; if ($next) { continue }
            $PackageName = $appx.PackageName; $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName
            New-Item "$store\Deprovisioned\$PackageFamilyName" -force >''; 
            foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageName" -force >'' } ; $eol += $PackageName
            dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >''
            remove-appxprovisionedpackage -packagename $PackageName -online -allusers >''
          }
          foreach ($appx in $($appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" })) {
            $next = !1; foreach ($no in $skip) { if ($appx.PackageFullName -like "*$no*") { $next = !0 } } ; if ($next) { continue }
            $PackageFullName = $appx.PackageFullName;
            New-Item "$store\Deprovisioned\$appx.PackageFamilyName" -force >''; 
            foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageFullName" -force >'' } ; $eol += $PackageFullName
            dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >''
            remove-appxpackage -package $PackageFullName -allusers >''
          }
        }

        ## undo eol unblock trick to prevent latest cumulative update (LCU) failing 
        foreach ($sid in $users) { foreach ($PackageName in $eol) { Remove-Item "$store\EndOfLife\$sid\$PackageName" -force -ErrorAction SilentlyContinue >'' } }
      }
      #update list
      &$showLocked
    }
    
    $removeLocked = New-Object System.Windows.Forms.Button
    $removeLocked.Location = New-Object System.Drawing.Point(270, 465)
    $removeLocked.Size = New-Object System.Drawing.Size(120, 35)
    $removeLocked.Text = 'Remove Locked Packages'
    $removeLocked.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $removeLocked.ForeColor = [System.Drawing.Color]::White
    #$removeLocked.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$removeLocked.FlatAppearance.BorderSize = 0
    #$removeLocked.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$removeLocked.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $removeLocked.Add_Click({
        &$removeLockedPackages
      })
    $form.Controls.Add($removeLocked)

    $applyExtras = New-Object System.Windows.Forms.Button
    $applyExtras.Location = New-Object System.Drawing.Point(18, 210)
    $applyExtras.Size = New-Object System.Drawing.Size(200, 25)
    $applyExtras.Text = 'Apply Extras'
    $applyExtras.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $applyExtras.ForeColor = [System.Drawing.Color]::White
    #$applyExtras.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$applyExtras.FlatAppearance.BorderSize = 0
    #$applyExtras.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$applyExtras.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $applyExtras.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $groupBox2.Controls.Add($applyExtras)
    #$form.Controls.Add($applyExtras)

    $checkAllBoxes = {
      if ($checkAll.BackColor -eq [System.Drawing.Color]::Black) {
        #set color back to default
        $checkAll.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
        #uncheck boxes
        for (($i = 0); $i -lt $checkedListBox.Items.Count; $i++) {
          $checkedListBox.SetItemChecked($i, $false)
        }
      }
      else {
        #change button to black
        $checkAll.BackColor = [System.Drawing.Color]::Black
        #check all buttons
        for (($i = 0); $i -lt $checkedListBox.Items.Count; $i++) {
          $checkedListBox.SetItemChecked($i, $true)
        }

      }

    }

    $checkAll = New-Object System.Windows.Forms.Button
    $checkAll.Location = New-Object System.Drawing.Point(450, 20)
    $checkAll.Size = New-Object System.Drawing.Size(90, 25)
    $checkAll.Text = 'Check All'
    $checkAll.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    $checkAll.ForeColor = [System.Drawing.Color]::White
    #$checkAll.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$checkAll.FlatAppearance.BorderSize = 0
    #$checkAll.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$checkAll.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $checkAll.Add_Click({
        &$checkAllBoxes
      })
    $form.Controls.Add($checkAll)
  
  
    #$label = New-Object System.Windows.Forms.Label
    #$label.Location = New-Object System.Drawing.Point(10, 10)
    #$label.Size = New-Object System.Drawing.Size(200, 20)
    #$label.Text = 'Debloat Presets:'
    #$label.ForeColor = 'White'
    #$label.Font = New-Object System.Drawing.Font('Segoe UI', 11) 
    #$form.Controls.Add($label)

    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(269, 18)
    $label2.Size = New-Object System.Drawing.Size(280, 20)
    $label2.Text = 'Installed Appx Packages:'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font('Segoe UI', 11) 
    $form.Controls.Add($label2)

    $label3 = New-Object System.Windows.Forms.Label
    $label3.Location = New-Object System.Drawing.Point(10, 230)
    $label3.Size = New-Object System.Drawing.Size(200, 20)
    $label3.Text = 'Custom Debloat:'
    $label3.ForeColor = 'White'
    $label3.Font = New-Object System.Drawing.Font('Segoe UI', 11) 
    $form.Controls.Add($label3)

    #$label4 = New-Object System.Windows.Forms.Label
    #$label4.Location = New-Object System.Drawing.Point(10, 335)
    #$label4.Size = New-Object System.Drawing.Size(200, 20)
    #$label4.Text = 'Remove Extras:'
    #$label4.ForeColor = 'White'
    #$label4.Font = New-Object System.Drawing.Font('Segoe UI', 11) 
    #$form.Controls.Add($label4)
  
      
    $checkbox2.Location = new-object System.Drawing.Size(15, 30)
    $checkbox2.Size = new-object System.Drawing.Size(150, 20)
    $checkbox2.Text = 'Debloat All'
    $checkbox2.ForeColor = 'White'
    $checkbox2.Checked = $false
    $groupBox.Controls.Add($checkbox2)
    #$Form.Controls.Add($checkbox2)  
      
  
      
    $checkbox3.Location = new-object System.Drawing.Size(15, 60)
    $checkbox3.Size = new-object System.Drawing.Size(170, 20)
    $checkbox3.Text = 'Keep Store,Xbox and Edge'
    $checkbox3.ForeColor = 'White'
    $checkbox3.Checked = $false
    $groupBox.Controls.Add($checkbox3)
    #$Form.Controls.Add($checkbox3)
      
  
      
    $checkbox4.Location = new-object System.Drawing.Size(15, 90)
    $checkbox4.Size = new-object System.Drawing.Size(170, 20)
    $checkbox4.Text = 'Keep Store and Xbox'
    $checkbox4.ForeColor = 'White'
    $checkbox4.Checked = $false
    $groupBox.Controls.Add($checkbox4)
    #$Form.Controls.Add($checkbox4)
     
  
      
    $checkbox5.Location = new-object System.Drawing.Size(15, 120)
    $checkbox5.Size = new-object System.Drawing.Size(200, 20)
    $checkbox5.Text = 'Debloat All Keep Edge'
    $checkbox5.ForeColor = 'White'
    $checkbox5.Checked = $false
    $groupBox.Controls.Add($checkbox5)
    #$Form.Controls.Add($checkbox5)
      
  
      
    $checkbox6.Location = new-object System.Drawing.Size(15, 150)
    $checkbox6.Size = new-object System.Drawing.Size(200, 20)
    $checkbox6.Text = 'Debloat All Keep Store'
    $checkbox6.ForeColor = 'White'
    $checkbox6.Checked = $false
    $groupBox.Controls.Add($checkbox6)
    #$Form.Controls.Add($checkbox6)


    $showLocked = {
      $checkedListBox.Items.Clear()
      if ($showLockedPackages.Checked) {
        foreach ($package in $Bloatware) {
          #using where-obj for wildcards to work
          $isProhibited = $prohibitedPackages | Where-Object { $package -like $_ }

          if ($package -in $lockedAppxPackages -and !$isProhibited) {
            #fix some package names
            if ($package -eq 'E2A4F912-2574-4A75-9BB0-0D023378592B') {
              $package = 'Microsoft.Windows.AppResolverUX'
            }
            elseif ($package -eq 'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE') {
              $package = 'Microsoft.Windows.AppSuggestedFoldersToLibraryDialog'
            }
            $checkedListBox.Items.Add($package, $false) | Out-Null
          }
        }
      }
      else {
        &$getPackages
      }


    }
    $showLockedPackages = New-Object System.Windows.Forms.CheckBox
    $showLockedPackages.Location = new-object System.Drawing.Size(15, 255)
    $showLockedPackages.Size = new-object System.Drawing.Size(200, 20)
    $showLockedPackages.Text = 'Show Locked Packages'
    $showLockedPackages.ForeColor = 'White'
    $showLockedPackages.Checked = $false
    $showLockedPackages.Add_CheckedChanged($showLocked)
    $Form.Controls.Add($showLockedPackages)

    $extraEdge = New-Object System.Windows.Forms.CheckBox
    $extraEdge.Location = new-object System.Drawing.Size(15, 25)
    $extraEdge.Size = new-object System.Drawing.Size(120, 20)
    $extraEdge.Text = 'Microsoft Edge'
    $extraEdge.ForeColor = 'White'
    $extraEdge.Checked = $false
    $groupBox2.Controls.Add($extraEdge)
    #$Form.Controls.Add($extraEdge)

    $extraTeamsOneDrive = New-Object System.Windows.Forms.CheckBox
    $extraTeamsOneDrive.Location = new-object System.Drawing.Size(15, 55)
    $extraTeamsOneDrive.Size = new-object System.Drawing.Size(150, 20)
    $extraTeamsOneDrive.Text = 'Teams and OneDrive'
    $extraTeamsOneDrive.ForeColor = 'White'
    $extraTeamsOneDrive.Checked = $false
    $groupBox2.Controls.Add($extraTeamsOneDrive)
    #$Form.Controls.Add($extraTeamsOneDrive)

    $extraUpdateTools = New-Object System.Windows.Forms.CheckBox
    $extraUpdateTools.Location = new-object System.Drawing.Size(15, 85)
    $extraUpdateTools.Size = new-object System.Drawing.Size(150, 20)
    $extraUpdateTools.Text = 'Windows Update Tools'
    $extraUpdateTools.ForeColor = 'White'
    $extraUpdateTools.Checked = $false
    $groupBox2.Controls.Add($extraUpdateTools)
    #$Form.Controls.Add($extraUpdateTools)


    $extraRemoveRemote = New-Object System.Windows.Forms.CheckBox
    $extraRemoveRemote.Location = new-object System.Drawing.Size(15, 115)
    $extraRemoveRemote.Size = new-object System.Drawing.Size(170, 20)
    $extraRemoveRemote.Text = 'Remote Desktop Connection'
    $extraRemoveRemote.ForeColor = 'White'
    $extraRemoveRemote.Checked = $false
    $groupBox2.Controls.Add($extraRemoveRemote)
    #$Form.Controls.Add($extraRemoveRemote)

    $extraDISM = New-Object System.Windows.Forms.CheckBox
    $extraDISM.Location = new-object System.Drawing.Size(15, 145)
    $extraDISM.Size = new-object System.Drawing.Size(220, 27)
    $extraDISM.Text = 'Hello Face, Quick-Assist and Steps Recorder'
    $extraDISM.ForeColor = 'White'
    $extraDISM.Checked = $false
    $groupBox2.Controls.Add($extraDISM)
    #$Form.Controls.Add($extraDISM)

    $extraStartMenu = New-Object System.Windows.Forms.CheckBox
    $extraStartMenu.Location = new-object System.Drawing.Size(15, 175)
    $extraStartMenu.Size = new-object System.Drawing.Size(220, 20)
    $extraStartMenu.Text = 'Clean Start Menu Icons'
    $extraStartMenu.ForeColor = 'White'
    $extraStartMenu.Checked = $false
    $groupBox2.Controls.Add($extraStartMenu)
    #$Form.Controls.Add($extraStartMenu)



    $checkedListBox = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox.Location = New-Object System.Drawing.Point(270, 50)
    $checkedListBox.Size = New-Object System.Drawing.Size(270, 415)
    $checkedListBox.BackColor = 'Black'
    $checkedListBox.ForeColor = 'White'
    $checkedListBox.ScrollAlwaysVisible = $true
    $Form.Controls.Add($checkedListBox)

    
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
      'Microsoft.DekstopAppInstaller'
      'Microsoft.Windows.Search'
    )

    
    $getPackages = {
      $checkedListBox.Items.Clear()
      $packages = (Get-AppxPackage -AllUsers).name
      #remove dups
      $Global:Bloatware = $packages | Sort-Object | Get-Unique
      foreach ($package in $Bloatware) {
        #using where-obj for wildcards to work
        $isProhibited = $prohibitedPackages | Where-Object { $package -like $_ }

        if ($package -notin $lockedAppxPackages -and !$isProhibited) {
          $checkedListBox.Items.Add($package, $false) | Out-Null
        }
      }
    }
    &$getPackages
  
    

    $form.Topmost = $true
  
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
          
      debloatPreset -choice 'debloatAll'
      Write-Host 'Removing Teams and One Drive'
      debloat-TeamsOneDrive
      debloat-LockedPackages
      Write-Host 'Removing Remote Desktop Connection'
      debloat-remotedesktop
      debloat-HealthUpdateTools
      Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
      debloat-dism
      
      Write-Host 'Uninstalling Edge...'
      $edge = Search-File '*EdgeRemove.ps1'
      &$edge
      Write-Host 'Cleaning Start Menu...'
      $unpin = Search-File '*unpin.ps1'
      & $unpin
    }
    if ($checkbox3.Checked) {
     
      #check for dependency issues
      check-depend

      debloatPreset -choice 'debloatKeepStore'
      Write-Host 'Removing Teams and One Drive'
      debloat-TeamsOneDrive
      debloat-HealthUpdateTools
      Write-Host 'Removing Remote Desktop Connection'
      debloat-remotedesktop
      Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
      debloat-dism
  
      Write-Host 'Cleaning Start Menu...'
      $unpin = Search-File '*unpin.ps1'
      & $unpin
  
    }
    if ($checkbox4.Checked) {
  
      #check for dependency issues
      check-depend
  
      debloatPreset -choice 'debloatKeepStoreXbox'
      Write-Host 'Removing Teams and One Drive'
      debloat-TeamsOneDrive
      debloat-HealthUpdateTools
      Write-Host 'Removing Remote Desktop Connection'
      debloat-remotedesktop
      Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
      debloat-dism

      Write-Host 'Uninstalling Edge...'
      $edge = Search-File '*EdgeRemove.ps1'
      &$edge
      Write-Host 'Cleaning Start Menu...'
      $unpin = Search-File '*unpin.ps1'
      & $unpin     
      
    }
    if ($checkbox5.Checked) {
      debloatPreset -choice 'debloatAll'
      Write-Host 'Removing Teams and One Drive'
      debloat-TeamsOneDrive
      Write-Host 'Removing Remote Desktop Connection'
      debloat-remotedesktop
      debloat-HealthUpdateTools
      Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
      debloat-dism

      Write-Host 'Cleaning Start Menu...'
      $unpin = Search-File '*unpin.ps1'
      & $unpin
  
    }
    if ($checkbox6.Checked) { 
    
      #check for dependency issues
      check-depend
    
      debloatPreset -choice 'debloatKeepStore'
      Write-Host 'Removing Teams and One Drive'
      debloat-TeamsOneDrive
      debloat-HealthUpdateTools
      Write-Host 'Removing Remote Desktop Connection'
      debloat-remotedesktop
      Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
      debloat-dism
  
      Write-Host 'Uninstalling Edge...'
      $edge = Search-File '*EdgeRemove.ps1'
      &$edge
      Write-Host 'Cleaning Start Menu...'
      $unpin = Search-File '*unpin.ps1'
      & $unpin
  
    }



    #------------------------- debloat extras

    if ($extraEdge.Checked) {
      Write-Host 'Uninstalling Edge...'
      $edge = Search-File '*EdgeRemove.ps1'
      &$edge
    }

    if ($extraTeamsOneDrive.Checked) {
      Write-Host 'Removing Teams and One Drive'
      debloat-TeamsOneDrive
    }

    if ($extraUpdateTools.Checked) {
      Write-Host 'Removing Windows Update Tools'
      debloat-HealthUpdateTools
    }

    if ($extraDISM.Checked) {
      Write-Host 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM'
      debloat-dism
    }

    if ($extraRemoveRemote.Checked) {
      Write-Host 'Removing Remote Desktop Connection'
      debloat-remotedesktop
    }

    if ($extraStartMenu.Checked) {
      Write-Host 'Cleaning Start Menu...'
      $unpin = Search-File '*unpin.ps1'
      & $unpin
    }


    if (!($Autorun)) {
      [System.Windows.Forms.MessageBox]::Show('Bloat Removed.')
    }
     
  }
  
}
Export-ModuleMember -Function debloat







function disable-services {
  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
    # ,[Parameter(mandatory=$false)] $setting 
  )


  function check-depend {
    #check if updates/services are disabled in the config 
    $configContent = Get-Content -Path "$env:USERPROFILE\ZCONFIG.cfg" -Force
    foreach ($line in $configContent) {
      #split line into settingName and value
      $splitLine = $line -split '='
      $lineName = $splitLine[0]
      $lineValue = $splitLine[1]
      if ($lineName.trim() -like 'debloatS*' -and $lineValue.trim() -eq '1') {
        #revert delivery optimization service so that store works properly
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'Start' /t REG_DWORD /d '2' /f
        Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DoSvc' /v 'DelayedAutostart' /t REG_DWORD /d '1' /f
      }

    }

  }


  if ($Autorun) {
    $msgBoxInput = 'Yes'
  }
  else {
    [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Do you want to disable Bluetooth, Printing and others?', 'zoicware', 'YesNo', 'Question')
  }
  
  
  switch ($msgBoxInput) {
  
    'Yes' {
      if (!($Autorun)) {
        #update config
        update-config -setting 'disableServices' -value 1
      }
      
      #disables some unecessary services 
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

      check-depend
  
      if (!($Autorun)) {
        [System.Windows.Forms.MessageBox]::Show('Services have been disabled.')
      }
  
    }
  
    'No' {}
  
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


  function check-depend {
    #check if updates/services are disabled in the config 
    $configContent = Get-Content -Path "$env:USERPROFILE\ZCONFIG.cfg" -Force
    foreach ($line in $configContent) {
      #split line into settingName and value
      $splitLine = $line -split '='
      $lineName = $splitLine[0]
      $lineValue = $splitLine[1]
      if ($lineName.trim() -like 'debloatS*' -and $lineValue.trim() -eq '1') {
        #revert updates so that store works properly
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
        return $true
      }

    }
      
  }



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
    $form.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    
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
    $OKButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $OKButton.FlatAppearance.BorderSize = 0
    $OKButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $OKButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)
  
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(150, 140)
    $CancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $CancelButton.ForeColor = [System.Drawing.Color]::White
    $CancelButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $CancelButton.FlatAppearance.BorderSize = 0
    $CancelButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $CancelButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
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
      if (check-depend) {
        Write-Host 'Store enabled...Updates Paused for 1 year'
      }
      else {
        Write-Host 'Disabling Updates...'
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
   
  
    }
  
  
    if ($checkbox2.Checked) {
  
      <#
      #check if tamper protection is disabled already
      $key = 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features'
      try {
        $tamper = Get-ItemPropertyValue -Path $key -Name 'TamperProtection' -ErrorAction Stop
        $tamperSource = Get-ItemPropertyValue -Path $key -Name 'TamperProtectionSource' -ErrorAction Stop
      }
      catch {
        #do nothing
      }
      
      if ((!($tamper -eq '4' -or '0' -and $tamperSource -eq '2')) -or !((Get-MpPreference).DisableTamperProtection)) {
       
        #display prompt to user
        [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
        [System.Windows.Forms.MessageBox]::Show('Please DO NOT Press Any Keys While Script Disables Tamper Protection.', 'ZOICWARE')

        #get current uac settings
        $key = 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        $promptValue = Get-ItemPropertyValue -Path $key -Name 'PromptOnSecureDesktop' -ErrorAction SilentlyContinue
        $luaValue = Get-ItemPropertyValue -Path $key -Name 'EnableLUA' -ErrorAction SilentlyContinue
        $promptValueAdmin = Get-ItemPropertyValue -Path $key -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue

        #disable uac to avoid popup when disabling tamper protection
        $command = {
          Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'PromptOnSecureDesktop' /t REG_DWORD /d '0' /f
          Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableLUA' /t REG_DWORD /d '0' /f
          Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'ConsentPromptBehaviorAdmin' /t REG_DWORD /d '0' /f
        }
        Invoke-Command $command | Out-Null

        #open security app 
        Start-Process -FilePath explorer.exe -ArgumentList windowsdefender://threat -WindowStyle Maximized 
        Start-Sleep 2
        #full screen the app with key shortcuts
        $wshell = New-Object -ComObject wscript.shell
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class Keyboard
{
    [DllImport("user32.dll")]
    public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, uint dwExtraInfo);
}
'@

        # Define key codes
        $VK_ALT = 0x12  # Alt key code
        $VK_SPACE = 0x20  # Space key code
        $VK_X = 0x58  # X key code

        # Simulate Alt+Space keystroke combination
        [Keyboard]::keybd_event($VK_ALT, 0, 0, 0)
        [Keyboard]::keybd_event($VK_SPACE, 0, 0, 0)
        Start-Sleep -Milliseconds 100  # Wait for a moment
        [Keyboard]::keybd_event($VK_SPACE, 0, 0x2, 0)
        [Keyboard]::keybd_event($VK_ALT, 0, 0x2, 0)

        # Press the 'X' key
        [Keyboard]::keybd_event($VK_X, 0, 0, 0)
        Start-Sleep -Milliseconds 100  # Wait for a moment
        [Keyboard]::keybd_event($VK_X, 0, 0x2, 0)

        Start-Sleep 2
        #get os version
        $OS = Get-CimInstance Win32_OperatingSystem
        #navigate to tamper protection and turn off
        #different options on windows 11 sec app so more tabs are needed to get to tamper protection

        if ($OS.Caption -like '*Windows 11*') {
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .35
          $wshell.SendKeys(' ')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .35
          $wshell.SendKeys(' ')
        }
        else {
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .35
          $wshell.SendKeys(' ')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .55
          $wshell.SendKeys('{TAB}')
          Start-Sleep .35
          $wshell.SendKeys(' ')
        }
        Start-Sleep .75
        #close sec app
        Stop-Process -name SecHealthUI -Force

        #set uac back to og values
        $command = {
          Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'PromptOnSecureDesktop' /t REG_DWORD /d $promptValue /f
          Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'EnableLUA' /t REG_DWORD /d $luaValue /f
          Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v 'ConsentPromptBehaviorAdmin' /t REG_DWORD /d $promptValueAdmin /f
        }
        Invoke-Command $command | Out-Null

        #update tamper values
        $key = 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features'
        try {
          $tamper = Get-ItemPropertyValue -Path $key -Name 'TamperProtection' -ErrorAction Stop
          $tamperSource = Get-ItemPropertyValue -Path $key -Name 'TamperProtectionSource' -ErrorAction Stop
        }
        catch {
          #do nothing
        }
      }
      
      #check again if tamper got disabled
      if ((!($tamper -eq '4' -or '0' -and $tamperSource -eq '2')) -or !((Get-MpPreference).DisableTamperProtection)) {
        Write-Host 'Tamper Protection NOT Disabled...Closing Script' -ForegroundColor Red
      }
      else {
#>

      #temp anti virus credit https://github.com/es3n1n/no-defender

      #install temp antivirus
      Write-Host 'Installing Temp Antivirus...'
      $filePath = Search-File '*no-defender-loader.exe' 
      Start-Process $filePath -ArgumentList '--av' -WindowStyle Hidden

      #wait for defender service to close before continue
      do {
        $proc = Get-Process -Name MsMpEng -ErrorAction SilentlyContinue
        Start-Sleep 1
      }while ($proc)

      Write-Host 'Disabling MsMpEng Service...'
      #edited toggle defender function https://github.com/AveYo/LeanAndMean
      function defeatMsMpEng {
        $id = 'Defender'; $key = 'Registry::HKU\S-1-5-21-*\Volatile Environment'; $code = @'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $U=[uintptr]; $Z=[uintptr]::size 
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += $U; 4..6|% {$D += $D[$_]."MakeByR`efType"()}; $F=@()
 $F+='kernel','CreateProcess',($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), 'advapi','RegOpenKeyEx',($U,$S,$I,$I,$D[9])
 $F+='advapi','RegSetValueEx',($U,$S,$I,$I,[byte[]],$I),'advapi','RegFlushKey',($U),'advapi','RegCloseKey',($U)
 0..4|% {$9=$D[0]."DefinePInvok`eMethod"($F[3*$_+1], $F[3*$_]+"32", 8214,1,$S, $F[3*$_+2], 1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"("f" + $n++, $_, 6)}}; $T=@(); 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 if ([environment]::username -ne "system") { $TI="Trusted`Installer"; start-service $TI -ea 0; $As=get-process -name $TI -ea 0
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $R=@($null, "powershell -nop -c iex(`$env:R); # $id", 0, 0, 0, 0x0E080610, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $R; return}; $env:R=''; rp $key $id -force -ea 0; $e=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$e.Invoke($null,@("$_",2))}
 ## Toggling was unreliable due to multiple windows programs with open handles on these keys
 ## so went with low-level functions instead! do not use them in other scripts without a trip to learn-microsoft-com  
 function RegSetDwords ($hive, $key, [array]$values, [array]$dword, $REG_TYPE=4, $REG_ACCESS=2, $REG_OPTION=0) {
   $rok = ($hive, $key, $REG_OPTION, $REG_ACCESS, ($hive -as $D[9]));  F "RegOpenKeyEx" $rok; $rsv = $rok[4]
   $values |% {$i = 0} { F "RegSetValueEx" ($rsv[0], [string]$_, 0, $REG_TYPE, [byte[]]($dword[$i]), 4); $i++ }
   F "RegFlushKey" @($rsv); F "RegCloseKey" @($rsv); $rok = $null; $rsv = $null;
 }  
 ## The ` sprinkles are used to keep ps event log clean, not quote the whole snippet on every run
 ################################################################################################################################ 
 
 ## get script options
 $toggle = 1; $toggle_rev = 0; 
 $TOGGLE_SMARTSCREENFILTER = 1

 stop-service "wscsvc" -force -ea 0 >'' 2>''
 kill -name "OFFmeansOFF","MpCmdRun" -force -ea 0 
 
 $HKLM = [uintptr][uint32]2147483650; $HKU = [uintptr][uint32]2147483651 
 $VALUES = "ServiceKeepAlive","PreviousRunningMode","IsServiceRunning","DisableAntiSpyware","DisableAntiVirus","PassiveMode"
 $DWORDS = 0, 0, 0, $toggle, $toggle, $toggle
 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS 
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS
 [GC]::Collect(); sleep 1
 pushd "$env:programfiles\Windows Defender"
 $mpcmdrun=("OFFmeansOFF.exe","MpCmdRun.exe")[(test-path "MpCmdRun.exe")]
 start -wait $mpcmdrun -args "-DisableService -HighPriority"
 $wait=14
 while ((get-process -name "MsMpEng" -ea 0) -and $wait -gt 0) {$wait--; sleep 1;}
 
 ## OFF means OFF
 pushd (split-path $(gp "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" ImagePath -ea 0).ImagePath.Trim('"'))
 ren MpCmdRun.exe OFFmeansOFF.exe -force -ea 0
 

 ## Comment to keep old scan history
 del "$env:ProgramData\Microsoft\Windows Defender\Scans\mpenginedb.db" -force -ea 0 
 del "$env:ProgramData\Microsoft\Windows Defender\Scans\History\Service" -recurse -force -ea 0

 RegSetDwords $HKLM "SOFTWARE\Policies\Microsoft\Windows Defender" $VALUES $DWORDS 
 RegSetDwords $HKLM "SOFTWARE\Microsoft\Windows Defender" $VALUES $DWORDS

 ## when toggling Defender, also toggle SmartScreen - set to 0 at top of the script to skip it
 if ($TOGGLE_SMARTSCREENFILTER -ne 0) {
   sp "HKLM:\CurrentControlSet\Control\CI\Policy" 'VerifiedAndReputablePolicyState' 0 -type Dword -force -ea 0
   sp "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" 'SmartScreenEnabled' @('Off','Warn')[$toggle -eq 0] -force -ea 0 
   gi Registry::HKEY_Users\S-1-5-21*\Software\Microsoft -ea 0 |% {
     sp "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'EnableWebContentEvaluation' $toggle_rev -type Dword -force -ea 0
     sp "$($_.PSPath)\Windows\CurrentVersion\AppHost" 'PreventOverride' $toggle_rev -type Dword -force -ea 0
     ni "$($_.PSPath)\Edge\SmartScreenEnabled" -ea 0 > ''
     sp "$($_.PSPath)\Edge\SmartScreenEnabled" "(Default)" $toggle_rev
   }
   if ($toggle_rev -eq 0) {kill -name smartscreen -force -ea 0}
 }
 
 
 ################################################################################################################################
'@; $V = ''; 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }; Set-ItemProperty $key $id $V, $code -type 7 -force -ea 0
        Start-Process powershell -args "-nop -c `n$V  `$env:R=(gi `$key -ea 0 |% {`$_.getvalue(`$id)-join''}); iex(`$env:R)" -verb runas -Wait
      }
      defeatMsMpEng
       
      #disables defender through gp edit
 
      Write-Host 'Disabling Defender with Group Policy' 

      $command = @'
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
Reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefusersvc" /v "Start" /t REG_DWORD /d "4" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows Security Health\State" /v "AppAndBrowser_StoreAppsSmartScreenOff" /t REG_DWORD /d 0 /f 
'@


      RunAsTI powershell "-nologo -windowstyle hidden -command $command"
      Start-Sleep 2
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
 
      RunAsTI powershell "-nologo -windowstyle hidden -command $command"

      Write-Host 'Cleaning Up...'
      #remove temp av
      Remove-Item -Path 'registry::HKLM\SOFTWARE\Avast Software' -Recurse -Force -ErrorAction SilentlyContinue
      Remove-Item -Path 'registry::HKLM\SYSTEM\ControlSet001\Services\wsc_proxy' -Recurse -Force -ErrorAction SilentlyContinue

    }
      
     
  
    
  
    
    if ($checkbox3.Checked) {
      Write-Host 'Disabling Telemetry...'
      #removes telemetry through gp edit
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'AllowTelemetry' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'AllowTelemetry' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'MaxTelemetryAllowed' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\System\ControlSet001\Services\dmwappushservice' /v 'Start' /t REG_DWORD /d '4' /f
      Reg.exe add 'HKLM\System\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener' /v 'Start' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKLM\Software\Policies\Microsoft\Biometrics' /v 'Enabled' /t REG_DWORD /d '0' /f
  
 
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser' -ErrorAction SilentlyContinue
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\Application Experience\ProgramDataUpdater' -ErrorAction SilentlyContinue
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\Autochk\Proxy' -ErrorAction SilentlyContinue
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\Consolidator' -ErrorAction SilentlyContinue
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\Customer Experience Improvement Program\UsbCeip' -ErrorAction SilentlyContinue
      Disable-ScheduledTask -TaskName 'Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector' -ErrorAction SilentlyContinue
  
    
  
    }
  
  
  
    #updates group policy so that the previous changes are applied 
    Write-Host 'Updating Policy...'
    gpupdate /force
  }
  
}
Export-ModuleMember -Function gpTweaks





function import-powerplan {

  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
    , [Parameter(mandatory = $false)] [bool]$importPPlan = $false
    , [Parameter(mandatory = $false)] [bool]$removeAllPlans = $false
    , [Parameter(mandatory = $false)] [bool]$rPowersaver = $false
    , [Parameter(mandatory = $false)] [bool]$rBalanced = $false
    , [Parameter(mandatory = $false)] [bool]$rHighPerformance = $false
  )
      
  $checkbox1 = New-Object System.Windows.Forms.CheckBox
  $checkbox2 = New-Object System.Windows.Forms.CheckBox
  $checkbox3 = New-Object System.Windows.Forms.CheckBox
  $checkbox4 = New-Object System.Windows.Forms.CheckBox
    
  #hashtable to loop through
  $settings = @{}
  $settings['removeallPlans'] = $checkbox1
  $settings['rPowersaver'] = $checkbox2
  $settings['rBalanced'] = $checkbox3
  $settings['rHighPerformance'] = $checkbox4
    
    
  if ($Autorun) {
    if ($importPPlan) {
      $msgBoxInput = 'Yes'
    }
    $result = [System.Windows.Forms.DialogResult]::OK
    $checkbox1.Checked = $removeAllPlans
    $checkbox2.Checked = $rPowersaver
    $checkbox3.Checked = $rBalanced
    $checkbox4.Checked - $rHighPerformance
  }
  else {
    [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Import Zoics Ultimate Performance Power Plan?', 'zoicware', 'YesNo', 'Question')
      
      
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()
      
    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Remove Unwanted Plans'
    $form.Size = New-Object System.Drawing.Size(300, 200)
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
      
    # Create the checkboxes
      
    $checkbox1.Text = 'Remove ALL'
    $checkbox1.Location = New-Object System.Drawing.Point(20, 20)
    $checkbox1.ForeColor = 'White'
    $form.Controls.Add($checkbox1)
      
      
    $checkbox2.Text = 'Power Saver'
    $checkbox2.Location = New-Object System.Drawing.Point(20, 50)
    $checkbox2.ForeColor = 'White'
    $form.Controls.Add($checkbox2)
      
      
    $checkbox3.Text = 'Balanced'
    $checkbox3.Location = New-Object System.Drawing.Point(20, 80)
    $checkbox3.ForeColor = 'White'
    $form.Controls.Add($checkbox3)
      
      
    $checkbox4.Text = 'High Performance'
    $checkbox4.Location = New-Object System.Drawing.Point(20, 110)
    $checkbox4.ForeColor = 'White'
    $checkbox4.AutoSize = $true
    $form.Controls.Add($checkbox4)
      
     
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(70, 140)
    $OKButton.Size = New-Object System.Drawing.Size(75, 23)
    $OKButton.Text = 'OK'
    $OKButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $OKButton.ForeColor = [System.Drawing.Color]::White
    $OKButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $OKButton.FlatAppearance.BorderSize = 0
    $OKButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $OKButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)
  
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(150, 140)
    $CancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $CancelButton.ForeColor = [System.Drawing.Color]::White
    $CancelButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $CancelButton.FlatAppearance.BorderSize = 0
    $CancelButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $CancelButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)
    
      
      
    # Show the form and wait for user input
    $result = $form.ShowDialog()
      
  }
      
      
      
  switch ($msgBoxInput) {
      
    'Yes' {
              
      if (!($Autorun)) {
        #update config
        update-config -setting 'usePowerPlan' -value 1
      }
              
      #imports power plan
      $p = Search-File '*zoicsultimateperformance.pow'
      
      powercfg -import ([string]$p ) 88888888-8888-8888-8888-888888888888     
      powercfg /setactive 88888888-8888-8888-8888-888888888888 
      powercfg -h off 
      if (!($Autorun)) {
        [System.Windows.Forms.MessageBox]::Show('Zoics Ultimate Performance is successfully enabled.')
      }
          
    }
      
    'No' {}
      
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
      #deletes balanced, high performance, and power saver
      powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
      powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
      powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a 
      
      
    }
    if ($checkbox2.Checked) {
      powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a
      
    }    
    if ($checkbox3.Checked) {
      powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
      
    }    
    if ($checkbox4.Checked) {
      powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
      
    }    
          
  }
      
}
Export-ModuleMember -Function import-powerplan






function import-reg {

  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
  )
    
    
    
    
  if ($AutoRun) {
    $msgBoxInput = 'Yes'
  }
  else {
    [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Import Registry Tweaks?', 'zoicware', 'YesNo', 'Question')
  }
      
      
  switch ($msgBoxInput) {
      
    'Yes' {
      #update config
      if (!($Autorun)) {
        update-config -setting 'registryTweaks' -value 1
      }
        
      $reg = Search-File '*RegTweak.ps1'
      & $reg
      #prevent event log error from disabling uac
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\luafv' /v 'Start' /t REG_DWORD /d '4' /f
      if (!($Autorun)) {
        [System.Windows.Forms.MessageBox]::Show('Registry Tweaks Applied.')
      }
        
    }
      
    'No' {}
      
  }
      
}
Export-ModuleMember -Function import-reg






function install-packs {
  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
  )
      
         
      
  if ($AutoRun) {
    $msgBoxInput = 'Yes'
  }
  else {
    [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Install DX, C++ Packages and NET 3.5?', 'zoicware', 'YesNo', 'Question')
  }
        
        
  switch ($msgBoxInput) {
        
    'Yes' {
      #update config
      if (!($Autorun)) {
        update-config -setting 'installPackages' -value 1
      }
      
          
      Write-host '------------------------------------'
      Write-host '|                                  |'
      Write-host '|       Packages Installing...     |'
      Write-host '|                                  |'
      Write-host '------------------------------------'
        
      $pathDX = Search-File '*DXSETUP.exe'
      $pathCpp = Search-File '*VisualCppRedist_AIO_x86_x64.exe'
      if ($pathDX -eq $null -or $pathCpp -eq $null) {
        Write-Host 'Packages Not Found...'
        Write-Host 'Attempting to install...'
        
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
        
          Write-Host 'Installing...'
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
          Write-Host 'Unable to install packages...Make sure you are connected to the internet'
        
        }
        
      }
      else {
        
        #run DXInstaller
        Start-Process $pathDX -ArgumentList '/silent'
        $wshell = New-Object -ComObject wscript.shell
        Start-Sleep 1
        $openWindows = Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | Select-Object MainWindowTitle
        foreach ($window in $openWindows) {
          if ($window -like '*DirectX*') {
            $wshell.SendKeys('~')
            Start-Process $pathDX -ArgumentList '/quiet' -Wait
          }

        }
        #run Cpp installer
        Start-Process $pathCpp -Argumentlist '/ai /gm2' -WindowStyle Hidden -Wait
          
      }
          
         
      [System.Windows.Forms.MessageBox]::Show('Please make sure your USB Flash Drive is plugged in.', 'Installing Net 3.5')
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
          Write-Host 'Installing NET 3.5...'
          Dism /online /enable-feature /featurename:NetFX3 /All /Source:$($driveLetter):\sources\sxs /LimitAccess
          $driveFound = $true
          break
        }
      }
    
        
      
      #cant find install wim 
      if (!($driveFound)) {
        Write-Host 'Drive NOT Found...'
        
      }
        
      Write-Host 'Cleaning up...[This may take a few minutes]'
        
      $ngenPath = [System.IO.Path]::Combine([Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory(), 'ngen.exe')
      Start-process $ngenPath -ArgumentList 'update /silent /nologo' -WindowStyle Hidden 
          
      Start-Process dism.exe -ArgumentList '/online /Cleanup-Image /StartComponentCleanup /ResetBase' -WindowStyle Hidden -Wait 
          
      if (!($Autorun)) {
        [System.Windows.Forms.MessageBox]::Show('Packages Installed.')
      }
          
    }
        
    'No' {}
        
  }
}
Export-ModuleMember -Function install-packs







function OptionalTweaks {
  param (
    [Parameter(mandatory = $false)] [bool]$Autorun = $false
    , [Parameter(mandatory = $false)] [bool]$opblackTheme = $false
    , [Parameter(mandatory = $false)] [bool]$opclassicTheme = $false 
    , [Parameter(mandatory = $false)] [bool]$opROFSW = $false 
    , [Parameter(mandatory = $false)] [bool]$opremoveSpeech = $false 
    , [Parameter(mandatory = $false)] [bool]$openableHAGS = $false 
    , [Parameter(mandatory = $false)] [bool]$optransTaskbar = $false
    , [Parameter(mandatory = $false)] [bool]$opdoubleClickPS = $false
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
    , [Parameter(mandatory = $false)] [bool]$legacyPhotoViewer = $false
    , [Parameter(mandatory = $false)] [bool]$legacy7calc = $false
    , [Parameter(mandatory = $false)] [bool]$legacy7task = $false
    , [Parameter(mandatory = $false)] [bool]$legacyVolumeFlyout = $false
    , [Parameter(mandatory = $false)] [bool]$legacyAltTab = $false
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
  )
        
      
      
      
  #create checkboxes
  $checkbox2 = new-object System.Windows.Forms.checkbox
  $classicblackBTN = new-object System.Windows.Forms.checkbox
  $checkbox4 = new-object System.Windows.Forms.checkbox
  $checkbox5 = new-object System.Windows.Forms.checkbox
  $checkbox6 = new-object System.Windows.Forms.checkbox
  $checkbox7 = new-object System.Windows.Forms.checkbox
  $checkbox8 = new-object System.Windows.Forms.checkbox
  $checkbox9 = new-object System.Windows.Forms.checkbox
  $checkbox12 = new-object System.Windows.Forms.checkbox
  $checkbox13 = new-object System.Windows.Forms.checkbox
  $checkbox14 = new-object System.Windows.Forms.checkbox
  $checkbox15 = new-object System.Windows.Forms.checkbox
  $checkbox16 = new-object System.Windows.Forms.checkbox
  $checkbox17 = new-object System.Windows.Forms.checkbox
  $checkbox18 = new-object System.Windows.Forms.checkbox
  $checkbox19 = new-object System.Windows.Forms.checkbox
  $checkbox20 = new-object System.Windows.Forms.checkbox
  $checkbox26 = new-object System.Windows.Forms.checkbox
  $checkbox22 = new-object System.Windows.Forms.checkbox
  $checkbox23 = new-object System.Windows.Forms.checkbox
  $checkbox24 = new-object System.Windows.Forms.checkbox
  $checkbox25 = new-object System.Windows.Forms.checkbox
  $checkbox27 = new-object System.Windows.Forms.checkbox
  $checkbox28 = new-object System.Windows.Forms.checkbox
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

  #hashtable for updating config
  $settings = @{}
  $settings['opblackTheme'] = $checkbox2
  $settings['opclassicTheme'] = $classicblackBTN
  $settings['opROFSW'] = $checkbox4
  $settings['opremoveSpeech'] = $checkbox5
  $settings['legacyPhotoViewer'] = $checkbox6
  $settings['openableHAGS'] = $checkbox7
  $settings['optransTaskbar'] = $checkbox8
  $settings['opremoveQuickAccess'] = $checkbox9
  $settings['legacy7calc'] = $checkbox12
  $settings['opblockRazerAsus'] = $checkbox13
  $settings['connewFiles'] = $checkbox14
  $settings['conmorePS'] = $checkbox15
  $settings['consnipping'] = $checkbox16
  $settings['conshutdown'] = $checkbox17
  $settings['conrunAsAdmin'] = $checkbox18
  $settings['conpsCmd'] = $checkbox19
  $settings['conkillTasks'] = $checkbox20
  $settings['conpermDel'] = $checkbox26
  $settings['legacy7task'] = $checkBox22
  $settings['opremoveNetworkIcon'] = $checkbox23
  $settings['opapplyPBO'] = $checkbox24
  $settings['legacyVolumeFlyout'] = $checkbox25
  $settings['opdoubleClickPS'] = $checkbox27
  $settings['legacyAltTab'] = $checkbox28
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
      
  if ($AutoRun) {
    $result = [System.Windows.Forms.DialogResult]::OK
    #setting options
    $checkbox2.Checked = $opblackTheme 
    $classicblackBTN.Checked = $opclassicTheme  
    $checkbox4.Checked = $opROFSW  
    $checkbox5.Checked = $opremoveSpeech
    $checkbox6.Checked = $legacyPhotoViewer 
    $checkbox7.Checked = $openableHAGS
    $checkbox8.Checked = $optransTaskbar
    $checkbox9.Checked = $opremoveQuickAccess
    $checkbox12.Checked = $legacy7calc
    $checkbox13.Checked = $opblockRazerAsus
    $checkbox14.Checked = $connewFiles
    $checkbox15.Checked = $conmorePS
    $checkbox16.Checked = $consnipping
    $checkbox17.Checked = $conshutdown
    $checkbox18.Checked = $conrunAsAdmin
    $checkbox19.Checked = $conpsCmd
    $checkbox20.Checked = $conkillTasks
    $checkbox26.Checked = $conpermDel
    $checkbox22.Checked = $legacy7task
    $checkbox23.Checked = $opremoveNetworkIcon
    $checkbox24.Checked = $opapplyPBO
    $checkbox25.Checked = $legacyVolumeFlyout
    $checkbox27.Checked = $opdoubleClickPS
    $checkbox28.Checked = $legacyAltTab
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
  }
  else {
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # Set the size of your form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Optional Tweaks'
    $form.Size = New-Object System.Drawing.Size(600, 580)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = 'Black'
            
    $TabControl = New-Object System.Windows.Forms.TabControl
    $TabControl.Location = New-Object System.Drawing.Size(10, 10)
    $TabControl.Size = New-Object System.Drawing.Size(570, 500) 
    $TabControl.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
        
        
    $TabPage1 = New-Object System.Windows.Forms.TabPage
    $TabPage1.Text = 'General'
    $TabPage1.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
        
    $TabPage2 = New-Object System.Windows.Forms.TabPage
    $TabPage2.Text = 'Ultimate Context Menu'
    $TabPage2.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
        
    $TabPage3 = New-Object System.Windows.Forms.TabPage
    $TabPage3.Text = 'Legacy Win Store'
    $TabPage3.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
           
           
    $TabControl.Controls.Add($TabPage1)
    $TabControl.Controls.Add($TabPage2)
    $TabControl.Controls.Add($TabPage3)
        
        
    $Form.Controls.Add($TabControl)    
           
    $label1 = New-Object System.Windows.Forms.Label
    $label1.Location = New-Object System.Drawing.Point(10, 10)
    $label1.Size = New-Object System.Drawing.Size(200, 20)
    $label1.Text = 'Add to Menu'
    $label1.ForeColor = 'White'
    $label1.Font = New-Object System.Drawing.Font('Segoe UI', 13)  
    $form.Controls.Add($label1)
    $TabPage2.Controls.Add($label1)
    
    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(260, 10)
    $label2.Size = New-Object System.Drawing.Size(200, 20)
    $label2.Text = 'Remove From Menu'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font('Segoe UI', 13)  
    $form.Controls.Add($label2)
    $TabPage2.Controls.Add($label2)  
         
    $checkbox2.Location = new-object System.Drawing.Size(10, 20)
    $checkbox2.Size = new-object System.Drawing.Size(150, 20)
    $checkbox2.Text = 'Black Theme'
    $checkbox2.ForeColor = 'White'
    $checkbox2.Checked = $false
    $Form.Controls.Add($checkbox2)  
    $TabPage1.Controls.Add($checkBox2)
        
            
    $classicblackBTN.Location = new-object System.Drawing.Size(15, 40)
    $classicblackBTN.Size = new-object System.Drawing.Size(150, 20)
    $classicblackBTN.Text = 'Classic Black Theme'
    $classicblackBTN.ForeColor = 'White'
    $classicblackBTN.Checked = $false
    $classicblackBTN.Visible = $false
    $Form.Controls.Add($classicblackBTN)  
    $TabPage1.Controls.Add($classicblackBTN)
            
        
            
    $checkbox4.Location = new-object System.Drawing.Size(10, 70)
    $checkbox4.Size = new-object System.Drawing.Size(170, 30)
    $checkbox4.Text = 'Remove Open File Security Warning'
    $checkbox4.ForeColor = 'White'
    $checkbox4.Checked = $false
    $Form.Controls.Add($checkbox4)
    $TabPage1.Controls.Add($checkBox4)
        
            
    $checkbox5.Location = new-object System.Drawing.Size(10, 110)
    $checkbox5.Size = new-object System.Drawing.Size(200, 20)
    $checkbox5.Text = 'Remove Speech Recognition App'
    $checkbox5.ForeColor = 'White'
    $checkbox5.Checked = $false
    $Form.Controls.Add($checkbox5)
    $TabPage1.Controls.Add($checkBox5)
        
            
    $checkbox6.Location = new-object System.Drawing.Size(10, 20)
    $checkbox6.Size = new-object System.Drawing.Size(150, 20)
    $checkbox6.Text = 'Classic Photo Viewer'
    $checkbox6.ForeColor = 'White'
    $checkbox6.Checked = $false
    $Form.Controls.Add($checkbox6)
    $TabPage3.Controls.Add($checkBox6)
        
            
    $checkbox7.Location = new-object System.Drawing.Size(10, 150)
    $checkbox7.Size = new-object System.Drawing.Size(200, 20)
    $checkbox7.Text = 'Enable HAGS'
    $checkbox7.ForeColor = 'White'
    $checkbox7.Checked = $false
    $Form.Controls.Add($checkbox7)
    $TabPage1.Controls.Add($checkBox7)
        
            
    $checkbox8.Location = new-object System.Drawing.Size(10, 190)
    $checkbox8.Size = new-object System.Drawing.Size(200, 20)
    $checkbox8.Text = 'Transparent Task Bar'
    $checkbox8.ForeColor = 'White'
    $checkbox8.Checked = $false
    $Form.Controls.Add($checkbox8)
    $TabPage1.Controls.Add($checkBox8)
        
            
    $checkbox9.Location = new-object System.Drawing.Size(220, 20)
    $checkbox9.Size = new-object System.Drawing.Size(270, 30)
    $checkbox9.Text = 'Remove Quick Access From File Explorer'
    $checkbox9.ForeColor = 'White'
    $checkbox9.Checked = $false
    $Form.Controls.Add($checkbox9)
    $TabPage1.Controls.Add($checkBox9)
        
            
    $checkbox12.Location = new-object System.Drawing.Size(10, 40)
    $checkbox12.Size = new-object System.Drawing.Size(150, 30)
    $checkbox12.Text = 'Win 7 Calculator'
    $checkbox12.ForeColor = 'White'
    $checkbox12.Checked = $false
    $Form.Controls.Add($checkbox12)
    $TabPage3.Controls.Add($checkBox12)
        
            
    $checkbox13.Location = new-object System.Drawing.Size(220, 60)
    $checkbox13.Size = new-object System.Drawing.Size(270, 30)
    $checkbox13.Text = 'Block Razer and ASUS Download Servers'
    $checkbox13.ForeColor = 'White'
    $checkbox13.Checked = $false
    $Form.Controls.Add($checkbox13)
    $TabPage1.Controls.Add($checkBox13)
        
    # CONTEXT MENU OPTIONS   
            
    $checkbox14.Location = new-object System.Drawing.Size(20, 40)
    $checkbox14.Size = new-object System.Drawing.Size(190, 20)
    $checkbox14.Text = "Aditional files to `"New`" Menu"
    $checkbox14.ForeColor = 'White'
    $checkbox14.Checked = $false
    $Form.Controls.Add($checkbox14) 
    $TabPage2.Controls.Add($checkBox14)
        
            
    $checkbox15.Location = new-object System.Drawing.Size(20, 70)
    $checkbox15.Size = new-object System.Drawing.Size(150, 20)
    $checkbox15.Text = 'Aditional ps1 options'
    $checkbox15.ForeColor = 'White'
    $checkbox15.Checked = $false
    $Form.Controls.Add($checkbox15)
    $TabPage2.Controls.Add($checkBox15)  
        
            
    $checkbox16.Location = new-object System.Drawing.Size(20, 100)
    $checkbox16.Size = new-object System.Drawing.Size(190, 20)
    $checkbox16.Text = 'Snipping Tool'
    $checkbox16.ForeColor = 'White'
    $checkbox16.Checked = $false
    $Form.Controls.Add($checkbox16)
    $TabPage2.Controls.Add($checkBox16) 
        
            
    $checkbox17.Location = new-object System.Drawing.Size(20, 130)
    $checkbox17.Size = new-object System.Drawing.Size(190, 20)
    $checkbox17.Text = 'Shutdown'
    $checkbox17.ForeColor = 'White'
    $checkbox17.Checked = $false
    $Form.Controls.Add($checkbox17)
    $TabPage2.Controls.Add($checkBox17)
        
            
    $checkbox18.Location = new-object System.Drawing.Size(20, 160)
    $checkbox18.Size = new-object System.Drawing.Size(250, 20)
    $checkbox18.Text = 'Run as Admin for ps1,bat,vbs files'
    $checkbox18.ForeColor = 'White'
    $checkbox18.Checked = $false
    $Form.Controls.Add($checkbox18)
    $TabPage2.Controls.Add($checkBox18)
        
            
    $checkbox19.Location = new-object System.Drawing.Size(20, 190)
    $checkbox19.Size = new-object System.Drawing.Size(250, 20)
    $checkbox19.Text = 'Powershell and Cmd'
    $checkbox19.ForeColor = 'White'
    $checkbox19.Checked = $false
    $Form.Controls.Add($checkbox19)
    $TabPage2.Controls.Add($checkBox19)
        
            
    $checkbox20.Location = new-object System.Drawing.Size(20, 220)
    $checkbox20.Size = new-object System.Drawing.Size(250, 20)
    $checkbox20.Text = 'Kill not Responding Tasks'
    $checkbox20.ForeColor = 'White'
    $checkbox20.Checked = $false
    $Form.Controls.Add($checkbox20)
    $TabPage2.Controls.Add($checkBox20)
        
            
    $checkbox26.Location = new-object System.Drawing.Size(20, 250)
    $checkbox26.Size = new-object System.Drawing.Size(250, 20)
    $checkbox26.Text = 'Delete Permanently'
    $checkbox26.ForeColor = 'White'
    $checkbox26.Checked = $false
    $Form.Controls.Add($checkbox26)
    $TabPage2.Controls.Add($checkBox26)
        
    
    $checkbox34.Location = new-object System.Drawing.Size(20, 280)
    $checkbox34.Size = new-object System.Drawing.Size(250, 30)
    $checkbox34.Text = 'Take Ownership'
    $checkbox34.ForeColor = 'White'
    $checkbox34.Checked = $false
    $Form.Controls.Add($checkbox34)
    $TabPage2.Controls.Add($checkBox34)
    

    # REMOVE CONTEXT MENU ITEMS

    $checkbox35.Location = new-object System.Drawing.Size(270, 40)
    $checkbox35.Size = new-object System.Drawing.Size(250, 30)
    $checkbox35.Text = 'Add to Favorites'
    $checkbox35.ForeColor = 'White'
    $checkbox35.Checked = $false
    $Form.Controls.Add($checkbox35)
    $TabPage2.Controls.Add($checkBox35)

    $checkbox36.Location = new-object System.Drawing.Size(270, 70)
    $checkbox36.Size = new-object System.Drawing.Size(250, 30)
    $checkbox36.Text = 'Customize this Folder'
    $checkbox36.ForeColor = 'White'
    $checkbox36.Checked = $false
    $Form.Controls.Add($checkbox36)
    $TabPage2.Controls.Add($checkBox36)

    $checkbox37.Location = new-object System.Drawing.Size(270, 100)
    $checkbox37.Size = new-object System.Drawing.Size(250, 30)
    $checkbox37.Text = 'Give Access to'
    $checkbox37.ForeColor = 'White'
    $checkbox37.Checked = $false
    $Form.Controls.Add($checkbox37)
    $TabPage2.Controls.Add($checkBox37)

    $checkbox38.Location = new-object System.Drawing.Size(270, 130)
    $checkbox38.Size = new-object System.Drawing.Size(250, 30)
    $checkbox38.Text = 'Open in Terminal (Win 11)'
    $checkbox38.ForeColor = 'White'
    $checkbox38.Checked = $false
    $Form.Controls.Add($checkbox38)
    $TabPage2.Controls.Add($checkBox38)

    $checkbox39.Location = new-object System.Drawing.Size(270, 160)
    $checkbox39.Size = new-object System.Drawing.Size(250, 30)
    $checkbox39.Text = 'Restore Previous Versions'
    $checkbox39.ForeColor = 'White'
    $checkbox39.Checked = $false
    $Form.Controls.Add($checkbox39)
    $TabPage2.Controls.Add($checkBox39)

    $checkbox40.Location = new-object System.Drawing.Size(270, 190)
    $checkbox40.Size = new-object System.Drawing.Size(250, 30)
    $checkbox40.Text = 'Print'
    $checkbox40.ForeColor = 'White'
    $checkbox40.Checked = $false
    $Form.Controls.Add($checkbox40)
    $TabPage2.Controls.Add($checkBox40)

    $checkbox41.Location = new-object System.Drawing.Size(270, 220)
    $checkbox41.Size = new-object System.Drawing.Size(250, 30)
    $checkbox41.Text = 'Send to'
    $checkbox41.ForeColor = 'White'
    $checkbox41.Checked = $false
    $Form.Controls.Add($checkbox41)
    $TabPage2.Controls.Add($checkBox41)

    $checkbox42.Location = new-object System.Drawing.Size(270, 250)
    $checkbox42.Size = new-object System.Drawing.Size(250, 30)
    $checkbox42.Text = 'Share'
    $checkbox42.ForeColor = 'White'
    $checkbox42.Checked = $false
    $Form.Controls.Add($checkbox42)
    $TabPage2.Controls.Add($checkBox42)

    $checkbox43.Location = new-object System.Drawing.Size(270, 280)
    $checkbox43.Size = new-object System.Drawing.Size(250, 30)
    $checkbox43.Text = 'Personalize (Desktop)'
    $checkbox43.ForeColor = 'White'
    $checkbox43.Checked = $false
    $Form.Controls.Add($checkbox43)
    $TabPage2.Controls.Add($checkBox43)

    $checkbox44.Location = new-object System.Drawing.Size(270, 310)
    $checkbox44.Size = new-object System.Drawing.Size(250, 30)
    $checkbox44.Text = 'Display (Desktop)'
    $checkbox44.ForeColor = 'White'
    $checkbox44.Checked = $false
    $Form.Controls.Add($checkbox44)
    $TabPage2.Controls.Add($checkBox44)



    $checkbox22.Location = new-object System.Drawing.Size(10, 70)
    $checkbox22.Size = new-object System.Drawing.Size(150, 20)
    $checkbox22.Text = 'Win 7 Task Manager'
    $checkbox22.ForeColor = 'White'
    $checkbox22.Checked = $false
    $Form.Controls.Add($checkbox22)
    $TabPage3.Controls.Add($checkBox22)
        
            
    $checkbox23.Location = new-object System.Drawing.Size(220, 100)
    $checkbox23.Size = new-object System.Drawing.Size(270, 30)
    $checkbox23.Text = 'Remove Network Icon From File Explorer'
    $checkbox23.ForeColor = 'White'
    $checkbox23.Checked = $false
    $Form.Controls.Add($checkbox23)
    $TabPage1.Controls.Add($checkBox23)
        
            
    $checkbox24.Location = new-object System.Drawing.Size(220, 140)
    $checkbox24.Size = new-object System.Drawing.Size(270, 30)
    $checkbox24.Text = 'Apply PBO Curve on Startup'
    $checkbox24.ForeColor = 'White'
    $checkbox24.Checked = $false
    $Form.Controls.Add($checkbox24)
    $TabPage1.Controls.Add($checkBox24)
        
            
    $checkbox25.Location = new-object System.Drawing.Size(180, 20)
    $checkbox25.Size = new-object System.Drawing.Size(150, 20)
    $checkbox25.Text = 'Classic Volume Flyout'
    $checkbox25.ForeColor = 'White'
    $checkbox25.Checked = $false
    $Form.Controls.Add($checkbox25)
    $TabPage3.Controls.Add($checkBox25)
        
            
    $checkbox27.Location = new-object System.Drawing.Size(10, 220)
    $checkbox27.Size = new-object System.Drawing.Size(210, 30)
    $checkbox27.Text = 'Add Double Click to Powershell Files'
    $checkbox27.ForeColor = 'White'
    $checkbox27.Checked = $false
    $Form.Controls.Add($checkbox27)
    $TabPage1.Controls.Add($checkBox27)
        
            
    $checkbox28.Location = new-object System.Drawing.Size(180, 40)
    $checkbox28.Size = new-object System.Drawing.Size(150, 20)
    $checkbox28.Text = 'Classic Alt-Tab'
    $checkbox28.ForeColor = 'White'
    $checkbox28.Checked = $false
    $Form.Controls.Add($checkbox28)
    $TabPage3.Controls.Add($checkBox28)
        
            
    $checkbox29.Location = new-object System.Drawing.Size(220, 180)
    $checkbox29.Size = new-object System.Drawing.Size(270, 30)
    $checkbox29.Text = 'Do not include drivers in Windows Update'
    $checkbox29.ForeColor = 'White'
    $checkbox29.Checked = $false
    $Form.Controls.Add($checkbox29)
    $TabPage1.Controls.Add($checkBox29)
        
            
    $checkbox31.Location = new-object System.Drawing.Size(10, 260)
    $checkbox31.Size = new-object System.Drawing.Size(210, 30)
    $checkbox31.Text = 'Remove Mouse and Sound Schemes'
    $checkbox31.ForeColor = 'White'
    $checkbox31.Checked = $false
    $Form.Controls.Add($checkbox31)
    $TabPage1.Controls.Add($checkBox31)
        
            
    $checkbox32.Location = new-object System.Drawing.Size(220, 220)
    $checkbox32.Size = new-object System.Drawing.Size(270, 30)
    $checkbox32.Text = 'Enable Windows 11 Sounds'
    $checkbox32.ForeColor = 'White'
    $checkbox32.Checked = $false
    $Form.Controls.Add($checkbox32)
    $TabPage1.Controls.Add($checkBox32)
        
            
    $checkbox33.Location = new-object System.Drawing.Size(220, 260)
    $checkbox33.Size = new-object System.Drawing.Size(270, 30)
    $checkbox33.Text = 'Remove Recycle Bin Name'
    $checkbox33.ForeColor = 'White'
    $checkbox33.Checked = $false
    $Form.Controls.Add($checkbox33)
    $TabPage1.Controls.Add($checkBox33)

    $checkbox45.Location = new-object System.Drawing.Size(10, 300)
    $checkbox45.Size = new-object System.Drawing.Size(270, 30)
    $checkbox45.Text = 'Security Updates Only'
    $checkbox45.ForeColor = 'White'
    $checkbox45.Checked = $false
    $Form.Controls.Add($checkbox45)
    $TabPage1.Controls.Add($checkBox45)
        
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(200, 510)
    $OKButton.Size = New-Object System.Drawing.Size(100, 23)
    $OKButton.Text = 'OK'
    $OKButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $OKButton.ForeColor = [System.Drawing.Color]::White
    $OKButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $OKButton.FlatAppearance.BorderSize = 0
    $OKButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $OKButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)
        
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(295, 510)
    $CancelButton.Size = New-Object System.Drawing.Size(100, 23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $CancelButton.ForeColor = [System.Drawing.Color]::White
    $CancelButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $CancelButton.FlatAppearance.BorderSize = 0
    $CancelButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $CancelButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)
        
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $label.Size = New-Object System.Drawing.Size(200, 20)
    $label.Text = 'Select Any Optional Tweaks:'
    $label.ForeColor = 'White'
    $form.Controls.Add($label)
        
    $checkbox2.Add_CheckedChanged({ 
        if ($checkbox2.Checked) {
          $classicblackBTN.Visible = $true
        
        }
        else {
        
          $classicblackBTN.Visible = $false
        
        }
            
      })    
    # Activate the form
    $Form.Add_Shown({ $Form.Activate() })
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
      if (test-path 'C:\UltimateContextMenu') {
        $path = Search-File '*BlackTheme.reg'
        Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
      }
      else {
        $path = Search-Directory '*UltimateContextMenu'
        Move-item $path -Destination 'C:\'
      
        $path = Search-File '*BlackTheme.reg'       
        Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
      
      }
              
      #setting lockscreen to black
      reg.exe delete 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System' /v 'DisableLogonBackgroundImage' /f *>$null
      
      $path = Search-File '*Black.jpg'
      Move-Item $path -Destination 'C:\Windows' -Force
      
      New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP' -Force
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP' -Name 'LockScreenImagePath' -Value 'C:\Windows\Black.jpg' -Force
      Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP' -Name 'LockScreenImageStatus' -Value 1
      
      if ($classicblackBTN.Checked) {
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
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Security' /V 'DisableSecuritySettingsCheck' /T 'REG_DWORD' /D '00000001' /F
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' /V '1806' /T 'REG_DWORD' /D '00000000' /F
      Reg.exe add 'HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3' /V '1806' /T 'REG_DWORD' /D '00000000' /F
      
    }
    if ($checkbox5.Checked) {
      $command = 'Remove-item -path C:\Windows\System32\Speech -recurse -force'
      RunAsTI powershell "-nologo -windowstyle hidden -command $command"
      Start-Sleep 2
    }
    if ($checkbox6.Checked) {
      Reg.exe add 'HKCU\SOFTWARE\Classes\.bmp' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.cr2' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.dib' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.gif' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.ico' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.jfif' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.jpe' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.jpeg' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.jpg' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.jxr' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.png' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.tif' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.tiff' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Classes\.wdp' /ve /t REG_SZ /d 'PhotoViewer.FileAssoc.Tiff' /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cr2\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithProgids' /v 'PhotoViewer.FileAssoc.Tiff' /t REG_NONE /d `"`" /f
    }
    if ($checkbox7.Checked) {
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' /v 'HwSchMode' /t REG_DWORD /d '2' /f
      
    }
      
    if ($checkbox8.checked) {
      
      $taskbar = Search-Directory '*TaskbarX'
      Move-Item -Path $taskbar -Destination 'C:\Program Files' -Force
      
      Start-Process -FilePath 'C:\Program Files\TaskbarX\TaskbarX.exe' -ArgumentList @('-tbs=1', '-dct=1')
      
      $pathTB = 'C:\Program Files\TaskbarX\TaskbarX.exe'
      $WshShell = New-Object -comObject WScript.Shell
      $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\TaskbarX.lnk')
      $Shortcut.TargetPath = $pathTB
      $Shortcut.Arguments = '-tbs=1 -dct=1'
      $Shortcut.Save()
      
    }
      
    if ($checkbox9.Checked) {
      
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'HubMode' /t REG_DWORD /d '1' /f
      
    }
            
      
    if ($checkbox12.Checked) {
      
      $folder = Search-Directory '*System322'
      Move-Item -Path $folder -Destination 'C:\'
      Rename-Item -Path 'C:\System322' -NewName 'System32'
      $command = 'Remove-item -path C:\Windows\System32\en-US\cacls.exe.mui -force; Remove-item -path C:\Windows\System32\Calc.exe -force'
      RunAsTI powershell "-nologo -windowstyle hidden -command $command"
      Start-Sleep 2
      Move-Item -Path 'C:\System32\en-US\calc.exe.mui' -Destination 'C:\Windows\System32\en-US' -Force 
      Move-Item -Path 'C:\System32\calc.exe' -Destination 'C:\Windows\System32' -Force
      Remove-Item -Path 'C:\System32' -Recurse -Force
      
      Remove-Item -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Calculator.lnk' -Force -ErrorAction SilentlyContinue
      $WshShell = New-Object -comObject WScript.Shell
      $Shortcut = $WshShell.CreateShortcut('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Calculator.lnk')
      $Shortcut.TargetPath = ('C:\Windows\System32\calc.exe')
      $Shortcut.Save()
      
    }
      
    if ($checkbox13.Checked) {
      
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
      
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
      }
      #fix for win 11
      $OS = Get-CimInstance Win32_OperatingSystem
      if ($OS.Caption -like '*Windows 11*') {
        $path = 'C:\UltimateContextMenu\newMenu11.reg'
      }
      else {
        $path = 'C:\UltimateContextMenu\newMenu.reg'
      }
      
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
      
    }
    if ($checkbox15.Checked) {
            
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
      }
      $path = 'C:\UltimateContextMenu\ps1Options.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
    }
    if ($checkbox16.Checked) {
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
      }
      #fix for win 11
      $OS = Get-CimInstance Win32_OperatingSystem
      if ($OS.Caption -like '*Windows 11*') {
        $path = 'C:\UltimateContextMenu\Snipping11.reg'
      }
      else {
        $path = 'C:\UltimateContextMenu\Snipping.reg'
      }
      
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
      
     
    }
    if ($checkbox17.Checked) {
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
      }
      $path = 'C:\UltimateContextMenu\Shutdown.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
      
    }
    if ($checkbox18.Checked) {
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
      }
      $path = 'C:\UltimateContextMenu\runAsAdmin.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
    }
    if ($checkbox19.Checked) {
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
      }
      $path = 'C:\UltimateContextMenu\powershellCmd.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
      
    }
    if ($checkbox20.Checked) {
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
      }
      $path = 'C:\UltimateContextMenu\killTasks.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
      
    }
      
    if ($checkbox26.Checked) {
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
      }
      $path = 'C:\UltimateContextMenu\superdel.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)
      
    }
      
      
    if ($checkbox22.Checked) {
      
      $taskmgr = Search-File '*classictask.exe'
      Start-Process -FilePath $taskmgr -ArgumentList '/LOADINF=default /VERYSILENT' -WorkingDirectory $PSScriptRoot
      
    }
      
    if ($checkbox23.Checked) {
      
      Reg.exe add 'HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}' /v 'System.IsPinnedToNameSpaceTree' /t REG_DWORD /d '0' /f
      
    }
      
    if ($checkbox24.Checked) {
      
      #limits (in order)
      $ppt = '0'
      $tdc = '0'
      $edc = '0'
      
      
      Add-Type -AssemblyName System.Windows.Forms
      
      # Retrieve the number of CPU cores
      $cpuCores = (Get-WmiObject -Class Win32_Processor).NumberOfCores
      
      $size = 300 + ($cpuCores * 20)
      
      # Create the form
      $form = New-Object System.Windows.Forms.Form
      $form.Text = 'PBO2 Tuner'
      $form.Size = New-Object System.Drawing.Size(400, $size)
      $form.StartPosition = 'CenterScreen'
      
      # Create a checkbox
      $checkBox = New-Object System.Windows.Forms.CheckBox
      $checkBox.Text = 'Custom Limits'
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
      $label1.Visible = $false
      
      $label2 = New-Object System.Windows.Forms.Label
      $label2.Text = 'TDC'
      $label2.Location = New-Object System.Drawing.Point(190, 200)
      $label2.Visible = $false
      
      $label3 = New-Object System.Windows.Forms.Label
      $label3.Text = 'EDC'
      $label3.Location = New-Object System.Drawing.Point(190, 230)
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
      $form.Controls.Add($label)
      
      # Create the radio buttons
      $radioButtons = @()
      $values = @(-10, -20, -30)
      for ($i = 0; $i -lt $values.Count; $i++) {
        $radioButton = New-Object System.Windows.Forms.RadioButton
        $radioButton.Location = [System.Drawing.Point]::new(200, 40 + $i * 30)
        $radioButton.Size = [System.Drawing.Size]::new(60, 20)
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
      
      
      
    if ($checkbox25.Checked) {
      
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MTCUVC' /v 'EnableMtcUvc' /t REG_DWORD /d '0' /f
      
      
    }
      
      
      
    if ($checkbox27.Checked) {
      #working 10 not 11
      Reg.exe add 'HKCR\Microsoft.PowerShellScript.1\Shell\Open\Command' /ve /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noLogo -executionpolicy bypass -file `"`"%1`"`"" /f
      
    }
      
      
      
    if ($checkbox28.Checked) {
      
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'AltTabSettings' /t REG_DWORD /d '1' /f
    }
      
      
    if ($checkbox29.Checked) {
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
      Write-Host 'Updating Policy...'
      gpupdate /force
    }
      
      
      
    if ($checkbox31.Checked) {
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
      
      $soundFolder = New-Item -Path "C:\Users\$env:USERNAME\Desktop" -Name 'Windows 10 Sounds' -ItemType Directory
      $win10sounds = Get-ChildItem -Path C:\Windows\Media -Recurse -Filter 'Windows*' | ForEach-Object { $_.FullName }
      foreach ($sound in $win10sounds) {
      
        Copy-Item -Path $sound -Destination $soundFolder -Force
      
      }
      
      
      $path = Search-Directory '*win11sounds'
    
      $command = @"
`$sounds = Get-ChildItem -Path $path -Recurse -Force | ForEach-Object { `$_.FullName }
foreach(`$sound in `$sounds){Move-item `$sound -destination C:\Windows\Media -force}
"@
      RunAsTI powershell "-noexit -command $command"
      
      
      
      
    }
      
    if ($checkbox33.Checked) {
      
      Reg.exe add 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}' /ve /t REG_SZ /d ' ' /f
      
    }
      
   
    if ($checkbox34.Checked) {
      $folder = Search-Directory '*UltimateContextMenu'
      if ($folder -ne 'C:\UltimateContextMenu') {
        Move-item $folder -Destination 'C:\' -Force
      }
      $path = 'C:\UltimateContextMenu\TakeOwnContext.reg'
      Start-Process -filepath "$env:windir\regedit.exe" -Argumentlist @('/s', $path)

    }

    if ($checkbox35.Checked) {
      Reg.exe delete 'HKCR\*\shell\pintohomefile' /f

    }

    if ($checkbox36.Checked) {
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
      Reg.exe delete 'HKCR\*\shellex\ContextMenuHandlers\Sharing' /f
      Reg.exe delete 'HKCR\Directory\Background\shellex\ContextMenuHandlers\Sharing' /f
      Reg.exe delete 'HKCR\Directory\shellex\ContextMenuHandlers\Sharing' /f
      Reg.exe delete 'HKCR\Drive\shellex\ContextMenuHandlers\Sharing' /f
      Reg.exe delete 'HKCR\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing' /f
      Reg.exe delete 'HKCR\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing' /f
    }

    if ($checkbox38.Checked) {
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{9F156763-7844-4DC4-B2B1-901F640F5155}' /t REG_SZ /d `"`" /f
    }

    if ($checkbox39.Checked) {
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
      Reg.exe delete 'HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\SendTo' /f
      Reg.exe delete 'HKCR\UserLibraryFolder\shellex\ContextMenuHandlers\SendTo' /f
    }

    if ($checkbox42.Checked) {
      Reg.exe delete 'HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing' /f
    }

    if ($checkbox43.Checked) {
      $command = "Remove-Item -Path 'registry::HKCR\DesktopBackground\Shell\Personalize' -Recurse -Force"
      RunAsTI powershell "-nologo -windowstyle hidden -command $command"
      Start-Sleep 2
    }

    if ($checkbox44.Checked) {
      $command = "Remove-Item -Path 'registry::HKCR\DesktopBackground\Shell\Display' -Recurse -Force"
      RunAsTI powershell "-nologo -windowstyle hidden -command $command"
      Start-Sleep 2
    }

    if ($checkbox45.Checked) {
      Write-Host 'Defering Feature Updates for 365 days(MAX)'
      Write-Host 'Defering Optional Updates for 30 days(MAX)'
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetAllowOptionalContent' /t REG_DWORD /d '0' /f >$null
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdates' /t REG_DWORD /d '1' /f >$null
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdatesPeriodInDays' /t REG_DWORD /d '365' /f >$null
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdates' /t REG_DWORD /d '1' /f >$null
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /t REG_DWORD /d '30' /f >$null
      Write-Host 'Updating Policy...'
      gpupdate /force
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
    $msgBoxInput = 'Yes'
  }
  else {
    [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Remove Scheduled Tasks?', 'zoicware', 'YesNo', 'Question')
  }
      
      
  switch ($msgBoxInput) {
      
    'Yes' {
        
      if (!($Autorun)) {
        update-config -setting 'scheduledTasks' -value 1
      }
    
      Write-Host 'Removing Scheduled Tasks...'
      #removes all schd tasks 
      $tasks = Get-ScheduledTask -TaskPath '*'
      foreach ($task in $tasks) {
        if (!($task.TaskName -eq 'SvcRestartTask' -or $task.TaskName -eq 'MsCtfMonitor')) {
          #if the task isnt ctf mon or svcrestarttask then stop it and unregister it
          Stop-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
          Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue

        }

      }
      
    }
      
    'No' {}
      
  }
      
      
      
}
Export-ModuleMember -Function remove-tasks









function Set-ConsoleOpacity {
  param(
    [ValidateRange(10, 100)]
    [int]$Opacity
  )

  # Check if pinvoke type already exists, if not import the relevant functions
  try {
    $Win32Type = [Win32.WindowLayer]
  }
  catch {
    $Win32Type = Add-Type -MemberDefinition @'
            [DllImport("user32.dll")]
            public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

            [DllImport("user32.dll")]
            public static extern int GetWindowLong(IntPtr hWnd, int nIndex);

            [DllImport("user32.dll")]
            public static extern bool SetLayeredWindowAttributes(IntPtr hwnd, uint crKey, byte bAlpha, uint dwFlags);
'@ -Name WindowLayer -Namespace Win32 -PassThru
  }

  # Calculate opacity value (0-255)
  $OpacityValue = [int]($Opacity * 2.56) - 1

  # Grab the host windows handle
  $ThisProcess = Get-Process -Id $PID
  $WindowHandle = $ThisProcess.MainWindowHandle

  # "Constants"
  $GwlExStyle = -20;
  $WsExLayered = 0x80000;
  $LwaAlpha = 0x2;

  if ($Win32Type::GetWindowLong($WindowHandle, -20) -band $WsExLayered -ne $WsExLayered) {
    # If Window isn't already marked "Layered", make it so
    [void]$Win32Type::SetWindowLong($WindowHandle, $GwlExStyle, $Win32Type::GetWindowLong($WindowHandle, $GwlExStyle) -bxor $WsExLayered)
  }

  # Set transparency
  [void]$Win32Type::SetLayeredWindowAttributes($WindowHandle, 0, $OpacityValue, $LwaAlpha)
}
Export-ModuleMember -Function Set-ConsoleOpacity






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
    , [Parameter(mandatory = $false)] [bool]$win10taskbar = $false
    , [Parameter(mandatory = $false)] [bool]$win10explorer = $false
    , [Parameter(mandatory = $false)] [bool]$servicesManual = $false
    , [Parameter(mandatory = $false)] [bool]$showTrayIcons = $false
    , [Parameter(mandatory = $false)] [bool]$enableOpenShell = $false 
    , [Parameter(mandatory = $false)] [bool]$win10Recycle = $false
    , [Parameter(mandatory = $false)] [bool]$disableBell = $false
    , [Parameter(mandatory = $false)] [bool]$win10Snipping = $false
  )
      
   
      
  $checkbox2 = new-object System.Windows.Forms.checkbox
  $checkbox4 = new-object System.Windows.Forms.checkbox
  $checkbox6 = new-object System.Windows.Forms.checkbox
  $checkbox3 = new-object System.Windows.Forms.checkbox
  $checkbox5 = new-object System.Windows.Forms.checkbox
  $checkbox7 = new-object System.Windows.Forms.checkbox
  $checkbox9 = new-object System.Windows.Forms.checkbox
  $checkbox11 = new-object System.Windows.Forms.checkbox
  $checkbox13 = new-object System.Windows.Forms.checkbox
      
  $settings = @{}
    
  $settings['removeEdges'] = $checkbox2
  $settings['win10TaskbarStartmenu'] = $checkbox4
  $settings['win10Explorer'] = $checkbox6
  $settings['servicesManual'] = $checkbox3
  $settings['showTrayIcons'] = $checkbox5
  $settings['enableOpenShell'] = $checkbox7 
  $settings['win10Recycle'] = $checkbox9
  $settings['disableBell'] = $checkbox11
  $settings['win10Snipping'] = $checkbox13
      
  if ($Autorun) {
    $result = [System.Windows.Forms.DialogResult]::OK
    $checkbox2.Checked = $removeEdges
    $checkbox4.Checked = $win10taskbar
    $checkbox6.Checked = $win10explorer
    $checkbox3.Checked = $servicesManual
    $checkbox5.Checked = $showTrayIcons
    $checkbox7.Checked = $enableOpenShell
    $checkbox9.Checked = $win10Recycle
    $checkbox11.Checked = $disableBell
    $checkbox13.Checked = $win10Snipping
  }
  else {
      
    # Load the necessary assemblies for Windows Forms
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [System.Windows.Forms.Application]::EnableVisualStyles()
      
    # Create a form
    $form = New-Object Windows.Forms.Form
    $form.Text = 'Windows 11 Tweaks'
    $form.Size = New-Object Drawing.Size(450, 450)
    $form.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
      
    $label1 = New-Object System.Windows.Forms.Label
    $label1.Location = New-Object System.Drawing.Point(10, 10)
    $label1.Size = New-Object System.Drawing.Size(200, 20)
    $label1.Text = 'Patch Explorer:'
    $label1.ForeColor = 'White'
    $label1.Font = New-Object System.Drawing.Font('Segoe UI', 13)  
    $form.Controls.Add($label1)
      
    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(10, 150)  
    $label2.Size = New-Object System.Drawing.Size(200, 20)
    $label2.Text = 'Misc:'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font('Segoe UI', 13)  
    $form.Controls.Add($label2)
      
    #explorer patcher options
       
    $checkbox2.Location = new-object System.Drawing.Size(20, 40)
    $checkbox2.Size = new-object System.Drawing.Size(200, 30)
    $checkbox2.Text = 'Remove Rounded Edges'
    $checkbox2.ForeColor = 'White'
    $checkbox2.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox2.Checked = $false
    $Form.Controls.Add($checkbox2) 
       
       
    $checkbox4.Location = new-object System.Drawing.Size(20, 70)
    $checkbox4.Size = new-object System.Drawing.Size(300, 30)
    $checkbox4.Text = 'Enable Windows 10 TaskBar and StartMenu'
    $checkbox4.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox4.ForeColor = 'White'
    $checkbox4.Checked = $false
    $Form.Controls.Add($checkbox4)
       
       
    $checkbox6.Location = new-object System.Drawing.Size(20, 100)
    $checkbox6.Size = new-object System.Drawing.Size(300, 30)
    $checkbox6.Text = 'Enable Windows 10 File Explorer'
    $checkbox6.ForeColor = 'White'
    $checkbox6.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox6.Checked = $false
    $Form.Controls.Add($checkbox6)   
       
      
    #misc options
      
    $checkbox3.Location = new-object System.Drawing.Size(20, 180)
    $checkbox3.Size = new-object System.Drawing.Size(200, 30)
    $checkbox3.Text = 'Set all Services to Manual'
    $checkbox3.ForeColor = 'White'
    $checkbox3.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox3.Checked = $false
    $Form.Controls.Add($checkbox3) 
    
    $checkbox5.Location = new-object System.Drawing.Size(20, 210)
    $checkbox5.Size = new-object System.Drawing.Size(200, 30)
    $checkbox5.Text = 'Show all Taskbar Tray Icons'
    $checkbox5.ForeColor = 'White'
    $checkbox5.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox5.Checked = $false
    $Form.Controls.Add($checkbox5)
    
    $checkbox7.Location = new-object System.Drawing.Size(20, 240)
    $checkbox7.Size = new-object System.Drawing.Size(300, 30)
    $checkbox7.Text = 'Replace Start Menu and Search with OpenShell'
    $checkbox7.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox7.ForeColor = 'White'
    $checkbox7.Checked = $false
    $Form.Controls.Add($checkbox7) 

    $checkbox9.Location = new-object System.Drawing.Size(20, 270)
    $checkbox9.Size = new-object System.Drawing.Size(300, 30)
    $checkbox9.Text = 'Restore Windows 10 Recycle Bin Icon'
    $checkbox9.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox9.ForeColor = 'White'
    $checkbox9.Checked = $false
    $Form.Controls.Add($checkbox9) 

    $checkbox11.Location = new-object System.Drawing.Size(20, 300)
    $checkbox11.Size = new-object System.Drawing.Size(300, 30)
    $checkbox11.Text = 'Disable Bell Icon on Taskbar'
    $checkbox11.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox11.ForeColor = 'White'
    $checkbox11.Checked = $false
    $Form.Controls.Add($checkbox11) 

    $checkbox13.Location = new-object System.Drawing.Size(20, 330)
    $checkbox13.Size = new-object System.Drawing.Size(300, 30)
    $checkbox13.Text = 'Restore Windows 10 Snipping Tool'
    $checkbox13.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $checkbox13.ForeColor = 'White'
    $checkbox13.Checked = $false
    $Form.Controls.Add($checkbox13) 
    
    
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(120, 380)
    $OKButton.Size = New-Object System.Drawing.Size(100, 23)
    $OKButton.Text = 'OK'
    $OKButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $OKButton.ForeColor = [System.Drawing.Color]::White
    $OKButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $OKButton.FlatAppearance.BorderSize = 0
    $OKButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $OKButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)
      
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(210, 380)
    $CancelButton.Size = New-Object System.Drawing.Size(100, 23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $CancelButton.ForeColor = [System.Drawing.Color]::White
    $CancelButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $CancelButton.FlatAppearance.BorderSize = 0
    $CancelButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $CancelButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)
      
      
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
      #install explorer patcher
      if (!(Test-Path -Path 'C:\Program Files\ExplorerPatcher\ep_setup.exe' -ErrorAction SilentlyContinue)) {
        $path = Search-File '*ep_setup.zip'
        #extract explorer patcher setup and exclude it from defender
        Add-MpPreference -ExclusionPath 'C:\ep_setup.exe' -Force 
        Set-MpPreference -ExclusionPath 'C:\ep_setup.exe' -DisableRealtimeMonitoring $true -Force
        Expand-Archive -Path $path -DestinationPath 'C:\' -Force
        Start-Process 'C:\ep_setup.exe' -WindowStyle Hidden -Wait 
        Remove-Item -Path 'C:\ep_setup.exe' -Force
        #disable notis
        Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Windows.Explorer' /v 'Enabled' /t REG_DWORD /d '0' /f
      }
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Start_ShowClassicMode' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'TaskbarAl' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKCU\Software\ExplorerPatcher' /v 'TaskbarGlomLevel' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKCU\Software\ExplorerPatcher' /v 'MMTaskbarGlomLevel' /t REG_DWORD /d '0' /f
      Reg.exe add 'HKCU\Software\ExplorerPatcher' /v 'HideControlCenterButton' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableNotificationCenter' /t REG_DWORD /d '1' /f
    }
      
      
    if ($checkbox6.Checked) {
      #check if explorer patcher is installed
      if (!(Test-Path -Path 'C:\Program Files\ExplorerPatcher\ep_setup.exe' -ErrorAction SilentlyContinue)) {
        $path = Search-File '*ep_setup.zip'
        #extract explorer patcher setup and exclude it from defender
        Add-MpPreference -ExclusionPath 'C:\ep_setup.exe' -Force 
        Set-MpPreference -ExclusionPath 'C:\ep_setup.exe' -DisableRealtimeMonitoring $true -Force
        Expand-Archive -Path $path -DestinationPath 'C:\' -Force
        Start-Process 'C:\ep_setup.exe' -WindowStyle Hidden -Wait 
        Remove-Item -Path 'C:\ep_setup.exe' -Force
        #disable notis
        Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.Windows.Explorer' /v 'Enabled' /t REG_DWORD /d '0' /f
      }
      #windows 10 file explorer config
      $path = Search-File '*ExplorerPatcher10.reg'
      Move-Item $path -Destination "$env:USERPROFILE\Desktop" -Force
      
      [System.Windows.Forms.MessageBox]::Show('Config Exported to Desktop...Import Under "About".', 'Explorer Patcher')
      Start-Process 'C:\Windows\System32\rundll32.exe' -ArgumentList '"C:\Program Files\ExplorerPatcher\ep_gui.dll",ZZGUI' -Wait   
    }
      
      
      
      
      
      
    if ($checkbox3.Checked) {
      #set all services to manual (that are allowed)
      $services = Get-Service
      $servicesKeep = 'AudioEndpointBuilder
      Audiosrv
      EventLog
      SysMain
      Themes
      WSearch
      NVDisplay.ContainerLocalSystem
      WlanSvc'
      foreach ($service in $services) { 
        if ($service.StartType -like '*Auto*') {
          if (!($servicesKeep -match $service.Name)) {
              
            Set-Service -Name $service.Name -StartupType Manual -ErrorAction SilentlyContinue
             
          }         
        }
      }
      Write-Host 'Services Set to Manual...'
    }
    
    
    
    if ($checkbox5.Checked) {
      #show all current tray icons
      Write-Host 'Showing All Apps on Taskbar'
      Reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer' /v 'EnableAutoTray' /t REG_DWORD /d '0' /f
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
      <Command>PowerShell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\UpdateTaskTrayIcons.ps1</Arguments>
    </Exec>
  </Actions>
</Task>
"@
      Set-Content -Path "$env:TEMP\UpdateTaskTray" -Value $content -Force

      schtasks /Create /XML "$env:TEMP\UpdateTaskTray" /TN '\UpdateTaskTray' /F | Out-Null 

      Remove-Item -Path "$env:TEMP\UpdateTaskTray" -Force -ErrorAction SilentlyContinue
      Write-Host 'Update Task Tray Created...New Apps Will Be Shown Upon Restarting'
    }
    
    
    if ($checkbox7.Checked) {
      #install openshell startmenu only
      $setup = Search-File '*OpenShellSetup.exe'
      Start-Process $setup -ArgumentList '/qn ADDLOCAL=StartMenu'
    
      Write-Host 'Disabling Windows Indexing...'
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
      Write-Host 'Moving Shortcuts...'
      if (!(Test-Path "$env:USERPROFILE\AppData\Roaming\OpenShell\Pinned")) {
        $var = New-Item -Path "$env:USERPROFILE\AppData\Roaming\OpenShell\Pinned" -ItemType Directory -Force

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
      Write-Host 'Explorer Restarting to Apply Changes...'
      Stop-Process -name 'sihost' -force

      Remove-Item -Path 'C:\OpenShellSettings.reg' -Force -ErrorAction SilentlyContinue

    }
    
    
    if ($checkbox9.Checked) {

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
      Write-Host 'WARNING: This tweak will break the calendar flyout' -ForegroundColor Red
      Reg.exe add 'HKCU\Software\Policies\Microsoft\Windows\Explorer' /v 'DisableNotificationCenter' /t REG_DWORD /d '1' /f
      Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableNotificationCenter' /t REG_DWORD /d '1' /f
    }

    if ($checkbox13.Checked) {
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


  }
      
           
}
Export-ModuleMember -Function W11Tweaks  
      
  
function install-key {

  #check for internet connection
  try {
    Invoke-WebRequest -Uri 'https://www.google.com' -Method Head -DisableKeepAlive -UseBasicParsing | Out-Null

    Write-Host 'Activating Windows with Generic Pro Key via KMS...'
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
  catch [System.Net.WebException] {
    Write-Host 'This tweak requires Internet Connection...'
  }

    
}  
Export-ModuleMember -Function install-key 


function UltimateCleanup {
  [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
  $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Do You Want to Clear All Event Viewer Logs?', 'zoicware', 'YesNo', 'Question')

  switch ($msgBoxInput) {
    'Yes' {  
      #clear event viewer logs
      Write-Host 'Clearing Event Viewer Logs...'
      wevtutil el | Foreach-Object { wevtutil cl "$_" >$null 2>&1 }   
    }
    'No' { }
  }
  #cleanup temp files
  $temp1 = 'C:\Windows\Temp'
  $temp2 = $env:TEMP
  Write-Host "Cleaning Temp Files in $temp1 , $temp2"
  $tempFiles = (Get-ChildItem -Path $temp1 , $temp2 -Recurse -Force).FullName
  foreach ($file in $tempFiles) {
    Remove-Item -Path $file -Recurse -Force -ErrorAction SilentlyContinue
  }
  Write-Host 'Running Disk Cleanup...'
  $key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
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
    reg.exe add "$key\$option" /v StateFlags0069 /t REG_DWORD /d 00000002 /f >$nul 2>&1
  }
  #nice
  Start-Process cleanmgr.exe -ArgumentList '/sagerun:69 /autoclean' 
  
}
Export-ModuleMember -Function UltimateCleanup



#run powershell as trusted installer credit : https://github.com/AveYo/LeanAndMean
#added -wait to prevent script from continuing too fast
function RunAsTI($cmd, $arg) {
  $id = 'RunAsTI'; $key = "Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code = @'
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
'@; $V = ''; 'cmd', 'arg', 'id', 'key' | ForEach-Object { $V += "`n`$$_='$($(Get-Variable $_ -val)-replace"'","''")';" }; Set-ItemProperty $key $id $($V, $code) -type 7 -force -ea 0
  Start-Process powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas -Wait
} # lean & mean snippet by AveYo, 2022.01.28
Export-ModuleMember -Function RunAsTI





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
      