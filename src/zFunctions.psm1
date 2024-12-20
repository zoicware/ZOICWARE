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
    catch {
      #remote desktop not found
      Write-Status -Message 'Remote Desktop Not Found' -Type Error
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
            Remove-WindowsPackage -Online -PackageName $package -NoRestart -ErrorAction Stop *>$null
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
    $form.Size = New-Object System.Drawing.Size(670, 580)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)

    $url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#debloat'
    $infobutton = New-Object Windows.Forms.Button
    $infobutton.Location = New-Object Drawing.Point(620, 0)
    $infobutton.Size = New-Object Drawing.Size(30, 27)
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
    $form.Controls.Add($infobutton)

  
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
      if ($customCheckedListBox.CheckedItems.Count -eq 0) { Write-Host 'No Packages Selected' }
      else {
        foreach ($package in $customCheckedListBox.CheckedItems.GetEnumerator()) {
          Write-Status -Message "Trying to remove $package" -Type Output
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
        Get-Packages -showLockedPackages $false
      }
    }


    $removeAppx = New-Object System.Windows.Forms.Button
    $removeAppx.Location = New-Object System.Drawing.Point(510, 465)
    $removeAppx.Size = New-Object System.Drawing.Size(120, 35)
    $removeAppx.Text = 'Remove Appx Packages'
    $removeAppx.Font = New-Object System.Drawing.Font($dmMonoFont, 9) 
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
      if ($customCheckedListBox.CheckedItems.Count -eq 0) { Write-Host 'No Locked Packages Selected' }
      else {
        $selectedLockedPackages = @()
        foreach ($package in $customCheckedListBox.CheckedItems.GetEnumerator()) {
          $selectedLockedPackages += $package
        }

        $provisioned = get-appxprovisionedpackage -online 
        $appxpackage = get-appxpackage -allusers
        $eol = @()
        $store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
        $users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }

        #uninstall packages
        foreach ($choice in $selectedLockedPackages) {
          Write-Status -Message "Trying to remove $choice" -Type Output
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
      Get-Packages -showLockedPackages $true
    }
    
    $removeLocked = New-Object System.Windows.Forms.Button
    $removeLocked.Location = New-Object System.Drawing.Point(270, 465)
    $removeLocked.Size = New-Object System.Drawing.Size(120, 35)
    $removeLocked.Text = 'Remove Locked Packages'
    $removeLocked.Font = New-Object System.Drawing.Font($dmMonoFont, 9) 
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
    $checkAll.Location = New-Object System.Drawing.Point(555, 28)
    $checkAll.Size = New-Object System.Drawing.Size(90, 21)
    $checkAll.Text = 'Check All'
    $checkALL.ForeColor = 'White'
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
    $label2.Location = New-Object System.Drawing.Point(269, 10)
    $label2.Size = New-Object System.Drawing.Size(280, 20)
    $label2.Text = 'Installed Appx Packages:'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font($dmMonoFont, 10) 
    $form.Controls.Add($label2)

    $label3 = New-Object System.Windows.Forms.Label
    $label3.Location = New-Object System.Drawing.Point(10, 230)
    $label3.Size = New-Object System.Drawing.Size(200, 20)
    $label3.Text = 'Custom Debloat:'
    $label3.ForeColor = 'White'
    $label3.Font = New-Object System.Drawing.Font($dmMonoFont, 10) 
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
    $checkbox3.Size = new-object System.Drawing.Size(190, 20)
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




    function Get-Packages {
      param (
        [bool]$showLockedPackages
      )

      # Clear the logos hashtable and the checked list box items
      $Global:logos.Clear()
      $customCheckedListBox.Items.Clear()

      $packageNames = (Get-AppxPackage -AllUsers).name
      #remove dups
      $Global:sortedPackages = $packageNames | Sort-Object | Get-Unique

      if ($showLockedPackages) {
        $Global:BloatwareLocked = @()
        foreach ($package in $sortedPackages) {
          $isProhibited = $prohibitedPackages | Where-Object { $package -like $_ }
          if ($package -in $lockedAppxPackages -and !$isProhibited) {
            if ($package -eq 'E2A4F912-2574-4A75-9BB0-0D023378592B') {
              $package = 'Microsoft.Windows.AppResolverUX'
            }
            elseif ($package -eq 'F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE') {
              $package = 'Microsoft.Windows.AppSuggestedFoldersToLibraryDialog'
            }
            $Global:BloatwareLocked += $package
          }
        }

        # Populate logos for locked packages
        foreach ($packageName in $Global:BloatwareLocked) {
          Add-LogoForPackage -packageName $packageName
        }

      }
      else {
        $Global:Bloatware = @()
        foreach ($package in $sortedPackages) {
          $isProhibited = $prohibitedPackages | Where-Object { $package -like $_ }
          if ($package -notin $lockedAppxPackages -and !$isProhibited) {
            $Global:Bloatware += $package
          }
        }

        # Populate logos for regular packages
        foreach ($packageName in $Global:Bloatware) {
          Add-LogoForPackage -packageName $packageName
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
        [string]$packageName
      )

      $systemApps = 'C:\Windows\SystemApps'
      $windowsApps = 'C:\Program Files\WindowsApps'
     
      $sysAppFolders = (Get-ChildItem -Path $systemApps -Directory).FullName
      foreach ($folder in $sysAppFolders) {
        if ($folder -like "*$packageName*") {
          if (Test-Path "$folder\Assets" -PathType Container) {
            #specfic logos
            if ($packageName -like 'Microsoft.AAD.BrokerPlugin') {
              $logos.Add($packageName, "$folder\Assets\PasswordExpiry.contrast-black_scale-100.png")
            }
            elseif ($packageName -like 'Microsoft.Windows.CallingShellApp') {
              $logos.Add($packageName, "$folder\Assets\square44x44logo.scale-100.png")
            }
            elseif ($packageName -like 'Microsoft.Windows.AssignedAccessLockApp') {
              try { $Global:logos.Add($packageName, $noLogoPath) }catch {}
                    
            }
            elseif ($packageName -like 'Microsoft.LockApp') {
              try { $Global:logos.Add($packageName, $noLogoPath) }catch {}
    
            }
            elseif ($packageName -like 'Microsoft.XboxGameCallableUI') {
              $logos.Add($packageName, "$folder\Assets\SmallLogo.scale-100.png")
            }
            else {
              #get generic logo
              $logo = (Get-ChildItem -Path "$folder\Assets\*.scale-100.png" | Select-Object -First 1).FullName
              if ($logo) {
                try { $Global:logos.Add($packageName, $logo) }catch {}
              }
            }
            
          }
        }
      }

      $winAppFolders = (Get-ChildItem -Path $windowsApps -Directory).FullName
      foreach ($folder in $winAppFolders) {
        if ($folder -like "*$packageName*") {
          if (Test-Path "$folder\Assets" -PathType Container) {
            if ($packageName -like '*Microsoft.549981C3F5F10*') {
              #cortana
              if (Test-Path "$folder\Assets\Store" -PathType Container) {
                $logo = (Get-ChildItem -Path "$folder\Assets\Store\*.scale-100.png" | Select-Object -First 1).FullName
                try { $Global:logos.Add($packageName, $logo) }catch {}
              }

            }
            elseif ($packageName -like '*MicrosoftStickyNotes*') {
              if (Test-Path "$folder\Assets\Icons" -PathType Container) {
                $logo = (Get-ChildItem -Path "$folder\Assets\Icons\*.scale-100.png" | Select-Object -First 1).FullName
                if ($logo) {
                  try { $Global:logos.Add($packageName, $logo) }catch {}
                }
                
              }
            }
            elseif ($packageName -like '*MicrosoftSolitaireCollection*') {
              if (Test-Path "$folder\Win10" -PathType Container) {
                $logo = (Get-ChildItem -Path "$folder\Assets\Icons\*.scale-100.png" | Select-Object -First 1).FullName
                if ($logo) {
                  try { $Global:logos.Add($packageName, $logo) }catch {}
                }
                
              }
            }
            elseif ($packageName -like '*Microsoft.Windows.Photos*') {
              if (Test-Path "$folder\Assets\Retail" -PathType Container) {
                $logo = (Get-ChildItem -Path "$folder\Assets\Retail\*.scale-100.png" | Select-Object -First 1).FullName
                if ($logo) {
                  try { $Global:logos.Add($packageName, $logo) }catch {}
                }
                
              }
            }
            else {
              $logo = (Get-ChildItem -Path "$folder\Assets\*.scale-100.png" | Select-Object -First 1).FullName
              if ($logo) {
                try { $Global:logos.Add($packageName, $logo) }catch {}
              }
              else {
                if (Test-Path "$folder\Assets\AppTiles" -PathType Container) {
                  $logo = (Get-ChildItem -Path "$folder\Assets\AppTiles\*.scale-100.png" | Select-Object -First 1).FullName
                  if ($logo) {
                    try { $Global:logos.Add($packageName, $logo) }catch {}
                  }
                }
              
              }
            }
            
          }
          elseif (Test-Path "$folder\Images" -PathType Container) {
            $logo = (Get-ChildItem -Path "$folder\Images\*.scale-100.png" | Select-Object -First 1).FullName
            if ($logo) {
              try { $Global:logos.Add($packageName, $logo) }catch {}
            }
          }
                    
        }
      }
      if (-not $Global:logos.ContainsKey($packageName)) {
        $Global:logos.Add($packageName, $noLogoPath) 
      }
    }
    


        
    $showLockedPackages = New-Object System.Windows.Forms.CheckBox
    $showLockedPackages.Location = new-object System.Drawing.Size(15, 255)
    $showLockedPackages.Size = new-object System.Drawing.Size(200, 20)
    $showLockedPackages.Text = 'Show Locked Packages'
    $showLockedPackages.ForeColor = 'White'
    $showLockedPackages.Checked = $false
    $showLockedPackages.Add_CheckedChanged({ Get-Packages -showLockedPackages $showLockedPackages.Checked })
    $Form.Controls.Add($showLockedPackages)

    $extraEdge = New-Object System.Windows.Forms.CheckBox
    $extraEdge.Location = new-object System.Drawing.Size(15, 25)
    $extraEdge.Size = new-object System.Drawing.Size(115, 20)
    $extraEdge.Text = 'Microsoft Edge'
    $extraEdge.ForeColor = 'White'
    $extraEdge.Checked = $false
    $groupBox2.Controls.Add($extraEdge)

    $extraWebview = New-Object System.Windows.Forms.CheckBox
    $extraWebview.Location = new-object System.Drawing.Size(130, 25)
    $extraWebview.Size = new-object System.Drawing.Size(108, 20)
    $extraWebview.Text = 'Edge WebView'
    $extraWebview.ForeColor = 'White'
    $extraWebview.Checked = $false
    $groupBox2.Controls.Add($extraWebview)

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


       
    #GLOBAL VARS
    $Global:logos = [System.Collections.Hashtable]::new()
    # $Global:Bloatware = @()
    $customCheckedListBox = [CustomCheckedListBox]::new()
    $Global:noLogoPath = Search-File '*1X1.png'
    $Global:sortedPackages = @()

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
      'MicrosoftWindows.LKG*'
      'MicrosoftWindows.Client.LKG'
      'MicrosoftWindows.Client.Photon'
      'MicrosoftWindows.Client.AIX'
      'MicrosoftWindows.Client.OOBE'
    )

        
    $customCheckedListBox.Location = New-Object System.Drawing.Point(270, 50)
    $customCheckedListBox.Size = New-Object System.Drawing.Size(360, 415)
    $customCheckedListBox.BackColor = 'Black'
    $customCheckedListBox.ForeColor = 'White'
    $customCheckedListBox.CheckOnClick = $true
    $form.Controls.Add($customCheckedListBox)
    Get-Packages -showLockedPackages $false
    [CustomCheckedListBox]::logos = $Global:logos

    # $customCheckedListBox = New-Object System.Windows.Forms.CheckedListBox
    # $customCheckedListBox.Location = New-Object System.Drawing.Point(270, 50)
    # $customCheckedListBox.Size = New-Object System.Drawing.Size(270, 415)
    # $customCheckedListBox.BackColor = 'Black'
    # $customCheckedListBox.ForeColor = 'White'
    # $customCheckedListBox.ScrollAlwaysVisible = $true
    # $Form.Controls.Add($customCheckedListBox)

    
        
    
       
    

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
      Write-Status -Message 'Removing Teams and One Drive' -Type Output
      debloat-TeamsOneDrive
      Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
      debloat-remotedesktop
      debloat-HealthUpdateTools
      Write-Status -Message 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM' -Type Output
      debloat-dism
      Write-Status -Message 'Uninstalling Edge...' -Type Output
      $edge = Search-File '*EdgeRemove.ps1'
      &$edge -Webview
      Write-Status -Message 'Cleaning Start Menu...' -Type Output
      $unpin = Search-File '*unpin.ps1'
      & $unpin
    }
    if ($checkbox3.Checked) {
     
      
      debloatPreset -choice 'debloatKeepStore'
      Write-Status -Message 'Removing Teams and One Drive' -Type Output
      debloat-TeamsOneDrive
      debloat-HealthUpdateTools
      Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
      debloat-remotedesktop
      Write-Status -Message 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM' -Type Output
      debloat-dism
      Write-Status -Message 'Cleaning Start Menu...' -Type Output
      $unpin = Search-File '*unpin.ps1'
      & $unpin
  
    }
    if ($checkbox4.Checked) {
  
     
      debloatPreset -choice 'debloatKeepStoreXbox'
      Write-Status -Message 'Removing Teams and One Drive' -Type Output
      debloat-TeamsOneDrive
      debloat-HealthUpdateTools
      Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
      debloat-remotedesktop
      Write-Status -Message 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM' -Type Output
      debloat-dism
      Write-Status -Message 'Uninstalling Edge...' -Type Output
      $edge = Search-File '*EdgeRemove.ps1'
      &$edge
      Write-Status -Message 'Cleaning Start Menu...' -Type Output
      $unpin = Search-File '*unpin.ps1'
      & $unpin     
      
    }
    if ($checkbox5.Checked) {
      debloatPreset -choice 'debloatAll'
      Write-Status -Message 'Removing Teams and One Drive' -Type Output
      debloat-TeamsOneDrive
      Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
      debloat-remotedesktop
      debloat-HealthUpdateTools
      Write-Status -Message 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM' -Type Output
      debloat-dism

      Write-Status -Message 'Cleaning Start Menu...' -Type Output
      $unpin = Search-File '*unpin.ps1'
      & $unpin
  
    }
    if ($checkbox6.Checked) { 
    
     
      debloatPreset -choice 'debloatKeepStore'
      Write-Status -Message 'Removing Teams and One Drive' -Type Output
      debloat-TeamsOneDrive
      debloat-HealthUpdateTools
      Write-Status -Message 'Removing Remote Desktop Connection' -Type Output
      debloat-remotedesktop
      Write-Status -Message 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM' -Type Output
      debloat-dism
  
      Write-Status -Message 'Uninstalling Edge...' -Type Output
      $edge = Search-File '*EdgeRemove.ps1'
      &$edge
      Write-Status -Message 'Cleaning Start Menu...' -Type Output
      $unpin = Search-File '*unpin.ps1'
      & $unpin
  
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

    if ($extraDISM.Checked) {
      Write-Status -Message 'Trying to remove Quick Assist, Hello Face, and Steps Recorder via DISM' -Type Output
      debloat-dism
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
    $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)
    
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
Reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg add "HKLM\SYSTEM\ControlSet001\Services\webthreatdefusersvc" /v "Start" /t REG_DWORD /d "4" /f
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
  )
      
  
  $checkbox1 = New-Object System.Windows.Forms.CheckBox
  $checkbox2 = New-Object System.Windows.Forms.CheckBox
  $checkbox3 = New-Object System.Windows.Forms.CheckBox
  $checkboxALL = New-Object System.Windows.Forms.CheckBox

    
  #hashtable to loop through
  $settings = @{}
  $settings['enableUltimate'] = $checkbox1
  $settings['enableMaxOverlay'] = $checkbox2
  $settings['enableHighOverlay'] = $checkbox3
  $settings['removeallPlans'] = $checkboxALL
    
  if ($Autorun) {
    if ($importPPlan) {
      $msgBoxInput = 'OK'
    }
    $result = [System.Windows.Forms.DialogResult]::OK
    $checkbox1.Checked = $enableUltimate
    $checkbox2.Checked = $enableMaxOverlay
    $checkbox3.Checked = $enableHighOverlay
    $checkboxALL.Checked = $removeallPlans
  }
  else {
    $msgBoxInput = Custom-MsgBox -message 'Import Zoics Ultimate Performance Power Plan?' -type Question
      
      
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()
      
    # Create the form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Remove Unwanted Plans'
    $form.Size = New-Object System.Drawing.Size(450, 220)
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)
    

    # Create the label
    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Remove Current Power Plans'
    $label.Location = New-Object System.Drawing.Point(10, 0)
    $label.Size = New-Object System.Drawing.Size(200, 20)
    $label.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $label.ForeColor = 'White'
    $form.Controls.Add($label)

    # Create the CheckedListBox
    $checkedListBox = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox.Size = New-Object System.Drawing.Size(200, 100)
    $checkedListBox.BackColor = 'Black'
    $checkedListBox.ForeColor = 'White'
    $checkedListBox.CheckOnClick = $true
    $checkedListBox.Location = New-Object System.Drawing.Point(10, 20)

    $checkboxALL.Text = 'Check All'
    $checkboxALL.Location = New-Object System.Drawing.Point(10, 120)
    $checkboxALL.Size = New-Object System.Drawing.Size(100, 20)
    $checkboxALL.ForeColor = 'White'
    $form.Controls.Add($checkboxALL)

    $checkboxALL.Add_CheckedChanged({
        $total = $checkedListBox.Items.Count
        $index = 0
        if ($checkboxALL.Checked) {
          for ($index; $index -lt $total; $index++) {
            $checkedListBox.SetItemChecked($index, $true)
          }
        }
        else {
          for ($index; $index -lt $total; $index++) {
            $checkedListBox.SetItemChecked($index, $false)
          }
        }
      })

    # Add items to the CheckedListBox
    $Global:output = powercfg /l
    $powerplanNames = @()
    foreach ($line in $output) {
      if ($line -match ':') {
        $start = $line.trim().IndexOf('(') + 1
        $end = $line.trim().IndexOf(')')
        $length = $end - $start
        $powerplanNames += $line.trim().Substring($start, $length)
      }
    }

    foreach ($name in $powerplanNames) {
      [void]$checkedListBox.Items.Add($name)
    }

    # Add the CheckedListBox to the form
    $form.Controls.Add($checkedListBox)

    
    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Enable Hidden Power Plans'
    $label.Location = New-Object System.Drawing.Point(230, 0)
    $label.Size = New-Object System.Drawing.Size(250, 20)
    $label.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $label.ForeColor = 'White'
    $form.Controls.Add($label)

    # Create the checkboxes
     
    $checkbox1.Text = 'Ultimate Performance'
    $checkbox1.Location = New-Object System.Drawing.Point(230, 20)
    $checkbox1.Size = New-Object System.Drawing.Size(200, 20)
    $checkbox1.ForeColor = 'White'
    $form.Controls.Add($checkbox1)
      
      
    $checkbox2.Text = 'Max Performance Overlay'
    $checkbox2.Location = New-Object System.Drawing.Point(230, 50)
    $checkbox2.Size = New-Object System.Drawing.Size(200, 20)
    $checkbox2.ForeColor = 'White'
    $form.Controls.Add($checkbox2)
      
      
    $checkbox3.Text = 'High Performance Overlay'
    $checkbox3.Location = New-Object System.Drawing.Point(230, 80)
    $checkbox3.Size = New-Object System.Drawing.Size(200, 20)
    $checkbox3.ForeColor = 'White'
    $form.Controls.Add($checkbox3)
      
      
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(135, 140)
    $OKButton.Size = New-Object System.Drawing.Size(75, 30)
    $OKButton.Text = 'Apply'
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
    $CancelButton.Location = New-Object System.Drawing.Point(215, 140)
    $CancelButton.Size = New-Object System.Drawing.Size(75, 30)
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
      
      
      
  switch ($msgBoxInput) {
      
    'OK' {
              
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
        Custom-MsgBox -message 'Custom Power Plan Active!' -type None
      }
          
    }
      
    'Cancel' {}
      
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
    
    if ($removeallPlans -or $checkboxALL.Checked) {
      $output = powercfg /L
      $powerPlans = @()
      foreach ($line in $output) {
        # extract guid manually to avoid lang issues
        if ($line -match ':') {
          $parse = $line -split ':'
          $index = $parse[1].Trim().indexof('(')
          $guid = $parse[1].Trim().Substring(0, $index)
          $powerPlans += $guid
        }
      }
      # delete all powerplans
      foreach ($plan in $powerPlans) {
        cmd /c "powercfg /delete $plan" | Out-Null
      }
    }


    if ($checkedListBox.CheckedItems) {
      $powerPlans = @()
      foreach ($line in $output) {
        foreach ($name in $checkedListBox.CheckedItems.GetEnumerator()) {
          if ($line -like "*$name*") {
            #extract GUID
            $parse = $line -split ':'
            $index = $parse[1].Trim().indexof('(')
            $guid = $parse[1].Trim().Substring(0, $index)
            $powerPlans += $guid
          }
        }
      }
      foreach ($guid in $powerPlans) {
        cmd /c "powercfg /delete $guid" | Out-Null
      }
    }
    if ($checkbox1.Checked) {
      #duplicate ultimate performance
      powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null


      #deletes balanced, high performance, and power saver
      #powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
      #powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
      #powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a 
      
      
    }
    if ($checkbox2.Checked) {
      #duplicate max performance overlay
      powercfg -duplicatescheme ded574b5-45a0-4f42-8737-46345c09c238 | Out-Null



      #powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a
      
    }    
    if ($checkbox3.Checked) {
      #duplicate high performance overlay
      powercfg -duplicatescheme 3af9b8d9-7c97-431d-ad78-34a8bfea439f | Out-Null



      #powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
      
    }    
   
    #powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
      
       
          
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
    $form3.Size = New-Object System.Drawing.Size(690, 570)
    $form3.StartPosition = 'CenterScreen'
    $form3.BackColor = 'Black'
    $form3.Font = New-Object System.Drawing.Font($dmMonoFont, 8)

    #info button
    $url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#registry-tweaks'
    $infobutton = New-Object Windows.Forms.Button
    $infobutton.Location = New-Object Drawing.Point(670, 10)
    $infobutton.Size = New-Object Drawing.Size(30, 30)
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

    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(10, 10)
    $label2.Size = New-Object System.Drawing.Size(280, 20)
    $label2.Text = 'Select Tweaks to Remove:'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font($dmMonoFont, 10) 
    $form3.Controls.Add($label2)

    $label3 = New-Object System.Windows.Forms.Label
    $label3.Location = New-Object System.Drawing.Point(35, 35)
    $label3.Size = New-Object System.Drawing.Size(150, 20)
    $label3.Text = 'Windows 10'
    $label3.ForeColor = 'White'
    $label3.Font = New-Object System.Drawing.Font($dmMonoFont, 9) 
    $form3.Controls.Add($label3)

    $label4 = New-Object System.Windows.Forms.Label
    $label4.Location = New-Object System.Drawing.Point(350, 35)
    $label4.Size = New-Object System.Drawing.Size(150, 20)
    $label4.Text = 'Windows 11'
    $label4.ForeColor = 'White'
    $label4.Font = New-Object System.Drawing.Font($dmMonoFont, 9) 
    $form3.Controls.Add($label4)

    $checkedListBox10 = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox10.Location = New-Object System.Drawing.Point(30, 55)
    $checkedListBox10.Size = New-Object System.Drawing.Size(270, 415)
    $checkedListBox10.BackColor = 'Black'
    $checkedListBox10.ForeColor = 'White'
    $checkedListBox10.CheckOnClick = $true
    $checkedListBox10.ScrollAlwaysVisible = $true
    $Form3.Controls.Add($checkedListBox10)

    $checkedListBox11 = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox11.Location = New-Object System.Drawing.Point(345, 55)
    $checkedListBox11.Size = New-Object System.Drawing.Size(270, 415)
    $checkedListBox11.BackColor = 'Black'
    $checkedListBox11.ForeColor = 'White'
    $checkedListBox11.CheckOnClick = $true
    $checkedListBox11.ScrollAlwaysVisible = $true
    $Form3.Controls.Add($checkedListBox11)

    $r10 = Search-File '*RegistryTweaks10.txt'
    $r11 = Search-File '*RegistryTweaks11.txt'
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
    #add to reg tweaks 10
    $content = Get-Content $r10
    $Global:regOptions10 = $content -split "`n"
    foreach ($line in $regOptions10) {
      if ($line -like ';*') {
        $name = $line -split ';'
        $checkedListBox10.Items.Add($name[1].Trim(), $false) | Out-Null
      }
    }
    #add to reg tweaks 11
    $content = Get-Content $r11
    $Global:regOptions11 = $content -split "`n"
    foreach ($line in $regOptions11) {
      if ($line -like ';*') {
        $name = $line -split ';'
        $checkedListBox11.Items.Add($name[1].Trim(), $false) | Out-Null
      }
      
    }

    $default = New-Object System.Windows.Forms.Button
    $default.Location = New-Object System.Drawing.Point(195, 485)
    $default.Size = New-Object System.Drawing.Size(120, 35)
    $default.Text = 'Import All Tweaks'
    $default.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $default.ForeColor = [System.Drawing.Color]::White
    $default.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form3.Controls.Add($default)

    $custom = New-Object System.Windows.Forms.Button
    $custom.Location = New-Object System.Drawing.Point(325, 485)
    $custom.Size = New-Object System.Drawing.Size(120, 35)
    $custom.Text = 'Import Custom Tweaks'
    $custom.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $custom.ForeColor = [System.Drawing.Color]::White
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

    $result = $form3.ShowDialog() 
  }
      
      
  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    #update config
    if (!($Autorun)) {
      update-config -setting 'registryTweaks' -value 1
    }

    if (Test-Path "$env:temp\CustomTweaks.reg") {
      #custom reg tweaks selected
      $regContent = Get-Content "$env:temp\CustomTweaks.reg" -Force

      Set-Content "$env:USERPROFILE\Desktop\RegTweaks.reg" -Value $regContent -Force
    }
    else {
      $reg10 = Search-File '*RegistryTweaks10.txt'
      $regContent = Get-Content $reg10 -Force
      
      $OS = Get-CimInstance Win32_OperatingSystem
      if ($OS.Caption -like '*Windows 11*') {
        #add win 11 tweaks
        $reg11 = Search-File '*RegistryTweaks11.txt'
        $regContent += Get-Content $reg11 -Force
        #disable password expire for 11
        net accounts /maxpwage:unlimited *>$null
      }

      Set-Content "$env:USERPROFILE\Desktop\RegTweaks.reg" -Value $regContent -Force
    }

    #set gpu msi mode
    $instanceID = (Get-PnpDevice -Class Display).InstanceId
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\$instanceID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v 'MSISupported' /t REG_DWORD /d '1' /f *>$null
    Write-Status -Message 'Applying Registry Tweaks...' -Type Output
    #run tweaks
    regedit.exe /s "$env:USERPROFILE\Desktop\RegTweaks.reg"
    Start-Sleep 2
    Write-Status -Message 'Restarting Explorer...' -Type Output
    Stop-Process -name 'sihost' -force
  
    #prevent event log error from disabling uac
    Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\luafv' /v 'Start' /t REG_DWORD /d '4' /f
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
  )
        
      
      
      
  #create checkboxes
  $checkbox2 = new-object System.Windows.Forms.checkbox
  $classicblackBTN = new-object System.Windows.Forms.checkbox
  $checkbox4 = new-object System.Windows.Forms.checkbox
  $checkbox5 = new-object System.Windows.Forms.checkbox
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
  $checkbox27 = new-object System.Windows.Forms.checkbox
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

  #hashtable for updating config
  $settings = @{}
  $settings['opblackTheme'] = $checkbox2
  $settings['opclassicTheme'] = $classicblackBTN
  $settings['opROFSW'] = $checkbox4
  $settings['opremoveSpeech'] = $checkbox5
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
  $settings['opdoubleClickPS'] = $checkbox27
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
      
  if ($AutoRun) {
    $result = [System.Windows.Forms.DialogResult]::OK
    #setting options
    $checkbox2.Checked = $opblackTheme 
    $classicblackBTN.Checked = $opclassicTheme  
    $checkbox4.Checked = $opROFSW  
    $checkbox5.Checked = $opremoveSpeech
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
    $checkbox27.Checked = $opdoubleClickPS
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
    $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)

    $url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#optional-tweaks'
    $infobutton = New-Object Windows.Forms.Button
    $infobutton.Location = New-Object Drawing.Point(555, 0)
    $infobutton.Size = New-Object Drawing.Size(30, 27)
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
    $form.Controls.Add($infobutton)
            
    $TabControl = New-Object System.Windows.Forms.TabControl
    $TabControl.Location = New-Object System.Drawing.Size(10, 10)
    $TabControl.Size = New-Object System.Drawing.Size(570, 500) 
    $TabControl.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
    
        
    $TabPage1 = New-Object System.Windows.Forms.TabPage
    $TabPage1.Text = 'General'
    $TabPage1.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
        
    $TabPage2 = New-Object System.Windows.Forms.TabPage
    $TabPage2.Text = 'Ultimate Context Menu'
    $TabPage2.BackColor = [System.Drawing.Color]::FromArgb(65, 65, 65)
        
  
           
    $TabControl.Controls.Add($TabPage1)
    $TabControl.Controls.Add($TabPage2)
  
        
        
    $Form.Controls.Add($TabControl)    
           
    $label1 = New-Object System.Windows.Forms.Label
    $label1.Location = New-Object System.Drawing.Point(10, 10)
    $label1.Size = New-Object System.Drawing.Size(200, 20)
    $label1.Text = 'Add to Menu'
    $label1.ForeColor = 'White'
    $label1.Font = New-Object System.Drawing.Font($dmMonoFont, 12)  
    $form.Controls.Add($label1)
    $TabPage2.Controls.Add($label1)
    
    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(260, 10)
    $label2.Size = New-Object System.Drawing.Size(200, 20)
    $label2.Text = 'Remove From Menu'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font($dmMonoFont, 12)  
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
        
            
        
            
    $checkbox13.Location = new-object System.Drawing.Size(220, 60)
    $checkbox13.Size = new-object System.Drawing.Size(270, 30)
    $checkbox13.Text = 'Block Razer and ASUS Download Servers'
    $checkbox13.ForeColor = 'White'
    $checkbox13.Checked = $false
    $Form.Controls.Add($checkbox13)
    $TabPage1.Controls.Add($checkBox13)
        
    # CONTEXT MENU OPTIONS   
            
    $checkbox14.Location = new-object System.Drawing.Size(20, 40)
    $checkbox14.Size = new-object System.Drawing.Size(225, 20)
    $checkbox14.Text = "Additional files to `"New`" Menu"
    $checkbox14.ForeColor = 'White'
    $checkbox14.Checked = $false
    $Form.Controls.Add($checkbox14) 
    $TabPage2.Controls.Add($checkBox14)
        
            
    $checkbox15.Location = new-object System.Drawing.Size(20, 70)
    $checkbox15.Size = new-object System.Drawing.Size(190, 20)
    $checkbox15.Text = 'Additional ps1 options'
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

    $checkbox46.Location = new-object System.Drawing.Size(270, 340)
    $checkbox46.Size = new-object System.Drawing.Size(250, 30)
    $checkbox46.Text = 'Extract All for Archive Files'
    $checkbox46.ForeColor = 'White'
    $checkbox46.Checked = $false
    $Form.Controls.Add($checkbox46)
    $TabPage2.Controls.Add($checkBox46)


    $checkbox48.Location = new-object System.Drawing.Size(270, 370)
    $checkbox48.Size = new-object System.Drawing.Size(250, 30)
    $checkbox48.Text = 'Troubleshoot Compatibility'
    $checkbox48.ForeColor = 'White'
    $checkbox48.Checked = $false
    $Form.Controls.Add($checkbox48)
    $TabPage2.Controls.Add($checkBox48)


    $checkbox49.Location = new-object System.Drawing.Size(270, 400)
    $checkbox49.Size = new-object System.Drawing.Size(250, 30)
    $checkbox49.Text = 'Include in Library'
    $checkbox49.ForeColor = 'White'
    $checkbox49.Checked = $false
    $Form.Controls.Add($checkbox49)
    $TabPage2.Controls.Add($checkBox49)



            
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
        
            
  
            
    $checkbox27.Location = new-object System.Drawing.Size(10, 220)
    $checkbox27.Size = new-object System.Drawing.Size(210, 30)
    $checkbox27.Text = 'Add Double Click to Powershell Files'
    $checkbox27.ForeColor = 'White'
    $checkbox27.Checked = $false
    $Form.Controls.Add($checkbox27)
    $TabPage1.Controls.Add($checkBox27)
        
 
       
            
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
    $checkbox45.Size = new-object System.Drawing.Size(210, 30)
    $checkbox45.Text = 'Security Updates Only'
    $checkbox45.ForeColor = 'White'
    $checkbox45.Checked = $false
    $Form.Controls.Add($checkbox45)
    $TabPage1.Controls.Add($checkBox45)

    $checkbox47.Location = new-object System.Drawing.Size(220, 300)
    $checkbox47.Size = new-object System.Drawing.Size(270, 30)
    $checkbox47.Text = 'Pause Updates for 1 Year'
    $checkbox47.ForeColor = 'White'
    $checkbox47.Checked = $false
    $Form.Controls.Add($checkbox47)
    $TabPage1.Controls.Add($checkBox47)

    $checkbox50.Location = new-object System.Drawing.Size(10, 340)
    $checkbox50.Size = new-object System.Drawing.Size(270, 30)
    $checkbox50.Text = 'Prevent OS Upgrade'
    $checkbox50.ForeColor = 'White'
    $checkbox50.Checked = $false
    $Form.Controls.Add($checkbox50)
    $TabPage1.Controls.Add($checkBox50)
        
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(195, 510)
    $OKButton.Size = New-Object System.Drawing.Size(100, 23)
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
    $CancelButton.Location = New-Object System.Drawing.Point(295, 510)
    $CancelButton.Size = New-Object System.Drawing.Size(100, 23)
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
      Write-Status -Message 'Applying Black Theme...' -Type Output
     
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
    if ($checkbox5.Checked) {
      Write-Status -Message 'Removing Speech App...' -Type Output
      $command = 'Remove-item -path C:\Windows\System32\Speech -recurse -force'
      Run-Trusted -command $command
      Start-Sleep 2
    }
    
    if ($checkbox7.Checked) {
      Write-Status -Message 'Enabling HAGS...' -Type Output
      Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' /v 'HwSchMode' /t REG_DWORD /d '2' /f
      
    }
      
    if ($checkbox8.checked) {
      Write-Status -Message 'Applying Transparent Taskbar...' -Type Output
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
      if ($OS.Caption -like '*Windows 11*') {
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
      if ($OS.Caption -like '*Windows 11*') {
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
      $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)
      
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
      
      
      
      
      
    if ($checkbox27.Checked) {
      Write-Status -Message 'Enabling Double Click to Run PowerShell Scripts...' -Type Output
      #working 10 not 11
      Reg.exe add 'HKCR\Microsoft.PowerShellScript.1\Shell\Open\Command' /ve /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -noLogo -executionpolicy bypass -file `"`"%1`"`"" /f
      
    }
      
      
      
      
    if ($checkbox29.Checked) {
      Write-Status -Message 'Excluding Drivers From Windows Update...' -Type Output
   
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f
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
      Reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' /v '{1d27f844-3a1f-4410-85ac-14651078412d}' /t REG_SZ /d '' /f *>$null
    }

    if ($checkbox49.Checked) {
      Write-Status -Message 'Removing Include in Library from Context Menu...' -Type Output
      #remove include in library
      Reg.exe delete 'HKCR\Folder\ShellEx\ContextMenuHandlers\Library Location' /f *>$null
      Reg.exe delete 'HKLM\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location' /f *>$null
    }


    if($checkbox50.Checked){
      Write-Status -Message 'Preventing Windows Update from Upgrading Versions...' -Type Output
      #get current os and build
      $buildVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
      $winName = ((Get-CimInstance Win32_OperatingSystem).Caption).Substring(10,10)

      Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ProductVersion" /t REG_SZ /d $winName /f
      Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "TargetReleaseVersion" /t REG_DWORD /d "1" /f
      Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "TargetReleaseVersionInfo" /t REG_SZ /d $buildVer /f
      gpupdate /force *>$null
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
      #removes all schd tasks 
      $tasks = Get-ScheduledTask -TaskPath '*'
      $i = 0
      $barLength = 50
      foreach ($task in $tasks) {
        if (!($task.TaskName -eq 'SvcRestartTask' -or $task.TaskName -eq 'MsCtfMonitor')) {
          $i++
          #if the task isnt ctf mon or svcrestarttask then stop it and unregister it
          $PercentComplete = [math]::Round($(($i / $tasks.Count) * 100)) 
          $progress = [math]::Round(($PercentComplete / 100) * $barLength)
          $bar = '#' * $progress
          $emptySpace = ' ' * ($barLength - $progress)
          $status = "[$bar$emptySpace] $PercentComplete% Complete"

          Write-Host -NoNewline "`r$status"
          Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
          
        }

      }
      
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
  }
  else {
      
    # Load the necessary assemblies for Windows Forms
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [System.Windows.Forms.Application]::EnableVisualStyles()
      
    # Create a form
    $form = New-Object Windows.Forms.Form
    $form.Text = 'Windows 11 Tweaks'
    $form.Size = New-Object Drawing.Size(450, 620)
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)

    $url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#windows-11-tweaks'
    $infobutton = New-Object Windows.Forms.Button
    $infobutton.Location = New-Object Drawing.Point(390, 0)
    $infobutton.Size = New-Object Drawing.Size(30, 27)
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
    $form.Controls.Add($infobutton)
      
    $label1 = New-Object System.Windows.Forms.Label
    $label1.Location = New-Object System.Drawing.Point(10, 10)
    $label1.Size = New-Object System.Drawing.Size(200, 25)
    $label1.Text = 'Patch Explorer:'
    $label1.ForeColor = 'White'
    $label1.Font = New-Object System.Drawing.Font($dmMonoFont, 12)  
    $form.Controls.Add($label1)
      
    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(10, 390)  
    $label2.Size = New-Object System.Drawing.Size(200, 20)
    $label2.Text = 'Misc:'
    $label2.ForeColor = 'White'
    $label2.Font = New-Object System.Drawing.Font($dmMonoFont, 12)  
    $form.Controls.Add($label2)

    $label3 = New-Object System.Windows.Forms.Label
    $label3.Location = New-Object System.Drawing.Point(10, 200)  
    $label3.Size = New-Object System.Drawing.Size(200, 20)
    $label3.Text = 'Win 10:'
    $label3.ForeColor = 'White'
    $label3.Font = New-Object System.Drawing.Font($dmMonoFont, 12)  
    $form.Controls.Add($label3)

    $lineStartPoint = New-Object System.Drawing.Point(10, 35)
$lineEndPoint = New-Object System.Drawing.Point(300, 35)
$lineColor = [System.Drawing.Color]::Gray
$lineWidth = 1.5

$form.Add_Paint({
    $graphics = $form.CreateGraphics()
    $pen = New-Object System.Drawing.Pen($lineColor, $lineWidth)
    $graphics.DrawLine($pen, $lineStartPoint, $lineEndPoint)
    $pen.Dispose()
    $graphics.Dispose()
})

$lineStartPoint2 = New-Object System.Drawing.Point(10, 225)
$lineEndPoint2 = New-Object System.Drawing.Point(300, 225)
$lineColor2 = [System.Drawing.Color]::Gray
$lineWidth2 = 1.5

$form.Add_Paint({
    $graphics = $form.CreateGraphics()
    $pen = New-Object System.Drawing.Pen($lineColor2, $lineWidth2)
    $graphics.DrawLine($pen, $lineStartPoint2, $lineEndPoint2)
    $pen.Dispose()
    $graphics.Dispose()
})

$lineStartPoint3 = New-Object System.Drawing.Point(10, 415)
$lineEndPoint3 = New-Object System.Drawing.Point(300, 415)
$lineColor3 = [System.Drawing.Color]::Gray
$lineWidth3 = 1.5

$form.Add_Paint({
    $graphics = $form.CreateGraphics()
    $pen = New-Object System.Drawing.Pen($lineColor3, $lineWidth3)
    $graphics.DrawLine($pen, $lineStartPoint3, $lineEndPoint3)
    $pen.Dispose()
    $graphics.Dispose()
})
      
    #explorer patcher options
       
    $checkbox2.Location = new-object System.Drawing.Size(20, 40)
    $checkbox2.Size = new-object System.Drawing.Size(200, 30)
    $checkbox2.Text = 'Remove Rounded Edges'
    $checkbox2.ForeColor = 'White'
    $checkbox2.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox2.Checked = $false
    $Form.Controls.Add($checkbox2) 
       
       
    $checkbox4.Location = new-object System.Drawing.Size(20, 70)
    $checkbox4.Size = new-object System.Drawing.Size(330, 30)
    $checkbox4.Text = 'Enable Windows 10 TaskBar and StartMenu'
    $checkbox4.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox4.ForeColor = 'White'
    $checkbox4.Checked = $false
    $Form.Controls.Add($checkbox4)
       
       
    $checkbox6.Location = new-object System.Drawing.Size(20, 100)
    $checkbox6.Size = new-object System.Drawing.Size(300, 30)
    $checkbox6.Text = 'Enable Windows 10 File Explorer'
    $checkbox6.ForeColor = 'White'
    $checkbox6.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox6.Checked = $false
    $Form.Controls.Add($checkbox6)   

    $checkbox8.Location = new-object System.Drawing.Size(20, 130)
    $checkbox8.Size = new-object System.Drawing.Size(300, 30)
    $checkbox8.Text = 'Hide Startmenu Recommended'
    $checkbox8.ForeColor = 'White'
    $checkbox8.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox8.Checked = $false
    $Form.Controls.Add($checkbox8) 
       
      
    #misc options
      
    $checkbox3.Location = new-object System.Drawing.Size(20, 420)
    $checkbox3.Size = new-object System.Drawing.Size(250, 30)
    $checkbox3.Text = 'Set all Services to Manual'
    $checkbox3.ForeColor = 'White'
    $checkbox3.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox3.Checked = $false
    $Form.Controls.Add($checkbox3) 
    
    $checkbox5.Location = new-object System.Drawing.Size(20, 450)
    $checkbox5.Size = new-object System.Drawing.Size(250, 30)
    $checkbox5.Text = 'Show all Taskbar Tray Icons'
    $checkbox5.ForeColor = 'White'
    $checkbox5.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox5.Checked = $false
    $Form.Controls.Add($checkbox5)
    
    $checkbox7.Location = new-object System.Drawing.Size(20, 160)
    $checkbox7.Size = new-object System.Drawing.Size(350, 30)
    $checkbox7.Text = 'Replace Start Menu and Search with OpenShell'
    $checkbox7.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox7.ForeColor = 'White'
    $checkbox7.Checked = $false
    $Form.Controls.Add($checkbox7) 

    $checkbox9.Location = new-object System.Drawing.Size(20, 230)
    $checkbox9.Size = new-object System.Drawing.Size(300, 30)
    $checkbox9.Text = 'Restore Windows 10 Recycle Bin Icon'
    $checkbox9.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox9.ForeColor = 'White'
    $checkbox9.Checked = $false
    $Form.Controls.Add($checkbox9) 

    $checkbox11.Location = new-object System.Drawing.Size(20, 480)
    $checkbox11.Size = new-object System.Drawing.Size(300, 30)
    $checkbox11.Text = 'Disable Bell Icon on Taskbar'
    $checkbox11.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox11.ForeColor = 'White'
    $checkbox11.Checked = $false
    $Form.Controls.Add($checkbox11) 

    $checkbox13.Location = new-object System.Drawing.Size(20, 260)
    $checkbox13.Size = new-object System.Drawing.Size(300, 30)
    $checkbox13.Text = 'Restore Windows 10 Snipping Tool'
    $checkbox13.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox13.ForeColor = 'White'
    $checkbox13.Checked = $false
    $Form.Controls.Add($checkbox13) 

    $checkbox15.Location = new-object System.Drawing.Size(20, 290)
    $checkbox15.Size = new-object System.Drawing.Size(300, 30)
    $checkbox15.Text = 'Restore Windows 10 Task Manager'
    $checkbox15.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox15.ForeColor = 'White'
    $checkbox15.Checked = $false
    $Form.Controls.Add($checkbox15) 

    $checkbox17.Location = new-object System.Drawing.Size(20, 320)
    $checkbox17.Size = new-object System.Drawing.Size(300, 30)
    $checkbox17.Text = 'Restore Windows 10 Notepad'
    $checkbox17.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox17.ForeColor = 'White'
    $checkbox17.Checked = $false
    $Form.Controls.Add($checkbox17) 
    
    $checkbox19.Location = new-object System.Drawing.Size(20, 350)
    $checkbox19.Size = new-object System.Drawing.Size(300, 30)
    $checkbox19.Text = 'Restore Windows 10 Icons'
    $checkbox19.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox19.ForeColor = 'White'
    $checkbox19.Checked = $false
    $Form.Controls.Add($checkbox19) 

    $checkbox21.Location = new-object System.Drawing.Size(20, 510)
    $checkbox21.Size = new-object System.Drawing.Size(300, 30)
    $checkbox21.Text = 'Dark Winver'
    $checkbox21.Font = New-Object System.Drawing.Font($dmMonoFont, 9)
    $checkbox21.ForeColor = 'White'
    $checkbox21.Checked = $false
    $Form.Controls.Add($checkbox21) 
    
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(112, 550)
    $OKButton.Size = New-Object System.Drawing.Size(100, 27)
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
    $CancelButton.Location = New-Object System.Drawing.Point(210, 550)
    $CancelButton.Size = New-Object System.Drawing.Size(100, 27)
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
      Stop-Process -Name explorer -Force
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
      
      $win10TaskDir = Search-Directory -filter '*Win10TaskManager'
      $filesToMove = Get-ChildItem -Path $win10TaskDir -Recurse -File

      #take own of current task manager files
      $paths = @(
        'C:\Windows\System32\en-US',
        'C:\Windows\System32\Taskmgr.exe',
        'C:\Windows\SystemResources\Taskmgr.exe.mun'
      )
      foreach ($path in $paths) {
        if ((get-item $path).Mode -like '*d*') {
          takeown /f $path /r /d Y *>$null
          icacls $path /grant administrators:F /t *>$null
        }
        else {
          takeown /f $path *>$null
          icacls $path /grant administrators:F /t *>$null
        }
        
      }

      #move files
      foreach ($file in $filesToMove) {
        $path = $file.FullName
        switch -Wildcard ($path) {
          '*Taskmgr.exe.mun' {  
            $command = "Remove-item C:\Windows\SystemResources\Taskmgr.exe.mun -Force; Move-Item -Path $path -Destination 'C:\Windows\SystemResources' -Force"
            Run-Trusted -command $command
          }
          '*Taskmgr.exe' {
            Move-Item -Path $path -Destination 'C:\Windows\System32' -Force
          }
          '*Taskmgr.exe.mui' {
            Move-Item -Path $path -Destination 'C:\Windows\System32\en-US' -Force
          }
        }
      }
      
      
    }

    if ($checkbox17.Checked) {
      #uninstall uwp notepad
      Write-Status -Message 'Uninstalling UWP Notepad' -Type Output

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

      Write-Status -Message 'Installing Windows 11 21h2 Notepad' -Type Output
   
      #install 21h2 notepad
      $21h2notepad = Search-Directory -filter '*notepad21h2'
      $folders = Get-ChildItem $21h2notepad -Directory
      foreach ($folder in $folders) {
        Run-Trusted -command "Move-Item -Path $($folder.FullName) -Destination `"$env:ProgramFiles\WindowsApps`""
      }
      #add the package 
      $notepadDirs = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps" -Directory | Where-Object { $_.FullName -like '*notepad*' }
      foreach ($dir in $notepadDirs) {
        try {
          Add-AppxPackage -Register -DisableDevelopmentMode "$($dir.FullName)\AppXManifest.xml" -ErrorAction Stop
        }
        catch {
          #ignore error
        }
      
      }
      
    }

    if ($checkbox8.Checked) {
    
      #search for hiderecommended script
      $hiderec = Search-File '*HideRecommended.ps1'
      Write-Status -Message 'Hiding Startmenu Recommended Section...' -Type Output
 
      & $hiderec 
      #create task to run at startup
      #get username and sid
      $currentUserName = $env:COMPUTERNAME + '\' + $env:USERNAME
      $username = Get-LocalUser -Name $env:USERNAME | Select-Object -ExpandProperty sid

      $content = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2024-05-20T12:59:50.8741407</Date>
    <Author>$currentUserName</Author>
    <URI>\HideRecommended</URI>
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
      <Arguments>-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\ProgramData\HideRecommended.ps1</Arguments>
    </Exec>
  </Actions>
</Task>
"@
      Set-Content -Path "$env:TEMP\hiderectask" -Value $content -Force

      schtasks /Create /XML "$env:TEMP\hiderectask" /TN '\HideRecommended' /F | Out-Null 

      Remove-Item -Path "$env:TEMP\hiderectask" -Force -ErrorAction SilentlyContinue

      Copy-Item -Path $hiderec -Destination $env:ProgramData

    }

    if ($checkbox19.Checked) {
      #enable windows 10 icons
      $ogIcons = 'C:\Windows\SystemResources\imageres.dll.mun'
      Write-Status -Message 'Making Backup of C:\Windows\SystemResources\imageres.dll.mun > Desktop' -Type Output
      
      #takeownership and move win10 imageres
      takeown.exe /f 'C:\Windows\SystemResources' *>$null
      icacls.exe 'C:\Windows\SystemResources' /grant Administrators:F /T /C *>$null
      takeown.exe /f $ogIcons *>$null
      icacls.exe $ogIcons /grant Administrators:F /T /C *>$null
      Copy-item $ogIcons -Destination "$env:USERPROFILE\Desktop" -Force
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
      if(!(Test-Path "$env:USERPROFILE\zBackup")){
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

    
 

    
}  
Export-ModuleMember -Function install-key 


function UltimateCleanup {

  Add-Type -AssemblyName System.Windows.Forms
  Add-Type -AssemblyName System.Drawing
  [System.Windows.Forms.Application]::EnableVisualStyles()

  # Create the form
  $form = New-Object System.Windows.Forms.Form
  $form.Text = 'Ultimate Cleanup'
  $form.Size = New-Object System.Drawing.Size(450, 400)
  $form.StartPosition = 'CenterScreen'
  $form.BackColor = 'Black'
  $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)

  $label = New-Object System.Windows.Forms.Label
  $label.Location = New-Object System.Drawing.Point(60, 10)
  $label.Size = New-Object System.Drawing.Size(250, 25)
  $label.Text = 'Disk Cleanup Options'
  $label.ForeColor = 'White'
  $label.Font = New-Object System.Drawing.Font($dmMonoFont, 10) 
  $form.Controls.Add($label)

  # Create the CheckedListBox
  $checkedListBox = New-Object System.Windows.Forms.CheckedListBox
  $checkedListBox.Location = New-Object System.Drawing.Point(40, 60)
  $checkedListBox.Size = New-Object System.Drawing.Size(200, 300)
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
  $checkBox1.Location = New-Object System.Drawing.Point(250, 70)
  $checkBox1.ForeColor = 'White'
  $checkBox1.AutoSize = $true

  $checkBox2 = New-Object System.Windows.Forms.CheckBox
  $checkBox2.Text = 'Clear Windows Logs'
  $checkBox2.Location = New-Object System.Drawing.Point(250, 100)
  $checkBox2.ForeColor = 'White'
  $checkBox2.AutoSize = $true

  $checkBox3 = New-Object System.Windows.Forms.CheckBox
  $checkBox3.Text = 'Clear TEMP Cache'
  $checkBox3.Location = New-Object System.Drawing.Point(250, 130)
  $checkBox3.ForeColor = 'White'
  $checkBox3.AutoSize = $true

  # Create the Clean button
  $buttonClean = New-Object System.Windows.Forms.Button
  $buttonClean.Text = 'Clean'
  $buttonClean.Location = New-Object System.Drawing.Point(250, 200)
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
  $checkALL.Location = New-Object System.Drawing.Point(40, 40)
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
    if ($checkedListBox.CheckedItems) {
      $key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches'
      foreach ($item in $checkedListBox.CheckedItems) {
        reg.exe add "$key\$item" /v StateFlags0069 /t REG_DWORD /d 00000002 /f >$nul 2>&1
      }
      Write-Status -Message 'Running Disk Cleanup...' -Type Output
    
      #nice
      Start-Process cleanmgr.exe -ArgumentList '/sagerun:69 /autoclean' -Wait
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


function Add-CustomFont {

  $privateFontCollection = New-Object System.Drawing.Text.PrivateFontCollection
  #add dm mono font
  $fontFile = Search-File '*DMMono-Regular.ttf'
  $privateFontCollection.AddFontFile($fontFile)
  $Global:dmMonoFont = $privateFontCollection.Families[0]
  
  
}
Export-ModuleMember -Function Add-CustomFont   


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
  $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)

  # Add Icon
  $pictureBox = New-Object System.Windows.Forms.PictureBox
  $pictureBox.Location = New-Object System.Drawing.Point(20, 30) 
  $pictureBox.Size = New-Object System.Drawing.Size(50, 50) 
  $pictureBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
  if ($type -eq 'Warning') {
    $imagePath = 'C:\Windows\System32\SecurityAndMaintenance_Alert.png'
  }
  if ($type -eq 'Question') {
    $imagePath = Search-File '*questionIcon.png'
  }
  if ($type -eq 'None') {
    $imagePath = Search-File '*greencheckIcon.png'
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
  $label.ForeColor = [System.Drawing.Color]::White
  $form.Controls.Add($label)

  # Create the OK button
  $okButton = New-Object System.Windows.Forms.Button
  if ($type -eq 'Question') {
    $okButton.Text = 'Yes'
  }
  else {
    $okButton.Text = 'OK'
  }
  if ($type -eq 'None') {
    $okButton.Location = New-Object System.Drawing.Point(105, 110)
  }
  else {
    $okButton.Location = New-Object System.Drawing.Point(100, 120)
  }
  $okButton.BackColor = [System.Drawing.Color]::FromArgb(53, 53, 52)
  $okButton.ForeColor = [System.Drawing.Color]::White
  $oKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $form.Controls.Add($okButton)

  if (!($type -eq 'None')) {
    # Create the Cancel button
    $cancelButton = New-Object System.Windows.Forms.Button
    if ($type -eq 'Question') {
      $cancelButton.Text = 'No'
    }
    else {
      $cancelButton.Text = 'Cancel'
    }
    $cancelButton.Location = New-Object System.Drawing.Point(180, 120)
    $cancelButton.BackColor = [System.Drawing.Color]::FromArgb(53, 53, 52)
    $cancelButton.ForeColor = [System.Drawing.Color]::White
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancelButton)

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
