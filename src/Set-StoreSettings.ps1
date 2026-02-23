# modified code from https://github.com/agadiffe/WindowsMize

class UwpRegistryKeyEntry {
    [string] $Path
    [string] $Name
    [string] $Value
    [string] $Type
}

function Set-UwpAppSetting {
    <#
    .SYNOPSIS
        Sets Microsoft Store app settings by modifying the settings.dat registry hive.
    
    .EXAMPLE
        PS> Set-UwpAppSetting -Name 'MicrosoftStore' -Setting $MicrosoftStoreSettings
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateSet('MicrosoftStore')]
        [string] $Name,

        [Parameter(Mandatory)]
        [UwpRegistryKeyEntry[]] $Setting
    )

    process {
        $AppxPathName = 'Microsoft.WindowsStore_8wekyb3d8bbwe'
        $AppxPath = "$env:LOCALAPPDATA\Packages\$AppxPathName"
        $AppxSettingsFilePath = "$AppxPath\Settings\settings.dat"

        #kill locking processes
        $procs = 'WinStore.App', 'backgroundTaskHost', 'StoreDesktopExtension'
        Stop-Process -name $procs -Force -ErrorAction SilentlyContinue

        if (Test-Path -Path $AppxSettingsFilePath) {
            $Setting | Set-UwpAppRegistryEntry -FilePath $AppxSettingsFilePath
        }
        else {
            Write-Warning -Message 'Microsoft Store is not installed (settings.dat not found)'
        }
    }
}

function Set-UwpAppRegistryEntry {
    <#
    .SYNOPSIS
        Modifies UWP app registry entries in the settings.dat file.
    
    .EXAMPLE
        PS> $setting = [PSCustomObject]@{
                Name  = 'VideoAutoplay'
                Value = '0'
                Type  = '5f5e10b'
            }
        PS> $setting | Set-UwpAppRegistryEntry -FilePath $FilePath
    #>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [UwpRegistryKeyEntry] $InputObject,

        [Parameter(Mandatory)]
        [string] $FilePath
    )

    begin {
        $AppSettingsRegPath = 'HKEY_USERS\APP_SETTINGS'
        $RegContent = "Windows Registry Editor Version 5.00`n"
    }

    process {
        $Value = $InputObject.Value
        $Value = switch ($InputObject.Type) {
            '5f5e10b' { 
                # Single byte for boolean
                '{0:x2}' -f [byte][int]$Value
            }
            '5f5e10c' { 
                # Unicode string 
                $bytes = [System.Text.Encoding]::Unicode.GetBytes($Value + "`0")
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' ' 
            }
            '5f5e104' { 
                # Int32
                $bytes = [BitConverter]::GetBytes([int]$Value)
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
            }
            '5f5e105' { 
                # UInt32
                $bytes = [BitConverter]::GetBytes([uint32]$Value)
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
            }
            '5f5e106' { 
                # Int64
                $bytes = [BitConverter]::GetBytes([int64]$Value)
                ($bytes | ForEach-Object { '{0:x2}' -f $_ }) -join ' '
            }
        }

        $Value = $Value -replace '\s+', ','
    
        # create timestamp for remaining bytes
        $timestampBytes = [BitConverter]::GetBytes([int64](Get-Date).ToFileTime())
        $Timestamp = ($timestampBytes | ForEach-Object { '{0:x2}' -f $_ }) -join ','
    
        # Build registry content
        if ($InputObject.Path) {
            $RegKey = $InputObject.Path
        }
        else {
            $RegKey = 'LocalState'
        }
        $RegContent += "`n[$AppSettingsRegPath\$RegKey]
        ""$($InputObject.Name)""=hex($($InputObject.Type)):$Value,$Timestamp`n" -replace '(?m)^ *'
    }

    end {
        $tempDir = (([System.IO.Path]::GetTempPath())).trimend('\')
        $SettingRegFilePath = "$tempDir\uwp_app_settings.reg"
        $RegContent | Out-File -FilePath $SettingRegFilePath

        # Load, import, and unload the registry hive
        reg.exe UNLOAD $AppSettingsRegPath 2>&1 | Out-Null
        reg.exe LOAD $AppSettingsRegPath $FilePath | Out-Null
        reg.exe IMPORT $SettingRegFilePath 2>&1 | Out-Null
        reg.exe UNLOAD $AppSettingsRegPath | Out-Null

        Remove-Item -Path $SettingRegFilePath
    }
}

$MicrosoftStoreSettings = [System.Collections.ArrayList]::new()

# Disable Video Autoplay
$VideoAutoplayReg = @{
    Name  = 'VideoAutoplay'
    Value = '0'  # '0' = disabled, '1' = enabled
    Type  = '5f5e10b'
}
$MicrosoftStoreSettings.Add([PSCustomObject]$VideoAutoplayReg) | Out-Null

# Disable Personalized Experiences
$PersonalizedExperiencesReg = @{
    Path  = 'LocalState\PersistentSettings'
    Name  = 'PersonalizationEnabled'
    Value = '0'  # '0' = disabled, '1' = enabled
    Type  = '5f5e10b'
}
$MicrosoftStoreSettings.Add([PSCustomObject]$PersonalizedExperiencesReg) | Out-Null

# Disable App Install Notifications
$EnableAppInstallNotisReg = @{
    Name  = 'EnableAppInstallNotifications'
    Value = '0'  # '0' = disabled, '1' = enabled
    Type  = '5f5e10b'
}
$MicrosoftStoreSettings.Add([PSCustomObject]$EnableAppInstallNotisReg) | Out-Null

Set-UwpAppSetting -Name 'MicrosoftStore' -Setting $MicrosoftStoreSettings