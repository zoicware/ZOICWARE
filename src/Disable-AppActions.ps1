function Set-UwpAppRegistryEntry {
    # modified to work in windows powershell from https://github.com/agadiffe/WindowsMize/blob/fe78912ccb1c83d440bd2123f5e43a6156fab31a/src/modules/applications/settings/public/Set-UwpAppSetting.ps1
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
        $InputObject,

        [Parameter(Mandatory)]
        [string] $FilePath
    )

    begin {
        $AppSettingsRegPath = 'HKEY_USERS\APP_SETTINGS'
        $RegContent = "Windows Registry Editor Version 5.00`n"

        reg.exe UNLOAD $AppSettingsRegPath 2>&1 | Out-Null

        $max = 30
        $attempts = 0
        $ProcessToStop = @(
            'AppActions'
            'SearchHost'
            'FESearchHost'
            'msedgewebview2'
            'TextInputHost'
            'VisualAssistExe'
            'WebExperienceHostApp'
        )
        Stop-Process -Name $ProcessToStop -Force -ErrorAction SilentlyContinue 
        # do while is needed here because wait-process in this case is not working maybe cause its just a trash function lol
        # using microsofts own example found in the docs does not work 
        # https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/wait-process?view=powershell-7.5#example-1-stop-a-process-and-wait

        # since we are trying multiple times while the processes are stopping this will work as soon as the file is freed 
        do {
            reg.exe LOAD $AppSettingsRegPath $FilePath *>$null
            $attempts++
        } while ($LASTEXITCODE -ne 0 -and $attempts -lt $max)
    
        if ($LASTEXITCODE -ne 0) {
            Write-Status -Message 'Unable to load settings.dat' -Type Error
            return
        }
      
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
    
        # build registry content
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
        $SettingRegFilePath = "$($tempDir)uwp_app_settings.reg"
        $RegContent | Out-File -FilePath $SettingRegFilePath

        reg.exe IMPORT $SettingRegFilePath 2>&1 | Out-Null
        reg.exe UNLOAD $AppSettingsRegPath | Out-Null

        Remove-Item -Path $SettingRegFilePath
    }
}


$settingsDat = "$env:LOCALAPPDATA\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\Settings\settings.dat"

if (Test-Path $settingsDat) {
    Stop-Process -name 'SearchHost', 'AppActions' -Force -ErrorAction SilentlyContinue
    $apps = @(
        'Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' 
        'Microsoft.Office.ActionsServer_8wekyb3d8bbwe' 
        'MSTeams_8wekyb3d8bbwe' 
        'Microsoft.Paint_8wekyb3d8bbwe' 
        'Microsoft.Windows.Photos_8wekyb3d8bbwe'
        'MicrosoftWindows.Client.CBS_cw5n1h2txyewy' #describe image (system)
    )

    foreach ($app in $apps) {
        $setting = [PSCustomObject]@{
            Name  = $app
            Path  = 'LocalState\DisabledApps'
            Value = '1' 
            Type  = '5f5e10b'
        }
        $setting | Set-UwpAppRegistryEntry -FilePath $settingsDat
    }
     
}