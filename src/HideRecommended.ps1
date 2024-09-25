If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}

function Get-ProductKey {
    <#
    .SYNOPSIS
        Retrieves product keys and OS information from a local or remote system/s.
    .DESCRIPTION
        Retrieves the product key and OS information from a local or remote system/s using WMI and/or ProduKey. Attempts to
        decode the product key from the registry, shows product keys from SoftwareLicensingProduct (SLP), and attempts to use
        ProduKey as well. Enables RemoteRegistry service if required.
        Originally based on this script: https://gallery.technet.microsoft.com/scriptcenter/Get-product-keys-of-local-83b4ce97
    .NOTES   
        Author: Matthew Carras
    #>

    Begin {
        [uint32]$HKLM = 2147483650 # HKEY_LOCAL_MACHINE definition for GetStringValue($hklm, $subkey, $value)

        # Define local function to decode binary product key data in registry
        # VBS Source: https://forums.mydigitallife.net/threads/vbs-windows-oem-slp-key.25284/
        function DecodeProductKeyData {
            param(
                [Parameter(Mandatory = $true)]
                [byte[]]$BinaryValuePID
            )
            Begin {
                # for decoding product key
                $KeyOffset = 52
                $CHARS = 'BCDFGHJKMPQRTVWXY2346789' # valid characters in product key
                $insert = 'N' # for Win8 or 10+
            } #end Begin
            Process {
                $ProductKey = ''
                $isWin8_or_10 = [math]::floor($BinaryValuePID[66] / 6) -band 1
                $BinaryValuePID[66] = ($BinaryValuePID[66] -band 0xF7) -bor (($isWin8_or_10 -band 2) * 4)
                for ( $i = 24; $i -ge 0; $i-- ) {
                    $Cur = 0
                    for ( $X = $KeyOffset + 14; $X -ge $KeyOffset; $X-- ) {
                        $Cur = $Cur * 256
                        $Cur = $BinaryValuePID[$X] + $Cur
                        $BinaryValuePID[$X] = [math]::Floor([double]($Cur / 24))
                        $Cur = $Cur % 24
                    } #end for $X
                    $ProductKey = $CHARS[$Cur] + $ProductKey
                } #end for $i
                If ( $isWin8_or_10 -eq 1 ) {
                    $ProductKey = $ProductKey.Insert($Cur + 1, $insert)
                }
                $ProductKey = $ProductKey.Substring(1)
                for ($i = 5; $i -le 26; $i += 6) {
                    $ProductKey = $ProductKey.Insert($i, '-')
                }
                $ProductKey
            } #end Process
        } # end DecodeProductKeyData function
    } # end Begin
    Process {
        $ComputerName = [string[]]$Env:ComputerName
        $WmiSplat = @{ ErrorAction = 'Stop' } # Given to all WMI-related commands
        $remoteReg = Get-WmiObject -List -Namespace 'root\default' -ComputerName $ComputerName @WmiSplat | Where-Object { $_.Name -eq 'StdRegProv' }
        # Get OEM info from registry
        $regManufacturer = ($remoteReg.GetStringValue($HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation', 'Manufacturer')).sValue
        $regModel = ($remoteReg.GetStringValue($HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation', 'Model')).sValue
        If ( $regManufacturer -And -Not $OEMManufacturer ) {
            $OEMManufacturer = $regManufacturer
        }
        If ( $regModel -And -Not $OEMModel ) {
            $OEMModel = $regModel
        }
        # Get & Decode Product Keys from registry
        $getvalue = 'DigitalProductId'
        $regpath = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $key = ($remoteReg.GetBinaryValue($HKLM, $regpath, $getvalue)).uValue
        If ( $key ) {
            $ProductKey = DecodeProductKeyData $key
            $ProductName = ($remoteReg.GetStringValue($HKLM, $regpath, 'ProductName')).sValue
            If ( -Not $ProductName ) { $ProductName = '' }
        } # end if
        return $ProductKey
    } # end process
} # end function

$KMS = @{
    Professional            = 'W269N-WFGWX-YVC9B-4J6C9-T83GX'
    ProfessionalWorkstation = 'NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J'
    Enterprise              = 'NPPR9-FWDCX-D2C8J-H872K-2YT43'
}

$CurrentSKU = (Get-WindowsEdition -Online).Edition
$Build = (Get-CimInstance -ClassName Win32_OperatingSystem).BuildNumber
#exit if build is not 22h2 or if version is not pro, proworkstation, or enterprise
if ($Build -lt 22621 -or $KMS.ContainsKey($CurrentSKU) -eq $false) {
    Write-Host 'Build Not Supported'
    Exit
}
#get current key to reset later
$CurrentKey = Get-ProductKey

#disable recommended section
if ((Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer') -eq $false) {
    New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Force | Out-Null
}
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'HideRecommendedSection' -Value 1 -Force
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_Layout' -Value 1 -Force
#kill startmenu
Stop-Process -Name 'StartMenuExperienceHost' -Force

# Switch to ProfessionalEducation KMS
& cscript.exe /nologo C:\Windows\system32\slmgr.vbs /ipk 6TP4R-GNPTD-KYYHQ-7B7DP-J447Y

#rerun startmenu after edition is switched
Start-Sleep -Milliseconds 750
Start-Process -FilePath 'C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe'
Start-Sleep -Seconds 1

# Use generic KMS key if we're not activated yet
if ($CurrentKey -eq '') {
    $CurrentKey = $KMS[$CurrentSKU]
}

# Restore original Product Key
& cscript.exe /nologo C:\Windows\system32\slmgr.vbs /ipk $CurrentKey
