If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}

# download file function source: https://gist.github.com/ChrisStro/37444dd012f79592080bd46223e27adc
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
                    #Write-Host "$finalBarCount"
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






$currentVersion = 'v1.3.7'

$offlineMode = $false
try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri 'https://www.google.com' -Method Head -DisableKeepAlive -UseBasicParsing | Out-Null
}
catch [System.Net.WebException] {
    $offlineMode = $true
}

if ($offlineMode) {
    $host.ui.RawUI.WindowTitle = 'ZOICWARE ', $currentVersion, '(OFFLINE)'
}
else {
    $host.ui.RawUI.WindowTitle = 'ZOICWARE ', $currentVersion  
}


#changes console to black
function color ($bc, $fc) {
    $a = (Get-Host).UI.RawUI
    $a.BackgroundColor = $bc
    $a.ForegroundColor = $fc 
    Clear-Host 
}	

color 'black' 'white'

# Get the console window width
$consoleWidth = $Host.UI.RawUI.WindowSize.Width

# Calculate the number of padding characters needed on each side
$padding = ($consoleWidth - 21) / 2

# Create the full title string with padding
$fullTitle = '~' * [Math]::Floor($padding) + ' ' + 'WELCOME TO ZOICWARE' + ' ' + '~' * [Math]::Ceiling($padding)


Write-Host $fullTitle -BackgroundColor White -ForegroundColor Black

#get system drive letter
$Global:sysDrive = $env:SystemDrive + '\'
#search on system drive if zoicware.ps1 is not in _FOLDERMUSTBEONCDRIVE
if ($PSScriptRoot -like '*_FOLDERMUSTBEONCDRIVE') {
    $Global:folder = $PSScriptRoot
}
else {
    Write-Host "Searching for functions in $sysDrive"
    $Global:folder = (Get-ChildItem -Path $sysDrive -Filter '_FOLDERMUSTBEONCDRIVE' -Recurse -Directory -ErrorAction SilentlyContinue -Force | Where-Object Name -NotIn '$Recycle.Bin' | Select-Object -First 1).FullName
}
$pack = $folder -replace '\\_FOLDERMUSTBEONCDRIVE' , ''
#check exclusion first 
try {
    $exclusionPaths = (Get-MpPreference -ErrorAction Stop).ExclusionPath
    if ($pack -notin $exclusionPaths -and $folder -notin $exclusionPaths) {
        #add _FOLDERMUSTBEONCDRIVE and zoicwareOS to defender exclusions
        Add-MpPreference -ExclusionPath $folder -Force -ErrorAction SilentlyContinue
        if (Test-Path $pack -ErrorAction SilentlyContinue) {
            Add-MpPreference -ExclusionPath $pack -Force -ErrorAction SilentlyContinue
        }
        else {
            #_FOLDERMUSTBEONCDRIVE is not in zoicwareOS folder
            $pack = (Get-ChildItem -Path $sysDrive -Filter 'zoicwareOS' -Recurse -Directory -ErrorAction SilentlyContinue -Force | Where-Object Name -NotIn '$Recycle.Bin' | Select-Object -First 1).FullName
            Add-MpPreference -ExclusionPath $pack -Force -ErrorAction SilentlyContinue
        } 
    }
}
catch {
    #defender disabled or stripped
}



#check if settings file is made
$settingsContent = @'
#ZOICWARE SCRIPT SETTINGS
dontCheckUpdates = 0
'@
  
  
$settingsLocation = "$env:USERPROFILE\zSettings.cfg"
if (!(Test-Path $settingsLocation)) {
    New-Item $settingsLocation -Force | Out-Null
    Set-Content $settingsLocation -Value $settingsContent -Force | Out-Null
}


#read settings file
$Global:dontCheck4Updates = $false
$readContent = (Get-Content -Path $settingsLocation -Raw -Force) -split "`r`n"
foreach ($line in $readContent) {
    if ($line -like '*dontCheckUpdates*') {
        $sLine = $line -split '='
        if ($sLine[1].Trim() -eq '1') {
            $Global:dontCheck4Updates = $true
        }
    }
}

if (!$offlineMode -and !$dontCheck4Updates) {
    if ($folder -ne $null) {
        try {
            #check github for update
            $headers = @{
                'User-Agent' = 'PowerShell'
            }
            $apiUrl = 'https://api.github.com/repos/zoicware/ZOICWARE/releases/latest'
            $ProgressPreference = 'SilentlyContinue'
            $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -UseBasicParsing -ErrorAction Stop
            $latestVer = $response.tag_name

            #check folder version
            if (!(Test-Path "$folder\$latestVer" -PathType Leaf)) {
                #folder is not updated 
                [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
                $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Install Newer Version of Zoicware?', 'zoicware', 'YesNo', 'Question')
                switch ($msgBoxInput) {
                    'Yes' {
                        # create download url
                        $downloadUrl = $response.assets | Where-Object { $_.name -eq 'zoicwareOS.zip' } | Select-Object -ExpandProperty browser_download_url

                        # download zip
                        Get-FileFromWeb -URL $downloadUrl -File "$env:TEMP\zoicwareOS.zip"
            
                        Expand-Archive -Path "$env:TEMP\zoicwareOS.zip" -DestinationPath "$env:TEMP\zoicwareOS" -Force
                        Rename-Item "$env:TEMP\zoicwareOS" -NewName "zoicwareOS$latestVer" -Force  
                        Move-Item "$env:TEMP\zoicwareOS$latestVer" -Destination "$env:USERPROFILE\Desktop" -Force
                        Remove-Item -Path "$env:TEMP\zoicwareOS.zip" -Force -ErrorAction SilentlyContinue

                        #rename old folder
                        Rename-Item $folder -NewName 'OLD' -Force
                        #start zoicware
                        Start-Process "$env:USERPROFILE\Desktop\zoicwareOS$latestver\zoicwareOS\RUN ZOICWARE.exe"
                        exit

                    }
                    'No' {}
                }
            }
        }
        catch {
            #no internet
        }
    }

}

if ($null -eq $folder) {
    Write-Warning "Functions NOT Found on $sysDrive" 
    Write-Host 'Press any Key to Exit: '
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}

#check that the folder is correct version
if (Test-Path "$folder\$currentVersion" -PathType Leaf) {
    $modulePath = "$folder\zFunctions.psm1"
    $winfetchModule = "$folder\winfetch.psm1"
    Import-Module -Name $modulePath -Force -Global *>$null
    Import-Module -Name $winfetchModule -Force *>$null
}
else {
    Write-Host "Folder Found But Not Updated at $folder"
    Write-Host "Make sure you do not have older versions of zoicware on $sysDrive"
    Write-Host 'Press any Key to Exit: '
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}
   

    

#display neofetch
winfetch -s

#create cfg 

$configContent = @'
#ZOICWARE TWEAK CONFIG
installPackages = 0
registryTweaks = 0
scheduledTasks = 0
gpDefender = 0
gpUpdates = 0
gpTel = 0
disableServices = 0
# (0-5) 1:Debloat all 2:Keep store,xbox,edge 3:Keep store,xbox 4:Keep edge 5:Keep store
debloatAll = 0 
debloatSXE = 0
debloatSX = 0
debloatE = 0
debloatS = 0
usePowerPlan = 0
removeallPlans = 0
enableUltimate = 0
enableMaxOverlay = 0
enableHighOverlay = 0 
#OPTIONAL TWEAKS
# (0-2) 1:enabled 2:classic enabled
opblackTheme = 0 
opclassicTheme = 0
#remove open file security warning
opROFSW = 0
opremoveSpeech = 0
openableHAGS = 0
optransTaskbar = 0
opremoveMouseSoundSchemes = 0
opremoveRecycle = 0
opremoveQuickAccess = 0
opblockRazerAsus = 0
opremoveNetworkIcon = 0
opapplyPBO = 0
opnoDriversInUpdate = 0
openable11Sounds = 0
opSecUpdatesOnly = 0
opPauseUpdates = 0
opStopOSUpgrade = 0
opDisablePowerShellLogs = 0
opNoGUIBoot = 0
opGameBarPopup = 0
#CONTEXT MENU TWEAKS
connewFiles = 0
conmorePS = 0
consnipping = 0
conshutdown = 0
conrunAsAdmin = 0
conpsCmd = 0
conkillTasks = 0
conpermDel = 0
conTakeOwn = 0
conFavorites = 0
conCustomizeFolder = 0
conGiveAccess = 0
conOpenTerm = 0
conRestorePrev = 0
conPrint = 0
conSend = 0
conShare = 0
conPersonalize = 0
conDisplay = 0
conExtractAll = 0
conTroubleshootComp = 0
conIncludeLibrary = 0
#WIN 11 TWEAKS
removeEdges = 0
win10TaskbarStartmenu = 0
win10Explorer = 0
servicesManual = 0
showTrayIcons = 0
enableOpenShell = 0
win10Recycle = 0
disableBellIcon = 0
win10Snipping = 0
win10TaskMgr = 0
win10Notepad = 0
hideRecommended = 0
win10Icons = 0
darkWinver = 0
removeQuickSettingTiles = 0
removeSystemLabel = 0
disableNotepadTabs = 0
hideHome = 0
'@


$config = "$env:USERPROFILE\ZCONFIG.cfg"
if (!(Test-Path -Path $config)) {
    Write-Host 'Creating Config to Track User Settings' -NoNewline
    Write-Host " [$config]" -ForegroundColor Yellow
    $var = New-Item -Path $config -ItemType File -Force
    Add-Content -Path $config -Value $configContent -Force

}
else {
    Write-Host 'Config Location ' -NoNewline
    Write-Host "[$config]" -ForegroundColor Yellow
    Write-Host '[+] Checking if Config is Updated...' -ForegroundColor Cyan
    #compare current config with updated config content
    $currentContent = Get-Content -Path $config -Force
    
    #make an array of setting names
    $currentConfigNames = @()
    $currentConfigSplit = $currentContent -split '='
    foreach ($line in $currentConfigSplit) {
        if ($line -notlike '#*' -and $line -notlike '0' -and $line -notlike '1') {
            $currentConfigNames += $line.Trim()
        }
    }
    
    $configContentArray = $configContent -split "`n"
    foreach ($line in $configContentArray) {
        if ($line -notlike '#*') {
            $settingName = $line -split '='
            if ($settingName[0].trim() -notin $currentConfigNames) { 
                Write-Host "Updating Config with [$($settingName[0].trim())]" -ForegroundColor Yellow
                #add newline before adding content instead of after (-nonewline)
                #trim new line from $line
                Add-Content -Path $config -Value "$([Environment]::NewLine)$($line.Trim())" -NoNewline -Force
            }
        }
    }

}





function restart-pc {

    $msgBoxInput = Custom-MsgBox -message '    Restart PC?' -Type Question

    switch ($msgBoxInput) {

        'OK' {
            #setting execution policy back to remote signed  
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'RemoteSigned' /f
            Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'RemoteSigned' /f
            #you can guess what this does
            Restart-Computer
        }

        'Cancel' {
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'RemoteSigned' /f
            Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'RemoteSigned' /f
        }

    }

}



#get icon folder path
$Global:iconDir = Search-Directory '*zoicwareIcons'

#do while with gui menu 

do {


    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # Create a form
    $form = New-Object Windows.Forms.Form
    $form.Text = 'ZOICWARE'
    $form.Size = New-Object Drawing.Size(610, 450)
    $form.BackColor = [System.Drawing.Color]::FromArgb(33, 33, 33) # #212121
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    # Add custom form icon
    $Global:customIcon = Search-File '*Powershell_black.ico'
    $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

    # Create the sidebar panel
    $sidebarPanel = New-Object System.Windows.Forms.Panel
    $sidebarPanel.Size = New-Object Drawing.Size(150, 410)
    $sidebarPanel.Location = New-Object Drawing.Point(0, 0)
    $sidebarPanel.BackColor = [System.Drawing.Color]::FromArgb(26, 26, 26) 
    $form.Controls.Add($sidebarPanel)

    # Create the main content panel
    $mainPanel = New-Object System.Windows.Forms.Panel
    $mainPanel.Size = New-Object Drawing.Size(450, 410)
    $mainPanel.Location = New-Object Drawing.Point(150, 0)
    $mainPanel.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 45) # #2D2D2D
    $mainPanel.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle # Subtle border for depth
    $form.Controls.Add($mainPanel)

    # Create panels for each section (Windows Tweaks, Post Tweak Setup, Utilities)
    $windowsTweaksPanel = New-Object System.Windows.Forms.Panel
    $windowsTweaksPanel.Size = New-Object Drawing.Size(450, 300)
    $windowsTweaksPanel.Location = New-Object Drawing.Point(0, 0)
    $windowsTweaksPanel.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) # #333333

    $postTweakSetupPanel = New-Object System.Windows.Forms.Panel
    $postTweakSetupPanel.Size = New-Object Drawing.Size(450, 300)
    $postTweakSetupPanel.Location = New-Object Drawing.Point(0, 0)
    $postTweakSetupPanel.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) # #333333
    $postTweakSetupPanel.Visible = $false

    $utilitiesPanel = New-Object System.Windows.Forms.Panel
    $utilitiesPanel.Size = New-Object Drawing.Size(450, 300)
    $utilitiesPanel.Location = New-Object Drawing.Point(0, 0)
    $utilitiesPanel.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) # #333333
    $utilitiesPanel.Visible = $false

    # Helper function to create modern buttons with icons
    function Create-ModernButton {
        param (
            [string]$Text,
            [System.Drawing.Point]$Location,
            [System.Drawing.Size]$Size,
            [scriptblock]$ClickAction,
            [string]$TooltipText,
            [string]$IconPath = $null
        )
        $button = New-Object Windows.Forms.Button
        $button.Text = $Text
        $button.Location = $Location
        $button.Size = $Size
        $button.BackColor = [System.Drawing.Color]::FromArgb(42, 42, 42) # #2A2A2A
        $button.ForeColor = 'White'
        $button.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
        $button.FlatAppearance.BorderSize = 1
        $button.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(80, 80, 80)
        $button.Cursor = 'Hand'
        # Add icon if provided
        if ($IconPath -and (Test-Path $IconPath)) {
            $icon = [System.Drawing.Image]::FromFile($IconPath)
            $button.Image = New-Object System.Drawing.Bitmap $icon, 24, 24
            $button.ImageAlign = [System.Drawing.ContentAlignment]::MiddleLeft
            $button.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
            $button.TextImageRelation = [System.Windows.Forms.TextImageRelation]::ImageBeforeText
            $button.Padding = New-Object System.Windows.Forms.Padding(20, 0, 0, 0) # Space between icon and text
        }
        # Hover effect
        $button.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }) # #4A4A4A
        $button.Add_MouseLeave({ $this.BackColor = [System.Drawing.Color]::FromArgb(42, 42, 42) }) # #2A2A2A
        $button.Add_Click($ClickAction)
        # Add tooltip
        $tooltip = New-Object System.Windows.Forms.ToolTip
        $tooltip.SetToolTip($button, $TooltipText)
        return $button
    }

    # Sidebar buttons with icons and hover effects
    $windowsTweaksButton = New-Object Windows.Forms.Button
    $windowsTweaksButton.Text = 'Windows Tweaks'
    $windowsTweaksButton.Location = New-Object Drawing.Point(10, 20)
    $windowsTweaksButton.Size = New-Object Drawing.Size(130, 40)
    $windowsTweaksButton.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) # #4A4A4A (active by default)
    $windowsTweaksButton.ForeColor = 'White'
    $windowsTweaksButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $windowsTweaksButton.FlatAppearance.BorderSize = 0
    $iconPath = "$iconDir\optionalTweaks.png"
    if (Test-Path $iconPath) {
        $icon = [System.Drawing.Image]::FromFile($iconPath)
        $windowsTweaksButton.Image = New-Object System.Drawing.Bitmap $icon, 24, 24
        $windowsTweaksButton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $windowsTweaksButton.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
        $windowsTweaksButton.TextImageRelation = [System.Windows.Forms.TextImageRelation]::ImageBeforeText
        $windowsTweaksButton.Padding = New-Object System.Windows.Forms.Padding(20, 0, 0, 0)
    }
    $windowsTweaksButton.Tag = 'Active'
    $windowsTweaksButton.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $windowsTweaksButton.Add_MouseLeave({ 
            if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }
            else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) }
        })
    $windowsTweaksButton.Add_Click({
            $windowsTweaksPanel.Visible = $true
            $postTweakSetupPanel.Visible = $false
            $utilitiesPanel.Visible = $false
            $windowsTweaksButton.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
            $windowsTweaksButton.Tag = 'Active'
            $postTweakSetupButton.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
            $postTweakSetupButton.Tag = 'Inactive'
            $utilitiesButton.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
            $utilitiesButton.Tag = 'Inactive'
        })
    $sidebarPanel.Controls.Add($windowsTweaksButton)

    $postTweakSetupButton = New-Object Windows.Forms.Button
    $postTweakSetupButton.Text = 'Windows Setup'
    $postTweakSetupButton.Location = New-Object Drawing.Point(10, 80)
    $postTweakSetupButton.Size = New-Object Drawing.Size(130, 40)
    $postTweakSetupButton.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) # #333333
    $postTweakSetupButton.ForeColor = 'White'
    $postTweakSetupButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $postTweakSetupButton.FlatAppearance.BorderSize = 0
    $iconPath = "$iconDir\postInstall.png"
    if (Test-Path $iconPath) {
        $icon = [System.Drawing.Image]::FromFile($iconPath)
        $postTweakSetupButton.Image = New-Object System.Drawing.Bitmap $icon, 24, 24
        $postTweakSetupButton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $postTweakSetupButton.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
        $postTweakSetupButton.TextImageRelation = [System.Windows.Forms.TextImageRelation]::ImageBeforeText
        $postTweakSetupButton.Padding = New-Object System.Windows.Forms.Padding(20, 0, 0, 0)
    }
    $postTweakSetupButton.Tag = 'Inactive'
    $postTweakSetupButton.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $postTweakSetupButton.Add_MouseLeave({ 
            if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }
            else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) }
        })
    $postTweakSetupButton.Add_Click({
            $windowsTweaksPanel.Visible = $false
            $postTweakSetupPanel.Visible = $true
            $utilitiesPanel.Visible = $false
            $windowsTweaksButton.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
            $windowsTweaksButton.Tag = 'Inactive'
            $postTweakSetupButton.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
            $postTweakSetupButton.Tag = 'Active'
            $utilitiesButton.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
            $utilitiesButton.Tag = 'Inactive'
        })
    $sidebarPanel.Controls.Add($postTweakSetupButton)

    $utilitiesButton = New-Object Windows.Forms.Button
    $utilitiesButton.Text = 'Utilities'
    $utilitiesButton.Location = New-Object Drawing.Point(10, 140)
    $utilitiesButton.Size = New-Object Drawing.Size(130, 40)
    $utilitiesButton.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) # #333333
    $utilitiesButton.ForeColor = 'White'
    $utilitiesButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Standard
    $utilitiesButton.FlatAppearance.BorderSize = 0
    $iconPath = "$iconDir\tweaks.png" 
    if ($iconPath -and (Test-Path $iconPath)) {
        $icon = [System.Drawing.Image]::FromFile($iconPath)
        $utilitiesButton.Image = New-Object System.Drawing.Bitmap $icon, 24, 24
        $utilitiesButton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $utilitiesButton.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
        $utilitiesButton.TextImageRelation = [System.Windows.Forms.TextImageRelation]::ImageBeforeText
        $utilitiesButton.Padding = New-Object System.Windows.Forms.Padding(20, 0, 0, 0)
    }
    $utilitiesButton.Tag = 'Inactive'
    $utilitiesButton.Add_MouseEnter({ $this.BackColor = [System.Drawing.Color]::FromArgb(90, 90, 90) })
    $utilitiesButton.Add_MouseLeave({ 
            if ($this.Tag -eq 'Active') { $this.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74) }
            else { $this.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51) }
        })
    $utilitiesButton.Add_Click({
            $windowsTweaksPanel.Visible = $false
            $postTweakSetupPanel.Visible = $false
            $utilitiesPanel.Visible = $true
            $windowsTweaksButton.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
            $windowsTweaksButton.Tag = 'Inactive'
            $postTweakSetupButton.BackColor = [System.Drawing.Color]::FromArgb(51, 51, 51)
            $postTweakSetupButton.Tag = 'Inactive'
            $utilitiesButton.BackColor = [System.Drawing.Color]::FromArgb(74, 74, 74)
            $utilitiesButton.Tag = 'Active'
        })
    $sidebarPanel.Controls.Add($utilitiesButton)

    # Settings button in sidebar
    $settingsButton = New-Object Windows.Forms.Button
    $settingsButton.Location = New-Object Drawing.Point(5, 380)
    $settingsButton.Size = New-Object Drawing.Size(30, 30)
    $settingsButton.Cursor = 'Hand'
    $settingsButton.Add_Click({ Display-Settings })
    $settingsButton.BackColor = [System.Drawing.Color]::FromArgb(26, 26, 26) # #1A1A1A
    $imagePath = "$iconDir\settingsIcon.png"
    $image = [System.Drawing.Image]::FromFile($imagePath)
    $settingsButton.Image = New-Object System.Drawing.Bitmap $image, 24, 25
    $settingsButton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $settingsButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $settingsButton.FlatAppearance.BorderSize = 0
    $sidebarPanel.Controls.Add($settingsButton)

    # Info button in sidebar
    $urlfeatures = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md'
    $infobutton = New-Object Windows.Forms.Button
    $infobutton.Location = New-Object Drawing.Point(35, 380)
    $infobutton.Size = New-Object Drawing.Size(30, 30)
    $infobutton.Cursor = 'Hand'
    $infobutton.Add_Click({
            try {
                Start-Process $urlfeatures -ErrorAction Stop
            }
            catch {
                Write-Host 'No Internet Connected...' -ForegroundColor Red
            }
        })
    $infobutton.BackColor = [System.Drawing.Color]::FromArgb(26, 26, 26) # #1A1A1A
    $image = [System.Drawing.Image]::FromFile('C:\Windows\System32\SecurityAndMaintenance.png')
    $infobutton.Image = New-Object System.Drawing.Bitmap $image, 24, 25
    $infobutton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $infobutton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $infobutton.FlatAppearance.BorderSize = 0
    $sidebarPanel.Controls.Add($infobutton)

    # Define button size
    $buttonWidth = 180
    $buttonHeight = 35
    $buttonSpacing = 15

    # Windows Tweaks Panel
    # Core Tweaks Section
    $coreTweaksLabel = New-Object Windows.Forms.Label
    $coreTweaksLabel.Text = 'Core Tweaks'
    $coreTweaksLabel.Location = New-Object Drawing.Point(10, 20)
    $coreTweaksLabel.Size = New-Object Drawing.Size(200, 20)
    $coreTweaksLabel.ForeColor = 'White'
    $coreTweaksLabel.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $windowsTweaksPanel.Controls.Add($coreTweaksLabel)

    $button2 = Create-ModernButton -Text 'Registry Tweaks' -Location (New-Object Drawing.Point(10, 50)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        import-reg
        $form.Visible = $true
    } -TooltipText 'Registry tweaks to improve system performance and usability.' -IconPath "$iconDir\registry.png"
    $windowsTweaksPanel.Controls.Add($button2)

    $button4 = Create-ModernButton -Text 'Group Policy Tweaks' -Location (New-Object Drawing.Point(10, 90)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        gpTweaks
        $form.Visible = $true
    } -TooltipText 'Disable Updates, Defender, Telemetry.' -IconPath "$iconDir\groupPolicy.png"
    $windowsTweaksPanel.Controls.Add($button4)

    $button5 = Create-ModernButton -Text 'Disable Services' -Location (New-Object Drawing.Point(10, 130)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        disable-services
        $form.Visible = $true
    } -TooltipText 'Disables unnecessary Windows services.' -IconPath "$iconDir\disableServices.png"
    $windowsTweaksPanel.Controls.Add($button5)

    $button3 = Create-ModernButton -Text 'Remove Scheduled Tasks' -Location (New-Object Drawing.Point(10, 170)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        remove-tasks
        $form.Visible = $true
    } -TooltipText 'Removes unnecessary scheduled tasks.' -IconPath "$iconDir\removeTasks.png"
    $windowsTweaksPanel.Controls.Add($button3)

    # Additional Tweaks Section
    $additionalTweaksLabel = New-Object Windows.Forms.Label
    $additionalTweaksLabel.Text = 'Additional Tweaks'
    $additionalTweaksLabel.Location = New-Object Drawing.Point(240, 20)
    $additionalTweaksLabel.Size = New-Object Drawing.Size(200, 20)
    $additionalTweaksLabel.ForeColor = 'White'
    $additionalTweaksLabel.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $windowsTweaksPanel.Controls.Add($additionalTweaksLabel)

    $button6 = Create-ModernButton -Text 'Debloat' -Location (New-Object Drawing.Point(240, 50)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        debloat
        $form.Visible = $true
    } -TooltipText 'Removes bloatware from the system.' -IconPath "$iconDir\cleanBroom.png"
    $windowsTweaksPanel.Controls.Add($button6)

    $button8 = Create-ModernButton -Text 'Power Tweaks' -Location (New-Object Drawing.Point(240, 90)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        import-powerplan
        $form.Visible = $true
    } -TooltipText 'Optimizes power settings for performance.' -IconPath "$iconDir\power.png"
    $windowsTweaksPanel.Controls.Add($button8)

    $button7 = Create-ModernButton -Text 'Optional Tweaks' -Location (New-Object Drawing.Point(240, 130)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        OptionalTweaks
        $form.Visible = $true
    } -TooltipText 'Applies additional optional tweaks.' -IconPath "$iconDir\optionalTweaks.png"
    $windowsTweaksPanel.Controls.Add($button7)

    $win11tweaks = Create-ModernButton -Text 'Windows 11 Tweaks' -Location (New-Object Drawing.Point(240, 170)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        W11Tweaks
        $form.Visible = $true
    } -TooltipText 'Applies tweaks specific to Windows 11.' -IconPath "$iconDir\windows11.png"
    $windowsTweaksPanel.Controls.Add($win11tweaks)

    # Run Tweaks in Order
    $button9 = Create-ModernButton -Text 'Run Tweaks in Order' -Location (New-Object Drawing.Point(10, 240)) -Size (New-Object Drawing.Size(430, 40)) -ClickAction {
        $form.Visible = $false
        import-reg
        remove-tasks
        gpTweaks
        disable-services
        debloat
        OptionalTweaks
        import-powerplan
        $OS = Get-CimInstance Win32_OperatingSystem
        if ($OS.Caption -like '*Windows 11*') {
            W11Tweaks
        }
        restart-pc
    } -TooltipText 'Runs all tweaks in sequence and restarts the PC.' 
    $windowsTweaksPanel.Controls.Add($button9)

    # Post Tweak Setup Panel
    # Install Options Section
    $installOptionsLabel = New-Object Windows.Forms.Label
    $installOptionsLabel.Text = 'Install Options'
    $installOptionsLabel.Location = New-Object Drawing.Point(10, 20)
    $installOptionsLabel.Size = New-Object Drawing.Size(200, 20)
    $installOptionsLabel.ForeColor = 'White'
    $installOptionsLabel.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $postTweakSetupPanel.Controls.Add($installOptionsLabel)

    # Center the buttons
    $startX = 50
    $button1 = Create-ModernButton -Text 'Install Packages' -Location (New-Object Drawing.Point($startX, 50)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        install-packs
        $form.Visible = $true
    } -TooltipText 'Installs essential software packages, C++ Runtimes, DirectX, Net3.5.' -IconPath "$iconDir\packageInstall.png"
    $postTweakSetupPanel.Controls.Add($button1)

    $installBrowsers = Create-ModernButton -Text 'Install Browsers' -Location (New-Object Drawing.Point(($startX + $buttonWidth + $buttonSpacing), 50)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        install-browsers
        $form.Visible = $true
    } -TooltipText 'Installs popular web browsers.' -IconPath "$iconDir\browser.png"
    $postTweakSetupPanel.Controls.Add($installBrowsers)

    $nvtweaks = Create-ModernButton -Text 'Install Nvidia Driver' -Location (New-Object Drawing.Point($startX, 90)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        $nvscript = Search-File '*NvidiaAutoinstall.ps1'
        &$nvscript
        $form.Visible = $true
    } -TooltipText 'Choose Nvidia Driver to install along with tweaks.' -IconPath "$iconDir\gpuDriver.png"
    $postTweakSetupPanel.Controls.Add($nvtweaks)

    $networkdriver = Create-ModernButton -Text 'Install Network Driver' -Location (New-Object Drawing.Point(($startX + $buttonWidth + $buttonSpacing), 90)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        $networkInstaller = Search-File '*LocalNetworkInstaller.ps1'
        &$networkInstaller
        $form.Visible = $true
    } -TooltipText 'Installs network drivers.' -IconPath "$iconDir\networkDriver.png"
    $postTweakSetupPanel.Controls.Add($networkdriver)

    # Additional Actions Section
    $additionalActionsLabel = New-Object Windows.Forms.Label
    $additionalActionsLabel.Text = 'Additional Actions'
    $additionalActionsLabel.Location = New-Object Drawing.Point(10, 140)
    $additionalActionsLabel.Size = New-Object Drawing.Size(200, 20)
    $additionalActionsLabel.ForeColor = 'White'
    $additionalActionsLabel.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $postTweakSetupPanel.Controls.Add($additionalActionsLabel)

    $cleanup = Create-ModernButton -Text 'Ultimate Cleanup' -Location (New-Object Drawing.Point($startX, 170)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        UltimateCleanup
        $form.Visible = $true
    } -TooltipText 'Performs a thorough system cleanup.' -IconPath "$iconDir\delete.png"
    $postTweakSetupPanel.Controls.Add($cleanup)

    $activate = Create-ModernButton -Text 'Activate Windows' -Location (New-Object Drawing.Point(($startX + $buttonWidth + $buttonSpacing), 170)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        install-key
        $form.Visible = $true
    } -TooltipText 'Activates Windows with a product key using KMS.' -IconPath "$iconDir\activation.png"
    $postTweakSetupPanel.Controls.Add($activate)

    # Utilities Panel
    $utilitiesLabel = New-Object Windows.Forms.Label
    $utilitiesLabel.Text = 'Utilities'
    $utilitiesLabel.Location = New-Object Drawing.Point(10, 20)
    $utilitiesLabel.Size = New-Object Drawing.Size(200, 20)
    $utilitiesLabel.ForeColor = 'White'
    $utilitiesLabel.Font = New-Object System.Drawing.Font('Segoe UI', 12, [System.Drawing.FontStyle]::Bold)
    $utilitiesPanel.Controls.Add($utilitiesLabel)

    $restoreButton = Create-ModernButton -Text 'Restore Tweaks' -Location (New-Object Drawing.Point($startX, 50)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        $restore = Search-File '*Restore.ps1'
        &$restore
        $form.Visible = $true
    } -TooltipText 'Restores previous tweaks.' -IconPath "$iconDir\restore.png"
    $utilitiesPanel.Controls.Add($restoreButton)

    $configButton = Create-ModernButton -Text 'Import/Export Config' -Location (New-Object Drawing.Point(($startX + $buttonWidth + $buttonSpacing), 50)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        $configUI = Search-File '*configUI.ps1'
        &$configUI
        $form.Visible = $true
    } -TooltipText 'Imports or exports configuration settings.' -IconPath "$iconDir\importExport.png"
    $utilitiesPanel.Controls.Add($configButton)

    $otherscriptsbttn = Create-ModernButton -Text 'Install Scripts' -Location (New-Object Drawing.Point($startX, 90)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        $otherScriptsUI = Search-File '*Install-OtherScripts.ps1'
        &$otherScriptsUI
        $form.Visible = $true
    } -TooltipText 'Installs additional scripts.' -IconPath "$iconDir\scripts.png"
    $utilitiesPanel.Controls.Add($otherscriptsbttn)

    $repairButton = Create-ModernButton -Text 'Repair Windows' -Location (New-Object Drawing.Point(($startX + $buttonWidth + $buttonSpacing), 90)) -Size (New-Object Drawing.Size($buttonWidth, $buttonHeight)) -ClickAction {
        $form.Visible = $false
        Repair-Windows
        $form.Visible = $true
    } -TooltipText 'Repairs various aspects of windows.' -IconPath "$iconDir\repair.png"
    $utilitiesPanel.Controls.Add($repairButton)

    # Add panels to main content area
    $mainPanel.Controls.Add($windowsTweaksPanel)
    $mainPanel.Controls.Add($postTweakSetupPanel)
    $mainPanel.Controls.Add($utilitiesPanel)

    # Show the form
    $result = $form.ShowDialog()


} while ($result -ne [System.Windows.Forms.DialogResult]::Cancel)

# Dispose of the form when it's closed
$form.Dispose()
