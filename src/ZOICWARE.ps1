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






$currentVersion = 'v1.3.4'

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
                        Start-Process "$env:USERPROFILE\Desktop\zoicwareOS$latestver\zoicwareOS\1 Setup\RUN ZOICWARE.exe"
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
opdoubleClickPS = 0
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



#install dm mono font
Add-CustomFont

#do while with gui menu 

do {


    # Load the necessary assemblies for Windows Forms
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    [System.Windows.Forms.Application]::EnableVisualStyles()
    
    # Create a form
    $form = New-Object Windows.Forms.Form
    $form.Text = 'ZOICWARE'
    $form.Size = New-Object Drawing.Size(500, 420)
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)


    #add custom form icon
    $Global:customIcon = Search-File '*Powershell_black.ico'
    $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)


    # settings button
    $settingsButton = New-Object Windows.Forms.Button
    $settingsButton.Location = New-Object Drawing.Point(420, 1)
    $settingsButton.Size = New-Object Drawing.Size(30, 30)
    $settingsButton.Cursor = 'Hand'
    $settingsButton.Add_Click({
            Display-Settings
        })
    $settingsButton.BackColor = 'Black'
    $imagePath = Search-File '*settingsIcon.png'
    $image = [System.Drawing.Image]::FromFile($imagePath)
    $resizedImage = New-Object System.Drawing.Bitmap $image, 24, 25
    $settingsButton.Image = $resizedImage
    $settingsButton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $settingsButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $settingsButton.FlatAppearance.BorderSize = 0
    # $infobutton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    # $infobutton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($settingsButton)



    # Info button
    $urlfeatures = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md'
    $infobutton = New-Object Windows.Forms.Button
    $infobutton.Location = New-Object Drawing.Point(450, 1)
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
    $infobutton.BackColor = 'Black'
    $image = [System.Drawing.Image]::FromFile('C:\Windows\System32\SecurityAndMaintenance.png')
    $resizedImage = New-Object System.Drawing.Bitmap $image, 24, 25
    $infobutton.Image = $resizedImage
    $infobutton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
    $infobutton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $infobutton.FlatAppearance.BorderSize = 0
    # $infobutton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    # $infobutton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($infobutton)


    # Create the TabControl
    $tabControl = New-Object System.Windows.Forms.TabControl
    $tabControl.Size = New-Object System.Drawing.Size(470, 300)
    $tabControl.Location = New-Object System.Drawing.Point(10, 10)

    # Create the first tab
    $tabPage1 = New-Object System.Windows.Forms.TabPage
    $tabPage1.Text = 'Windows Tweaks'
    $tabPage1.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 75)
    $tabPage1.ForeColor = 'White'

    # Create the second tab
    $tabPage2 = New-Object System.Windows.Forms.TabPage
    $tabPage2.Text = 'Post Tweak Setup'
    $tabPage2.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 75)
    $tabPage2.ForeColor = 'White'

    # Add the tabs to the TabControl
    $tabControl.TabPages.Add($tabPage1)
    $tabControl.TabPages.Add($tabPage2)

    # Add the TabControl to the form
    $form.Controls.Add($tabControl)

    # Define button size
    $buttonWidth = 150
    $buttonHeight = 33

    # Create buttons for the first tab (Windows Tweaks)
    $button2 = New-Object Windows.Forms.Button
    $button2.Text = 'Registry Tweaks'
    $button2.Location = New-Object Drawing.Point(20, 20)
    $button2.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $button2.Add_Click({
            $form.Visible = $false
            import-reg
            $form.Visible = $true
        })
    $button2.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button2.ForeColor = 'White'
    $tabPage1.Controls.Add($button2)

    $button3 = New-Object Windows.Forms.Button
    $button3.Text = 'Remove Scheduled Tasks'
    $button3.Location = New-Object Drawing.Point(20, 60)
    $button3.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $button3.Add_Click({
            $form.Visible = $false
            remove-tasks
            $form.Visible = $true
        })
    $button3.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button3.ForeColor = 'White'
    $tabPage1.Controls.Add($button3)

    $button4 = New-Object Windows.Forms.Button
    $button4.Text = 'Group Policy Tweaks'
    $button4.Location = New-Object Drawing.Point(20, 100)
    $button4.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $button4.Add_Click({
            $form.Visible = $false
            gpTweaks 
            $form.Visible = $true
        })
    $button4.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button4.ForeColor = 'White'
    $tabPage1.Controls.Add($button4)

    $button5 = New-Object Windows.Forms.Button
    $button5.Text = 'Disable Services'
    $button5.Location = New-Object Drawing.Point(20, 140)
    $button5.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $button5.Add_Click({
            $form.Visible = $false
            disable-services
            $form.Visible = $true
        })
    $button5.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button5.ForeColor = 'White'
    $tabPage1.Controls.Add($button5)

    $button6 = New-Object Windows.Forms.Button
    $button6.Text = 'Debloat'
    $button6.Location = New-Object Drawing.Point(250, 20)
    $button6.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $button6.Add_Click({
            $form.Visible = $false
            debloat
            $form.Visible = $true
        })
    $button6.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button6.ForeColor = 'White'
    $tabPage1.Controls.Add($button6)

    $button7 = New-Object Windows.Forms.Button
    $button7.Text = 'Optional Tweaks'
    $button7.Location = New-Object Drawing.Point(250, 60)
    $button7.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $button7.Add_Click({
            $form.Visible = $false
            OptionalTweaks 
            $form.Visible = $true
        })
    $button7.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button7.ForeColor = 'White'
    $tabPage1.Controls.Add($button7)

    $button8 = New-Object Windows.Forms.Button
    $button8.Text = 'Power Tweaks'
    $button8.Location = New-Object Drawing.Point(250, 100)
    $button8.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $button8.Add_Click({
            $form.Visible = $false
            import-powerplan
            $form.Visible = $true
        })
    $button8.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button8.ForeColor = 'White'
    $tabPage1.Controls.Add($button8)

    $win11tweaks = New-Object Windows.Forms.Button
    $win11tweaks.Text = 'Windows 11 Tweaks'
    $win11tweaks.Location = New-Object Drawing.Point(250, 140)
    $win11tweaks.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $win11tweaks.Add_Click({
            $form.Visible = $false
            W11Tweaks
            $form.Visible = $true
        })
    $win11tweaks.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $win11tweaks.ForeColor = 'White'
    $tabPage1.Controls.Add($win11tweaks)

    $button9 = New-Object Windows.Forms.Button
    $button9.Text = 'Run Tweaks in Order'
    $button9.Location = New-Object Drawing.Point(120, 245)
    $button9.Size = New-Object Drawing.Size(180, 25)
    $button9.Add_Click({
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
        })
    $button9.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button9.ForeColor = 'White'
    $tabPage1.Controls.Add($button9)

    $installGroupBox = New-Object System.Windows.Forms.GroupBox
    $installGroupBox.Text = 'Install Options'
    $installGroupBox.Location = New-Object Drawing.Point(10, 10)
    $installGroupBox.Size = New-Object Drawing.Size(440, 140)
    $installGroupBox.ForeColor = 'White'
    $tabPage2.Controls.Add($installGroupBox)

    $button1 = New-Object Windows.Forms.Button
    $button1.Text = 'Install Necessary Packages'
    $button1.Location = New-Object Drawing.Point(10, 20)
    $button1.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $button1.Add_Click({
            $form.Visible = $false
            install-packs
            $form.Visible = $true
        })
    $button1.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button1.ForeColor = 'White'
    $installGroupBox.Controls.Add($button1)

    $nvtweaks = New-Object Windows.Forms.Button
    $nvtweaks.Text = 'Install Nvidia Driver'
    $nvtweaks.Location = New-Object Drawing.Point(10, 60)
    $nvtweaks.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $nvtweaks.Add_Click({
            $form.Visible = $false
            $nvscript = Search-File '*NvidiaAutoinstall.ps1'
            &$nvscript
            $form.Visible = $true
        })
    $nvtweaks.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $nvtweaks.ForeColor = 'White'
    $installGroupBox.Controls.Add($nvtweaks)

    $networkdriver = New-Object Windows.Forms.Button
    $networkdriver.Text = 'Install Network Driver'
    $networkdriver.Location = New-Object Drawing.Point(240, 20)
    $networkdriver.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $networkdriver.Add_Click({
            $form.Visible = $false
            $networkInstaller = Search-File '*LocalNetworkInstaller.ps1'
            &$networkInstaller
            $form.Visible = $true
        })
    $networkdriver.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $networkdriver.ForeColor = 'White'
    $installGroupBox.Controls.Add($networkdriver)

    $installBrowsers = New-Object Windows.Forms.Button
    $installBrowsers.Text = 'Install Browsers'
    $installBrowsers.Location = New-Object Drawing.Point(240, 60)
    $installBrowsers.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $installBrowsers.Add_Click({
            $form.Visible = $false
            install-browsers
            $form.Visible = $true
        })
    $installBrowsers.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $installBrowsers.ForeColor = 'White'
    $installGroupBox.Controls.Add($installBrowsers)

    $cleanup = New-Object Windows.Forms.Button
    $cleanup.Text = 'Ultimate Cleanup'
    $cleanup.Location = New-Object Drawing.Point(18, 160)
    $cleanup.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $cleanup.Add_Click({
            $form.Visible = $false
            UltimateCleanup
            $form.Visible = $true
        })
    $cleanup.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $cleanup.ForeColor = 'White'
    $tabPage2.Controls.Add($cleanup)

    $activate = New-Object Windows.Forms.Button
    $activate.Text = 'Activate Windows'
    $activate.Location = New-Object Drawing.Point(248, 160)
    $activate.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $activate.Add_Click({
            $form.Visible = $false
            install-key
            $form.Visible = $true
        })
    $activate.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $activate.ForeColor = 'White'
    $tabPage2.Controls.Add($activate)

    # Add buttons outside of tabs 
    $buttonY = 320  
    $buttonWidth = 110
    $buttonHeight = 33
    $buttonSpacing = 10
    $startX = 10  

    $restoreButton = New-Object Windows.Forms.Button
    $restoreButton.Text = 'Restore Tweaks'
    $restoreButton.Location = New-Object Drawing.Point($startX, $buttonY)
    $restoreButton.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $restoreButton.Add_Click({
            $form.Visible = $false
            $restore = Search-File '*Restore.ps1' 
            &$restore
            $form.Visible = $true
        })
    $restoreButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $restoreButton.ForeColor = 'White'
    $form.Controls.Add($restoreButton)

    $configButton = New-Object Windows.Forms.Button
    $configButton.Text = 'Import/Export Config'
    $configButton.Location = New-Object Drawing.Point(($startX + $buttonWidth + $buttonSpacing), $buttonY)
    $configButton.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $configButton.Add_Click({
            $form.Visible = $false
            $configUI = Search-File '*configUI.ps1' 
            &$configUI
            $form.Visible = $true
        })
    $configButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30) 
    $configButton.ForeColor = 'White'
    $form.Controls.Add($configButton)

    $otherscriptsbttn = New-Object Windows.Forms.Button
    $otherscriptsbttn.Text = 'Install Other Scripts'
    $otherscriptsbttn.Location = New-Object Drawing.Point(($startX + ($buttonWidth + $buttonSpacing) * 2), $buttonY)
    $otherscriptsbttn.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $otherscriptsbttn.Add_Click({
            $form.Visible = $false
            $otherScriptsUI = Search-File '*Install-OtherScripts.ps1' 
            &$otherScriptsUI
            $form.Visible = $true
        })
    $otherscriptsbttn.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30) 
    $otherscriptsbttn.ForeColor = 'White'
    $form.Controls.Add($otherscriptsbttn)

    $restartButton = New-Object Windows.Forms.Button
    $restartButton.Text = 'Restart PC'
    $restartButton.Location = New-Object Drawing.Point(($startX + ($buttonWidth + $buttonSpacing) * 3), $buttonY)
    $restartButton.Size = New-Object Drawing.Size($buttonWidth, $buttonHeight)
    $restartButton.Add_Click({
            $form.Visible = $false
            restart-pc
        })
    $restartButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $restartButton.ForeColor = 'White'
    $form.Controls.Add($restartButton)

    

    $result = $form.ShowDialog()
} while ($result -ne [System.Windows.Forms.DialogResult]::Cancel)

# Dispose of the form when it's closed
$form.Dispose()
