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






$currentVersion = 'v1.1.9'


$host.ui.RawUI.WindowTitle = 'ZOICWARE ', $currentVersion  

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

Write-Host "Searching for functions in $sysDrive"
$Global:folder = (Get-ChildItem -Path $sysDrive -Filter '_FOLDERMUSTBEONCDRIVE' -Recurse -Directory -ErrorAction SilentlyContinue -Force | Where-Object Name -NotIn '$Recycle.Bin' | Select-Object -First 1).FullName
$pack = $folder -replace '\\_FOLDERMUSTBEONCDRIVE' , ''
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
if ($folder -ne $null) {
    try {
        #check github for update
        $headers = @{
            'User-Agent' = 'PowerShell'
        }
        $apiUrl = 'https://api.github.com/repos/zoicware/ZOICWARE/releases/latest'
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -UseBasicParsing -ErrorAction Stop
        $latestVer = $response.tag_name

        #check folder version
        if (!(Test-Path "$folder\$latestVer" -PathType Leaf)) {
            #folder is not updated 
            [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
            $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Install Newer Version of Zoicware?', 'zoicware', 'YesNo', 'Question')
            switch ($msgBoxInput) {
                'Yes' {
                    #get latest download link from github releases
                    $response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
                    $downloadLink = $response.body

                    Get-FileFromWeb -URL $downloadLink -File "$env:TEMP\ZOICWARE.zip"
                    #replace pack
                    Expand-Archive -Path "$env:TEMP\ZOICWARE.zip" -DestinationPath $env:TEMP -Force
                    Rename-Item "$env:TEMP\zoicwareOS" -NewName "zoicwareOS$latestVer" -Force  
                    Move-Item "$env:TEMP\zoicwareOS$latestVer" -Destination "$env:USERPROFILE\Desktop" -Force
                    Remove-Item -Path "$env:TEMP\ZOICWARE.zip" -Force -ErrorAction SilentlyContinue
                    #rename old folder
                    Rename-Item $folder -NewName 'OLD' -Force
                    #start zoicware
                    Start-Process "$env:USERPROFILE\Desktop\zoicwareOS$latestver\1 Setup\RUN ZOICWARE.exe"
                    exit
                }
                'No' {}
            }
        }
    }
    catch {
        #no internet
    }
    


    #check that the folder is correct version
    if (Test-Path "$folder\$currentVersion" -PathType Leaf) {
        $modulePath = "$folder\zFunctions.psm1"
        $winfetchModule = "$folder\winfetch.psm1"
        Import-Module -Name $modulePath -Force -Global 
        Import-Module -Name $winfetchModule -Force
    }
    else {
        Write-Host "Latest Functions NOT Found...Make sure you do not have older versions of zoicware on $sysDrive"
        Write-Host 'Press any Key to Exit: '
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        exit
    }
   
}
else {
    Write-Warning "Functions NOT Found on $sysDrive" 
    Write-Host 'Press any Key to Exit: '
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
    exit
}


#set ps console to be slightly transparent
Set-ConsoleOpacity -Opacity 93

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
# (0-4) 1:Remove all 2:Power saver 3:Balanced 4:High performance
removeallPlans = 0 
rPowersaver = 0
rBalanced = 0
rHighPerformance = 0
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
#LEGACY FEATURES TWEAKS
legacyPhotoViewer = 0
legacy7calc = 0
legacy7task = 0
legacyVolumeFlyout = 0
legacyAltTab = 0 
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
    Write-Host 'Checking if Config is Updated...'
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
                Write-Host "Updating Config with [$($settingName[0].trim())]" -ForegroundColor Red
                #add newline before adding content instead of after (-nonewline)
                #trim new line from $line
                Add-Content -Path $config -Value "$([Environment]::NewLine)$($line.Trim())" -NoNewline -Force
            }
        }
    }

}





function restart-pc {

    [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer', 'zoicware', 'YesNo', 'Question')

    switch ($msgBoxInput) {

        'Yes' {
            #setting execution policy back to remote signed  
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'Path' /t REG_SZ /d 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' /f
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'RemoteSigned' /f
            Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'Path' /t REG_SZ /d 'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe' /f
            Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'RemoteSigned' /f
            #you can guess what this does
            Restart-Computer
        }

        'No' {


            Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'Path' /t REG_SZ /d 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' /f
            Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'RemoteSigned' /f
            Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'Path' /t REG_SZ /d 'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe' /f
            Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'RemoteSigned' /f


        }

    }

}





#do while with gui menu 

do {


    # Load the necessary assemblies for Windows Forms
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    [System.Windows.Forms.Application]::EnableVisualStyles()
    
    # Create a form
    $form = New-Object Windows.Forms.Form
    $form.Text = 'ZOICWARE'
    $form.Size = New-Object Drawing.Size(500, 580)
    $form.BackColor = 'Black'
   

    #group boxes
    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text = 'Windows Tweaks'
    $groupBox.Size = New-Object System.Drawing.Size(450, 280)
    $groupBox.Location = New-Object System.Drawing.Point(15, 10)
    $groupBox.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    $groupBox.ForeColor = 'White'
    $form.Controls.Add($groupBox)

    $groupBox2 = New-Object System.Windows.Forms.GroupBox
    $groupBox2.Text = 'Post Tweak Setup'
    $groupBox2.Size = New-Object System.Drawing.Size(300, 200)
    $groupBox2.Location = New-Object System.Drawing.Point(15, 320)
    $groupBox2.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    $groupBox2.ForeColor = 'White'
    $form.Controls.Add($groupBox2)

    # Create 9 buttons and add them to the form
    $button1 = New-Object Windows.Forms.Button
    $button1.Text = 'Install Necessary Packages'
    $button1.Location = New-Object Drawing.Point(20, 20)
    $button1.Size = New-Object Drawing.Size(150, 33)
    $button1.Add_Click({

            $form.Visible = $false
            install-packs
            $form.Visible = $true

        })
    $button1.BackColor = 'Gray'
    $button1.ForeColor = 'White'
    # $button1.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    # $button1.FlatAppearance.BorderSize = 0
    # $button1.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    # $button1.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox.Controls.Add($button1)

    $button2 = New-Object Windows.Forms.Button
    $button2.Text = 'Import Registry Tweaks'
    $button2.Location = New-Object Drawing.Point(20, 80)
    $button2.Size = New-Object Drawing.Size(150, 33)
    $button2.Add_Click({

            $form.Visible = $false
            import-reg
            $form.Visible = $true

        })
    $button2.BackColor = 'Gray'
    $button2.ForeColor = 'White'
    # $button2.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    # $button2.FlatAppearance.BorderSize = 0
    # $button2.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    # $button2.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox.Controls.Add($button2)

    $button3 = New-Object Windows.Forms.Button
    $button3.Text = 'Remove Scheduled Tasks'
    $button3.Location = New-Object Drawing.Point(20, 140)
    $button3.Size = New-Object Drawing.Size(150, 33)
    $button3.Add_Click({

            $form.Visible = $false
            remove-tasks
            $form.Visible = $true

        })
    $button3.BackColor = 'Gray'
    $button3.ForeColor = 'White'
    #$button3.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$button3.FlatAppearance.BorderSize = 0
    #$button3.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$button3.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox.Controls.Add($button3)

    $button4 = New-Object Windows.Forms.Button
    $button4.Text = 'Group Policy Tweaks'
    $button4.Location = New-Object Drawing.Point(20, 200)
    $button4.Size = New-Object Drawing.Size(150, 33)
    $button4.Add_Click({

            $form.Visible = $false
            gpTweaks 
            $form.Visible = $true

        })
    $button4.BackColor = 'Gray'
    $button4.ForeColor = 'White'
    #$button4.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$button4.FlatAppearance.BorderSize = 0
    #$button4.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$button4.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox.Controls.Add($button4)

    $button5 = New-Object Windows.Forms.Button
    $button5.Text = 'Disable Services'
    $button5.Location = New-Object Drawing.Point(250, 20)
    $button5.Size = New-Object Drawing.Size(150, 33)
    $button5.Add_Click({

            $form.Visible = $false
            disable-services
            $form.Visible = $true

        })
    $button5.BackColor = 'Gray'
    $button5.ForeColor = 'White'
    #$button5.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$button5.FlatAppearance.BorderSize = 0
    #$button5.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$button5.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox.Controls.Add($button5)

    $button6 = New-Object Windows.Forms.Button
    $button6.Text = 'Debloat'
    $button6.Location = New-Object Drawing.Point(250, 80)
    $button6.Size = New-Object Drawing.Size(150, 33)
    $button6.Add_Click({

            $form.Visible = $false
            debloat 
            $form.Visible = $true

        })
    $button6.BackColor = 'Gray'
    $button6.ForeColor = 'White'
    #$button6.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$button6.FlatAppearance.BorderSize = 0
    #$button6.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$button6.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox.Controls.Add($button6)

    $button7 = New-Object Windows.Forms.Button
    $button7.Text = 'Optional Tweaks'
    $button7.Location = New-Object Drawing.Point(250, 140)
    $button7.Size = New-Object Drawing.Size(150, 33)
    $button7.Add_Click({

            $form.Visible = $false
            OptionalTweaks 
            $form.Visible = $true

        })
    $button7.BackColor = 'Gray'
    $button7.ForeColor = 'White'
    #$button7.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$button7.FlatAppearance.BorderSize = 0
    #$button7.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$button7.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox.Controls.Add($button7)

    $button8 = New-Object Windows.Forms.Button
    $button8.Text = 'Import/Remove Power Plans'
    $button8.Location = New-Object Drawing.Point(250, 200)
    $button8.Size = New-Object Drawing.Size(150, 33)
    $button8.Add_Click({

            $form.Visible = $false
            import-powerplan
            $form.Visible = $true

        })
    $button8.BackColor = 'Gray'
    $button8.ForeColor = 'White'
    #$button8.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$button8.FlatAppearance.BorderSize = 0
    #$button8.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$button8.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox.Controls.Add($button8)

    $button9 = New-Object Windows.Forms.Button
    $button9.Text = 'Run Tweaks in Order'
    $button9.Location = New-Object Drawing.Point(120, 245)
    $button9.Size = New-Object Drawing.Size(180, 25)
    $button9.Add_Click({
            $form.Visible = $false
            install-packs
            import-reg
            remove-tasks
            gpTweaks
            disable-services
            debloat
            OptionalTweaks
            import-powerplan
            restart-pc
        })
    $button9.BackColor = 'Gray'
    $button9.ForeColor = 'White'
    #$button9.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$button9.FlatAppearance.BorderSize = 0
    #$button9.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$button9.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox.Controls.add($button9)


    $restartButton = New-Object Windows.Forms.Button
    $restartButton.Text = 'Restart PC'
    $restartButton.Location = New-Object Drawing.Point(345, 490)
    $restartButton.Size = New-Object Drawing.Size(130, 30)
    $restartButton.Add_Click({
            $form.Visible = $false
            restart-pc
        })
    $restartButton.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    $restartButton.ForeColor = 'White'
    #$restartButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$restartButton.FlatAppearance.BorderSize = 0
    #$restartButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$restartButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($restartButton)



    $restoreButton = New-Object Windows.Forms.Button
    $restoreButton.Text = 'Restore Changes'
    $restoreButton.Location = New-Object Drawing.Point(30, 350)
    $restoreButton.Size = New-Object Drawing.Size(130, 30)
    $restoreButton.Add_Click({
            $form.Visible = $false
            $restore = Search-File '*Restore.ps1' 
            &$restore
            $form.Visible = $true
        })
    $restoreButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $restoreButton.ForeColor = [System.Drawing.Color]::White
    $restoreButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $restoreButton.FlatAppearance.BorderSize = 0
    $restoreButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $restoreButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($restoreButton)


    $cleanup = New-Object Windows.Forms.Button
    $cleanup.Text = 'Ultimate Cleanup'
    $cleanup.Location = New-Object Drawing.Point(15, 80)
    $cleanup.Size = New-Object Drawing.Size(130, 30)
    $cleanup.Add_Click({
            $form.Visible = $false
            UltimateCleanup
            $form.Visible = $true
        })
    $cleanup.BackColor = 'Gray'
    $cleanup.ForeColor = 'White'
    #$cleanup.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$cleanup.FlatAppearance.BorderSize = 0
    #$cleanup.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$cleanup.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox2.Controls.add($cleanup)


    $win11tweaks = New-Object Windows.Forms.Button
    $win11tweaks.Text = 'Windows 11 Tweaks'
    $win11tweaks.Location = New-Object Drawing.Point(150, 80)
    $win11tweaks.Size = New-Object Drawing.Size(130, 30)
    $win11tweaks.Add_Click({
            $form.Visible = $false
            W11Tweaks
            $form.Visible = $true
        })
    $win11tweaks.BackColor = 'Gray'
    $win11tweaks.ForeColor = 'White'
    #$win11tweaks.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$win11tweaks.FlatAppearance.BorderSize = 0
    #$win11tweaks.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$win11tweaks.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox2.Controls.add($win11tweaks)

    $nvtweaks = New-Object Windows.Forms.Button
    $nvtweaks.Text = 'Install Nvidia Driver'
    $nvtweaks.Location = New-Object Drawing.Point(150, 30)
    $nvtweaks.Size = New-Object Drawing.Size(130, 30)
    $nvtweaks.Add_Click({
            $form.Visible = $false
            $nvscript = Search-File '*NVScriptInstaller.ps1'
            &$nvscript
            $form.Visible = $true
        })
    $nvtweaks.BackColor = 'Gray'
    $nvtweaks.ForeColor = 'White'
    #$nvtweaks.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$nvtweaks.FlatAppearance.BorderSize = 0
    #$nvtweaks.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$nvtweaks.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox2.Controls.add($nvtweaks)

    $networkdriver = New-Object Windows.Forms.Button
    $networkdriver.Text = 'Install Network Driver'
    $networkdriver.Location = New-Object Drawing.Point(15, 30)
    $networkdriver.Size = New-Object Drawing.Size(130, 30)
    $networkdriver.Add_Click({
            $form.Visible = $false
            $networkInstaller = Search-File '*LocalNetworkInstaller.ps1'
            &$networkInstaller
            $form.Visible = $true
        })
    $networkdriver.BackColor = 'Gray'
    $networkdriver.ForeColor = 'White'
    #$networkdriver.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$networkdriver.FlatAppearance.BorderSize = 0
    #$networkdriver.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$networkdriver.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox2.Controls.add($networkdriver)


    $activate = New-Object Windows.Forms.Button
    $activate.Text = 'Activate Windows'
    $activate.Location = New-Object Drawing.Point(80, 120)
    $activate.Size = New-Object Drawing.Size(130, 30)
    $activate.Add_Click({
            $form.Visible = $false
            install-key
            $form.Visible = $true
        })
    $activate.BackColor = 'Gray'
    $activate.ForeColor = 'White'
    #$activate.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$activate.FlatAppearance.BorderSize = 0
    #$activate.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$activate.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $groupBox2.Controls.Add($activate)


    $configButton = New-Object Windows.Forms.Button
    $configButton.Text = 'Import && Export Config'
    $configButton.Location = New-Object Drawing.Point(345, 445)
    $configButton.Size = New-Object Drawing.Size(130, 30)
    $configButton.Add_Click({
            $form.Visible = $false
            $configUI = Search-File '*configUI.ps1' 
            &$configUI
            $form.Visible = $true
        })
    $configButton.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)
    $configButton.ForeColor = 'White'
    #$configButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    #$configButton.FlatAppearance.BorderSize = 0
    #$configButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    #$configButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($configButton)

    $result = $form.ShowDialog()
} while ($result -ne [System.Windows.Forms.DialogResult]::Cancel)

# Dispose of the form when it's closed
$form.Dispose()

