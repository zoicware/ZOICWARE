
$host.ui.RawUI.WindowTitle = 'ZOICWARE'  

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
$Global:nsudo = (Get-ChildItem -Path $folder, $sysDrive -Filter NSudoLG.exe -Recurse -File -ErrorAction SilentlyContinue -Force | Where-Object Name -NotIn '$Recycle.Bin' | Select-Object -First 1).FullName
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
    #check that the folder is correct version
    $currentVersion = 'v1.1.6'
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
    $form.Size = New-Object Drawing.Size(500, 520)
    $form.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

    # Create 9 buttons and add them to the form
    $button1 = New-Object Windows.Forms.Button
    $button1.Text = 'Install Necessary Packages'
    $button1.Location = New-Object Drawing.Point(20, 20)
    $button1.Size = New-Object Drawing.Size(200, 40)
    $button1.Add_Click({

            $form.Visible = $false
            install-packs
            $form.Visible = $true

        })
    $button1.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button1.ForeColor = [System.Drawing.Color]::White
    $button1.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button1.FlatAppearance.BorderSize = 0
    $button1.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $button1.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($button1)


    $button2 = New-Object Windows.Forms.Button
    $button2.Text = 'Import Registry Tweaks'
    $button2.Location = New-Object Drawing.Point(20, 80)
    $button2.Size = New-Object Drawing.Size(200, 40)
    $button2.Add_Click({

            $form.Visible = $false
            import-reg
            $form.Visible = $true

        })
    $button2.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button2.ForeColor = [System.Drawing.Color]::White
    $button2.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button2.FlatAppearance.BorderSize = 0
    $button2.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $button2.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($button2)

    $button3 = New-Object Windows.Forms.Button
    $button3.Text = 'Remove Scheduled Tasks'
    $button3.Location = New-Object Drawing.Point(20, 140)
    $button3.Size = New-Object Drawing.Size(200, 40)
    $button3.Add_Click({

            $form.Visible = $false
            remove-tasks
            $form.Visible = $true

        })
    $button3.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button3.ForeColor = [System.Drawing.Color]::White
    $button3.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button3.FlatAppearance.BorderSize = 0
    $button3.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $button3.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($button3)

    $button4 = New-Object Windows.Forms.Button
    $button4.Text = 'Group Policy Tweaks'
    $button4.Location = New-Object Drawing.Point(20, 200)
    $button4.Size = New-Object Drawing.Size(200, 40)
    $button4.Add_Click({

            $form.Visible = $false
            gpTweaks 
            $form.Visible = $true

        })
    $button4.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button4.ForeColor = [System.Drawing.Color]::White
    $button4.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button4.FlatAppearance.BorderSize = 0
    $button4.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $button4.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($button4)

    $button5 = New-Object Windows.Forms.Button
    $button5.Text = 'Disable Services'
    $button5.Location = New-Object Drawing.Point(250, 20)
    $button5.Size = New-Object Drawing.Size(200, 40)
    $button5.Add_Click({

            $form.Visible = $false
            disable-services
            $form.Visible = $true

        })
    $button5.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button5.ForeColor = [System.Drawing.Color]::White
    $button5.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button5.FlatAppearance.BorderSize = 0
    $button5.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $button5.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($button5)

    $button6 = New-Object Windows.Forms.Button
    $button6.Text = 'Debloat'
    $button6.Location = New-Object Drawing.Point(250, 80)
    $button6.Size = New-Object Drawing.Size(200, 40)
    $button6.Add_Click({

            $form.Visible = $false
            debloat 
            $form.Visible = $true

        })
    $button6.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button6.ForeColor = [System.Drawing.Color]::White
    $button6.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button6.FlatAppearance.BorderSize = 0
    $button6.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $button6.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($button6)

    $button7 = New-Object Windows.Forms.Button
    $button7.Text = 'Optional Tweaks'
    $button7.Location = New-Object Drawing.Point(250, 140)
    $button7.Size = New-Object Drawing.Size(200, 40)
    $button7.Add_Click({

            $form.Visible = $false
            OptionalTweaks 
            $form.Visible = $true

        })
    $button7.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button7.ForeColor = [System.Drawing.Color]::White
    $button7.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button7.FlatAppearance.BorderSize = 0
    $button7.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $button7.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($button7)

    $button8 = New-Object Windows.Forms.Button
    $button8.Text = 'Import/Remove Power Plans'
    $button8.Location = New-Object Drawing.Point(250, 200)
    $button8.Size = New-Object Drawing.Size(200, 40)
    $button8.Add_Click({

            $form.Visible = $false
            import-powerplan
            $form.Visible = $true

        })
    $button8.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button8.ForeColor = [System.Drawing.Color]::White
    $button8.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button8.FlatAppearance.BorderSize = 0
    $button8.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $button8.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($button8)

    $button9 = New-Object Windows.Forms.Button
    $button9.Text = 'Run Tweaks in Order'
    $button9.Location = New-Object Drawing.Point(150, 260)
    $button9.Size = New-Object Drawing.Size(180, 30)
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
    $button9.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $button9.ForeColor = [System.Drawing.Color]::White
    $button9.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $button9.FlatAppearance.BorderSize = 0
    $button9.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $button9.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($button9)


    $restartButton = New-Object Windows.Forms.Button
    $restartButton.Text = 'Restart PC'
    $restartButton.Location = New-Object Drawing.Point(130, 300)
    $restartButton.Size = New-Object Drawing.Size(100, 30)
    $restartButton.Add_Click({
            $form.Visible = $false
            restart-pc
        })
    $restartButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $restartButton.ForeColor = [System.Drawing.Color]::White
    $restartButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $restartButton.FlatAppearance.BorderSize = 0
    $restartButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $restartButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
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
    $cleanup.Location = New-Object Drawing.Point(240, 300)
    $cleanup.Size = New-Object Drawing.Size(100, 30)
    $cleanup.Add_Click({
            $form.Visible = $false
            UltimateCleanup
            $form.Visible = $true
        })
    $cleanup.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $cleanup.ForeColor = [System.Drawing.Color]::White
    $cleanup.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $cleanup.FlatAppearance.BorderSize = 0
    $cleanup.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $cleanup.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($cleanup)


    $win11tweaks = New-Object Windows.Forms.Button
    $win11tweaks.Text = 'Windows 11 Tweaks >'
    $win11tweaks.Location = New-Object Drawing.Point(320, 430)
    $win11tweaks.Size = New-Object Drawing.Size(130, 30)
    $win11tweaks.Add_Click({
            $form.Visible = $false
            W11Tweaks
            $form.Visible = $true
        })
    $win11tweaks.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $win11tweaks.ForeColor = [System.Drawing.Color]::White
    $win11tweaks.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $win11tweaks.FlatAppearance.BorderSize = 0
    $win11tweaks.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $win11tweaks.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($win11tweaks)

    $nvtweaks = New-Object Windows.Forms.Button
    $nvtweaks.Text = 'Install Nvidia Driver >'
    $nvtweaks.Location = New-Object Drawing.Point(320, 390)
    $nvtweaks.Size = New-Object Drawing.Size(130, 30)
    $nvtweaks.Add_Click({
            $form.Visible = $false
            $nvscript = Search-File '*NVScriptInstaller.ps1'
            &$nvscript
            $form.Visible = $true
        })
    $nvtweaks.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $nvtweaks.ForeColor = [System.Drawing.Color]::White
    $nvtweaks.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $nvtweaks.FlatAppearance.BorderSize = 0
    $nvtweaks.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $nvtweaks.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($nvtweaks)

    $networkdriver = New-Object Windows.Forms.Button
    $networkdriver.Text = 'Install Network Driver >'
    $networkdriver.Location = New-Object Drawing.Point(320, 350)
    $networkdriver.Size = New-Object Drawing.Size(130, 30)
    $networkdriver.Add_Click({
            $form.Visible = $false
            $networkInstaller = Search-File '*LocalNetworkInstaller.ps1'
            &$networkInstaller
            $form.Visible = $true
        })
    $networkdriver.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $networkdriver.ForeColor = [System.Drawing.Color]::White
    $networkdriver.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $networkdriver.FlatAppearance.BorderSize = 0
    $networkdriver.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $networkdriver.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($networkdriver)


    $activate = New-Object Windows.Forms.Button
    $activate.Text = 'Activate Windows'
    $activate.Location = New-Object Drawing.Point(30, 430)
    $activate.Size = New-Object Drawing.Size(130, 30)
    $activate.Add_Click({
            $form.Visible = $false
            install-key
            $form.Visible = $true
        })
    $activate.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $activate.ForeColor = [System.Drawing.Color]::White
    $activate.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $activate.FlatAppearance.BorderSize = 0
    $activate.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $activate.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($activate)


    $configButton = New-Object Windows.Forms.Button
    $configButton.Text = 'Import/Export Config'
    $configButton.Location = New-Object Drawing.Point(30, 390)
    $configButton.Size = New-Object Drawing.Size(130, 30)
    $configButton.Add_Click({
            $form.Visible = $false
            $configUI = Search-File '*configUI.ps1' 
            &$configUI
            $form.Visible = $true
        })
    $configButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $configButton.ForeColor = [System.Drawing.Color]::White
    $configButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $configButton.FlatAppearance.BorderSize = 0
    $configButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $configButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $form.Controls.Add($configButton)

    $result = $form.ShowDialog()
} while ($result -ne [System.Windows.Forms.DialogResult]::Cancel)

# Dispose of the form when it's closed
$form.Dispose()




 