@(set "0=%~f0"^)#) & powershell -nop -c iex([io.file]::ReadAllText($env:0)) & exit /b
sp 'HKCU:\Volatile Environment' 'Windows_Optimizer' @'


$host.ui.RawUI.WindowTitle = 'ZOICWARE'  

#windows 10 22h2 automatic setup script by zoic and help from Narf

#if not ran as admin ask for admin rights
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}


try{
if((Get-ItemPropertyValue -path registry::HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -name "ExecutionPolicy") -ne "Bypass" -or (Get-ItemPropertyValue -path registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell -name "ExecutionPolicy") -ne "Bypass"){
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Bypass" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Bypass" /f


}

}catch{
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Bypass" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Bypass" /f

}



#changes console to black
function color ($bc,$fc) {
$a = (Get-Host).UI.RawUI
$a.BackgroundColor = $bc
$a.ForegroundColor = $fc ; cls}	

color "black" "white"


#create cfg 
$config = "$env:TEMP\ZCONFIG.cfg"
if(!(Test-Path -Path "$env:TEMP\ZCONFIG.cfg")){
$var = New-Item -Path $config -ItemType File -Force

$configContent = @"
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
openableGameBar = 0
opblockRazerAsus = 0
opremoveNetworkIcon = 0
opapplyPBO = 0
opnoDriversInUpdate = 0
opremoveBackupApp = 0
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
#LEGACY FEATURES TWEAKS
legacyPhotoViewer = 0
legacy7calc = 0
legacySnipping = 0
legacy7task = 0
legacyVolumeFlyout = 0
legacyAltTab = 0 
#WIN 11 TWEAKS
removeEdges = 0
10TaskbarStartmenu = 0
10Explorer = 0
servicesManual = 0
"@

Add-Content -Path $config -Value $configContent -Force

}

#dot sourcing for functions
$folder = Get-ChildItem -path C:\ -Filter _FOLDERMUSTBEONCDRIVE -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; }
$functions = Get-ChildItem "$folder\Functions" -Filter *.ps1 -Recurse -Force
foreach($func in $functions){
  .$func.FullName
}



function restart-pc {

[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  #setting execution policy back to remote signed  
  Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f
#you can guess what this does
Restart-Computer
 }

'No'{


Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "Path" /t REG_SZ /d "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "RemoteSigned" /f


	}

}

}





#do while with gui menu 

do {


# Load the necessary assemblies for Windows Forms
[void][System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

# Create a form
$form = New-Object Windows.Forms.Form
$form.Text = "ZOICWARE"
$form.Size = New-Object Drawing.Size(500, 500)

# Create 9 buttons and add them to the form
$button1 = New-Object Windows.Forms.Button
$button1.Text = "Install Necessary Packages"
$button1.Location = New-Object Drawing.Point(20, 20)
$button1.Size = New-Object Drawing.Size(200, 40)
$button1.Add_Click({

$form.Visible = $false
install-packs
$form.Visible = $true

})
$form.Controls.Add($button1)


$button2 = New-Object Windows.Forms.Button
$button2.Text = "Import Registry Tweaks"
$button2.Location = New-Object Drawing.Point(20, 80)
$button2.Size = New-Object Drawing.Size(200, 40)
$button2.Add_Click({

$form.Visible = $false
import-reg
$form.Visible = $true

})
$form.Controls.Add($button2)

$button3 = New-Object Windows.Forms.Button
$button3.Text = "Remove Scheduled Tasks"
$button3.Location = New-Object Drawing.Point(20, 140)
$button3.Size = New-Object Drawing.Size(200, 40)
$button3.Add_Click({

$form.Visible = $false
remove-tasks
$form.Visible = $true

})
$form.Controls.Add($button3)

$button4 = New-Object Windows.Forms.Button
$button4.Text = "Group Policy Tweaks"
$button4.Location = New-Object Drawing.Point(20, 200)
$button4.Size = New-Object Drawing.Size(200, 40)
$button4.Add_Click({

$form.Visible = $false
gpTweaks 
$form.Visible = $true

})
$form.Controls.Add($button4)

$button5 = New-Object Windows.Forms.Button
$button5.Text = "Disable Services"
$button5.Location = New-Object Drawing.Point(250, 20)
$button5.Size = New-Object Drawing.Size(200, 40)
$button5.Add_Click({

$form.Visible = $false
disable-services
$form.Visible = $true

})
$form.Controls.Add($button5)

$button6 = New-Object Windows.Forms.Button
$button6.Text = "Debloat"
$button6.Location = New-Object Drawing.Point(250, 80)
$button6.Size = New-Object Drawing.Size(200, 40)
$button6.Add_Click({

$form.Visible = $false
debloat 
$form.Visible = $true

})
$form.Controls.Add($button6)

$button7 = New-Object Windows.Forms.Button
$button7.Text = "Optional Tweaks"
$button7.Location = New-Object Drawing.Point(250, 140)
$button7.Size = New-Object Drawing.Size(200, 40)
$button7.Add_Click({

$form.Visible = $false
OptionalTweaks 
$form.Visible = $true

})
$form.Controls.Add($button7)

$button8 = New-Object Windows.Forms.Button
$button8.Text = "Import/Remove Power Plans"
$button8.Location = New-Object Drawing.Point(250, 200)
$button8.Size = New-Object Drawing.Size(200, 40)
$button8.Add_Click({

$form.Visible = $false
import-powerplan
$form.Visible = $true

})
$form.Controls.Add($button8)

$button9 = New-Object Windows.Forms.Button
$button9.Text = "Run From Start"
$button9.Location = New-Object Drawing.Point(135, 280)
$button9.Size = New-Object Drawing.Size(200, 40)
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
$form.Controls.Add($button9)


$restartButton = New-Object Windows.Forms.Button
$restartButton.Text = "Restart PC"
$restartButton.Location = New-Object Drawing.Point(90, 340)
$restartButton.Size = New-Object Drawing.Size(120, 30)
$restartButton.Add_Click({
    $form.Visible = $false
    restart-pc
})
$form.Controls.Add($restartButton)



$restoreButton = New-Object Windows.Forms.Button
$restoreButton.Text = "Restore Changes"
$restoreButton.Location = New-Object Drawing.Point(250, 340)
$restoreButton.Size = New-Object Drawing.Size(120, 30)
$restoreButton.Add_Click({
    $form.Visible = $false
    $restore = Get-ChildItem -path C:\ -Filter Restore.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; } 
    &$restore
    $form.Visible = $true
})
$form.Controls.Add($restoreButton)


$win11tweaks = New-Object Windows.Forms.Button
$win11tweaks.Text = "Windows 11 Tweaks >"
$win11tweaks.Location = New-Object Drawing.Point(320, 410)
$win11tweaks.Size = New-Object Drawing.Size(130, 30)
$win11tweaks.Add_Click({
    $form.Visible = $false
    W11Tweaks
    $form.Visible = $true
})
$form.Controls.Add($win11tweaks)


$configButton = New-Object Windows.Forms.Button
$configButton.Text = "Import/Export Config"
$configButton.Location = New-Object Drawing.Point(30, 410)
$configButton.Size = New-Object Drawing.Size(130, 30)
$configButton.Add_Click({
    $form.Visible = $false
    $configUI = Get-ChildItem -path C:\ -Filter configUI.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; } 
    &$configUI
    $form.Visible = $true
})
$form.Controls.Add($configButton)

    $result = $form.ShowDialog()
} while ($result -ne [System.Windows.Forms.DialogResult]::Cancel)

# Dispose of the form when it's closed
$form.Dispose()





'@.replace("$@","'@").replace("@$","@'") -force -ea 0;
$A = '-nop -noe -c & {iex((gp ''Registry::HKEY_Users\S-1-5-21*\Volatile*'' Windows_Optimizer -ea 0)[0].Windows_Optimizer)}'
start powershell -args $A -verb runas
$_Press_Enter   
 