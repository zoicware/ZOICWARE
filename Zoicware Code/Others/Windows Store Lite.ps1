#install common uwp apps without the windows store by zoic
#if updates are disabled the script may need to enable them temporarily to install the app properly
#all settings changed will be reverted when done if you choose

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}


Write-host "---------- Checking Dependencies -----------"


    #check for updates disabled
   $service= Get-Service -Name 'UsoSvc'
   $reg= Get-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -ErrorAction SilentlyContinue
    
if($service.StartType -eq "Disabled" -or $reg -ne $null){
Write-host "ENABLING UPDATES..."
    $pause = (Get-Date).AddDays(365); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause

    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "WUServer" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "WUStatusServer" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "UpdateServiceUrlAlternate" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetProxyBehaviorForUpdateDetection" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /f
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "UseWUServer" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "DelayedAutoStart" /t REG_DWORD /d "0" /f

gpupdate /force

[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Updates have been Enabled and Paused. You can choose to disable them after installing your desired apps','zoicware')


}


#check for appx service running
$appxSvc = Get-WmiObject -Class Win32_Service | Where-Object { $_.Name -eq "AppXSvc" }
$start = $appxSvc.StartMode

if($appxSvc.State -ne "Running" -and $start -eq "Disabled"){
Write-host "-------------- APPX Service Disabled ------------"
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AppXSvc" /v "Start" /t REG_DWORD /d "3" /f
 [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('APPX Service Enabled, Please restart and run again.','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  Restart-Computer
  }

  
  'No'{exit}

}

}


#check for winget package

$winget=Get-AppxPackage -Name Microsoft.DesktopAppInstaller

if($winget -eq $null){
Write-host "INSTALLING WINGET..."

# Get the download URL of the latest winget installer from GitHub:
$API_URL = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
$DOWNLOAD_URL = $(Invoke-RestMethod -UseBasicParsing $API_URL).assets.browser_download_url | Where-Object {$_.EndsWith(".msixbundle")}

# Download the installer:
$progressPreference = 'silentlyContinue'
Invoke-WebRequest -URI $DOWNLOAD_URL -OutFile winget.msixbundle -UseBasicParsing

# Install winget:

$progressPreference = 'silentlyContinue'
Invoke-WebRequest -URI https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.3 -OutFile xaml.zip -UseBasicParsing
New-Item -ItemType Directory -Path xaml
Expand-Archive -Path xaml.zip -DestinationPath xaml
Add-AppxPackage -Path "xaml\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx"
Remove-Item xaml.zip
Remove-Item xaml -Recurse

$progressPreference = 'silentlyContinue'
Invoke-WebRequest -URI https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -OutFile UWPDesktop.appx -UseBasicParsing
Add-AppxPackage UWPDesktop.appx
Remove-Item UWPDesktop.appx

Add-AppxPackage winget.msixbundle -ErrorAction Stop




# Remove the installer:
Remove-Item winget.msixbundle
}


$checkboxes = @()
$apps = @()

[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    
    # Set the size of your form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Windows Store Lite'
    $form.Size = New-Object System.Drawing.Size(500,500)
    $form.StartPosition = 'CenterScreen'


    $checkbox2 = new-object System.Windows.Forms.checkbox
    $checkbox2.Location = new-object System.Drawing.Size(10,30)
    $checkbox2.Size = new-object System.Drawing.Size(150,20)
    $checkbox2.Text = "Xbox"
    $checkbox2.Tag = "9MV0B5HZVK9Z"
    $checkbox2.Checked = $false
    $Form.Controls.Add($checkbox2)  
    $checkboxes += $checkbox2

    $checkbox3 = new-object System.Windows.Forms.checkbox
    $checkbox3.Location = new-object System.Drawing.Size(10,60)
    $checkbox3.Size = new-object System.Drawing.Size(170,30)
    $checkbox3.Text = "Xbox Game Bar"
    $checkbox3.Tag = "Game Bar"
    $checkbox3.Checked = $false
    $Form.Controls.Add($checkbox3)
     $checkboxes += $checkbox3

    $checkbox4 = new-object System.Windows.Forms.checkbox
    $checkbox4.Location = new-object System.Drawing.Size(10,100)
    $checkbox4.Size = new-object System.Drawing.Size(170,30)
    $checkbox4.Text = "Netflix"
    $checkbox4.Tag = "9WZDNCRFJ3TJ"
    $checkbox4.Checked = $false
    $Form.Controls.Add($checkbox4)
    $checkboxes += $checkbox4

    $checkbox5 = new-object System.Windows.Forms.checkbox
    $checkbox5.Location = new-object System.Drawing.Size(10,140)
    $checkbox5.Size = new-object System.Drawing.Size(200,20)
    $checkbox5.Text = "Spotify"
    $checkbox5.Tag = "9NCBCSZSJRSB"
    $checkbox5.Checked = $false
    $Form.Controls.Add($checkbox5)
    $checkboxes += $checkbox5

    $checkbox6 = new-object System.Windows.Forms.checkbox
    $checkbox6.Location = new-object System.Drawing.Size(10,180)
    $checkbox6.Size = new-object System.Drawing.Size(200,20)
    $checkbox6.Text = "WhatsApp"
    $checkbox6.Tag = "9NKSQGP7F2NH"
    $checkbox6.Checked = $false
    $Form.Controls.Add($checkbox6)
    $checkboxes += $checkbox6

    $checkbox7 = new-object System.Windows.Forms.checkbox
    $checkbox7.Location = new-object System.Drawing.Size(10,220)
    $checkbox7.Size = new-object System.Drawing.Size(200,20)
    $checkbox7.Text = "Calculator"
    $checkbox7.Tag = "9WZDNCRFHVN5"
    $checkbox7.Checked = $false
    $Form.Controls.Add($checkbox7)
    $checkboxes += $checkbox7

    $checkbox8 = new-object System.Windows.Forms.checkbox
    $checkbox8.Location = new-object System.Drawing.Size(10,260)
    $checkbox8.Size = new-object System.Drawing.Size(200,20)
    $checkbox8.Text = "iTunes"
    $checkbox8.Tag = "9PB2MZ1ZMB1S"
    $checkbox8.Checked = $false
    $Form.Controls.Add($checkbox8)
    $checkboxes += $checkbox8
    

    $checkbox9 = new-object System.Windows.Forms.checkbox
    $checkbox9.Location = new-object System.Drawing.Size(10,300)
    $checkbox9.Size = new-object System.Drawing.Size(200,20)
    $checkbox9.Text = "Movies TV"
    $checkbox9.Tag = "9WZDNCRFJ3P2"
    $checkbox9.Checked = $false
    $Form.Controls.Add($checkbox9)
    $checkboxes += $checkbox9

    $checkbox10 = new-object System.Windows.Forms.checkbox
    $checkbox10.Location = new-object System.Drawing.Size(10,340)
    $checkbox10.Size = new-object System.Drawing.Size(200,20)
    $checkbox10.Text = "SoundCloud"
    $checkbox10.Tag = "9NVJBT29B36L"
    $checkbox10.Checked = $false
    $Form.Controls.Add($checkbox10)
    $checkboxes += $checkbox10


    # Create a label
$label = New-Object System.Windows.Forms.Label
$label.Text = "Search for an App:"
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(250, 10)

# Create a text box for search input
$searchBox = New-Object System.Windows.Forms.TextBox
$searchBox.Location = New-Object System.Drawing.Point(250, 30)
$searchBox.Size = New-Object System.Drawing.Size(150, 20)



# Create a label for installation ID
$labelID = New-Object System.Windows.Forms.Label
$labelID.Text = "Copy and Paste the ID:"
$labelID.AutoSize = $true
$labelID.Location = New-Object System.Drawing.Point(250, 130) 
$labelID.Visible = $false

# Create a text box for ID input
$idBox = New-Object System.Windows.Forms.TextBox
$idBox.Location = New-Object System.Drawing.Point(250, 150)
$idBox.Size = New-Object System.Drawing.Size(200, 20)
$idBox.Visible = $false


# Create a button for install action
$installButton = New-Object System.Windows.Forms.Button
$installButton.Location = New-Object System.Drawing.Point(250, 180)
$installButton.Size = New-Object System.Drawing.Size(100, 23)
$installButton.Text = "Install"
$installButton.Add_Click({ Install })
$installButton.Visible = $false

# Function to handle search action
function Search {
 $searchText = $searchBox.Text 
 cls 
 Start-Process "winget" -ArgumentList "search --accept-source-agreements ", $searchText -NoNewWindow -Wait
 
 $labelID.Visible = $true
 $idBox.Visible = $true
 $installButton.Visible = $true
}

# Function to handle install action
function Install {
    $appId = $idBox.Text
    # Run the winget install command asynchronously
    Write-Host "Installing Please Wait..."
    Start-Process "winget" -ArgumentList "install", "--accept-source-agreements", "--accept-package-agreements", $appId -NoNewWindow -RedirectStandardOutput "output.txt" -Wait
    $output = Get-Content "output.txt" -Raw 
    
    if($output -match "Successfully installed"){
    Write-Host "Successfully installed."

    }
    
    if ($output -match "The installer cannot be run from an administrator context") {
    cls
        Write-Host "The installer cannot be run from an administrator context"
        Write-Host ""
        Write-Host "Copy and Paste the command in a Non-Elevated Powershell Console:"
        Write-Host "winget install --accept-source-agreements --accept-package-agreements $($appId)"
          
}
    
}




# Create a button for search action
$searchButton = New-Object System.Windows.Forms.Button
$searchButton.Location = New-Object System.Drawing.Point(250, 60)
$searchButton.Size = New-Object System.Drawing.Size(100, 23)
$searchButton.Text = "Search"
$searchButton.Add_Click({ 
Search})

$form.Controls.Add($label)
$form.Controls.Add($searchBox)
$form.Controls.Add($searchButton)
$form.Controls.Add($installButton)
$form.Controls.Add($idBox)
$form.Controls.Add($labelID)

    $OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(150,420)
$OKButton.Size = New-Object System.Drawing.Size(100,23)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(245,420)
$CancelButton.Size = New-Object System.Drawing.Size(100,23)
$CancelButton.Text = 'Cancel'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,10)
$label.Size = New-Object System.Drawing.Size(200,20)
$label.Text = 'Choose any UWP App to install:'
$form.Controls.Add($label)

   # Activate the form
    $Form.Add_Shown({$Form.Activate()})
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{

#url apps.microsoft.com/store/apps

#add apps to a list
foreach($checkbox in $checkboxes){
if($checkbox.checked){
$apps += $checkbox.Tag

}

}

$i = 1
#loop through the apps and install them
foreach($app in $apps){

$scriptblock = [scriptblock]::Create("Start-Process -FilePath winget -ArgumentList `"install --accept-source-agreements --accept-package-agreements $app`" -NoNewWindow")
Start-Job -Name "App $i" -ScriptBlock $scriptblock | Wait-Job | Out-String
$i++


}

 }
 
 
 
#check if all the apps installed
foreach($checkbox in $checkboxes){
if($checkbox.Checked){

$installed =  winget list --name $checkbox.Text

    if($installed -contains "No installed package found matching input criteria."){
    cls
    Start-Process -FilePath winget -ArgumentList "install --accept-source-agreements --accept-package-agreements $($checkbox.Tag)" -NoNewWindow -PassThru -RedirectStandardOutput "output.txt"
    sleep 1
    cls
    Write-Host "Trying to install $($checkbox.Text) Again [PRESS S TO SKIP]"
    Write-Host "Installing..."
    $success = $null
    while($true) {
   $success = Get-Content -Path "output.txt" -Raw 
   if($success -match "Successfully installed"){ 
   Write-Host "Installed Successfully"
   sleep 3
   break }

   if($success -imatch "already installed"){
   cls
   break

   }

    if ($Host.UI.RawUI.KeyAvailable) {
    $input = $Host.UI.RawUI.ReadKey()
    if($input.character -like "s"){
    Stop-Process -Name winget -Force
    break
    }
    }
    sleep 1
    }
    Remove-Item "output.txt" -Force -ErrorAction SilentlyContinue
    }
    else{
    cls
    Write-Host "$($checkbox.Text) Installed Successfully"
    
    }


}
 


 }



# Create a form
$form = New-Object Windows.Forms.Form
$form.Text = "zoicware"
$form.Size = New-Object Drawing.Size(300, 150)

# Create a "Disable Updates" button
$btnDisableUpdates = New-Object Windows.Forms.Button
$btnDisableUpdates.Text = "Disable Updates"
$btnDisableUpdates.Location = New-Object Drawing.Point(20, 20)
$btnDisableUpdates.Size = New-Object Drawing.Size(105,50)
$btnDisableUpdates.Add_Click({
reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseUpdatesExpiryTime" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "WUServer" /t REG_SZ /d "https://DoNotUpdateWindows10.com/" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "WUStatusServer" /t REG_SZ /d "https://DoNotUpdateWindows10.com/" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "UpdateServiceUrlAlternate" /t REG_SZ /d "https://DoNotUpdateWindows10.com/" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetProxyBehaviorForUpdateDetection" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "UseWUServer" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v "Start" /t REG_DWORD /d "4" /f 
Disable-ScheduledTask -TaskName "Microsoft\Windows\WindowsUpdate\Scheduled Start" | Out-Null
gpupdate /force
$form.Dispose()
})
$form.Controls.Add($btnDisableUpdates)

# Create a "Leave Paused" button
$btnLeavePaused = New-Object Windows.Forms.Button
$btnLeavePaused.Text = "Leave Paused/Default"
$btnLeavePaused.Location = New-Object Drawing.Point(150, 20)
$btnLeavePaused.Size = New-Object Drawing.Size(105,50)
$btnLeavePaused.Add_Click({
    $form.Dispose()
    exit
})
$form.Controls.Add($btnLeavePaused)

# Show the form
$form.ShowDialog()

# Clean up
$form.Dispose()
