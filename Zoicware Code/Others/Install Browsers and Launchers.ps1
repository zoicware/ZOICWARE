# app installer by zoicware

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

$choice = 0
DO
{

Write-host "-------------------------------------"
Write-host "|                                   |"
Write-host "|    Select your Option Below       |"
Write-host "|                                   |"
Write-host "-------------------------------------"

$choice = Read-host "Enter 1 for Browsers `nEnter 2 for Launchers `nEnter 3 to Quit `n"




#installing browsers
if($choice -eq 1){

#creating powershell list box 
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Install Browsers'
$form.Size = New-Object System.Drawing.Size(300,200)
$form.StartPosition = 'CenterScreen'

$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(75,120)
$OKButton.Size = New-Object System.Drawing.Size(75,23)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(150,120)
$CancelButton.Size = New-Object System.Drawing.Size(75,23)
$CancelButton.Text = 'Cancel'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(280,20)
$label.Text = 'Please select what browser to install:'
$form.Controls.Add($label)

$listBox = New-Object System.Windows.Forms.Listbox
$listBox.Location = New-Object System.Drawing.Point(10,40)
$listBox.Size = New-Object System.Drawing.Size(260,20)

$listBox.SelectionMode = 'MultiExtended'

[void] $listBox.Items.Add('Chrome')
[void] $listBox.Items.Add('Firefox')
[void] $listBox.Items.Add('Brave')


$listBox.Height = 70
$form.Controls.Add($listBox)
$form.Topmost = $true

$result = $form.ShowDialog()


if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    

    if($listbox.SelectedItems.Contains('Chrome'))
    {
       
            Write-host "-------------------------------------"
            Write-host "|                                   |"
            Write-host "|        Installing Chrome          |"
            Write-host "|                                   |"
            Write-host "-------------------------------------"
        $chrome = Get-ChildItem -Path C:\ -Filter _ChromeSetup.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$chrome) -Args "/silent /install" -Wait 


    }
    if($listbox.SelectedItems.Contains('Firefox'))
    {
            Write-host "-------------------------------------"
            Write-host "|                                   |"
            Write-host "|        Installing Firefox         |"
            Write-host "|                                   |"
            Write-host "-------------------------------------"
        $firefox = Get-ChildItem -Path C:\ -Filter FirefoxInstaller.msi -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$firefox) -Args "/q" -Wait 


    }
    if($listbox.SelectedItems.Contains('Brave'))
    {
            Write-host "-------------------------------------"
            Write-host "|                                   |"
            Write-host "|        Installing Brave           |"
            Write-host "|                                   |"
            Write-host "-------------------------------------"
    $brave = Get-ChildItem -Path C:\ -Filter BraveBrowserSetup.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$brave) -Args "/silent /install" -Wait 



    }

   }

   Clear-Host
}
#installing launchers
elseif($choice -eq 2){

#creating powershell list box 
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Install Game Launchers'
$form.Size = New-Object System.Drawing.Size(300,200)
$form.StartPosition = 'CenterScreen'

$OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(75,120)
$OKButton.Size = New-Object System.Drawing.Size(75,23)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(150,120)
$CancelButton.Size = New-Object System.Drawing.Size(75,23)
$CancelButton.Text = 'Cancel'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,20)
$label.Size = New-Object System.Drawing.Size(280,20)
$label.Text = 'Please select what Launchers to install:'
$form.Controls.Add($label)

$listBox = New-Object System.Windows.Forms.Listbox
$listBox.Location = New-Object System.Drawing.Point(10,40)
$listBox.Size = New-Object System.Drawing.Size(260,20)

$listBox.SelectionMode = 'MultiExtended'

[void] $listBox.Items.Add('Steam')
[void] $listBox.Items.Add('Epic')
[void] $listBox.Items.Add('Origin')
[void] $listBox.Items.Add('Battlenet')

$listBox.Height = 70
$form.Controls.Add($listBox)
$form.Topmost = $true

$result = $form.ShowDialog()


if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    
if($listbox.SelectedItems.Contains('Steam')){

    $steam = Get-ChildItem -Path C:\ -Filter SteamSetup.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$steam) -Wait


}
if($listbox.SelectedItems.Contains('Epic')){

    $epic = Get-ChildItem -Path C:\ -Filter Epic.msi -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$epic) -Wait


}
if($listbox.SelectedItems.Contains('Origin')){

    $origin = Get-ChildItem -Path C:\ -Filter Origin.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$origin) -Wait


}
if($listbox.SelectedItems.Contains('Battlenet')){

    $bnet = Get-ChildItem -Path C:\ -Filter Battlenet.exe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  start-process -FilePath ([string]$bnet) -Wait

}


}



Clear-Host
}









}while($choice -ne 3)





