#CHROME AND EDGE UPDATER BY ZOIC


If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

Write-Output "DON'T TOUCH THE MOUSE OR KEYBOARD UNTIL SCRIPT FINISHES IN APPROX 90 SECONDS"



Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Browser Update'
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
$label.Text = 'Please select the browser you want to update:'
$form.Controls.Add($label)

$listBox = New-Object System.Windows.Forms.Listbox
$listBox.Location = New-Object System.Drawing.Point(10,40)
$listBox.Size = New-Object System.Drawing.Size(260,20)

$listBox.SelectionMode = 'One'

[void] $listBox.Items.Add('Chrome')
[void] $listBox.Items.Add('Edge')


$listBox.Height = 70
$form.Controls.Add($listBox)
$form.Topmost = $true

$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{
    $x = $listBox.SelectedItems
    
    if($x -eq 'Chrome')
    {
#enabling update services
Set-Service "GoogleChromeElevationService" -StartupType Automatic
Set-Service "gupdatem" -StartupType Automatic
Set-Service "gupdate" -StartupType Automatic
Start-Service "GoogleChromeElevationService"
Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdateTaskMachineCore*'} | Enable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdateTaskMachineUA*'} | Enable-ScheduledTask

#updating
start chrome -Verb RunAs
Sleep 1
$wshell = New-Object -ComObject wscript.shell; 
$wshell.AppActivate('Chrome') 
Sleep 1
$wshell.SendKeys('chrome://settings/help')
Sleep .5
$wshell.SendKeys("{ENTER}")
Sleep 10
$id = (Get-Process GoogleUpdate).Id
Wait-Process -id $id
Stop-Process -name chrome
Wait-Process -name chrome
start chrome -Verb RunAs

Sleep 1
$wshell.AppActivate('Chrome')
Sleep 1
$wshell.SendKeys('chrome://settings/help')
Sleep .5
$wshell.SendKeys("{ENTER}")
sleep 2
Stop-Process -name chrome
Wait-Process -name chrome

#disabling update services
Set-Service "GoogleChromeElevationService" -StartupType Disabled
Set-Service "gupdatem" -StartupType Disabled
Set-Service "gupdate" -StartupType Disabled
Stop-Service "gupdatem"
Stop-Service "gupdate"
Stop-Service "GoogleChromeElevationService"
Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdateTaskMachineCore*'} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'GoogleUpdateTaskMachineUA*'} | Disable-ScheduledTask
        
    }
    elseif($x -eq 'Edge')
    {
        
 #Enabling Services

Set-Service "MicrosoftEdgeElevationService" -StartupType Automatic
Set-Service "edgeupdate" -StartupType Automatic
Set-Service "edgeupdatem" -StartupType Automatic

#Starting Services
 
Start-Service "MicrosoftEdgeElevationService" 

#Enabling Scheduled Tasks

Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineCore*'} | Enable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineUA*'} | Enable-ScheduledTask



#Update Edge
start msedge
Sleep 1
$wshell = New-Object -ComObject wscript.shell; # shell for sending keys
$wshell.AppActivate('Edge') # make sure edge is the active window
Sleep 1
$wshell.SendKeys('edge://settings/help')
Sleep .5
$wshell.SendKeys("{ENTER}")
Sleep 10
$id = (Get-Process MicrosoftEdgeUpdate).Id
Wait-Process -id $id
Stop-Process -name msedge
Wait-Process -name msedge


#Disabling Services

Set-Service "MicrosoftEdgeElevationService" -StartupType Disabled
Set-Service "edgeupdate" -StartupType Disabled
Set-Service "edgeupdatem" -StartupType Disabled

#Stoping Services

Stop-Service "MicrosoftEdgeElevationService"
Stop-Service "edgeupdate"
Stop-Service "edgeupdatem"

#Disabling Scheduled Tasks

Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineCore*'} | Disable-ScheduledTask
Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineUA*'} | Disable-ScheduledTask
        
    }
   


}





