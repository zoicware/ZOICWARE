# pbo tuner automation by zoic
# this script will create a task on startup to apply your pbo undervolt

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

$github = $false
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Install PBO Tuner?','zoicware','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {
  $github = $true
  Write-Host "Installing PBO Tuner"
Invoke-RestMethod 'https://github.com/zoicware/PBO/archive/refs/heads/main.zip' -OutFile "C:\PBO.zip"
Expand-Archive "C:\PBO.zip" -DestinationPath "C:\"
Remove-Item "C:\PBO.zip" -Recurse -Force
Expand-Archive "C:\PBO-main\PBOTuner.zip" -DestinationPath "C:\"
Remove-Item "C:\PBO-main" -Recurse -Force

 }

'No'{}

}

#limits (in order)
$ppt = "0"
$tdc = "0"
$edc = "0"


Add-Type -AssemblyName System.Windows.Forms

# Retrieve the number of CPU cores
$cpuCores = (Get-WmiObject -Class Win32_Processor).NumberOfCores

$size = 300+($cpuCores*20)

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "PBO2 Tuner"
$form.Size = New-Object System.Drawing.Size(400,$size)
$form.StartPosition = "CenterScreen"

# Create a checkbox
$checkBox = New-Object System.Windows.Forms.CheckBox
$checkBox.Text = "Custom Limits"
$checkBox.Location = New-Object System.Drawing.Point(200, 140)

# Create three textboxes
$limitBox1 = New-Object System.Windows.Forms.TextBox
$limitBox1.Location = New-Object System.Drawing.Point(220, 170)
$limitBox1.Size = New-Object System.Drawing.Size(60, 20)
$limitBox1.Visible = $false
$limitBox1.MaxLength = 3

$limitBox2 = New-Object System.Windows.Forms.TextBox
$limitBox2.Location = New-Object System.Drawing.Point(220, 200)
$limitBox2.Size = New-Object System.Drawing.Size(60, 20)
$limitBox2.Visible = $false
$limitBox2.MaxLength = 3

$limitBox3 = New-Object System.Windows.Forms.TextBox
$limitBox3.Location = New-Object System.Drawing.Point(220, 230)
$limitBox3.Size = New-Object System.Drawing.Size(60, 20)
$limitBox3.Visible = $false
$limitBox3.MaxLength = 3

# Create three labels
$label1 = New-Object System.Windows.Forms.Label
$label1.Text = "PPT"
$label1.Location = New-Object System.Drawing.Point(190, 170)
$label1.Visible = $false

$label2 = New-Object System.Windows.Forms.Label
$label2.Text = "TDC"
$label2.Location = New-Object System.Drawing.Point(190, 200)
$label2.Visible = $false

$label3 = New-Object System.Windows.Forms.Label
$label3.Text = "EDC"
$label3.Location = New-Object System.Drawing.Point(190, 230)
$label3.Visible = $false

# Add event handler for checkbox checked event
$checkBox.add_CheckedChanged({
    if ($checkBox.Checked) {
        $limitBox1.Visible = $true
        $limitBox2.Visible = $true
        $limitBox3.Visible = $true
        $label1.Visible = $true
        $label2.Visible = $true
        $label3.Visible = $true
    } else {
        $limitBox1.Visible = $false
        $limitBox2.Visible = $false
        $limitBox3.Visible = $false
        $label1.Visible = $false
        $label2.Visible = $false
        $label3.Visible = $false
    }
})

# Add controls to the form
$form.Controls.Add($checkBox)
$form.Controls.Add($limitBox1)
$form.Controls.Add($limitBox2)
$form.Controls.Add($limitBox3)
$form.Controls.Add($label1)
$form.Controls.Add($label2)
$form.Controls.Add($label3)

# Create the label
$label = New-Object System.Windows.Forms.Label
$label.Location = [System.Drawing.Point]::new(10, 20)
$label.Size = [System.Drawing.Size]::new(380, 20)
$label.Text = "Enter the Undervolt for each core:"
$form.Controls.Add($label)

# Create the radio buttons
$radioButtons = @()
$values = @(-10, -20, -30)
for ($i = 0; $i -lt $values.Count; $i++) {
    $radioButton = New-Object System.Windows.Forms.RadioButton
    $radioButton.Location = [System.Drawing.Point]::new(200, 40 + $i * 30)
    $radioButton.Size = [System.Drawing.Size]::new(60, 20)
    $radioButton.Text = $values[$i].ToString()

    # Create a closure to capture the correct radio button object
    $eventHandler = {
        $selectedRadioButton = $this
        $selectedValue = $selectedRadioButton.Text
        foreach ($textBox in $textboxes) {
            $textBox.Text = $selectedValue
        }
    }
    $radioButton.Add_Click($eventHandler)

    $form.Controls.Add($radioButton)
    $radioButtons += $radioButton
}

# Create the text boxes with labels
$textBoxes = @()
for ($i = 0; $i -lt $cpuCores; $i++) {
    $coreNumber = $i
    $coreLabel = "Core "+ $coreNumber
    
    # Create the label
    $coreLabelControl = New-Object System.Windows.Forms.Label
    $coreLabelControl.Location = [System.Drawing.Point]::new(10, 40 + $i * 30)
    $coreLabelControl.Size = [System.Drawing.Size]::new(60, 20)
    $coreLabelControl.Text = $coreLabel
    $form.Controls.Add($coreLabelControl)
    
    # Create the text box
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = [System.Drawing.Point]::new(80, 40 + $i * 30)
    $textBox.Size = [System.Drawing.Size]::new(60, 20)
    $textBox.MaxLength = 3
    $form.Controls.Add($textBox)
    $textBoxes += $textBox
}

# Create the button
$button = New-Object System.Windows.Forms.Button
$button.Location = [System.Drawing.Point]::new(150, 40 + $cpuCores * 30)
$button.Size = [System.Drawing.Size]::new(100, 30)
$button.Text = "Apply"
$button.Add_Click({
$exePath = "non"

if($github){

$pbo = Get-ChildItem -Path C:\ -Filter PBOTuner -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
Move-item -Path $pbo -Destination "C:\Program Files" -Force
$exePath = "C:\Program Files\PBOTuner\PBO2 tuner.exe"

}
else{

$exePath = Get-ChildItem -Path C:\ -Filter "PBO2 Tuner.exe" -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }

}    

#format: (-)num cpu core undervolt ppt tdc edc 0
if($checkBox.Checked){

if($limitBox1.Text -ne ""){
$ppt = $limitBox1.Text
}

if($limitBox2.Text -ne ""){
$tdc = $limitBox2.Text
}

if($limitBox3.Text -ne ""){
$edc = $limitBox3.Text

}

$values = ($textBoxes.ForEach({ $_.Text }) -join " ") +" "+$ppt+" "+$tdc+" "+$edc+" 0"
}
else{
$values = $textBoxes.ForEach({ $_.Text }) -join " "

}
$taskName = "PBO Tuner"


# Create a new scheduled task action to run the executable
$action = New-ScheduledTaskAction -Execute $exePath -Argument $values

# Create a new scheduled task trigger for user logon
$trigger = New-ScheduledTaskTrigger -AtLogOn


# Register the scheduled task using the User Principal Name
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User $env:USERNAME -RunLevel Highest -Force

$form.Close()
})
$form.Controls.Add($button)

# Show the form
$form.ShowDialog() | Out-Null