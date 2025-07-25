Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Install Other Scripts'
$form.Size = New-Object System.Drawing.Size(350, 400)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$form.BackColor = 'Black'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9) 
$form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

$type = $form.GetType()
$propInfo = $type.GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
$propInfo.SetValue($form, $true, $null)

$startColor = [System.Drawing.Color]::FromArgb(61, 74, 102)   #rgb(61, 74, 102)
$endColor = [System.Drawing.Color]::FromArgb(0, 0, 0)       #rgb(0, 0, 0)

# Override the form's paint event to apply the gradient
$form.Add_Paint({
        param($sender, $e)
        $rect = New-Object System.Drawing.Rectangle(0, 0, $form.Width, $form.Height)
        $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
            $rect, 
            $startColor, 
            $endColor, 
            [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal
        )
        $e.Graphics.FillRectangle($brush, $rect)
        $brush.Dispose()
    })


$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10, 10)
$label.Size = New-Object System.Drawing.Size(200, 20)
$label.Text = 'Create Desktop Shortcut to:'
$label.ForeColor = 'White'
$label.BackColor = [System.Drawing.Color]::Transparent
$label.Font = New-Object System.Drawing.Font('Segoe UI', 10) 
$form.Controls.Add($label)

$label2 = New-Object System.Windows.Forms.Label
$label2.Location = New-Object System.Drawing.Point(170, 40)
$label2.Size = New-Object System.Drawing.Size(200, 20)
$label2.Text = 'Include Source Code?'
$label2.ForeColor = 'White'
$label2.BackColor = [System.Drawing.Color]::Transparent
$label2.Font = New-Object System.Drawing.Font('Segoe UI', 8) 
$form.Controls.Add($label2)

$label3 = New-Object System.Windows.Forms.Label
$label3.Location = New-Object System.Drawing.Point(217, 60)
$label3.Size = New-Object System.Drawing.Size(30, 20)
$label3.Text = 'Yes'
$label3.ForeColor = 'White'
$label3.BackColor = [System.Drawing.Color]::Transparent
$label3.Font = New-Object System.Drawing.Font('Segoe UI', 8) 
$form.Controls.Add($label3)

$label4 = New-Object System.Windows.Forms.Label
$label4.Location = New-Object System.Drawing.Point(282, 60)
$label4.Size = New-Object System.Drawing.Size(30, 20)
$label4.Text = 'No'
$label4.ForeColor = 'White'
$label4.BackColor = [System.Drawing.Color]::Transparent
$label4.Font = New-Object System.Drawing.Font('Segoe UI', 8) 
$form.Controls.Add($label4)

$checkbox1 = New-Object System.Windows.Forms.CheckBox
$checkbox1.Location = new-object System.Drawing.Size(20, 80)
$checkbox1.Size = new-object System.Drawing.Size(190, 30)
$checkbox1.Text = 'Service Manager Plus'
$checkbox1.ForeColor = 'White'
$checkbox1.BackColor = [System.Drawing.Color]::Transparent
$checkbox1.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$checkbox1.Checked = $false
$Form.Controls.Add($checkbox1) 

$checkbox2 = New-Object System.Windows.Forms.CheckBox
$checkbox2.Location = new-object System.Drawing.Size(20, 110)
$checkbox2.Size = new-object System.Drawing.Size(190, 30)
$checkbox2.Text = 'Windows Update Manager'
$checkbox2.ForeColor = 'White'
$checkbox2.BackColor = [System.Drawing.Color]::Transparent
$checkbox2.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$checkbox2.Checked = $false
$Form.Controls.Add($checkbox2) 

$checkbox3 = New-Object System.Windows.Forms.CheckBox
$checkbox3.Location = new-object System.Drawing.Size(20, 140)
$checkbox3.Size = new-object System.Drawing.Size(190, 30)
$checkbox3.Text = 'Strip Windows Defender'
$checkbox3.ForeColor = 'White'
$checkbox3.BackColor = [System.Drawing.Color]::Transparent
$checkbox3.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$checkbox3.Checked = $false
$Form.Controls.Add($checkbox3) 

$checkbox4 = New-Object System.Windows.Forms.CheckBox
$checkbox4.Location = new-object System.Drawing.Size(20, 170)
$checkbox4.Size = new-object System.Drawing.Size(190, 30)
$checkbox4.Text = 'Repair Bad Tweaks'
$checkbox4.ForeColor = 'White'
$checkbox4.BackColor = [System.Drawing.Color]::Transparent
$checkbox4.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$checkbox4.Checked = $false
$Form.Controls.Add($checkbox4)

$checkbox5 = New-Object System.Windows.Forms.CheckBox
$checkbox5.Location = new-object System.Drawing.Size(20, 200)
$checkbox5.Size = new-object System.Drawing.Size(190, 30)
$checkbox5.Text = 'Remove Windows AI'
$checkbox5.ForeColor = 'White'
$checkbox5.BackColor = [System.Drawing.Color]::Transparent
$checkbox5.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$checkbox5.Checked = $false
$Form.Controls.Add($checkbox5)

$yesCheckboxes = @()
$noCheckboxes = @()

#create no source code checkboxes
for ($i = 0; $i -lt 5; $i++) {
    $checkboxno = New-Object System.Windows.Forms.CheckBox
    $checkboxno.Text = ''
    $checkboxno.BackColor = [System.Drawing.Color]::Transparent
    $checkboxno.Checked = $true
    $checkboxno.Location = New-Object System.Drawing.Point(285, (80 + ($i * 30)))
    $noCheckboxes += $checkboxno
    $form.Controls.Add($checkboxno)
}

#create yes source code checkboxes
for ($i = 0; $i -lt 5; $i++) {
    $checkboxyes = New-Object System.Windows.Forms.CheckBox
    $checkboxyes.Text = ''
    $checkboxyes.Checked = $false
    $checkboxyes.BackColor = [System.Drawing.Color]::Transparent
    $checkboxyes.Location = New-Object System.Drawing.Point(220, (80 + ($i * 30)))
    $yesCheckboxes += $checkboxyes
    $form.Controls.Add($checkboxyes)

    $checkboxyes.Add_CheckedChanged({
            if ($checkboxyes.Checked) {
                $noCheckboxes[$i].Checked = $false
            }
            else {
                $noCheckboxes[$i].Checked = $true
            }
        }.GetNewClosure())
}

$installbttn = Create-ModernButton -Text 'Install' -Location (New-Object Drawing.Point(120, 330)) -Size (New-Object Drawing.Size(100, 30)) -DialogResult ([System.Windows.Forms.DialogResult]::OK) -borderSize 2
$form.Controls.Add($installbttn)


$result = $form.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    if (!(Check-Internet)) {
        $ProgressPreference = 'SilentlyContinue'

        if ($checkbox1.Checked) {
            $sourceUri = 'https://github.com/zoicware/ServiceManagerPlus/archive/refs/heads/main.zip'
            #check if source code should be included
            $source = $yesCheckboxes[0].Checked
            if ($source) {
                Invoke-WebRequest -Uri $sourceUri -UseBasicParsing -OutFile "$env:USERPROFILE\Desktop\ServiceManagerPlus(Source).zip"
            }

            $headers = @{
                'User-Agent' = 'PowerShell'
            }
            $apiUrl = 'https://api.github.com/repos/zoicware/ServiceManagerPlus/releases/latest'
            $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -UseBasicParsing -ErrorAction Stop
            $downloadUrl = $response.assets | Where-Object { $_.name -eq 'ServiceManagerPlus.zip' } | Select-Object -ExpandProperty browser_download_url
            Invoke-WebRequest -Uri $downloadUrl -UseBasicParsing -OutFile "$env:USERPROFILE\Desktop\ServiceManagerPlus.zip"
            Expand-Archive "$env:USERPROFILE\Desktop\ServiceManagerPlus.zip" -DestinationPath "$env:USERPROFILE\Desktop"

            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\ServiceManagerPlus.lnk")
            $Shortcut.TargetPath = "$env:USERPROFILE\Desktop\ServiceManagerPlus\ServiceManagerPlus.exe"
            $Shortcut.WorkingDirectory = "$env:USERPROFILE\Desktop\ServiceManagerPlus"
            $Shortcut.Save()
            #run as admin
            $bytes = [System.IO.File]::ReadAllBytes($Shortcut.FullName)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($Shortcut.FullName, $bytes)

            Remove-Item "$env:USERPROFILE\Desktop\ServiceManagerPlus.zip" -Force -ErrorAction SilentlyContinue
        }

        if ($checkbox2.Checked) {
            $sourceUri = 'https://github.com/zoicware/WindowsUpdateManager/archive/refs/heads/main.zip'
            #check if source code should be included
            $source = $yesCheckboxes[1].Checked
            if ($source) {
                Invoke-WebRequest -Uri $sourceUri -UseBasicParsing -OutFile "$env:USERPROFILE\Desktop\WindowsUpdateManager(Source).zip"
            }


            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\WindowsUpdateManager.lnk")
            $Shortcut.TargetPath = 'powershell.exe'
            $Shortcut.Arguments = '-ExecutionPolicy Bypass -c iwr https://raw.githubusercontent.com/zoicware/WindowsUpdateManager/main/WindowsUpdateManager.ps1 | iex'
            $Shortcut.Save()
            #run as admin
            $bytes = [System.IO.File]::ReadAllBytes($Shortcut.FullName)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($Shortcut.FullName, $bytes)
        }

        if ($checkbox3.Checked) {
            $sourceUri = 'https://raw.githubusercontent.com/zoicware/DefenderProTools/main/StripDefenderV3.ps1'
            #check if source code should be included
            $source = $yesCheckboxes[2].Checked
            if ($source) {
                Invoke-WebRequest -Uri $sourceUri -UseBasicParsing -OutFile "$env:USERPROFILE\Desktop\StripDefenderV3.ps1"
            }


            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\StripDefender.lnk")
            $Shortcut.TargetPath = 'powershell.exe'
            $Shortcut.Arguments = '-ExecutionPolicy Bypass -c iwr https://raw.githubusercontent.com/zoicware/DefenderProTools/main/StripDefenderV3.ps1 | iex'
            $Shortcut.Save()
            #run as admin
            $bytes = [System.IO.File]::ReadAllBytes($Shortcut.FullName)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($Shortcut.FullName, $bytes)
        }

        if ($checkbox4.Checked) {
            $sourceUri = 'https://raw.githubusercontent.com/zoicware/RepairBadTweaks/main/RepairTweaks.ps1'
            #check if source code should be included
            $source = $yesCheckboxes[3].Checked
            if ($source) {
                Invoke-WebRequest -Uri $sourceUri -UseBasicParsing -OutFile "$env:USERPROFILE\Desktop\RepairTweaks.ps1"
            }


            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\RepairBadTweaks.lnk")
            $Shortcut.TargetPath = 'powershell.exe'
            $Shortcut.Arguments = '-ExecutionPolicy Bypass -c iwr https://raw.githubusercontent.com/zoicware/RepairBadTweaks/main/RepairTweaks.ps1 | iex'
            $Shortcut.Save()
            #run as admin
            $bytes = [System.IO.File]::ReadAllBytes($Shortcut.FullName)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($Shortcut.FullName, $bytes)
        }

        if ($checkbox5.Checked) {
            $sourceUri = 'https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1'
            #check if source code should be included
            $source = $yesCheckboxes[4].Checked
            if ($source) {
                Invoke-WebRequest -Uri $sourceUri -UseBasicParsing -OutFile "$env:USERPROFILE\Desktop\RemoveWindowsAi.ps1"
            }


            $WshShell = New-Object -comObject WScript.Shell
            $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\RemoveWindowsAI.lnk")
            $Shortcut.TargetPath = 'powershell.exe'
            $Shortcut.Arguments = '-ExecutionPolicy Bypass -c iwr https://raw.githubusercontent.com/zoicware/RemoveWindowsAI/main/RemoveWindowsAi.ps1 | iex'
            $Shortcut.Save()
            #run as admin
            $bytes = [System.IO.File]::ReadAllBytes($Shortcut.FullName)
            $bytes[0x15] = $bytes[0x15] -bor 0x20
            [System.IO.File]::WriteAllBytes($Shortcut.FullName, $bytes)
        }
    }
    
}

