$runtweak = Search-File '*RunTweaks.ps1'
.$runtweak
 
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Import/Export Tweak Config'
$form.Size = New-Object System.Drawing.Size(500, 280)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$form.BackColor = 'Black'
$form.Font = New-Object System.Drawing.Font('Segoe UI', 8) 
$form.AllowDrop = $true
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


$url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#importing-and-exporting-tweaks'
$infobutton = New-Object Windows.Forms.Button
$infobutton.Location = New-Object Drawing.Point(450, 0)
$infobutton.Size = New-Object Drawing.Size(30, 27)
$infobutton.Cursor = 'Hand'
$infobutton.Add_Click({
        try {
            Start-Process $url -ErrorAction Stop
        }
        catch {
            Write-Host 'No Internet Connected...' -ForegroundColor Red
        }
            
    })
$infobutton.BackColor = [System.Drawing.Color]::Transparent
$image = [System.Drawing.Image]::FromFile('C:\Windows\System32\SecurityAndMaintenance.png')
$resizedImage = New-Object System.Drawing.Bitmap $image, 24, 25
$infobutton.Image = $resizedImage
$infobutton.ImageAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$infobutton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$infobutton.FlatAppearance.BorderSize = 0
#$infobutton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$infobutton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$form.Controls.Add($infobutton)

$dconfiglabel = New-Object System.Windows.Forms.Label
$dconfiglabel.Location = New-Object System.Drawing.Point(10, 20)
$dconfiglabel.Size = New-Object System.Drawing.Size(120, 20)
$dconfiglabel.Text = 'Current Config:'
$dconfiglabel.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$dconfiglabel.BackColor = [System.Drawing.Color]::Transparent
$dconfiglabel.ForeColor = 'White'
$form.Controls.Add($dconfiglabel)

$dconfigTextbox = New-Object System.Windows.Forms.TextBox
$dconfigTextbox.Location = New-Object System.Drawing.Point(130, 20)
$dconfigTextbox.BackColor = [System.Drawing.Color]::FromArgb(47, 49, 58)
$dconfigTextbox.ForeColor = 'White'
$dconfigTextbox.Size = New-Object System.Drawing.Size(300, 20)
if (Test-Path "$env:USERPROFILE\ZCONFIG.cfg" -ErrorAction SilentlyContinue) {
    $dconfigTextbox.Text = "$env:USERPROFILE\ZCONFIG.cfg"
}
else {
    $dconfigTextbox.Text = 'DEFAULT CONFIG NOT FOUND'
}
$form.Controls.Add($dconfigTextbox)


$destLabel = New-Object System.Windows.Forms.Label
$destLabel.Location = New-Object System.Drawing.Point(10, 60)
$destLabel.Size = New-Object System.Drawing.Size(120, 25)
$destLabel.Text = 'Import Config:'
$destLabel.Font = New-Object System.Drawing.Font('Segoe UI', 10)
$destLabel.BackColor = [System.Drawing.Color]::Transparent
$destLabel.ForeColor = 'White'
$form.Controls.Add($destLabel)

$iconfigTextbox = New-Object System.Windows.Forms.TextBox
$iconfigTextbox.Location = New-Object System.Drawing.Point(130, 60)
$iconfigTextbox.Size = New-Object System.Drawing.Size(300, 20)
$iconfigTextbox.BackColor = [System.Drawing.Color]::FromArgb(47, 49, 58)
$iconfigTextbox.ForeColor = 'White'
$iconfigTextbox.Text = $null
$form.Controls.Add($iconfigTextbox)

$filebrowsebttn = New-Object System.Windows.Forms.Button
$filebrowsebttn.Location = New-Object System.Drawing.Point(440, 60)
$filebrowsebttn.Size = New-Object System.Drawing.Size(40, 20)
$filebrowsebttn.Text = '...'
$filebrowsebttn.Cursor = 'Hand'
$filebrowsebttn.Font = New-Object System.Drawing.Font($filebrowsebttn.Font.Name, 10)
$filebrowsebttn.BackColor = [System.Drawing.Color]::FromArgb(18, 19, 27)
$filebrowsebttn.ForeColor = [System.Drawing.Color]::White
$filebrowsebttn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$filebrowsebttn.FlatAppearance.BorderSize = 1
#$filebrowsebttn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$filebrowsebttn.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$filebrowsebttn.Add_Click({    
        $Global:selectedFile = Show-ModernFilePicker -Mode File -fileType cfg
        if ($Global:selectedFile) {
            $iconfigTextbox.Text = $Global:selectedFile 
        }
        
    })
$form.Controls.Add($filebrowsebttn)

$resetConfigBttn = Create-ModernButton -Text 'Reset Current Config' -Location (New-Object Drawing.Point(10, 90)) -Size (New-Object Drawing.Size(130, 30)) -borderSize 2 -ClickAction {
    $msgBoxInput = Custom-MsgBox -Message 'Are you sure you want to reset your current config?' -Type Question

    switch ($msgBoxInput) {
  
        'OK' {
            #set all config settings back to 0
            $currentConfig = Get-Content -Path "$env:USERPROFILE\ZCONFIG.cfg" -Force
            $newConfig = @()
            foreach ($line in $currentConfig) {
                if ($line -notmatch '#') {
                    $splitLine = $line -split '='
                    $settingName = $splitLine[0]
                    $newConfig += "$($settingName.trim()) = 0"
                }
                else {
                    $newConfig += $line
                }
      
            }
            $newConfig | Out-File -FilePath "$env:USERPROFILE\ZCONFIG.cfg" -Force

            Write-Status -Message 'Config Reset!' -Type Output

        }

        'Cancel' {

        }
    }
}


$form.Controls.Add($resetConfigBttn)


$customConfig = Create-ModernButton -Text 'Build Custom Config' -Location (New-Object Drawing.Point(10, 130)) -Size (New-Object Drawing.Size(130, 30)) -borderSize 2 -ClickAction {
    $form.Visible = $false

    $tweakNames = @()
    $configContentArray = $configContent -split "`n"
    foreach ($line in $configContentArray) {
        if ($line -notlike '#*') {
            $settingName = $line -split '='
            $tweakNames += $settingName[0].Trim()
        }
    }

    $form3 = New-Object System.Windows.Forms.Form
    $form3.Text = 'Build Config'
    $form3.Size = New-Object System.Drawing.Size(400, 550)
    $form3.StartPosition = 'CenterScreen'
    $form3.BackColor = 'Black'
    $form3.Font = New-Object System.Drawing.Font('Segoe UI', 9) 
    $form3.Icon = New-Object System.Drawing.Icon($Global:customIcon)

    $type = $form3.GetType()
    $propInfo = $type.GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
    $propInfo.SetValue($form3, $true, $null)

    $startColor = [System.Drawing.Color]::FromArgb(61, 74, 102)   #rgb(61, 74, 102)
    $endColor = [System.Drawing.Color]::FromArgb(0, 0, 0)       #rgb(0, 0, 0)

    # Override the form's paint event to apply the gradient
    $form3.Add_Paint({
            param($sender, $e)
            $rect = New-Object System.Drawing.Rectangle(0, 0, $form3.Width, $form3.Height)
            $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
                $rect, 
                $startColor, 
                $endColor, 
                [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal
            )
            $e.Graphics.FillRectangle($brush, $rect)
            $brush.Dispose()
        })


    $label2 = New-Object System.Windows.Forms.Label
    $label2.Location = New-Object System.Drawing.Point(10, 10)
    $label2.Size = New-Object System.Drawing.Size(280, 20)
    $label2.Text = 'Select Tweaks:'
    $label2.ForeColor = 'White'
    $label2.BackColor = [System.Drawing.Color]::Transparent
    $label2.Font = New-Object System.Drawing.Font('Segoe UI', 11) 
    $form3.Controls.Add($label2)

    $checkedListBox = New-Object System.Windows.Forms.CheckedListBox
    $checkedListBox.Location = New-Object System.Drawing.Point(55, 35)
    $checkedListBox.Size = New-Object System.Drawing.Size(270, 415)
    $checkedListBox.BackColor = 'Black'
    $checkedListBox.CheckOnClick = $true
    $checkedListBox.ForeColor = 'White'
    $checkedListBox.ScrollAlwaysVisible = $true
    $Form3.Controls.Add($checkedListBox)

    foreach ($name in $tweakNames) {
        $checkedListBox.Items.Add($name, $false) | Out-Null
    }


    $saveConfig = Create-ModernButton -Text 'Save' -Location (New-Object Drawing.Point(130, 455)) -Size (New-Object Drawing.Size(120, 35)) -borderSize 2 -ClickAction {
        $fileDialog = New-Object System.Windows.Forms.SaveFileDialog
        $fileDialog.Filter = 'CFG Files (*.cfg)|*.cfg|All Files (*.*)|*.*'
        if ($fileDialog.ShowDialog() -eq 'OK') {
            $values = @()
            foreach ($line in $checkedListBox.CheckedItems.GetEnumerator()) {
                $values += "$line = 1"
            }
            $date = Get-Date -Format 'MM-dd-yy'
            New-Item -path $fileDialog.FileName -Force -Value "#Custom Config Created $($date) `n"
            foreach ($value in $values) {
                Add-Content -Path $fileDialog.FileName -Value $value
            }
            $form3.Close()
        }
    }

    $form3.Controls.Add($saveConfig)

    $form3.ShowDialog() | Out-Null

    $form.Visible = $true

}


$form.Controls.Add($customConfig)

$runConfig = Create-ModernButton -Text 'Run Tweaks' -Location (New-Object Drawing.Point(130, 190)) -Size (New-Object Drawing.Size(120, 30)) -borderSize 2 -ClickAction {
    $form.Visible = $false
    $importedConfig = Get-Content $Global:selectedFile -Force -ErrorAction SilentlyContinue
    if ($importedConfig -eq $null) {
        Write-Status -Message 'Config is Empty' -Type Error
    }
    else {
        #check each option in config and run tweak if value is 1
        $enabledSettings = @()
        foreach ($line in $importedConfig) {
            if ($line -notmatch '#') {
                $parts = $line -split '='
                $settingName = $parts[0].Trim()
                $value = $parts[1].Trim()
                if ($value -eq '1') {
                    $enabledSettings += $settingName
                }
            }

        }
        RunTweaks -enabledSettings $enabledSettings
    }
    $form.Visible = $true
}

$form.Controls.Add($runConfig)

$exportConfig = Create-ModernButton -Text 'Export Tweaks' -Location (New-Object Drawing.Point(250, 190)) -Size (New-Object Drawing.Size(120, 30)) -borderSize 2 -ClickAction {
    if (Test-Path "$env:USERPROFILE\ZCONFIG.cfg" -ErrorAction SilentlyContinue) {
        Write-Status -Message 'Select Export Destination...' -Type Output
        $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    
        if ($folderDialog.ShowDialog() -eq 'OK') {
    
            $selectedFolder = $folderDialog.SelectedPath
            Copy-Item -Path "$env:USERPROFILE\ZCONFIG.cfg" -Destination $selectedFolder -Force
            $date = Get-Date -Format 'MM-dd-yy'
            Rename-Item -Path "$selectedFolder\ZCONFIG.cfg" -NewName "ZCONFIG$($date).cfg" -Force

            Write-Status -Message 'Config Exported' -Type Output
    
        }
    
    }
    else {
        Write-Status -Message 'Config Not Found!' -Type Error
    }
}



$form.Controls.Add($exportConfig)

#add drop config feature
$form.Add_DragEnter({
        param($sender, $e)
        if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
            $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
        }
        else {
            $e.Effect = [System.Windows.Forms.DragDropEffects]::None
        }
    })

$form.Add_DragDrop({
        param($sender, $e)
        $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
        if ($files -ne $null) {
            $iconfigTextbox.Text = $files[0]
        }
    })


$form.ShowDialog()

