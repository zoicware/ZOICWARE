$runtweak = Search-File '*RunTweaks.ps1'
.$runtweak
 
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Import/Export Tweak Config'
$form.Size = New-Object System.Drawing.Size(500, 250)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$form.BackColor = 'Black'
$form.Font = New-Object System.Drawing.Font($dmMonoFont, 8) 
$form.AllowDrop = $true


$url = 'https://github.com/zoicware/ZOICWARE/blob/main/features.md#importing-and-exporting-tweaks'
$infobutton = New-Object Windows.Forms.Button
$infobutton.Location = New-Object Drawing.Point(450, 0)
$infobutton.Size = New-Object Drawing.Size(30, 27)
$infobutton.Add_Click({
        try {
            Start-Process $url -ErrorAction Stop
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
$infobutton.FlatAppearance.BorderSize = 1
#$infobutton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$infobutton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$form.Controls.Add($infobutton)

$dconfiglabel = New-Object System.Windows.Forms.Label
$dconfiglabel.Location = New-Object System.Drawing.Point(10, 20)
$dconfiglabel.Size = New-Object System.Drawing.Size(120, 20)
$dconfiglabel.Text = 'Current Config:'
$dconfiglabel.ForeColor = 'White'
$form.Controls.Add($dconfiglabel)

$dconfigTextbox = New-Object System.Windows.Forms.TextBox
$dconfigTextbox.Location = New-Object System.Drawing.Point(130, 20)
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
$destLabel.ForeColor = 'White'
$form.Controls.Add($destLabel)

$iconfigTextbox = New-Object System.Windows.Forms.TextBox
$iconfigTextbox.Location = New-Object System.Drawing.Point(130, 60)
$iconfigTextbox.Size = New-Object System.Drawing.Size(300, 20)
$iconfigTextbox.Text = $null
$form.Controls.Add($iconfigTextbox)

$filebrowsebttn = New-Object System.Windows.Forms.Button
$filebrowsebttn.Location = New-Object System.Drawing.Point(440, 60)
$filebrowsebttn.Size = New-Object System.Drawing.Size(40, 20)
$filebrowsebttn.Text = '...'
$filebrowsebttn.Font = New-Object System.Drawing.Font($filebrowsebttn.Font.Name, 10, [System.Drawing.FontStyle]::Bold)
$filebrowsebttn.BackColor = [System.Drawing.Color]::FromArgb(75, 75, 75)
$filebrowsebttn.ForeColor = [System.Drawing.Color]::White
$filebrowsebttn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$filebrowsebttn.FlatAppearance.BorderSize = 1
#$filebrowsebttn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$filebrowsebttn.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$filebrowsebttn.Add_Click({
        $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $fileDialog.Filter = 'CFG Files (*.cfg)|*.cfg|All Files (*.*)|*.*'

        if ($fileDialog.ShowDialog() -eq 'OK') {
            $Global:selectedFile = $fileDialog.FileName
            $iconfigTextbox.Text = $Global:selectedFile
        }

    })
$form.Controls.Add($filebrowsebttn)


$resetConfigBttn = New-Object System.Windows.Forms.Button
$resetConfigBttn.Location = New-Object System.Drawing.Point(10, 100)
$resetConfigBttn.Size = New-Object System.Drawing.Size(130, 25)
$resetConfigBttn.Font = New-Object System.Drawing.Font($dmMonoFont, 7) 
$resetConfigBttn.Text = 'Reset Current Config'
$resetConfigBttn.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$resetConfigBttn.ForeColor = [System.Drawing.Color]::White
#$resetConfigBttn.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
#$resetConfigBttn.FlatAppearance.BorderSize = 0
#$resetConfigBttn.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$resetConfigBttn.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$resetConfigBttn.Add_Click({
        [reflection.assembly]::loadwithpartialname('System.Windows.Forms') | Out-Null 
        $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Are you sure you want to reset your current config?', 'zoicware', 'YesNo', 'Question')

        switch ($msgBoxInput) {
  
            'Yes' {
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

                Write-Host 'Config Reset!'

            }

            'No' {

            }
        }
    })
$form.Controls.Add($resetConfigBttn)


$customConfig = New-Object System.Windows.Forms.Button
$customConfig.Location = New-Object System.Drawing.Point(10, 130)
$customConfig.Size = New-Object System.Drawing.Size(130, 25)
$customConfig.Text = 'Build Custom Config'
$customConfig.Font = New-Object System.Drawing.Font($dmMonoFont, 7) 
$customConfig.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$customConfig.ForeColor = [System.Drawing.Color]::White
$customConfig.Add_Click({
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
        $form3.Font = New-Object System.Drawing.Font($dmMonoFont, 9) 

        $label2 = New-Object System.Windows.Forms.Label
        $label2.Location = New-Object System.Drawing.Point(10, 10)
        $label2.Size = New-Object System.Drawing.Size(280, 20)
        $label2.Text = 'Select Tweaks:'
        $label2.ForeColor = 'White'
        $label2.Font = New-Object System.Drawing.Font($dmMonoFont, 11) 
        $form3.Controls.Add($label2)

        $checkedListBox = New-Object System.Windows.Forms.CheckedListBox
        $checkedListBox.Location = New-Object System.Drawing.Point(55, 35)
        $checkedListBox.Size = New-Object System.Drawing.Size(270, 415)
        $checkedListBox.BackColor = 'Black'
        $checkedListBox.ForeColor = 'White'
        $checkedListBox.ScrollAlwaysVisible = $true
        $Form3.Controls.Add($checkedListBox)

        foreach ($name in $tweakNames) {
            $checkedListBox.Items.Add($name, $false) | Out-Null
        }

        $saveConfig = New-Object System.Windows.Forms.Button
        $saveConfig.Location = New-Object System.Drawing.Point(130, 455)
        $saveConfig.Size = New-Object System.Drawing.Size(120, 35)
        $saveConfig.Text = 'Save'
        $saveConfig.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
        $saveConfig.ForeColor = [System.Drawing.Color]::White
        #$removeLocked.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
        #$removeLocked.FlatAppearance.BorderSize = 0
        #$removeLocked.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
        #$removeLocked.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
        $saveConfig.Add_Click({
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
            })
        $form3.Controls.Add($saveConfig)

        $form3.ShowDialog() | Out-Null

        $form.Visible = $true

    })
$form.Controls.Add($customConfig)

$runConfig = New-Object System.Windows.Forms.Button
$runConfig.Location = New-Object System.Drawing.Point(130, 170)
$runConfig.Size = New-Object System.Drawing.Size(120, 30)
$runConfig.Text = 'Run Tweaks'
$runConfig.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$runConfig.ForeColor = [System.Drawing.Color]::White
#$runConfig.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
#$runConfig.FlatAppearance.BorderSize = 0
#$runConfig.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$runConfig.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$runConfig.Add_Click({
        $importedConfig = Get-Content $Global:selectedFile -Force -ErrorAction SilentlyContinue
        if ($importedConfig -eq $null) {
            Write-Host 'Imported Config Empty!'
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
    })
$form.Controls.Add($runConfig)

$exportConfig = New-Object System.Windows.Forms.Button
$exportConfig.Location = New-Object System.Drawing.Point(250, 170)
$exportConfig.Size = New-Object System.Drawing.Size(120, 30)
$exportConfig.Text = 'Export Tweaks'
$exportConfig.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$exportConfig.ForeColor = [System.Drawing.Color]::White
#$exportConfig.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
#$exportConfig.FlatAppearance.BorderSize = 0
#$exportConfig.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
#$exportConfig.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
$exportConfig.Add_Click({
        if (Test-Path "$env:USERPROFILE\ZCONFIG.cfg" -ErrorAction SilentlyContinue) {
            Write-Host 'Choose a Destination Directory:'
            $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    
            if ($folderDialog.ShowDialog() -eq 'OK') {
    
                $selectedFolder = $folderDialog.SelectedPath
                Copy-Item -Path "$env:USERPROFILE\ZCONFIG.cfg" -Destination $selectedFolder -Force
                $date = Get-Date -Format 'MM-dd-yy'
                Rename-Item -Path "$selectedFolder\ZCONFIG.cfg" -NewName "ZCONFIG$($date).cfg" -Force

                Write-Host 'Config Exported'`
    
            }
    
        }
        else {
            Write-Host 'CONFIG NOT FOUND!'
        }
    })
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

