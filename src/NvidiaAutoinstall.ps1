#nvidia driver auto installation script by zoic

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}


function Run-Trusted([String]$command) {

    Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue
    #get bin path to revert later
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='TrustedInstaller'"
    $DefaultBinPath = $service.PathName
    #convert command to base64 to avoid errors with spaces
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)
    #change bin to command
    sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
    #run the command
    sc.exe start TrustedInstaller | Out-Null
    #set bin back to default
    sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
    Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue

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


if (!(Check-Internet)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Status -Message 'Checking if 7zip is Installed...' -Type Output
    
    $7zinstalledAlr = $false    
    $7zipinstalled = $false 
    if ((Test-path HKLM:\SOFTWARE\7-Zip\) -eq $true) {
        $7zpath = Get-ItemProperty -path  HKLM:\SOFTWARE\7-Zip\ -Name Path
        $7zpath = $7zpath.Path
        $7zpathexe = $7zpath + '7z.exe'
        if ((Test-Path $7zpathexe) -eq $true) {
            $archiverProgram = $7zpathexe
            $7zipinstalled = $true 
            $7zinstalledAlr = $true
        }    
    }
    else {
        Write-Status -Message 'Installing 7zip...' -Type Output
       
        $7zip = 'https://www.7-zip.org/a/7z2301-x64.exe'
        $output = "$env:TEMP\7Zip.exe"
        $ProgressPreference = 'SilentlyContinue' 
        Invoke-RestMethod $7zip -OutFile $output | Wait-Event -Timeout 1
        
        Start-Process $output -Wait -ArgumentList '/S' 
        # Delete the installer once it completes
        Remove-Item $output -Force
        $7zpath = Get-ItemProperty -path  HKLM:\SOFTWARE\7-Zip\ -Name Path
        $7zpath = $7zpath.Path
        $7zpathexe = $7zpath + '7z.exe'
        if ((Test-Path $7zpathexe) -eq $true) {
            $archiverProgram = $7zpathexe
            $7zipinstalled = $true 
        }   
    }
    




    #install ddu
    $choice = Custom-MsgBox -message 'Install Display Driver Uninstaller?' -type Question

    switch ($choice) {
        'OK' {
            Write-Status -Message 'Installing Display Driver Uninstaller...'  -Type Output
        
            Remove-Item "$env:TEMP\DDU.exe" -ErrorAction SilentlyContinue -Force
            Remove-Item "$env:TEMP\DDU v18.0.8.6" -Recurse -Force -ErrorAction SilentlyContinue
            $url = 'https://www.wagnardsoft.com/DDU/download/DDU%20v18.0.8.6.exe'  
            $ProgressPreference = 'SilentlyContinue' 
            try {
                Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\DDU.exe" -ErrorAction Stop
            }
            catch {
                Write-Status -Message 'Unable to Install DDU Due to Download Error!'  -Type Error
                break
            }
            
            Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList "x -bso0 -bsp1 -bse1 -aoa `"$env:TEMP\DDU.exe`" -o`"$env:TEMP`"" -Wait

            $choice2 = Custom-MsgBox -message 'Boot to Safe Mode to Run (Recommended)?' -type Question

            if ($choice2 -eq 'OK') {
                Write-Status -Message 'Booting to Safe Mode...'  -Type Output
             
                #add safe mode minimal
                Start-process bcdedit.exe -ArgumentList '/set {current} safeboot minimal'
                
                #create script to run on safe mode startup
                $currentValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit').Userinit
                $safeModeScript = "
                Start-process bcdedit.exe -ArgumentList '/deletevalue safeboot'
                Start-Process -FilePath `"$env:TEMP\DDU v18.0.8.6\Display Driver Uninstaller.exe`"
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit' -Value `"$currentValue`"
                "
                New-Item "$env:TEMP\safemodescript.ps1" -Value $safeModeScript -Force | Out-Null
                #create winlogon key
                $scriptRun = "powershell.exe -nop -ep bypass -f $env:TEMP\safemodescript.ps1"
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit' -Value "$currentValue, $scriptRun" -Force
                shutdown /f /r /t 0
            }
            else {
                #run ddu
                Start-Process -FilePath "$env:TEMP\DDU v18.0.8.6\Display Driver Uninstaller.exe" -Wait
            }


        }
        'Cancel' {}
    }

    #getting latest driver version num
    $uri = 'https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php' +
    '?func=DriverManualLookup' +
    '&psid=120' + 
    '&pfid=929' +  
    '&osID=57' + 
    '&languageCode=1033' + 
    '&isWHQL=1' + 
    '&dch=1' + 
    '&sort1=0' + 
    '&numberOfResults=4' 

    $response = Invoke-RestMethod -Uri $uri -UseBasicParsing
    $versions = $response.IDS.downloadInfo.Version  

    #add html agility pack to parse html response
    $dllPath = Search-File '*HtmlAgilityPack.dll'
    Add-Type -Path $dllPath 
    # NVIDIA API 
    $searchUrl = 'https://www.nvidia.com/Download/processFind.aspx?psid=120&pfid=929&osid=57&lid=1&whql=1&lang=en-us&ctk=0&dtcid=1'
    $response = Invoke-WebRequest -Uri $searchUrl -UseBasicParsing
    $htmlDoc = New-Object HtmlAgilityPack.HtmlDocument
    $htmlDoc.LoadHtml($response.Content)

    $content = $htmlDoc.DocumentNode.InnerText

    $sections = $content -split 'Release Highlights:'

    # get the 4 latest highlights
    $highlights = $sections[1..4]

    # cleanup the text
    $releaseHighlights = @()
    foreach ($highlight in $highlights) {
        $trimmedHighlight = $highlight.Trim() -replace '\s+', ' '
        $trimmedHighlight = $trimmedHighlight -replace 'Learn More in our Game Ready Driver article here. GeForce Game Ready Driver&nbsp;' , ''
        $trimmedHighlight = $trimmedHighlight -replace '&amp;' , '&'
        $trimmedHighlight = $trimmedHighlight -replace '&ouml;' , 'o' #for god of ragnarok game
        $trimmedHighlight = $trimmedHighlight -replace '\[\d+\]' , '' #remove issue ids
        $trimmedHighlight = $trimmedHighlight -replace '  ' , "`n" #move double space to a newline
        $trimmedHighlight = $trimmedHighlight -replace 'WHQL \d{3}\.\d{2} [A-Za-z]+ \d{1,2}, \d{4}' , '' #remove driver version/release date
        $releaseHighlights += $trimmedHighlight
    }


    if ($versions -eq $null) {
        Write-Status -Message 'UNABLE TO GET LATEST DRIVERS FROM NVIDIA API'  -Type Warning
        Write-Status -Message 'Use the Text Box Instead Ex. 551.86'  -Type Warning
        
    }

    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Nvidia Autoinstall'
    $form.Size = New-Object System.Drawing.Size(480, 400)
    $form.FormBorderStyle = 'FixedDialog'
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

    $labelCombo = New-Object System.Windows.Forms.Label
    $labelCombo.Location = New-Object System.Drawing.Point(20, 10)
    $labelCombo.Size = New-Object System.Drawing.Size(250, 20)
    $labelCombo.ForeColor = 'White'
    $labelCombo.Text = 'Choose NVIDIA Game Ready Driver:'
    $labelCombo.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($labelCombo)

    $comboBox = New-Object System.Windows.Forms.ComboBox
    $comboBox.Location = New-Object System.Drawing.Point(20, 40)
    $comboBox.Size = New-Object System.Drawing.Size(200, 20)
    $comboBox.DropDownStyle = 'DropDownList'
    $comboBox.BackColor = [System.Drawing.Color]::FromArgb(55, 55, 55)
    $comboBox.ForeColor = 'White'
    $versions | ForEach-Object { $comboBox.Items.Add($_) }
    $comboBox.SelectedIndex = 0
    $form.Controls.Add($comboBox)

 
    $textBox = New-Object System.Windows.Forms.RichTextBox
    $textBox.Location = New-Object System.Drawing.Point(20, 70)
    $textBox.Size = New-Object System.Drawing.Size(400, 200)
    $textBox.Multiline = $true
    $textBox.Text = $ReleaseHighlights[0]
    $textBox.ReadOnly = $true
    $textBox.ScrollBars = 'Vertical'
    $textBox.BackColor = [System.Drawing.Color]::FromArgb(55, 55, 55)
    $textBox.ForeColor = 'White'
    $form.Controls.Add($textBox)

    $comboBox.Add_SelectedIndexChanged({
            $textBox.Text = $ReleaseHighlights[$comboBox.SelectedIndex]
        })

    # Create a checkbox
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Location = New-Object System.Drawing.Point(20, 280)
    $checkbox.Size = New-Object System.Drawing.Size(110, 20)
    $checkbox.ForeColor = 'White'
    $checkbox.Text = 'Strip Driver?'
    $form.Controls.Add($checkbox)

    $checkbox2 = New-Object System.Windows.Forms.CheckBox
    $checkbox2.Location = New-Object System.Drawing.Point(130, 280)
    $checkbox2.Size = New-Object System.Drawing.Size(250, 20)
    $checkbox2.ForeColor = 'White'
    $checkbox2.Text = 'Install Notebook Version (laptops)'
    $form.Controls.Add($checkbox2)

   
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(20, 310)
    $label.Size = New-Object System.Drawing.Size(130, 30)
    $label.ForeColor = 'White'
    $label.Text = 'Driver not listed? Enter Version:'
    $form.Controls.Add($label)

    $textboxCustom = New-Object System.Windows.Forms.TextBox
    $textboxCustom.Location = New-Object System.Drawing.Point(150, 310)
    $textboxCustom.Size = New-Object System.Drawing.Size(80, 20)
    $textboxCustom.Text = 'Ex. 420.69'
    $textboxCustom.MaxLength = 8
    $form.Controls.Add($textboxCustom)
    $textboxCustom.Add_TextChanged({
            if ($textboxCustom.Text -ne 'Ex. 420.69' -and $textboxCustom.Text -ne '') {
                $comboBox.SelectedIndex = -1
            }
        })

    $tooltip1 = New-Object System.Windows.Forms.ToolTip
    $tooltip1.SetToolTip($textboxCustom, 'Add, hf to the end for HotFix drivers
    Ex. 420.69hf')

    $buttonOK = New-Object System.Windows.Forms.Button
    $buttonOK.Location = New-Object System.Drawing.Point(370, 330)
    $buttonOK.Size = New-Object System.Drawing.Size(80, 25)
    $buttonOK.Text = 'OK'
    $buttonOK.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $buttonOK.ForeColor = [System.Drawing.Color]::White
    $buttonOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $buttonOK
    $form.Controls.Add($buttonOK)

    $buttonSkip = New-Object System.Windows.Forms.Button
    $buttonSkip.Location = New-Object System.Drawing.Point(290, 330)
    $buttonSkip.Size = New-Object System.Drawing.Size(80, 25)
    $buttonSkip.Text = 'Skip'
    $buttonSkip.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $buttonSkip.ForeColor = [System.Drawing.Color]::White
    $buttonSkip.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.AcceptButton = $buttonSkip
    $form.Controls.Add($buttonSkip)

    $result = $form.ShowDialog()
    $selectedDriver = ''
    $stripDriver = $false
    $laptop = $false

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        if ($textboxCustom.Text -ne 'Ex. 420.69' -and $textboxCustom.Text -ne '') {
            $selectedDriver = $textboxCustom.Text
        }
        elseif ($comboBox.SelectedIndex -ge 0) {
            $selectedDriver = $comboBox.SelectedItem
        }

        if ($checkbox.Checked) {
            $stripDriver = $true
        }

        if ($checkbox2.Checked) {
            $laptop = $true
        }

        Write-Status -Message 'INSTALLING FILES'  -Type Output
    


        # Checking Windows bitness
        if ([Environment]::Is64BitOperatingSystem) {
            $windowsArchitecture = '64bit'
        }
        else {
            $windowsArchitecture = '32bit'
        }

        #installing latest driver
        if ($laptop) {
            if ($selectedDriver -like '*hf') {
                #remove hf
                $driverNum = $selectedDriver -replace 'hf', ''
                $url = "https://international.download.nvidia.com/Windows/$selectedDriver/$driverNum-notebook-win10-win11-$windowsArchitecture-international-dch-hf.exe"
            }
            else {
                $url = "https://international.download.nvidia.com/Windows/$selectedDriver/$selectedDriver-notebook-win10-win11-$windowsArchitecture-international-dch-whql.exe"
            }

        }
        else {
            if ($selectedDriver -like '*hf') {
                #remove hf
                $driverNum = $selectedDriver -replace 'hf', ''
                $url = "https://international.download.nvidia.com/Windows/$selectedDriver/$driverNum-desktop-win10-win11-$windowsArchitecture-international-dch-hf.exe"
            }
            else {
                $url = "https://international.download.nvidia.com/Windows/$selectedDriver/$selectedDriver-desktop-win10-win11-$windowsArchitecture-international-dch-whql.exe"
            }

        }

        Get-FileFromWeb -URL $url -File "C:\$selectedDriver.exe"

        New-item -Path "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall" -ItemType Directory -Force
        $extractFolder = "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall"
        $exepath = "C:\$selectedDriver.exe"
        if ($stripDriver) {
            if ([version]$selectedDriver -ge '566.36') {
                $filesToExtract = 'Display.Driver NvApp NVI2 EULA.txt ListDevices.txt setup.cfg setup.exe'
            }
            else {
                $filesToExtract = 'Display.Driver GFExperience NVI2 EULA.txt ListDevices.txt setup.cfg setup.exe'
            }
        

        }

        #extracting driver files to (%temp%)
        if ($7zipinstalled) {
            if ($stripDriver) {
                Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList "x -bso0 -bsp1 -bse1 -aoa $exepath $filesToExtract -o""$extractFolder""" -wait
            }
            else {

                Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList "x -bso0 -bsp1 -bse1 -aoa $exepath -o""$extractFolder""" -wait
            }
    
        }
        else {
            Write-Status -Message '7zip not installed '  -Type Error
     
            Start-Sleep 3
            exit
        }



        #deleting some files from GFExperince folder
        if ($stripDriver) {
            Write-Status -Message 'Stripping Driver...'  -Type Output
       
            if ([version]$selectedDriver -ge '566.36') {
                $targetDirectory = "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall\NvApp"
            }
            else {
                $targetDirectory = "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall\GFExperience"
            }
        

            # List of folders to exclude from deletion
            $excludedFolders = @(
                'PrivacyPolicy',
                'locales'
            )
            if ([version]$selectedDriver -ge '566.36') {
                $excludedFolders += 'CEF', 'Unified_EULA', 'EULA'
            }
            # List of files to exclude from deletion
            $excludedFiles = @(
                'EULA.html',
                'EULA.txt'
            )

            # Get all items (files and folders) in the target directory
            $items = Get-ChildItem -Path $targetDirectory -Force 

            # Iterate through each item
            foreach ($item in $items) {
                $itemName = $item.Name

                # Check if the item is a folder and not in the excludedFolders list
                if ($item.PSIsContainer -and $excludedFolders -notcontains $itemName) {
                    # Remove the folder and its contents recursively
                    Remove-Item -Path $item.FullName -Recurse -Force 
                }

                # Check if the item is a file and should not be excluded
                elseif ($item.PSIsContainer -eq $false -and $excludedFiles -notcontains $itemName) {
                    # Check if the file contains the word "FunctionalConsent_" in its name
                    if ($itemName -like '*FunctionalConsent_*') {
                        # Skip the file and move to the next item
                        continue
                    }

                    # Remove the file
                    Remove-Item -Path $item.FullName -Force
                }
            }

            if ([version]$selectedDriver -ge '566.36') {
                $files = Get-ChildItem -Path "$targetDirectory\CEF"
                foreach ($file in $files) {
                    if ($file.FullName -like '*locales*') {
                        continue
                    }
                    else {
                        if ($file.PSIsContainer) {
                            Remove-Item $file.FullName -Recurse -Force
                        }
                        else {
                            Remove-Item $file.FullName -Force
                        }
                    }
                
                }
            }
        }

        #disabling hdcp
        $subkeys = (Get-ChildItem -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -Force -ErrorAction SilentlyContinue).Name

        foreach ($key in $subkeys) {
            if ($key -notlike '*Configuration') {
                Set-ItemProperty -Path "registry::$key" -Name 'RMHdcpKeyglobZero' -Value 1 -Force
            }

        }
        Write-Status -Message 'Installing Driver...'  -Type Output
    
        #starting setup.exe in current directory (%temp%)
        Start-Process "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall\setup.exe" -WorkingDirectory "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall" -ArgumentList '-clean -s' -wait 
        Clear-Host
        Write-Status -Message 'Driver installed, Cleaning up...'  -Type Output
   
        #cleaning up
        Remove-Item "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall" -Recurse -Force
        Remove-Item "$env:USERPROFILE\AppData\Local\Temp\NvidiaLogging" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\$selectedDriver.exe" -Force 
        Remove-Item "$env:TEMP\DDU.exe" -ErrorAction SilentlyContinue -Force
        Remove-Item "$env:TEMP\DDU v18.0.8.6" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\safemodescript.ps1" -Force -ErrorAction SilentlyContinue
        #uninstalling 7zip
        if ($7zinstalledAlr -eq $false) {
            $path = (Get-ChildItem -Path C:\ -Filter 7-Zip -Recurse -ErrorAction SilentlyContinue -Force | select-object -first 1).FullName
            Start-Process "$path\Uninstall.exe" -wait -ArgumentList '/S'
            remove-item 'HKLM:\SOFTWARE\7-Zip' -Force -Recurse -ErrorAction SilentlyContinue

        }



        Write-Status -Message 'Disabling Telemetry...'  -Type Output
    
        if ($stripDriver) {
            #removing a dll file needed to communicate with a telemetry server
      (Get-ChildItem -Path "$env:windir\System32\DriverStore\FileRepository\nv_dispi*" -Directory).FullName | ForEach-Object { 
                takeown /f "$_\NvTelemetry64.dll" *>$null
                icacls "$_\NvTelemetry64.dll" /grant administrators:F /t *>$null
                Remove-Item "$_\NvTelemetry64.dll" -Force 
            }
        

        }
        else {
            #disables updater and telemetry tasks
            Get-ScheduledTask -TaskName '*NvDriverUpdateCheckDaily*' | Disable-ScheduledTask 
            Get-ScheduledTask -TaskName '*NVIDIA GeForce Experience SelfUpdate*' | Disable-ScheduledTask
            Get-ScheduledTask -TaskName '*NvProfileUpdaterDaily*' | Disable-ScheduledTask
            Get-ScheduledTask -TaskName '*NvProfileUpdaterOnLogon*' | Disable-ScheduledTask
            Get-ScheduledTask -TaskName '*NvTmRep_CrashReport1*' | Disable-ScheduledTask
            Get-ScheduledTask -TaskName '*NvTmRep_CrashReport2*' | Disable-ScheduledTask
            Get-ScheduledTask -TaskName '*NvTmRep_CrashReport3*' | Disable-ScheduledTask
            Get-ScheduledTask -TaskName '*NvTmRep_CrashReport4*' | Disable-ScheduledTask
            #disables frame view service
            Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\FvSvc' /v 'Start' /t REG_DWORD /d '4' /f

        }

    }
    



    Write-Status -message 'Fixing Nvidia DRS Folder...' -type Output
    $path = "$env:ProgramData\NVIDIA Corporation\Drs"
    (Get-ChildItem -Path $path).FullName | Foreach-Object { Unblock-File $_ }

    #getting monitor ids and adding them to an array
    $monitorDevices = pnputil /enum-devices | Select-String -Pattern 'DISPLAY'

    if ($monitorDevices) {
        $dList = @()
    
        foreach ($device in $monitorDevices) {
            $deviceId = $device.ToString() -replace '^.*?DISPLAY\\(.*?)\\.*$', '$1'
        
            if ($deviceId.Length -eq 7 -and !$dList.Contains($deviceId)) {
            
                $dList += $deviceId
            
                
            }
        }
        
    }


    #adding saturation reg key paths to an array
    $paths = @()
    for ($i = 0; $i -lt $dList.Length; $i++) {
        $paths += Get-ChildItem -Path 'registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\nvlddmkm\State\DisplayDatabase\' | Where-Object { $_.Name -like "*$($dList[$i])*" } | Select-Object -First 1

    }

    #get monitor info
    $monitors = Get-WmiObject -Namespace root\wmi -Class WmiMonitorID
    $manufacturerNames = @()
    $soundDevices = Get-WmiObject -Class Win32_SoundDevice
    $pnpDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.PNPDeviceID -ne $null }
    $videoControllers = Get-WmiObject -Class Win32_VideoController

    $allmonitors = @()
    #find related sound device
    foreach ($monitor in $monitors) {
        $manufacturerName = [System.Text.Encoding]::ASCII.GetString($monitor.UserFriendlyName -ne 0)
        $manufacturerNames += $manufacturerName

        $monitorInstance = $monitor.InstanceName

        # Try to find a matching PnP device for the monitor
        $monitorPnp = $pnpDevices | Where-Object {
            $_.PNPDeviceID -like "*$monitorInstance*" -or
            $_.Name -like "*$manufacturerName*" -or
            $_.PNPDeviceID -match 'DISPLAY\\'
        }

        # Find the video controller associated with the monitor
        $relatedVideoController = $videoControllers | Where-Object {
            $_.PNPDeviceID -like "*$monitorInstance*" -or
            $_.Name -like '*NVIDIA*' -or 
            $_.PNPDeviceID -match 'PCI\\VEN_10DE'  
        }

        if ($monitorPnp -or $relatedVideoController) {
            # Look for sound devices tied to the monitor
            $relatedSound = $soundDevices | Where-Object {
                $soundPnp = $pnpDevices | Where-Object { $_.PNPDeviceID -like "*$($_.DeviceID)*" }
                $soundPnp -and (
                ($relatedVideoController -and $_.DeviceID -like '*VEN_10DE*') -or 
                ($monitorPnp -and $soundPnp.PNPDeviceID -like "*$($monitorPnp.PNPDeviceID)*") -or
                ($soundPnp.Service -eq 'HDAUDIO' -and $_.DeviceID -like '*VEN_10DE*')  
                )
            }

            if ($relatedSound) {
                $monitorObj = [PSCustomObject]@{
                    MonitorName   = $manufacturerName
                    SoundDeviceID = $relatedSound.DeviceID
                }
                $allmonitors += $monitorObj
            }
    
        }
    }
   

    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Size = New-Object System.Drawing.Size(400, 430)
    $form.StartPosition = 'CenterScreen'
    $form.Text = 'Post Install Tweaks'
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $form.Icon = New-Object System.Drawing.Icon($Global:customIcon)

    $TabControl = New-Object System.Windows.Forms.TabControl
    $TabControl.Location = New-Object System.Drawing.Size(10, 10)
    $TabControl.Size = New-Object System.Drawing.Size(370, 350) 
    $TabControl.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)


    $TabPage1 = New-Object System.Windows.Forms.TabPage
    $TabPage1.Text = 'General'
    $TabPage1.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

    $TabPage2 = New-Object System.Windows.Forms.TabPage
    $TabPage2.Text = 'Monitor'
    $TabPage2.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)


   
    $TabControl.Controls.Add($TabPage1)
    $TabControl.Controls.Add($TabPage2)



    $Form.Controls.Add($TabControl) 


    $checkbox1 = new-object System.Windows.Forms.checkbox
    $checkbox1.Location = new-object System.Drawing.Size(10, 20)
    $checkbox1.Size = new-object System.Drawing.Size(170, 20)
    $checkbox1.Text = 'Import NVCP Settings'
    $checkbox1.ForeColor = 'White'
    $checkbox1.Checked = $false
    $Form.Controls.Add($checkbox1)  
    $TabPage1.Controls.Add($checkBox1)

    $radiobutton1 = New-Object System.Windows.Forms.RadioButton
    $radiobutton1.Location = New-Object System.Drawing.Size(180, 20)
    $radiobutton1.Size = New-Object System.Drawing.Size(75, 20)
    $radiobutton1.Text = 'Rebar On'
    $radiobutton1.ForeColor = 'White'
    $radiobutton1.Checked = $false
    $radioButton1.Visible = $false
    $Form.Controls.Add($radiobutton1)
    $TabPage1.Controls.Add($radiobutton1)

    $radiobutton2 = New-Object System.Windows.Forms.RadioButton
    $radiobutton2.Location = New-Object System.Drawing.Size(270, 20)
    $radiobutton2.Size = New-Object System.Drawing.Size(85, 20)
    $radiobutton2.Text = 'Rebar Off'
    $radiobutton2.ForeColor = 'White'
    $radiobutton2.Checked = $false
    $radioButton2.Visible = $false
    $Form.Controls.Add($radiobutton2)
    $TabPage1.Controls.Add($radiobutton2)



    $checkbox1.add_CheckedChanged({
            if ($checkbox1.Checked) {
                $radioButton1.Visible = $true
                $radioButton2.Visible = $true
            }
            else {
                $radioButton1.Visible = $false
                $radioButton2.Visible = $false
            }
        })

    $checkbox2 = new-object System.Windows.Forms.checkbox
    $checkbox2.Location = new-object System.Drawing.Size(10, 50)
    $checkbox2.Size = new-object System.Drawing.Size(170, 20)
    $checkbox2.Text = 'Enable Legacy Sharpen'
    $checkbox2.ForeColor = 'White'
    $checkbox2.Checked = $false
    $Form.Controls.Add($checkbox2)
    $TabPage1.Controls.Add($checkBox2)

    $checkbox3 = new-object System.Windows.Forms.checkbox
    $checkbox3.Location = new-object System.Drawing.Size(10, 80)
    $checkbox3.Size = new-object System.Drawing.Size(170, 20)
    $checkbox3.Text = 'Enable MSI Mode'
    $checkbox3.ForeColor = 'White'
    $checkbox3.Checked = $false
    $Form.Controls.Add($checkbox3)
    $TabPage1.Controls.Add($checkBox3)

    $checkbox4 = new-object System.Windows.Forms.checkbox
    $checkbox4.Location = new-object System.Drawing.Size(10, 110)
    $checkbox4.Size = new-object System.Drawing.Size(170, 20)
    $checkbox4.Text = 'Remove GPU Idle States'
    $checkbox4.ForeColor = 'White'
    $checkbox4.Checked = $false
    $Form.Controls.Add($checkbox4)
    $TabPage1.Controls.Add($checkBox4)


    $vibrance = New-Object System.Windows.Forms.Label
    $vibrance.Text = 'Digital Vibrance'
    $vibrance.ForeColor = 'White'
    $vibrance.AutoSize = $true
    $vibrance.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold) 
    $vibrance.Location = New-Object System.Drawing.Point(100, 10)
    $tabPage2.Controls.Add($vibrance)
        
    $trackbarValues = @{}
    $checkboxes = @()
    for ($i = 0; $i -lt $dList.Length; $i++) {
        $y = 35 + ($i * 80)

        #checkbox for disabling monitor speakers
        $checkbox = new-object System.Windows.Forms.checkbox
        $checkbox.Location = new-object System.Drawing.Size(10, ($y + 20))
        $checkbox.Size = new-object System.Drawing.Size(100, 20)
        $checkbox.Text = 'Disable Speakers'
        $checkbox.ForeColor = 'White'
        $checkbox.Checked = $false
        $checkbox.Tag = $allmonitors[$i].SoundDeviceID
        $Form.Controls.Add($checkbox)
        $TabPage2.Controls.Add($checkBox)
        $checkboxes += $checkbox

        # Create a label for the manufacturer name
        $nameLabel = New-Object System.Windows.Forms.Label
        $nameLabel.Text = $allmonitors[$i].MonitorName
        $nameLabel.ForeColor = 'White'
        $nameLabel.AutoSize = $true
        $nameLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        $nameLabel.Location = New-Object System.Drawing.Point(10, $y)
        $tabPage2.Controls.Add($nameLabel)

        # Create a trackbar for the value
        $trackBar = New-Object System.Windows.Forms.TrackBar
        $trackBar.Minimum = 0
        $trackBar.Maximum = 100
        $trackBar.TickFrequency = 5
        $trackBar.SmallChange = 1
        $trackBar.LargeChange = 10
        $trackBar.Location = New-Object System.Drawing.Point(100, $y)
        $trackBar.Width = 200
        $tabPage2.Controls.Add($trackBar)
        $midpoint = [Math]::Round(($trackBar.Minimum + $trackBar.Maximum) / 2)
        $trackBar.Value = $midpoint

        # Assign a unique tag to each trackbar
        $trackBar.Tag = $i

        # Create a label to display the value
        $valueLabel = New-Object System.Windows.Forms.Label
        $valueLabel.AutoSize = $true
        $valueLabel.ForeColor = 'White'
        $valueLabel.Location = New-Object System.Drawing.Point(300, $y)
        $valueLabel.Text = '50'
        $tabPage2.Controls.Add($valueLabel)

        # Add an event handler to update the value label when the trackbar value changes
        $handler = {
            param (
                $valueLabel,
                $trackBar,
                $trackbarValues
            )

            $trackBar.add_Scroll({
                    $valueLabel.Text = $trackBar.Value.ToString()
                    $trackbarValues[$trackBar.Tag] = $trackBar.Value

                })
        }

     

        # Create a new closure for each trackbar and value label pair
        $closure = $handler.GetNewClosure()
        $closure.Invoke($valueLabel, $trackBar, $trackbarValues)

        # Add the initial value to the trackbarValues hashtable
        $trackbarValues[$i] = $midpoint
    }




    # Create an "Apply" button
    $applyButton = New-Object System.Windows.Forms.Button
    $applyButton.Location = New-Object System.Drawing.Point(150, 360)
    $applyButton.Size = New-Object System.Drawing.Size(100, 30)
    $applyButton.Text = 'Apply'
    $applyButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $applyButton.ForeColor = [System.Drawing.Color]::White
    $applyButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($applyButton)

    # Show the form
    $dialogResult = $form.ShowDialog()

    # Handle the button click event
    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {

        if ($checkbox1.Checked) {

            if ($radioButton1.Checked) {
                $nip = Search-File '*RebarON.nip'
            }
            elseif ($radioButton2.Checked) {
                $nip = Search-File '*RebarOFF.nip'
            }
            else {
                Write-Status -Message 'REBAR OPTION NOT SELECTED DEFAULTING TO ON...'  -Type Warning
                
                $nip = Search-File '*RebarON.nip'
            }
           
            $inspector = Search-File '*nvidiaProfileInspector.exe'
        
            $arguments = 's', '-load', $nip
            & $inspector $arguments | Wait-Process

            #removes try icon
            Reg.exe add 'HKCU\SOFTWARE\NVIDIA Corporation\NvTray' /v 'StartOnLogin' /t REG_DWORD /d '0' /f

        }

    
        if ($checkbox2.Checked) {
            Write-Status -Message 'Enabling Legacy Sharpen...'  -Type Output
            #enables legacy sharpen
            #check correct path
            if (test-path 'HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters\FTS') {
                Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters\FTS' /v 'EnableGR535' /t REG_DWORD /d '0' /f
            }
            else {
                Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS' /v 'EnableGR535' /t REG_DWORD /d '0' /f
            }
            
        
        }

        if ($checkbox3.Checked) {
            Write-Status -Message 'Enabling MSI Mode For Driver...'  -Type Output
            #sets msi mode
            $instanceID = (Get-PnpDevice -Class Display).InstanceId
            Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\$instanceID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v 'MSISupported' /t REG_DWORD /d '1' /f

        }

        if ($checkbox4.Checked) {
            Write-Status -Message 'Disabling P0 State...'  -Type Output
            #disable p0 state
            $subkeys = (Get-ChildItem -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -Force -ErrorAction SilentlyContinue).Name

            foreach ($key in $subkeys) {
                if ($key -notlike '*Configuration') {
                    Set-ItemProperty -Path "registry::$key" -Name 'DisableDynamicPstate' -Value 1 -Force
                }

            }
        }
   

        foreach ($checkbox in $checkboxes) {
            if ($checkbox.Checked) {
                Write-Status -message 'Disabling Monitor Speakers...' -type output
                pnputil.exe /disable-device $checkbox.Tag
            }
        }

        #looping through trackbar values and setting them in registry to the corresponding monitor 
        $i = 0
   
        foreach ($key in $trackbarValues.Keys) {
            $value = $trackbarValues[$key]
            $path = $paths[$i]
            $command = "Reg.exe add $path /v `"SaturationRegistryKey`" /t REG_DWORD /d $value /f"
            Run-Trusted -command $command
            Start-Sleep 1
            $i++
        }

   
    }


}

