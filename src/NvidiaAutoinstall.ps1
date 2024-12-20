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

    Write-Host 'Checking if 7zip is Installed...'
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
   
        Write-Host 'Installing 7zip...'
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

            Write-Host 'Installing Display Driver Uninstaller...' 
            Remove-Item "$env:TEMP\DDU.exe" -ErrorAction SilentlyContinue -Force
            Remove-Item "$env:TEMP\DDU v18.0.8.6" -Recurse -Force -ErrorAction SilentlyContinue
            $url = 'https://www.wagnardsoft.com/DDU/download/DDU%20v18.0.8.6.exe'  
            $ProgressPreference = 'SilentlyContinue' 
            try {
                Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\DDU.exe" -ErrorAction Stop
            }
            catch {
                Write-Host 'Unable to Install DDU Due to Download Error!' -ForegroundColor Red
                break
            }
            
            Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList "x -bso0 -bsp1 -bse1 -aoa `"$env:TEMP\DDU.exe`" -o`"$env:TEMP`"" -Wait

            $choice2 = Custom-MsgBox -message 'Boot to Safe Mode to Run (Recommended)?' -type Question

            if ($choice2 -eq 'OK') {
                Write-Host 'Booting to Safe Mode...'
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
    $searchUrl = 'https://www.nvidia.com/Download/processFind.aspx?psid=1&pfid=816&osid=57&lid=1&whql=1&lang=en-us&ctk=0&dtcid=1'
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

        Write-Host 'UNABLE TO GET LATEST DRIVERS FROM NVIDIA API'
        Write-Host
        Write-Host 'Use the Text Box Instead Ex. 551.86'
    }

    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    # Create a new form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Choose a Driver to Install'
    $form.Size = New-Object System.Drawing.Size(480, 700)
    $form.FormBorderStyle = 'FixedDialog'
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)

    # Create radio buttons
    $radioButton1 = New-Object System.Windows.Forms.RadioButton
    $radioButton1.Location = New-Object System.Drawing.Point(20, 20)
    $radioButton1.Size = New-Object System.Drawing.Size(100, 20)
    $radioButton1.ForeColor = 'White'
    $radioButton1.Text = $versions[0]
    $form.Controls.Add($radioButton1)

    $textBox1 = New-Object System.Windows.Forms.RichTextBox
    $textBox1.Location = New-Object System.Drawing.Point(20, 40)
    $textBox1.Size = New-Object System.Drawing.Size(400, 100)
    $textBox1.Multiline = $true
    $textbox1.Text = $releaseHighlights[0]
    $textBox1.ReadOnly = $true
    $textBox1.ScrollBars = 'Vertical'
    $textBox1.BackColor = [System.Drawing.Color]::FromArgb(55, 55, 55)
    $textBox1.ForeColor = 'White'
    $form.Controls.Add($textBox1)

    $radioButton2 = New-Object System.Windows.Forms.RadioButton
    $radioButton2.Location = New-Object System.Drawing.Point(20, 160)
    $radioButton2.Size = New-Object System.Drawing.Size(100, 20)
    $radioButton2.ForeColor = 'White'
    $radioButton2.Text = $versions[1]
    $form.Controls.Add($radioButton2)

    $textBox2 = New-Object System.Windows.Forms.RichTextBox
    $textBox2.Location = New-Object System.Drawing.Point(20, 180)
    $textBox2.Size = New-Object System.Drawing.Size(400, 100)
    $textBox2.Multiline = $true
    $textbox2.Text = $releaseHighlights[1]
    $textBox2.ReadOnly = $true
    $textBox2.ScrollBars = 'Vertical'
    $textBox2.BackColor = [System.Drawing.Color]::FromArgb(55, 55, 55)
    $textBox2.ForeColor = 'White'
    $form.Controls.Add($textBox2)


    $radioButton3 = New-Object System.Windows.Forms.RadioButton
    $radioButton3.Location = New-Object System.Drawing.Point(20, 300)
    $radioButton3.Size = New-Object System.Drawing.Size(100, 20)
    $radioButton3.ForeColor = 'White'
    $radioButton3.Text = $versions[2]
    $form.Controls.Add($radioButton3)

    $textBox3 = New-Object System.Windows.Forms.RichTextBox
    $textBox3.Location = New-Object System.Drawing.Point(20, 320)
    $textBox3.Size = New-Object System.Drawing.Size(400, 100)
    $textBox3.Multiline = $true
    $textbox3.Text = $releaseHighlights[2]
    $textBox3.ReadOnly = $true
    $textBox3.ScrollBars = 'Vertical'
    $textBox3.BackColor = [System.Drawing.Color]::FromArgb(55, 55, 55)
    $textBox3.ForeColor = 'White'
    $form.Controls.Add($textBox3)


    $radioButton4 = New-Object System.Windows.Forms.RadioButton
    $radioButton4.Location = New-Object System.Drawing.Point(20, 440)
    $radioButton4.Size = New-Object System.Drawing.Size(100, 20)
    $radioButton4.ForeColor = 'White'
    $radioButton4.Text = $versions[3]
    $form.Controls.Add($radioButton4)


    $textBox4 = New-Object System.Windows.Forms.RichTextBox
    $textBox4.Location = New-Object System.Drawing.Point(20, 460)
    $textBox4.Size = New-Object System.Drawing.Size(400, 100)
    $textBox4.Multiline = $true
    $textbox4.Text = $releaseHighlights[3]
    $textBox4.ReadOnly = $true
    $textBox4.ScrollBars = 'Vertical'
    $textBox4.BackColor = [System.Drawing.Color]::FromArgb(55, 55, 55)
    $textBox4.ForeColor = 'White'
    $form.Controls.Add($textBox4)


    # Create a checkbox
    $checkbox = New-Object System.Windows.Forms.CheckBox
    $checkbox.Location = New-Object System.Drawing.Point(20, 580)
    $checkbox.Size = New-Object System.Drawing.Size(110, 20)
    $checkbox.ForeColor = 'White'
    $checkbox.Text = 'Strip Driver?'
    $form.Controls.Add($checkbox)

    $checkbox2 = New-Object System.Windows.Forms.CheckBox
    $checkbox2.Location = New-Object System.Drawing.Point(130, 580)
    $checkbox2.Size = New-Object System.Drawing.Size(250, 20)
    $checkbox2.ForeColor = 'White'
    $checkbox2.Text = 'Install Notebook Version (laptops)'
    $form.Controls.Add($checkbox2)

    # Create a label for the text box
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(20, 610)
    $label.Size = New-Object System.Drawing.Size(130, 30)
    $label.ForeColor = 'White'
    $label.Text = 'Driver not listed? Enter Version:'
    $form.Controls.Add($label)


    # Create a textbox for custom version
    $textbox = New-Object System.Windows.Forms.TextBox
    $textbox.Location = New-Object System.Drawing.Point(150, 610)
    $textbox.Size = New-Object System.Drawing.Size(80, 20)
    $textbox.Text = 'Ex. 420.69'
    $textbox.MaxLength = 6
    $form.Controls.Add($textbox)
    $textbox.Add_TextChanged({
    
            $radioButton1.Checked = $false
            $radioButton2.Checked = $false
            $radioButton3.Checked = $false
            $radioButton4.Checked = $false
        })





    # Create an OK button
    $buttonOK = New-Object System.Windows.Forms.Button
    $buttonOK.Location = New-Object System.Drawing.Point(370, 630)
    $buttonOK.Size = New-Object System.Drawing.Size(80, 25)
    $buttonOK.Text = 'OK'
    $buttonOK.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $buttonOK.ForeColor = [System.Drawing.Color]::White
    $buttonOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $buttonOK
    $form.Controls.Add($buttonOK)

    # Show the form
    $result = $form.ShowDialog()
    $selectedDriver = ''
    $stripDriver = $false
    $laptop = $false
    # Get the selected values
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    
        if ($radioButton1.Checked) {
            $selectedDriver = $versions[0]
        }
        elseif ($radioButton2.Checked) {
            $selectedDriver = $versions[1]
        }
        elseif ($radioButton3.Checked) {
            $selectedDriver = $versions[2]
        }
        elseif ($radioButton4.Checked) {
            $selectedDriver = $versions[3]
        }
        elseif ($textbox.Text -ne '') {

            $selectedDriver = $textbox.Text

        }

        if ($checkbox.Checked) {
            $stripDriver = $true

        }

        if ($checkbox2.Checked) {
            $laptop = $true

        }
    }
    else {

        exit

    }



    Write-Host '------------- INSTALLING FILES ------------------'


    # Checking Windows bitness
    if ([Environment]::Is64BitOperatingSystem) {
        $windowsArchitecture = '64bit'
    }
    else {
        $windowsArchitecture = '32bit'
    }

    #installing latest driver
    if ($laptop) {
        $url = "https://us.download.nvidia.com/Windows/$selectedDriver/$selectedDriver-notebook-win10-win11-$windowsArchitecture-international-dch-whql.exe"

    }
    else {
        $url = "https://us.download.nvidia.com/Windows/$selectedDriver/$selectedDriver-desktop-win10-win11-$windowsArchitecture-international-dch-whql.exe"

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
        Write-host '------------ 7zip not installed ----------------'
        Start-Sleep 3
        exit
    }



    #deleting some files from GFExperince folder
    if ($stripDriver) {
        write-host '---------------- Stripping Driver ------------------'
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

    Write-Host '------------------- Installing Driver --------------------'
    #starting setup.exe in current directory (%temp%)
    Start-Process "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall\setup.exe" -WorkingDirectory "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall" -ArgumentList '-clean -s' -wait 
    Clear-Host
    write-host '------------------- Driver installed, Cleaning up -------------------'
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




    write-host '----------------- Disabling Telemetry --------------------'
    if ($stripDriver) {
        #removing a dll file needed to communicate with a telemetry server
        $path = (Get-ChildItem -Path C:\ -Filter NvTelemetry64.dll -Recurse -File -ErrorAction SilentlyContinue -Force | select-object -first 1).FullName
        Remove-Item $path -Force -ErrorAction SilentlyContinue

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



    #getting names of connected monitors
    $monitors = Get-WmiObject -Namespace root\wmi -Class WmiMonitorID

    $manufacturerNames = @()

    foreach ($monitor in $monitors) {
        $manufacturerName = [System.Text.Encoding]::ASCII.GetString($monitor.UserFriendlyName -ne 0)
        $manufacturerNames += $manufacturerName
    }







    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $form = New-Object System.Windows.Forms.Form
    $form.Size = New-Object System.Drawing.Size(400, 430)
    $form.StartPosition = 'CenterScreen'
    $form.Text = 'Post Install Tweaks'
    $form.BackColor = 'Black'
    $form.Font = New-Object System.Drawing.Font($dmMonoFont, 8)

    $TabControl = New-Object System.Windows.Forms.TabControl
    $TabControl.Location = New-Object System.Drawing.Size(10, 10)
    $TabControl.Size = New-Object System.Drawing.Size(370, 350) 
    $TabControl.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)


    $TabPage1 = New-Object System.Windows.Forms.TabPage
    $TabPage1.Text = 'General'
    $TabPage1.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

    $TabPage2 = New-Object System.Windows.Forms.TabPage
    $TabPage2.Text = 'Digital Vibrance'
    $TabPage2.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)


   
    $TabControl.Controls.Add($TabPage1)
    $TabControl.Controls.Add($TabPage2)



    $Form.Controls.Add($TabControl) 


    $checkbox1 = new-object System.Windows.Forms.checkbox
    $checkbox1.Location = new-object System.Drawing.Size(10, 20)
    $checkbox1.Size = new-object System.Drawing.Size(100, 20)
    $checkbox1.Text = 'Import NVCP Settings'
    $checkbox1.ForeColor = 'White'
    $checkbox1.Checked = $false
    $Form.Controls.Add($checkbox1)  
    $TabPage1.Controls.Add($checkBox1)

    $radiobutton1 = New-Object System.Windows.Forms.RadioButton
    $radiobutton1.Location = New-Object System.Drawing.Size(110, 20)
    $radiobutton1.Size = New-Object System.Drawing.Size(75, 20)
    $radiobutton1.Text = 'Rebar On'
    $radiobutton1.ForeColor = 'White'
    $radiobutton1.Checked = $false
    $radioButton1.Visible = $false
    $Form.Controls.Add($radiobutton1)
    $TabPage1.Controls.Add($radiobutton1)

    $radiobutton2 = New-Object System.Windows.Forms.RadioButton
    $radiobutton2.Location = New-Object System.Drawing.Size(190, 20)
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


    $trackbarValues = @{}
    for ($i = 0; $i -lt $dList.Length; $i++) {
        $y = 35 + ($i * 80)

        # Create a label for the manufacturer name
        $nameLabel = New-Object System.Windows.Forms.Label
        $nameLabel.Text = $manufacturerNames[$i]
        $nameLabel.ForeColor = 'White'
        $nameLabel.AutoSize = $true
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
                Write-Host 'REBAR OPTION NOT SELECTED DEFAULTING TO ON'
                $nip = Search-File '*RebarON.nip'
            }
           
            $inspector = Search-File '*nvidiaProfileInspector.exe'
        
            $arguments = 's', '-load', $nip
            & $inspector $arguments | Wait-Process

            #removes try icon
            Reg.exe add 'HKCU\SOFTWARE\NVIDIA Corporation\NvTray' /v 'StartOnLogin' /t REG_DWORD /d '0' /f

        }

    
        if ($checkbox2.Checked) {
            #enables legacy sharpen
            Reg.exe add 'HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS' /v 'EnableGR535' /t REG_DWORD /d '0' /f

        }

        if ($checkbox3.Checked) {
            #sets msi mode
            $instanceID = (Get-PnpDevice -Class Display).InstanceId
            Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\$instanceID\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v 'MSISupported' /t REG_DWORD /d '1' /f

        }

        if ($checkbox4.Checked) {
            #disable p0 state
            $subkeys = (Get-ChildItem -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -Force -ErrorAction SilentlyContinue).Name

            foreach ($key in $subkeys) {
                if ($key -notlike '*Configuration') {
                    Set-ItemProperty -Path "registry::$key" -Name 'DisableDynamicPstate' -Value 1 -Force
                }

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

