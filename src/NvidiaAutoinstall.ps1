#nvidia driver auto installation script by zoic

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}

$Global:tempDir = (([System.IO.Path]::GetTempPath())).trimend('\')

function Download-AppxPackage {
    param(
        # there has to be an alternative, as sometimes the API fails on PackageFamilyName
        [string]$PackageFamilyName,
        [string]$ProductId,
        [string]$outputDir
    )
    if (-Not ($PackageFamilyName -Or $ProductId)) {
        # can't do anything without at least one
        Write-Error 'Missing either PackageFamilyName or ProductId.'
        return $null
    }
                  
    try {
        $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome # needed as sometimes the API will block things when it knows requests are coming from PowerShell
    }
    catch {
        $UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    }
                  
    $DownloadedFiles = @()
    $errored = $false
    $allFilesDownloaded = $true
                  
    $apiUrl = 'https://store.rg-adguard.net/api/GetFiles'
    $versionRing = 'Retail'
                  
    $architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
        'x86' { 'x86' }
        { @('x64', 'amd64') -contains $_ } { 'x64' }
        'arm' { 'arm' }
        'arm64' { 'arm64' }
        default { 'neutral' } # should never get here
    }
                  
    if (Test-Path $outputDir -PathType Container) {
        New-Item -Path "$outputDir\$PackageFamilyName" -ItemType Directory -Force | Out-Null
        $downloadFolder = "$outputDir\$PackageFamilyName"
    }
    else {
        $downloadFolder = Join-Path $tempDir $PackageFamilyName
        if (!(Test-Path $downloadFolder -PathType Container)) {
            New-Item $downloadFolder -ItemType Directory -Force | Out-Null
        }
    }
                    
    $body = @{
        type = if ($ProductId) { 'ProductId' } else { 'PackageFamilyName' }
        url  = if ($ProductId) { $ProductId } else { $PackageFamilyName }
        ring = $versionRing
        lang = 'en-US'
    }

    $headers = @{
        'User-Agent'       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        'Accept'           = 'application/json, text/javascript, */*; q=0.01'
        'Content-Type'     = 'application/x-www-form-urlencoded; charset=UTF-8'
        'X-Requested-With' = 'XMLHttpRequest'
        'Origin'           = 'https://store.rg-adguard.net'
        'Referer'          = 'https://store.rg-adguard.net/'
    }
      
                  
    # required due to the api being protected behind Cloudflare now
    if (-Not $apiWebSession) {
        $global:apiWebSession = $null
        $apiHostname = (($apiUrl.split('/'))[0..2]) -Join '/'
        Invoke-WebRequest -Uri $apiHostname -UserAgent $UserAgent -SessionVariable $apiWebSession -UseBasicParsing
    }
                  
    $raw = $null
    try {
        $raw = Invoke-RestMethod -Method Post -Uri $apiUrl -Headers $headers -Body $body -WebSession $apiWebSession
    }
    catch {
        $errorMsg = 'An error occurred: ' + $_
        Write-Host $errorMsg
        $errored = $true
        return $false
    }
                  
    # hashtable of packages by $name
    #  > values = hashtables of packages by $version
    #    > values = arrays of packages as objects (containing: url, filename, name, version, arch, publisherId, type)
    [Collections.Generic.Dictionary[string, Collections.Generic.Dictionary[string, array]]] $packageList = @{}
    # populate $packageList
    $patternUrlAndText = '<tr style.*<a href=\"(?<url>.*)"\s.*>(?<text>.*\.(app|msi)x.*)<\/a>'
    $raw | Select-String $patternUrlAndText -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object {
        $url = ($_.Groups['url']).Value
        $text = ($_.Groups['text']).Value
        $textSplitUnderscore = $text.split('_')
        $name = $textSplitUnderscore.split('_')[0]
        $version = $textSplitUnderscore.split('_')[1]
        $arch = ($textSplitUnderscore.split('_')[2]).ToLower()
        $publisherId = ($textSplitUnderscore.split('_')[4]).split('.')[0]
        $textSplitPeriod = $text.split('.')
        $type = ($textSplitPeriod[$textSplitPeriod.length - 1]).ToLower()
                  
        # create $name hash key hashtable, if it doesn't already exist
        if (!($packageList.keys -match ('^' + [Regex]::escape($name) + '$'))) {
            $packageList["$name"] = @{}
        }
        # create $version hash key array, if it doesn't already exist
        if (!(($packageList["$name"]).keys -match ('^' + [Regex]::escape($version) + '$'))) {
            ($packageList["$name"])["$version"] = @()
        }
                   
        # add package to the array in the hashtable
        ($packageList["$name"])["$version"] += @{
            url         = $url
            filename    = $text
            name        = $name
            version     = $version
            arch        = $arch
            publisherId = $publisherId
            type        = $type
        }
    }
                  
    # an array of packages as objects, meant to only contain one of each $name
    $latestPackages = @()
    # grabs the most updated package for $name and puts it into $latestPackages
    $packageList.GetEnumerator() | ForEach-Object { ($_.value).GetEnumerator() | Select-Object -Last 1 } | ForEach-Object {
        $packagesByType = $_.value
        $msixbundle = ($packagesByType | Where-Object { $_.type -match '^msixbundle$' })
        $appxbundle = ($packagesByType | Where-Object { $_.type -match '^appxbundle$' })
        $msix = ($packagesByType | Where-Object { ($_.type -match '^msix$') -And ($_.arch -match ('^' + [Regex]::Escape($architecture) + '$')) })
        $appx = ($packagesByType | Where-Object { ($_.type -match '^appx$') -And ($_.arch -match ('^' + [Regex]::Escape($architecture) + '$')) })
        if ($msixbundle) { $latestPackages += $msixbundle }
        elseif ($appxbundle) { $latestPackages += $appxbundle }
        elseif ($msix) { $latestPackages += $msix }
        elseif ($appx) { $latestPackages += $appx }
    }
                  
    # download packages
    $latestPackages | ForEach-Object {
        $url = $_.url
        $filename = $_.filename
        # TODO: may need to include detection in the future of expired package download URLs..... in the case that downloads take over 10 minutes to complete
                  
        $downloadFile = Join-Path $downloadFolder $filename
                  
        # If file already exists, ask to replace it
        if (Test-Path $downloadFile) {
            Write-Host "`"${filename}`" already exists at `"${downloadFile}`"."
            $confirmation = ''
            while (!(($confirmation -eq 'Y') -Or ($confirmation -eq 'N'))) {
                $confirmation = Read-Host "`nWould you like to re-download and overwrite the file at `"${downloadFile}`" (Y/N)?"
                $confirmation = $confirmation.ToUpper()
            }
            if ($confirmation -eq 'Y') {
                Remove-Item -Path $downloadFile -Force
            }
            else {
                $DownloadedFiles += $downloadFile
            }
        }
                  
        if (!(Test-Path $downloadFile)) {
            Write-Host "Attempting download of `"${filename}`" to `"${downloadFile}`" . . ."
            $fileDownloaded = $null
            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue' # avoids slow download when using Invoke-WebRequest
            try {
                Invoke-WebRequest -Uri $url -OutFile $downloadFile
                $fileDownloaded = $?
            }
            catch {
                $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
                $errorMsg = 'An error occurred: ' + $_
                Write-Host $errorMsg
                $errored = $true
                break $false
            }
            $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
            if ($fileDownloaded) { $DownloadedFiles += $downloadFile }
            else { $allFilesDownloaded = $false }
        }
    }
    if ($errored) { Write-Host 'Completed with some errors.' }
    if (-Not $allFilesDownloaded) { Write-Host 'Warning: Not all packages could be downloaded.' }
    return $DownloadedFiles
}

function Edit-Nip {
    param (
        [string]$nipPath,
        [string]$settingId,
        [string]$settingValue,
        [string]$valueType,
        [string]$settingNameInfo
    )
    #get nip content (profile inspector uses standard xml formatting)
    [xml]$nipContent = Get-Content $nipPath
    $settings = $nipContent.ArrayOfProfile.Profile.Settings
    #create new setting node
    $newSetting = $nipContent.CreateElement('ProfileSetting')
    $newsettingNameInfo = $nipContent.CreateElement('SettingNameInfo')
    if ($settingNameInfo) {
        $newsettingNameInfo.InnerText = $settingNameInfo
    }
    $newSetting.AppendChild($newsettingNameInfo) | Out-Null

    #create the new setting
    $newsettingID = $nipContent.CreateElement('SettingID')
    $newsettingID.InnerText = $settingId
    $newSetting.AppendChild($newsettingID) | Out-Null
    
    $newsettingValue = $nipContent.CreateElement('SettingValue')
    $newsettingValue.InnerText = $settingValue
    $newSetting.AppendChild($newsettingValue) | Out-Null
    
    $newvalueType = $nipContent.CreateElement('ValueType')
    $newvalueType.InnerText = $valueType
    $newSetting.AppendChild($newvalueType) | Out-Null
    
    #add new setting to nip
    $settings.AppendChild($newSetting) | Out-Null
    $nipContent.Save($nipPath)

    
}



function Run-Trusted([String]$command) {

    Stop-Service -Name TrustedInstaller -Force -ErrorAction SilentlyContinue
    #get bin path to revert later
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='TrustedInstaller'"
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
        $output = "$tempDir\7Zip.exe"
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
    

    #check if ddu is already installed before asking 
    if (!(Test-Path "$folder\DDU v18.0.8.6\Display Driver Uninstaller.exe")) {
        Write-Status -message "DDU Not Found in  $folder\DDU v18.0.8.6\Display Driver Uninstaller.exe" -type warning
        #install ddu
        $choice = Custom-MsgBox -message 'Install Display Driver Uninstaller?' -type Question

        switch ($choice) {
            'OK' {
                Write-Status -Message 'Installing Display Driver Uninstaller...'  -Type Output
        
                Remove-Item "$tempDir\DDU.exe" -ErrorAction SilentlyContinue -Force
                Remove-Item "$tempDir\DDU v18.0.8.6" -Recurse -Force -ErrorAction SilentlyContinue
                $url = 'https://www.wagnardsoft.com/DDU/download/DDU%20v18.0.8.6.exe'  
                $ProgressPreference = 'SilentlyContinue' 
                try {
                    Invoke-WebRequest -Uri $url -OutFile "$tempDir\DDU.exe" -ErrorAction Stop
                }
                catch {
                    Write-Status -Message 'Unable to Install DDU Due to Download Error!'  -Type Error
                    break
                }
            
                Start-Process -FilePath $archiverProgram -NoNewWindow -ArgumentList "x -bso0 -bsp1 -bse1 -aoa `"$tempDir\DDU.exe`" -o`"$folder`"" -Wait
            }
        }
    }
    else {
        Write-Status -message 'DDU Found...' -type output
    }


    if ((Test-Path "$folder\DDU v18.0.8.6\Display Driver Uninstaller.exe")) {
        $choice2 = Custom-MsgBox -message 'Boot to Safe Mode to Run DDU (Recommended)?' -type Question
   

        if ($choice2 -eq 'OK') {
            Write-Status -Message 'Booting to Safe Mode...'  -Type Output
             
            #add safe mode minimal
            Start-process bcdedit.exe -ArgumentList '/set {current} safeboot minimal' 
                
            #create script to run on safe mode startup
            $currentValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit').Userinit
            $safeModeScript = "
                Start-process bcdedit.exe -ArgumentList '/deletevalue safeboot'
                Start-Process -FilePath `"$folder\DDU v18.0.8.6\Display Driver Uninstaller.exe`" -args `"-Restart -CleanNvidia -PreventWinUpdate -RemovePhysx -RemoveGFE -RemoveNVBROADCAST -RemoveNVCP`" -WindowStyle Hidden
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit' -Value `"$currentValue`"
                "
            New-Item "$tempDir\safemodescript.ps1" -Value $safeModeScript -Force | Out-Null
            #create winlogon key
            $scriptRun = "powershell.exe -nop -ep bypass -f $tempDir\safemodescript.ps1"
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'Userinit' -Value "$currentValue, $scriptRun" -Force
            shutdown /f /r /t 0
        }
    
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
        $trimmedHighlight = $trimmedHighlight -replace '&nbsp;' , ' ' 
        $trimmedHighlight = $trimmedHighlight -replace '&quot;' , '"' 
        $trimmedHighlight = $trimmedHighlight -replace '&gt;' , '>' 
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

    $labelCombo = New-Object System.Windows.Forms.Label
    $labelCombo.Location = New-Object System.Drawing.Point(20, 10)
    $labelCombo.Size = New-Object System.Drawing.Size(250, 20)
    $labelCombo.ForeColor = 'White'
    $labelCombo.BackColor = [System.Drawing.Color]::Transparent
    $labelCombo.Text = 'Choose NVIDIA Game Ready Driver:'
    $labelCombo.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($labelCombo)

    $comboBox = New-Object System.Windows.Forms.ComboBox
    $comboBox.Location = New-Object System.Drawing.Point(20, 40)
    $comboBox.Size = New-Object System.Drawing.Size(200, 20)
    $comboBox.DropDownStyle = 'DropDownList'
    $comboBox.BackColor = [System.Drawing.Color]::FromArgb(47, 49, 58)
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
    $textBox.BackColor = 'Black'
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
    $checkbox.BackColor = [System.Drawing.Color]::Transparent
    $form.Controls.Add($checkbox)

    $checkbox2 = New-Object System.Windows.Forms.CheckBox
    $checkbox2.Location = New-Object System.Drawing.Point(130, 280)
    $checkbox2.Size = New-Object System.Drawing.Size(250, 20)
    $checkbox2.ForeColor = 'White'
    $checkbox2.Text = 'Install Notebook Version (laptops)'
    $checkbox2.BackColor = [System.Drawing.Color]::Transparent
    $form.Controls.Add($checkbox2)

   
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(20, 310)
    $label.Size = New-Object System.Drawing.Size(130, 30)
    $label.ForeColor = 'White'
    $label.Text = 'Driver not listed? Enter Version:'
    $label.BackColor = [System.Drawing.Color]::Transparent
    $form.Controls.Add($label)

    $textboxCustom = New-Object System.Windows.Forms.TextBox
    $textboxCustom.Location = New-Object System.Drawing.Point(150, 310)
    $textboxCustom.Size = New-Object System.Drawing.Size(80, 20)
    $textboxCustom.Text = 'Ex. 420.69'
    $textboxCustom.ForeColor = 'White'
    $textboxCustom.BackColor = [System.Drawing.Color]::FromArgb(47, 49, 58)
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

    $buttonOK = Create-ModernButton -Text 'OK' -Location (New-Object Drawing.Point(370, 330)) -Size (New-Object Drawing.Size(80, 27)) -DialogResult ([System.Windows.Forms.DialogResult]::OK) -borderSize 2

    $form.Controls.Add($buttonOK)

    $buttonSkip = Create-ModernButton -Text 'Skip' -Location (New-Object Drawing.Point(285, 330)) -Size (New-Object Drawing.Size(80, 27)) -DialogResult ([System.Windows.Forms.DialogResult]::Cancel) -borderSize 2

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
                try {
                    Invoke-WebRequest $url -UseBasicParsing -ErrorAction Stop
                }
                catch {
                    $url = "https://international.download.nvidia.com/Windows/$selectedDriver/$driverNum-desktop-notebook-win10-win11-$windowsArchitecture-international-dch.hf.exe"
                }
                
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

                try {
                    Invoke-WebRequest $url -UseBasicParsing -ErrorAction Stop
                }
                catch {
                    $url = "https://international.download.nvidia.com/Windows/$selectedDriver/$driverNum-desktop-notebook-win10-win11-$windowsArchitecture-international-dch.hf.exe"
                }
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
            if ($selectedDriver -like '*hf*') {
                $driverNum = $selectedDriver -replace 'hf', ''
            }
            else {
                $driverNum = $selectedDriver
            }
            if ([version]$driverNum -ge '566.36') {
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
            if ($selectedDriver -like '*hf*') {
                $driverNum = $selectedDriver -replace 'hf', ''
            }
            else {
                $driverNum = $selectedDriver
            }
            if ([version]$driverNum -ge '566.36') {
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
            if ([version]$driverNum -ge '566.36') {
                $excludedFolders += 'CEF', 'Unified_EULA', 'EULA'
            }
            # List of files to exclude from deletion
            $excludedFiles = @(
                'EULA.html',
                'EULA.txt'
                'license.txt'
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

            if ([version]$driverNum -ge '566.36') {
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


        Write-Status -Message 'Installing Driver...'  -Type Output
    
        #starting setup.exe in current directory (%temp%)
        Start-Process "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall\setup.exe" -WorkingDirectory "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall" -ArgumentList '-clean -s' -wait 
        Clear-Host
        Write-Status -Message 'Driver installed, Cleaning up...'  -Type Output
   
        #cleaning up
        Remove-Item "$env:USERPROFILE\AppData\Local\Temp\NVCleanstall" -Recurse -Force
        Remove-Item "$env:USERPROFILE\AppData\Local\Temp\NvidiaLogging" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\$selectedDriver.exe" -Force 
        Remove-Item "$tempDir\DDU.exe" -ErrorAction SilentlyContinue -Force
        Remove-Item "$tempDir\DDU v18.0.8.6" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "$tempDir\safemodescript.ps1" -Force -ErrorAction SilentlyContinue
        #uninstalling 7zip
        if ($7zinstalledAlr -eq $false) {
            $path = (Get-ChildItem -Path C:\ -Filter 7-Zip -Recurse -ErrorAction SilentlyContinue -Force | select-object -first 1).FullName
            Start-Process "$path\Uninstall.exe" -wait -ArgumentList '/S'
            remove-item 'HKLM:\SOFTWARE\7-Zip' -Force -Recurse -ErrorAction SilentlyContinue

        }


        Write-status -message 'Checking for NVCP...' -type output
        $appx = Get-AppxPackage -AllUsers | Where-Object { $_.PackageFullName -like '*nvidia*' }

        if (!$appx) {
            Write-Status -message 'NVCP Not Found... Installing' -type output
            Remove-Item "$tempDir\NVIDIACorp.NVIDIAControlPanel*" -Force -Recurse -ErrorAction SilentlyContinue
            $downloadedFiles = Download-AppxPackage -PackageFamilyName 'NVIDIACorp.NVIDIAControlPanel_56jybvy8sckqj' -outputDir "$tempDir" 
            $package = $downloadedFiles | Where-Object { $_ -match '\.appx$' } | Select-Object -First 1
            if ($package) {
                try {
                    Add-AppPackage $package -ErrorAction Stop
                }
                catch {
                    Write-status -message "Can't install NVCP via appx package... make sure you have the appx service enabled" 
                }
                
            }
            else {
                Write-status -message "Can't find NVCP Installer" 
            }
        }


        Write-Status -Message 'Disabling Telemetry...'  -Type Output
    
        if ($stripDriver) {
            #removing a dll file needed to communicate with a telemetry server
            (Get-ChildItem -Path "$env:windir\System32\DriverStore\FileRepository\nv_dispi*" -Directory).FullName | ForEach-Object { 
                takeown /f "$_\NvTelemetry64.dll" *>$null
                icacls "$_\NvTelemetry64.dll" /grant *S-1-5-32-544:F /t *>$null
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

    #removes tray icon
    Reg.exe add 'HKCU\SOFTWARE\NVIDIA Corporation\NvTray' /v 'StartOnLogin' /t REG_DWORD /d '0' /f
    #new way
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters\Global\Startup\ForceStopNvTrayIcon' /ve /t REG_DWORD /d '1' /f
    Reg.exe add 'HKLM\SYSTEM\ControlSet001\Services\nvlddmkm\Parameters\Global\Startup\StartNvTray' /ve /t REG_DWORD /d '0' /f
    $keys = Get-ChildItem -path 'HKCU:\Control Panel\NotifyIconSettings'
    foreach ($key in $keys) {
        $props = Get-ItemProperty $key.PSPath
        if ($props.executablepath -like '*NVDisplay.Container*') {
            Set-ItemProperty -Path $props.PSPath -Name 'IsPromoted' -Value 0 -Force
        }
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
 
  
    #get monitor info
    <#
    $monitors = Get-WmiObject -Namespace root\wmi -Class WmiMonitorID
    $manufacturerNames = @()
    $soundDevices = Get-WmiObject -Class Win32_SoundDevice
    $pnpDevices = Get-WmiObject -Class Win32_PnPEntity | Where-Object { $_.PNPDeviceID -ne $null }
    $videoControllers = Get-WmiObject -Class Win32_VideoController
    #>
    $monitors = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorID
    $manufacturerNames = @()
    $soundDevices = Get-CimInstance -ClassName Win32_SoundDevice
    $pnpDevices = Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.PNPDeviceID -ne $null }
    $videoControllers = Get-CimInstance -ClassName Win32_VideoController

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
    Add-Type -AssemblyName WindowsFormsIntegration
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
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

    $type = $TabControl.GetType()
    $propInfo = $type.GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
    $propInfo.SetValue($TabControl, $true, $null)

    $startColor = [System.Drawing.Color]::FromArgb(61, 74, 102)   #rgb(61, 74, 102)
    $endColor = [System.Drawing.Color]::FromArgb(0, 0, 0)       #rgb(0, 0, 0)

    # Override the form's paint event to apply the gradient
    $TabControl.Add_Paint({
            param($sender, $e)
            $rect = New-Object System.Drawing.Rectangle(0, 0, $TabControl.Width, $TabControl.Height)
            $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
                $rect, 
                $startColor, 
                $endColor, 
                [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal
            )
            $e.Graphics.FillRectangle($brush, $rect)
            $brush.Dispose()
        })



    $TabPage1 = New-Object System.Windows.Forms.TabPage
    $TabPage1.Text = 'General'
    $TabPage1.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

    $type = $TabPage1.GetType()
    $propInfo = $type.GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
    $propInfo.SetValue($TabPage1, $true, $null)

    # Override the form's paint event to apply the gradient
    $TabPage1.Add_Paint({
            param($sender, $e)
            $rect = New-Object System.Drawing.Rectangle(0, 0, $TabPage1.Width, $TabPage1.Height)
            $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
                $rect, 
                $startColor, 
                $endColor, 
                [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal
            )
            $e.Graphics.FillRectangle($brush, $rect)
            $brush.Dispose()
        })

    $TabPage2 = New-Object System.Windows.Forms.TabPage
    $TabPage2.Text = 'Monitor'
    $TabPage2.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

    $type = $TabPage2.GetType()
    $propInfo = $type.GetProperty('DoubleBuffered', [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
    $propInfo.SetValue($TabPage2, $true, $null)

    # Override the form's paint event to apply the gradient
    $TabPage2.Add_Paint({
            param($sender, $e)
            $rect = New-Object System.Drawing.Rectangle(0, 0, $TabPage2.Width, $TabPage2.Height)
            $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
                $rect, 
                $startColor, 
                $endColor, 
                [System.Drawing.Drawing2D.LinearGradientMode]::ForwardDiagonal
            )
            $e.Graphics.FillRectangle($brush, $rect)
            $brush.Dispose()
        })
   
    $TabControl.Controls.Add($TabPage1)
    $TabControl.Controls.Add($TabPage2)



    $Form.Controls.Add($TabControl) 


    $checkbox1 = new-object System.Windows.Forms.checkbox
    $checkbox1.Location = new-object System.Drawing.Size(10, 20)
    $checkbox1.Size = new-object System.Drawing.Size(170, 20)
    $checkbox1.Text = 'Import NVCP Settings'
    $checkbox1.ForeColor = 'White'
    $checkbox1.BackColor = [System.Drawing.Color]::Transparent
    $checkbox1.Checked = $false
    $Form.Controls.Add($checkbox1)  
    $TabPage1.Controls.Add($checkBox1)

    $radiobutton1 = New-Object System.Windows.Forms.checkbox
    $radiobutton1.Location = New-Object System.Drawing.Size(180, 20)
    $radiobutton1.Size = New-Object System.Drawing.Size(75, 20)
    $radiobutton1.Text = 'Rebar On'
    $radiobutton1.ForeColor = 'White'
    $radioButton1.BackColor = [System.Drawing.Color]::Transparent
    $radiobutton1.Checked = $false
    $radioButton1.Visible = $false
    $Form.Controls.Add($radiobutton1)
    $TabPage1.Controls.Add($radiobutton1)

    $radiobutton2 = New-Object System.Windows.Forms.checkbox
    $radiobutton2.Location = New-Object System.Drawing.Size(270, 20)
    $radiobutton2.Size = New-Object System.Drawing.Size(85, 20)
    $radiobutton2.Text = 'GSYNC On'
    $radiobutton2.ForeColor = 'White'
    $radiobutton2.BackColor = [System.Drawing.Color]::Transparent
    $radiobutton2.Checked = $false
    $radioButton2.Visible = $false
    $Form.Controls.Add($radiobutton2)
    $TabPage1.Controls.Add($radiobutton2)

    $radiobutton3 = New-Object System.Windows.Forms.checkbox
    $radiobutton3.Location = New-Object System.Drawing.Size(180, 40)
    $radiobutton3.Size = New-Object System.Drawing.Size(125, 20)
    $radiobutton3.Text = 'DLSS Force Latest'
    $radiobutton3.ForeColor = 'White'
    $radiobutton3.BackColor = [System.Drawing.Color]::Transparent
    $radiobutton3.Checked = $false
    $radioButton3.Visible = $false
    $Form.Controls.Add($radiobutton3)
    $TabPage1.Controls.Add($radiobutton3)



    $checkbox1.add_CheckedChanged({
            if ($checkbox1.Checked) {
                $radioButton1.Visible = $true
                $radioButton2.Visible = $true
                $radioButton3.Visible = $true
            }
            else {
                $radioButton1.Visible = $false
                $radioButton2.Visible = $false
                $radioButton3.Visible = $false
            }
        })

    $checkbox2 = new-object System.Windows.Forms.checkbox
    $checkbox2.Location = new-object System.Drawing.Size(10, 50)
    $checkbox2.Size = new-object System.Drawing.Size(170, 20)
    $checkbox2.Text = 'Enable Legacy Sharpen'
    $checkbox2.ForeColor = 'White'
    $checkbox2.BackColor = [System.Drawing.Color]::Transparent
    $checkbox2.Checked = $false
    $Form.Controls.Add($checkbox2)
    $TabPage1.Controls.Add($checkBox2)

    $checkbox3 = new-object System.Windows.Forms.checkbox
    $checkbox3.Location = new-object System.Drawing.Size(10, 80)
    $checkbox3.Size = new-object System.Drawing.Size(170, 20)
    $checkbox3.Text = 'Enable MSI Mode'
    $checkbox3.ForeColor = 'White'
    $checkbox3.BackColor = [System.Drawing.Color]::Transparent
    $checkbox3.Checked = $false
    $Form.Controls.Add($checkbox3)
    $TabPage1.Controls.Add($checkBox3)

    $checkbox4 = new-object System.Windows.Forms.checkbox
    $checkbox4.Location = new-object System.Drawing.Size(10, 110)
    $checkbox4.Size = new-object System.Drawing.Size(170, 20)
    $checkbox4.Text = 'Remove GPU Idle States'
    $checkbox4.ForeColor = 'White'
    $checkbox4.BackColor = [System.Drawing.Color]::Transparent
    $checkbox4.Checked = $false
    $Form.Controls.Add($checkbox4)
    $TabPage1.Controls.Add($checkBox4)

    $checkbox5 = new-object System.Windows.Forms.checkbox
    $checkbox5.Location = new-object System.Drawing.Size(10, 140)
    $checkbox5.Size = new-object System.Drawing.Size(170, 20)
    $checkbox5.Text = 'Disable HDCP'
    $checkbox5.ForeColor = 'White'
    $checkbox5.BackColor = [System.Drawing.Color]::Transparent
    $checkbox5.Checked = $false
    $Form.Controls.Add($checkbox5)
    $TabPage1.Controls.Add($checkBox5)


    $vibrance = New-Object System.Windows.Forms.Label
    $vibrance.Text = 'Digital Vibrance'
    $vibrance.ForeColor = 'White'
    $vibrance.BackColor = [System.Drawing.Color]::Transparent
    $vibrance.AutoSize = $true
    $vibrance.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold) 
    $vibrance.Location = New-Object System.Drawing.Point(100, 10)
    $tabPage2.Controls.Add($vibrance)
        
    $trackbarValues = @{}
    $checkboxes = @()
    $checkboxesColor = @()
    for ($i = 0; $i -lt $dList.Length; $i++) {
        $y = 35 + ($i * 80)

        #checkbox for disabling monitor speakers
        $checkbox = new-object System.Windows.Forms.checkbox
        $checkbox.Location = new-object System.Drawing.Size(10, ($y + 20))
        $checkbox.Size = new-object System.Drawing.Size(100, 20)
        $checkbox.Text = 'Disable Speakers'
        $checkbox.ForeColor = 'White'
        $checkbox.BackColor = [System.Drawing.Color]::Transparent
        $checkbox.Checked = $false
        $checkbox.Tag = $allmonitors[$i].SoundDeviceID
        $Form.Controls.Add($checkbox)
        $TabPage2.Controls.Add($checkBox)
        $checkboxes += $checkbox

        $checkboxColor = new-object System.Windows.Forms.checkbox
        $checkboxColor.Location = new-object System.Drawing.Size(10, ($y + 40))
        $checkboxColor.Size = new-object System.Drawing.Size(120, 20)
        $checkboxColor.Text = 'Use Nvidia Color'
        $checkboxColor.ForeColor = 'White'
        $checkboxColor.BackColor = [System.Drawing.Color]::Transparent
        $checkboxColor.Checked = $false
        $checkboxColor.Tag = $paths[$i]
        $Form.Controls.Add($checkboxColor)
        $TabPage2.Controls.Add($checkboxColor)
        $checkboxesColor += $checkboxColor

        # Create a label for the manufacturer name
        $nameLabel = New-Object System.Windows.Forms.Label
        $nameLabel.Text = $allmonitors[$i].MonitorName
        $nameLabel.ForeColor = 'White'
        $nameLabel.AutoSize = $true
        $nameLabel.BackColor = [System.Drawing.Color]::Transparent
        $nameLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        $nameLabel.Location = New-Object System.Drawing.Point(10, $y)
        $tabPage2.Controls.Add($nameLabel)

        # Create ElementHost to host WPF Slider
        $elementHost = New-Object System.Windows.Forms.Integration.ElementHost
        $elementHost.Location = New-Object System.Drawing.Point(100, $y)
        $elementHost.Size = New-Object System.Drawing.Size(200, 40)
        $elementHost.BackColor = [System.Drawing.Color]::Transparent

        # Create WPF Slider (replaces TrackBar)
        $trackBar = New-Object System.Windows.Controls.Slider
        $trackBar.Minimum = 0
        $trackBar.Maximum = 100
        $trackBar.TickFrequency = 5
        $trackBar.SmallChange = 1
        $trackBar.LargeChange = 10
        $trackBar.Background = [System.Windows.Media.Brushes]::Transparent
        $trackBar.Foreground = [System.Windows.Media.Brushes]::White
        $trackBar.IsSnapToTickEnabled = $false
        $trackBar.TickPlacement = [System.Windows.Controls.Primitives.TickPlacement]::None

        # Create a custom style for transparency
        $sliderStyle = New-Object System.Windows.Style([System.Windows.Controls.Slider])
        $backgroundSetter = New-Object System.Windows.Setter([System.Windows.Controls.Control]::BackgroundProperty, [System.Windows.Media.Brushes]::Transparent)
        $sliderStyle.Setters.Add($backgroundSetter)
        $trackBar.Style = $sliderStyle

        # Host the WPF slider in the ElementHost
        $elementHost.Child = $trackBar

        # Add the ElementHost to the tab page
        $tabPage2.Controls.Add($elementHost)

        # Calculate and set the midpoint value
        $midpoint = [Math]::Round(($trackBar.Minimum + $trackBar.Maximum) / 2)
        $trackBar.Value = $midpoint

        # Assign a unique tag to each slider (WPF uses Tag property differently)
        $trackBar.Tag = $i

        # Create a label to display the value
        $valueLabel = New-Object System.Windows.Forms.Label
        $valueLabel.AutoSize = $true
        $valueLabel.ForeColor = 'White'
        $valueLabel.BackColor = [System.Drawing.Color]::Transparent
        $valueLabel.Location = New-Object System.Drawing.Point(300, $y)
        $valueLabel.Text = '50'
        $tabPage2.Controls.Add($valueLabel)

        # Add an event handler to update the value label when the slider value changes
        $handler = {
            param (
                $valueLabel,
                $trackBar,
                $trackbarValues
            )

            # WPF Slider uses ValueChanged event instead of Scroll
            $trackBar.add_ValueChanged({
                    $valueLabel.Text = [Math]::Round($trackBar.Value, 0).ToString()
                    $trackbarValues[$trackBar.Tag] = [Math]::Round($trackBar.Value, 0)
                })
        }

        # Create a new closure for each slider and value label pair
        $closure = $handler.GetNewClosure()
        $closure.Invoke($valueLabel, $trackBar, $trackbarValues)

        # Add the initial value to the trackbarValues hashtable
        $trackbarValues[$i] = $midpoint
    }


    $applyButton = Create-ModernButton -Text 'Apply' -Location (New-Object Drawing.Point(140, 360)) -Size (New-Object Drawing.Size(100, 30)) -borderSize 2 -DialogResult ([System.Windows.Forms.DialogResult]::OK)

    $form.Controls.Add($applyButton)

    # Show the form
    $dialogResult = $form.ShowDialog()

    # Handle the button click event
    if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) {

        if ($checkbox1.Checked) {
            Write-Status -message 'Importing Nvidia Control Panel Settings...' -type Output
            #create a copy to add user selected settings
            $stockNip = Search-File '*DefaultProfile.nip'
            $dirPath = Split-Path $stockNip -Parent
            #just to be sure
            Remove-Item "$dirPath\Custom.nip" -Force -ErrorAction SilentlyContinue
            Copy-Item $stockNip -Destination "$dirPath\Custom.nip" -Force

            if ($radioButton1.Checked) {
                #enable rebar
                Edit-Nip -nipPath "$dirPath\Custom.nip" -settingId '983226' -settingValue '1' -valueType 'Dword'
                Edit-Nip -nipPath "$dirPath\Custom.nip" -settingId '983227' -settingValue '1' -valueType 'Dword'
                Edit-Nip -nipPath "$dirPath\Custom.nip" -settingId '983295' -settingValue 'AAAAQAAAAAA=' -valueType 'Binary'
            }
            if ($radioButton2.Checked) {
                #enable gsync
                Edit-Nip -nipPath "$dirPath\Custom.nip" -settingId '278196567' -settingValue '1' -valueType 'Dword' -settingNameInfo 'Toggle the VRR global feature'
                Edit-Nip -nipPath "$dirPath\Custom.nip" -settingId '278196727' -settingValue '1' -valueType 'Dword' -settingNameInfo 'VRR requested state'
                Edit-Nip -nipPath "$dirPath\Custom.nip" -settingId '279476687' -settingValue '0' -valueType 'Dword' -settingNameInfo 'G-SYNC'
                Edit-Nip -nipPath "$dirPath\Custom.nip" -settingId '294973784' -settingValue '1' -valueType 'Dword' -settingNameInfo 'Enable G-SYNC globally'
            }

            if ($radioButton3.Checked) {
                #enable dlss latest
                Edit-Nip -nipPath "$dirPath\Custom.nip" -settingId '283385331' -settingValue '16777215' -valueType 'Dword' -settingNameInfo 'Override DLSS-SR presets'
                Edit-Nip -nipPath "$dirPath\Custom.nip" -settingId '283385345' -settingValue '1' -valueType 'Dword' -settingNameInfo 'Enable DLSS-SR override'
            }          
           
            $inspector = Search-File '*nvidiaProfileInspector.exe'
        
            $arguments = '-silentImport', '-silent', "$dirPath\Custom.nip"
            & $inspector $arguments | Wait-Process

            
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

        if ($checkbox5.Checked) {
            Write-Status -Message 'Disabling HDCP...'  -Type Output
            #disabling hdcp
            $subkeys = (Get-ChildItem -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}' -Force -ErrorAction SilentlyContinue).Name

            foreach ($key in $subkeys) {
                if ($key -notlike '*Configuration') {
                    Set-ItemProperty -Path "registry::$key" -Name 'RMHdcpKeyglobZero' -Value 1 -Force
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
            if ($value -ne 50) {
                Write-Status -message 'Applying Digital Vibrance...' -type output
                $path = $paths[$i]
                $command = "Reg.exe add $path /v `"SaturationRegistryKey`" /t REG_DWORD /d $value /f"
                Run-Trusted -command $command
                Start-Sleep 1
                $i++
            }
        
        }

        foreach ($checkbox in $checkboxesColor) {
            if ($checkbox.Checked) {
                Write-Status -message 'Enabling Nvidia Color...' -type Output
                $path = $checkbox.Tag
                try {
                    $colorConfig = Get-ItemPropertyValue "registry::$path" -Name ColorformatConfig -ErrorAction Stop

                    #index 10 = 0 for full color range
                    #index 12 = 0 for nvidia color 1 for default
                    #index 16 = 3 for nvidia color 4 for default
                    $colorConfig[10] = 0
                    $colorConfig[12] = 0
                    $colorConfig[16] = 3
                    $hexValue = ($colorConfig | ForEach-Object { '{0:X2}' -f $_ }) -join ''
                    $command = "Reg.exe add $path /v `"ColorformatConfig`" /t REG_BINARY /d `"$hexValue`" /f"
                    Run-Trusted -command $command
                    Start-Sleep 1
                }
                catch {
                    #value has not been set yet
                    $value = 'db02000014000000000a00080000000003010000'
                    $command = "Reg.exe add $path /v `"ColorformatConfig`" /t REG_BINARY /d `"$value`" /f"
                    Run-Trusted -command $command
                    Start-Sleep 1
                }
            
               
            }
            
        }
        Write-Status -message 'Restarting Graphics Driver to Apply Changes...' -type Output
        $d = Get-PnpDevice | Where-Object { $_.class -like 'Display*' }
        $d  | Disable-PnpDevice -Confirm:$false
        $d  | Enable-PnpDevice -Confirm:$false
 
    }


}

