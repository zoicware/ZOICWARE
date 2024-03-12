Write-Host "----------- CHOOSE DOWNLOAD LOCATION ----------"

# Load the Windows.Forms assembly
Add-Type -AssemblyName System.Windows.Forms

# Create a folder selection dialog
$folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
$folderBrowser.Description = "Select a download location"
$folderBrowser.RootFolder = [System.Environment+SpecialFolder]::Desktop
$folderBrowser.ShowNewFolderButton = $true


# Show the dialog and get the selected folder
$result = $folderBrowser.ShowDialog()

if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $selectedFolder = $folderBrowser.SelectedPath
    
}
else {
    exit
}

$packages = $false
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Install Latest Packages and Internet Driver?', 'zoicware', 'YesNo', 'Question')
switch ($msgBoxInput) {

    'Yes' {
        $packages = $true
        Write-Host "Installing Packages..."
        #install C++
        $ProgressPreference = 'SilentlyContinue'
        $url = "https://api.github.com/repos/abbodi1406/vcredist/releases/latest"
        $response = Invoke-RestMethod -Uri $url -UseBasicParsing
        $version = $response.tag_name
        Invoke-RestMethod -Uri "https://github.com/abbodi1406/vcredist/releases/download/$version/VisualCppRedist_AIO_x86_x64.exe" -UseBasicParsing -OutFile "$env:TEMP\VisualCppRedist_AIO_x86_x64.exe"
        Move-Item "$env:TEMP\VisualCppRedist_AIO_x86_x64.exe" -Destination $selectedFolder

        #install directx
        $ProgressPreference = 'SilentlyContinue'
        $dir = New-Item -Path "$env:TEMP\DirectXRedist" -ItemType Directory -Force
        $DXPath = New-Item -Path "$env:TEMP\DirectXRedist\DX" -ItemType Directory -Force
        Invoke-RestMethod -Uri 'https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe' -UseBasicParsing -OutFile "$env:TEMP\DirectXRedist\DXinstaller.exe"
        Start-Process -FilePath "$env:TEMP\DirectXRedist\DXinstaller.exe" -ArgumentList "/Q /T:$DXPath /C" -WindowStyle Hidden -Wait
        #put pack path
        Move-Item $DXPath -Destination $selectedFolder -Force 
        Remove-Item -Path $dir -Force -Recurse


        Write-Host "Install Network Driver..."

        # Get all network adapters
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }
        $intel = $false
        $realtek = $false
        $gigabit = $false
        $wifi = $false
        # Loop through each adapter
        foreach ($adapter in $adapters) {
            if ($adapter.Description -like '*Intel*' -and $adapter.Description -like '*Ethernet*') {
                $intel = $true
                Start-Process 'https://www.intel.com/content/www/us/en/download/18293/intel-network-adapter-driver-for-windows-10.html'
            }
            elseif ($adapter.Description -like '*Realtek*') {
                $realtek = $true
                Start-Process 'https://www.realtek.com/en/component/zoo/category/network-interface-controllers-10-100-1000m-gigabit-ethernet-pci-express-software' -Wait

            }
            elseif ($adapter.Description -like '*Intel*' -and $adapter.Description -like '*Gigabit*') {
                $gigabit = $true
                Start-Process 'https://www.intel.com/content/www/us/en/download/18652/intel-gigabit-ethernet-network-connection-driver-for-windows-10-for-legacy-intel-nuc.html' -Wait

            }
            elseif ($adapter.Description -like '*Intel*' -and $adapter.Description -like '*Wi-Fi*') {
                $wifi = $true
                Start-Process 'https://www.intel.com/content/www/us/en/download/19351/windows-10-and-windows-11-wi-fi-drivers-for-intel-wireless-adapters.html' -Wait

            }
            else {

                Write-Host "Not Supported"

            }
        
      

        }
      
        #adapter not supported searching google with adapter name + driver
        if ($intel -ne $true -and $realtek -ne $true -and $gigabit -ne $true -and $wifi -ne $true) {
            foreach ($adapter in $adapters) {
                $adapterSearch = $adapter.Description -replace ' ' , '+'
                $url = "https://www.google.com/search?q=$adapterSearch+driver"
                Start-Process $url -Wait
            }

        }

  
    }

    'No' {}

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
                $progbar = ""
                $progbar = $progbar.PadRight($curBarSize, [char]9608)
                $progbar = $progbar.PadRight($BarSize, [char]9617)
        
                if (!$Complete.IsPresent) {
                    Write-Host -NoNewLine "`r$ProgressText $progbar [ $($CurrentValue.ToString("#.###").PadLeft($TotalValue.ToString("#.###").Length))$ValueSuffix / $($TotalValue.ToString("#.###"))$ValueSuffix ] $($percentComplete.ToString("##0.00").PadLeft(6)) % complete"
                }
                else {
                    Write-Host -NoNewLine "`r$ProgressText $progbar [ $($TotalValue.ToString("#.###").PadLeft($TotalValue.ToString("#.###").Length))$ValueSuffix / $($TotalValue.ToString("#.###"))$ValueSuffix ] $($percentComplete.ToString("##0.00").PadLeft(6)) % complete"                    
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
                $File = Join-Path (Get-Location -PSProvider "FileSystem") ($File -Split '^\.')[1]
            }
            
            if ($File -and !(Split-Path $File)) {
                $File = Join-Path (Get-Location -PSProvider "FileSystem") $File
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
            $writer = new-object System.IO.FileStream $File, "Create"
  
            # start download
            $finalBarCount = 0 #show final bar only one time
            do {
          
                $count = $reader.Read($buffer, 0, $buffer.Length)
          
                $writer.Write($buffer, 0, $count)
              
                $total += $count
                $totalMB = $total / 1024 / 1024
          
                if ($fullSize -gt 0) {
                    Show-Progress -TotalValue $fullSizeMB -CurrentValue $totalMB -ProgressText "Downloading $($File.Name)" -ValueSuffix "MB"
                }

                if ($total -eq $fullSize -and $count -eq 0 -and $finalBarCount -eq 0) {
                    Show-Progress -TotalValue $fullSizeMB -CurrentValue $totalMB -ProgressText "Downloading $($File.Name)" -ValueSuffix "MB" -Complete
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
#get latest download link from github releases
$apiUrl = "https://api.github.com/repos/zoicware/ZOICWARE/releases/latest"
$response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
$downloadLink = $response.body

Get-FileFromWeb -URL $downloadLink -File "$selectedFolder\ZOICWARE.zip"


if ($packages) {
    Write-Host "Moving Packages into Pack..."
    $zoicware = "$selectedFolder\ZOICWARE.zip"
    Expand-Archive -Path $zoicware -DestinationPath "$selectedFolder\ZOICWARE" -Force 
    Move-Item -Path "$selectedFolder\DX" -Destination "$selectedFolder\ZOICWARE\zoicwareOS\_FOLDERMUSTBEONCDRIVE" -Force
    Move-Item -Path "$selectedFolder\VisualCppRedist_AIO_x86_x64.exe" -Destination "$selectedFolder\ZOICWARE\zoicwareOS\_FOLDERMUSTBEONCDRIVE" -Force
    Remove-Item -Path $zoicware -Force

}




