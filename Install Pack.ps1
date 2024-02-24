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
    
} else {
    exit
}

$packages = $false
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Install Latest Packages and Internet Driver?','zoicware','YesNo','Question')
switch  ($msgBoxInput) {

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
   if($adapter.Description -like '*Intel*' -and $adapter.Description -like '*Ethernet*'){
   $intel = $true
   start 'https://www.intel.com/content/www/us/en/download/18293/intel-network-adapter-driver-for-windows-10.html'
   }
   elseif($adapter.Description -like '*Realtek*'){
   $realtek = $true
   start 'https://www.realtek.com/en/component/zoo/category/network-interface-controllers-10-100-1000m-gigabit-ethernet-pci-express-software' -Wait

   }
   elseif($adapter.Description -like '*Intel*' -and $adapter.Description -like '*Gigabit*'){
   $gigabit = $true
   start 'https://www.intel.com/content/www/us/en/download/18652/intel-gigabit-ethernet-network-connection-driver-for-windows-10-for-legacy-intel-nuc.html' -Wait

   }
   elseif($adapter.Description -like '*Intel*' -and $adapter.Description -like '*Wi-Fi*'){
   $wifi = $true
   start 'https://www.intel.com/content/www/us/en/download/19351/windows-10-and-windows-11-wi-fi-drivers-for-intel-wireless-adapters.html' -Wait

   }
   else{

   Write-Host "Not Supported"

   }
        
      

      }
      
#adapter not supported searching google with adapter name + driver
if($intel -ne $true -and $realtek -ne $true -and $gigabit -ne $true -and $wifi -ne $true){
foreach($adapter in $adapters){
    $adapterSearch = $adapter.Description -replace ' ' , '+'
    $url = "https://www.google.com/search?q=$adapterSearch+driver"
    start $url -Wait
    }

}

  
   }

'No'{}

}

#get latest dropbox link
$ProgressPreference = 'SilentlyContinue'
$apiUrl = "https://api.github.com/repos/zoicware/ZOICWAREWIN10/releases/latest"
$response = Invoke-RestMethod -Uri $apiUrl -UseBasicParsing
$downloadLink = $response.body

 $WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile($downloadLink, "$selectedFolder\ZOICWARE.zip")



if($packages){
Write-Host "Moving Packages into Pack..."
$zoicware = "$selectedFolder\ZOICWARE.zip"
Expand-Archive -Path $zoicware -DestinationPath "$selectedFolder\ZOICWARE" -Force 
Move-Item -Path "$selectedFolder\DX" -Destination "$selectedFolder\ZOICWARE\zoicwareOS\_FOLDERMUSTBEONCDRIVE" -Force
Move-Item -Path "$selectedFolder\VisualCppRedist_AIO_x86_x64.exe" -Destination "$selectedFolder\ZOICWARE\zoicwareOS\_FOLDERMUSTBEONCDRIVE" -Force
Remove-Item -Path $zoicware -Force

}




