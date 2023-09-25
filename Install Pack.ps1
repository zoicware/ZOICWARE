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






$url = "https://github.com/zoicware/ZOICWAREWIN10/releases/latest"
$page=Invoke-WebRequest -Uri $url
# Define a regular expression pattern to match the URL
$pattern = "https://drive.google.com/file/d/([A-Za-z0-9_-]+)/view\?usp=sharing"

# Use regex to find the URL and extract the FILE_ID
if ($page -match $pattern) {
    $fileId = $matches[1]
 }

 # Download the Virus Warning into _tmp.txt
Invoke-WebRequest -Uri "https://drive.google.com/uc?export=download&id=$fileId" -OutFile "_tmp.txt" -SessionVariable googleDriveSession

# Get confirmation code from _tmp.txt
$searchString = Select-String -Path "_tmp.txt" -Pattern "confirm="
$searchString -match "confirm=(?<content>.*)&amp;id="
$confirmCode = $matches['content']

# Delete _tmp.txt
Remove-Item "_tmp.txt"


$download = $selectedFolder+"\ZOICWARE.zip"
# Download the real file
cls 
Write-host "---------- DOWNLOADING PLEASE WAIT ----------"


$retryCount = 0
$maxRetries = 100


do {
    try {
    $ProgressPreference = 'SilentlyContinue'
        $response = Invoke-WebRequest -Uri "https://drive.google.com/uc?export=download&confirm=${confirmCode}&id=$fileId" -UseBasicParsing -OutFile $download -WebSession $googleDriveSession -Verbose
         
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -eq 500) {
            Write-Host "Received a 500 Internal Server Error. Retrying in 1 second..."
            Start-Sleep -Seconds 1
            $retryCount++
        } else {
            Write-Host "Request failed with error: $($_.Exception.Message)"
            break
        }
    }

    
} while ($retryCount -ne 0 -and $retryCount -lt $maxRetries)

if ($retryCount -gt $maxRetries) {
    Write-Host "Maximum number of retries reached. Request still failed."
}
