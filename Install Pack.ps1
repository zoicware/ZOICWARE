#THIS SCRIPT IS UNDER CONSTRUCTION

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




$download = $selectedFolder+"\ZOICWARE.zip"
# Download the real file
cls 
Write-host "---------- DOWNLOADING PLEASE WAIT ----------"

$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://drive.google.com/uc?export=download&confirm=&id=$fileId" -UseBasicParsing -OutFile $download 








