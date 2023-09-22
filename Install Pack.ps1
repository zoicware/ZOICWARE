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






$url = "https://api.github.com/repos/zoicware/ZOICWAREWIN10/releases/latest"
$pat = "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"

# Create a header for authentication
$headers = @{
    "Authorization" = "Bearer $pat"
    "User-Agent" = "PowerShell"
}
$latestRelease = Invoke-RestMethod -Uri $url -Headers $headers -UseBasicParsing
$dURL = $latestRelease.body


# Use a regular expression to extract the file ID
$fileID = [regex]::Match($dURL, "/d/([^/]+)/").Groups[1].Value



$download = $selectedFolder+"\ZOICWARE.zip"
# Download the real file
cls 
Write-host "---------- DOWNLOADING PLEASE WAIT ----------"

$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "https://drive.google.com/uc?export=download&confirm=&id=$fileID" -UseBasicParsing -OutFile $download 









