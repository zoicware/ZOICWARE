param(
    [string]$pfpPath
)
 
$pfps = Get-ChildItem -Path $pfpPath

$userSID = Get-CimInstance Win32_UserAccount | Select-Object SID -First 1
#add 1001 to end
$lastNum = $userSID.SID.Split('-')[-1]
$regSID = $userSID.SID.TrimEnd($lastNum) + '1001'

$publicFolder = "C:\Users\Public\AccountPictures\$regSID"
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AccountPicture\Users\$regSID"
if ((Test-Path $publicFolder) -and (Test-Path $regPath)) {
    #generate a new guid
    $newGUID = "{$((New-Guid).ToString().ToUpper())}" #needs to have curly braces and all caps
    foreach ($blackPfp in $pfps) {
        $file = Copy-Item $blackPfp.FullName -Destination $publicFolder -Force -PassThru
        Rename-Item $file.Fullname -NewName "$newGUID-$($blackPfp.Name)"
        $value = "$publicFolder\$newGUID-$($blackPfp.Name)"
        New-ItemProperty -Path $regPath -Name $(($blackPfp.Name) -replace '.jpg', '') -Value $value -Force
    }

}