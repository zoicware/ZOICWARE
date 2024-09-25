If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}
#check for internet connection
try {
    Invoke-WebRequest -Uri 'https://www.google.com' -Method Head -DisableKeepAlive -UseBasicParsing | Out-Null

    Write-Host 'Installing Latest Nvidia AutoInstall Script from Github...'

    #delete if nvidiaautoinstall has already been downloaded
    Remove-Item -Path "$folder\NvidiaAutoinstall.ps1" -Recurse -Force -ErrorAction SilentlyContinue
    $ProgressPreference = 'SilentlyContinue'
    $uri = 'https://raw.githubusercontent.com/zoicware/NvidiaAutoinstall/main/NvidiaAutoinstall.ps1'
    Invoke-WebRequest -Uri $uri -UseBasicParsing -OutFile "$folder\NvidiaAutoinstall.ps1"
    #run the script
    &"$folder\NvidiaAutoinstall.ps1"
}
catch [System.Net.WebException] {
    Write-Host 'This tweak requires Internet Connection...'
}

