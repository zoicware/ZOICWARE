If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}
#check for internet connection
try {
    Invoke-WebRequest -Uri 'https://www.google.com' -Method Head -DisableKeepAlive -UseBasicParsing | Out-Null

    Write-Host 'Installing Latest Nvidia AutoInstall Script from Github...'

    Invoke-RestMethod 'https://github.com/zoicware/NvidiaAutoinstall/archive/refs/heads/main.zip' -UseBasicParsing -OutFile 'C:\NV.zip'
    Expand-Archive 'C:\NV.zip' -DestinationPath 'C:\'
    Remove-Item 'C:\NV.zip' -Recurse -Force
    Expand-Archive 'C:\NvidiaAutoinstall-main\NvidiaAutoinstall.zip' -DestinationPath 'C:\'
    Remove-Item 'C:\NvidiaAutoinstall-main' -Recurse -Force
    Move-Item -LiteralPath 'C:\NvidiaAutoinstall' -Destination $PSScriptRoot
    #run the script
    #Start-Process PowerShell.exe -ArgumentList "-File `"$PSScriptRoot\NvidiaAutoinstall\NvidiaAutoinstall.ps1`"" 
    &"$PSScriptRoot\NvidiaAutoinstall\NvidiaAutoinstall.ps1"
}
catch [System.Net.WebException] {
    Write-Host 'This tweak requires Internet Connection...'
}

