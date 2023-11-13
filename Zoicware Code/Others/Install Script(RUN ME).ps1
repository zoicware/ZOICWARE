If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}


Invoke-RestMethod 'https://github.com/zoicware/NvidiaAutoinstall/archive/refs/heads/main.zip' -OutFile "C:\NV.zip"
Expand-Archive "C:\NV.zip" -DestinationPath "C:\"
Remove-Item "C:\NV.zip" -Recurse -Force
Expand-Archive "C:\NvidiaAutoinstall-main\NvidiaAutoinstall.zip" -DestinationPath "C:\"
Remove-Item "C:\NvidiaAutoinstall-main" -Recurse -Force
Move-Item -LiteralPath "C:\NvidiaAutoinstall" -Destination $PSScriptRoot

Start-Process PowerShell.exe -ArgumentList "-File `"$PSScriptRoot\NvidiaAutoinstall\NvidiaAutoinstall.ps1`"" 

exit