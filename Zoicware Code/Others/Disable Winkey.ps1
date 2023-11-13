If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}




    Write-Host "----Disabling Windows Key----"

    Invoke-RestMethod 'https://github.com/zoicware/DisableWinkey/archive/refs/heads/main.zip' -OutFile "C:\DisableWinKey.zip"
Expand-Archive "C:\DisableWinkey.zip" -DestinationPath "C:\" -force
Remove-Item "C:\DisableWinkey.zip"


regini.exe "C:\DisableWinkey-main\disable_winkey.ini"

Remove-item "C:\DisableWinkey-main" -force -Recurse

cls
Write-Host "----Restart to Apply Changes----"
pause

