If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}


#get os version
$OS = Get-CimInstance Win32_OperatingSystem

if ($OS.Caption -like '*Windows 11*') {

    #windows 11 start menu unpin

    $unpinFile = Search-Directory '*LocalState1'

    #kill file explorer to replace start menu data
    Stop-Process -name 'sihost' -force
    Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Recurse -Force
    Move-Item $unpinFile -Destination "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy" -Force
    Rename-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState1" -NewName 'LocalState' -Force

}
else {


    #windows 10 startmenu unpin

    $START_MENU_LAYOUT = @'
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
    <LayoutOptions StartTileGroupCellWidth="6" />
    <DefaultLayoutOverride>
        <StartLayoutCollection>
            <defaultlayout:StartLayout GroupCellWidth="6" />
        </StartLayoutCollection>
    </DefaultLayoutOverride>
</LayoutModificationTemplate>
'@

    $layoutFile = 'C:\Windows\StartMenuLayout.xml'

    #Delete layout file if it already exists
    If (Test-Path $layoutFile) {
        Remove-Item $layoutFile
    }

    #Creates the blank layout file
    $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

    $regAliases = @('HKLM', 'HKCU')

    #Assign the start layout and force it to apply with "LockedStartLayout" at both the machine and user level
    foreach ($regAlias in $regAliases) {
        $basePath = $regAlias + ':\SOFTWARE\Policies\Microsoft\Windows'
        $keyPath = $basePath + '\Explorer' 
        IF (!(Test-Path -Path $keyPath)) { 
            New-Item -Path $basePath -Name 'Explorer'
        }
        Set-ItemProperty -Path $keyPath -Name 'LockedStartLayout' -Value 1
        Set-ItemProperty -Path $keyPath -Name 'StartLayoutFile' -Value $layoutFile
    }

    #Restart Explorer, open the start menu (necessary to load the new layout), and give it a few seconds to process
    Stop-Process -name 'sihost' -force
    Start-Sleep -s 5
    $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
    Start-Sleep -s 5

    #Enable the ability to pin items again by disabling "LockedStartLayout"
    foreach ($regAlias in $regAliases) {
        $basePath = $regAlias + ':\SOFTWARE\Policies\Microsoft\Windows'
        $keyPath = $basePath + '\Explorer' 
        Set-ItemProperty -Path $keyPath -Name 'LockedStartLayout' -Value 0
    }

    #Restart Explorer and delete the layout file
    Stop-Process -name 'sihost' -force

    Remove-Item $layoutFile

    Start-Sleep 3

    $wshell.SendKeys('^{ESCAPE}')


}