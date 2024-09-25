param(
    [switch]$Webview
)
#change region for uninstall
$NationPath = 'registry::HKEY_USERS\.DEFAULT\Control Panel\International\Geo'
$OGNation = Get-ItemPropertyValue -Path $NationPath -Name 'Nation' 
Set-ItemProperty -Path $NationPath -Name 'Nation' -Value 68 -Force

# Allow uninstall
Reg.exe add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev' /v 'AllowUninstall' /t REG_SZ /f >$null
New-Item -Path "$env:SystemRoot\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -ItemType Directory -ErrorAction SilentlyContinue -Force >$null 
New-Item -Path "$env:SystemRoot\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -ItemType File -Name 'MicrosoftEdge.exe' -Force >$null

#define packages
$remove_appx = @('MicrosoftEdge')
if ($Webview) { $remove_appx += 'Win32WebViewHost' }
$remove_win32 = @('Microsoft Edge', 'Microsoft Edge Update')
$skip = @()
#define constants
$global:IS64 = [Environment]::Is64BitOperatingSystem
$global:PROGRAMS = ($env:ProgramFiles, ${env:ProgramFiles(x86)})[$IS64]
$global:SOFTWARE = ('SOFTWARE', 'SOFTWARE\WOW6432Node')[$IS64]
$global:ALLHIVES = 'HKCU:\SOFTWARE', 'HKLM:\SOFTWARE', 'HKCU:\SOFTWARE\Policies', 'HKLM:\SOFTWARE\Policies'
if ($IS64) { $global:ALLHIVES += "HKCU:\$SOFTWARE", "HKLM:\$SOFTWARE", "HKCU:\$SOFTWARE\Policies", "HKLM:\$SOFTWARE\Policies" }

## Shut down Edge clone stuff
Set-Location $env:systemdrive
taskkill /im explorer.exe /f *>$null
$shut = 'explorer', 'Widgets', 'widgetservice', 'MicrosoftEdge*', 'chredge', 'msedge', 'edge'
$shut, 'msteams', 'msfamily', 'Clipchamp' | ForEach-Object { Stop-Process -name $_ -force -ErrorAction SilentlyContinue }

## Clear Win32 uninstall block
foreach ($name in $remove_win32) {
    foreach ($sw in $ALLHIVES) {
        $key = "$sw\Microsoft\Windows\CurrentVersion\Uninstall\$name"
        #path doesnt exist go to next
        if (-not (test-path $key)) { continue }
        foreach ($val in 'NoRemove', 'NoModify', 'NoRepair') { Remove-ItemProperty $key $val -force -ErrorAction SilentlyContinue >$null }
        foreach ($val in 'ForceRemove', 'Delete') { Set-ItemProperty $key $val 1 -type Dword -force -ErrorAction SilentlyContinue >$null }
    }
}

## Find all Edge setup.exe
$edges = @()
'LocalApplicationData', 'ProgramFilesX86', 'ProgramFiles' | ForEach-Object {
    $folder = [Environment]::GetFolderPath($_)
    $edges += Get-ChildItem "$folder\Microsoft\Edge*\setup.exe" -Recurse -ErrorAction SilentlyContinue
}

## Remove found *Edge* appx packages
## using end of life exploit to uninstall locked packages
$provisioned = get-appxprovisionedpackage -online
$appxpackage = get-appxpackage -allusers
$eol = @()
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$users = @('S-1-5-18')
if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }
foreach ($choice in $remove_appx) {
    if ('' -eq $choice.Trim()) { continue }
    foreach ($appx in $($provisioned | Where-Object { $_.PackageName -like "*$choice*" })) {
        $next = !1
        foreach ($no in $skip) { if ($appx.PackageName -like "*$no*") { $next = !0 } }
        if ($next) { continue }
        $PackageName = $appx.PackageName
        $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName 
        New-Item "$store\Deprovisioned\$PackageFamilyName" -force >$null
        foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageName" -force >$null }
        $eol += $PackageName
        dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >$null
        remove-appxprovisionedpackage -packagename $PackageName -online -allusers >$null
    }
    foreach ($appx in $($appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" })) {
        $next = !1
        foreach ($no in $skip) { if ($appx.PackageFullName -like "*$no*") { $next = !0 } }
        if ($next) { continue }
        $PackageFullName = $appx.PackageFullName
        New-Item "$store\Deprovisioned\$appx.PackageFamilyName" -force >$null
        foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageFullName" -force >$null }
        $eol += $PackageFullName
        dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >$null
        remove-appxpackage -package $PackageFullName -allusers >$null
    }
}

## Run found *Edge* setup.exe with uninstall args
foreach ($setup in $edges) {
    if (-not (test-path $setup)) { continue }
    $target = '--msedge'
    $sulevel = ('--system-level', '--user-level')[$setup -like '*\AppData\Local\*']
    $removal = "--uninstall $target $sulevel --verbose-logging --force-uninstall"
    try { Start-Process -wait $setup -args $removal } catch {}
    #do not continue until each uninstall finishes
    do { Start-Sleep 3 } while ((get-process -name 'setup', 'MicrosoftEdge*' -ea 0).Path -like '*\Microsoft\Edge*')
}


#uninstall webview
if ($Webview) {
    # find edgeupdate.exe
    $edgeupdate = @(); 'LocalApplicationData', 'ProgramFilesX86', 'ProgramFiles' | ForEach-Object {
        $folder = [Environment]::GetFolderPath($_)
        $edgeupdate += Get-ChildItem "$folder\Microsoft\EdgeUpdate\*.*.*.*\MicrosoftEdgeUpdate.exe" -rec -ea 0
    }
    #run edge update to uninstall webview 
    foreach ($path in $edgeupdate) {
        if (Test-Path $path) { Start-Process -Wait $path -Args '/unregsvc' | Out-Null }
        do { Start-Sleep 3 } while ((Get-Process -Name 'setup', 'MicrosoftEdge*' -ErrorAction SilentlyContinue).Path -like '*\Microsoft\Edge*')
        if (Test-Path $path) { Start-Process -Wait $path -Args '/uninstall' | Out-Null }
        do { Start-Sleep 3 } while ((Get-Process -Name 'setup', 'MicrosoftEdge*' -ErrorAction SilentlyContinue).Path -like '*\Microsoft\Edge*')
    }
    # finalize uninstall
    reg.exe delete 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView' /f *>$null
    reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView' /f *>$null
}


## EdgeUpdate graceful cleanup
foreach ($sw in $ALLHIVES) { Remove-Item "$sw\Microsoft\EdgeUpdate" -recurse -force -ErrorAction SilentlyContinue }
Unregister-ScheduledTask -TaskName MicrosoftEdgeUpdate* -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item "$PROGRAMS\Microsoft\Temp" -recurse -force -ErrorAction SilentlyContinue

## remove end of life exploit 
foreach ($sid in $users) { foreach ($PackageName in $eol) { Remove-Item "$store\EndOfLife\$sid\$PackageName" -force -ErrorAction SilentlyContinue >$null } }

if (!(get-process -name 'explorer' -ea 0)) { Start-Process explorer }

#set back to og nation
Set-ItemProperty -Path $NationPath -Name 'Nation' -Value $OGNation -Force


