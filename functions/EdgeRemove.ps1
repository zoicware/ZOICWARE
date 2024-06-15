
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}


#---------------------------------------------- Script Snippet from AveYo fixed by Zoic
#remove webview
$also_remove_webview = 1

#allow uninstall
reg add 'HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev' /v 'AllowUninstall' /t REG_SZ /f >$null
New-Item -Path "$env:SystemRoot\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -ItemType Directory -ErrorAction SilentlyContinue -Force >$null 
New-Item -Path "$env:SystemRoot\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" -ItemType File -Name 'MicrosoftEdge.exe' -Force >$null

$remove_appx = @('MicrosoftEdge'); $remove_win32 = @('Microsoft Edge', 'Microsoft Edge Update'); $skip = @() # @("DevTools")
if ($also_remove_webview -eq 1) { $remove_appx += 'Win32WebViewHost'; $remove_win32 += 'Microsoft EdgeWebView' }


$global:WEBV = $also_remove_webview -eq 1
$global:IS64 = [Environment]::Is64BitOperatingSystem
$global:IFEO = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
$global:EDGE_UID = '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
$global:WEBV_UID = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
$global:UPDT_UID = '{F3C4FE00-EFD5-403B-9569-398A20F1BA4A}'
$global:PROGRAMS = ($env:ProgramFiles, ${env:ProgramFiles(x86)})[$IS64]
$global:SOFTWARE = ('SOFTWARE', 'SOFTWARE\WOW6432Node')[$IS64]
$global:ALLHIVES = 'HKCU:\SOFTWARE', 'HKLM:\SOFTWARE', 'HKCU:\SOFTWARE\Policies', 'HKLM:\SOFTWARE\Policies'
if ($IS64) { $global:ALLHIVES += "HKCU:\$SOFTWARE", "HKLM:\$SOFTWARE", "HKCU:\$SOFTWARE\Policies", "HKLM:\$SOFTWARE\Policies" }
## -------------------------------------------------------------------------------------------------------------------------------


## 3 shut down edge & webview clone stuff
Set-Location $env:systemdrive; taskkill /im explorer.exe /f 2>&1 >''
$shut = 'explorer', 'Widgets', 'widgetservice', 'msedgewebview2', 'MicrosoftEdge*', 'chredge', 'msedge', 'edge'
$shut, 'msteams', 'msfamily', 'WebViewHost', 'Clipchamp' | ForEach-Object { Stop-Process -name $_ -force -ea 0 }

## clear win32 uninstall block
foreach ($name in $remove_win32) {
    foreach ($sw in $ALLHIVES) {
        $key = "$sw\Microsoft\Windows\CurrentVersion\Uninstall\$name"; if (-not (test-path $key)) { continue }
        foreach ($val in 'NoRemove', 'NoModify', 'NoRepair') { Remove-ItemProperty $key $val -force -ErrorAction SilentlyContinue >$null }
        foreach ($val in 'ForceRemove', 'Delete') { Set-ItemProperty $key $val 1 -type Dword -force -ErrorAction SilentlyContinue >$null }
    }
}


## find all Edge setup.exe and gather BHO paths for OpenWebSearch / MSEdgeRedirect usage
$edges = @(); $bho = @(); $edgeupdates = @(); 'LocalApplicationData', 'ProgramFilesX86', 'ProgramFiles' | ForEach-Object {
    $folder = [Environment]::GetFolderPath($_); $bho += Get-ChildItem "$folder\Microsoft\Edge*\ie_to_edge_stub.exe" -rec -ea 0
    if ($WEBV) { $edges += Get-ChildItem "$folder\Microsoft\Edge*\setup.exe" -rec -ea 0 | Where-Object { $_ -like '*EdgeWebView*' } }
    $edges += Get-ChildItem "$folder\Microsoft\Edge*\setup.exe" -rec -ea 0 | Where-Object { $_ -notlike '*EdgeWebView*' }
    $edgeupdates += Get-ChildItem "$folder\Microsoft\EdgeUpdate\*.*.*.*\MicrosoftEdgeUpdate.exe" -rec -ea 0
}


## 4 remove found *Edge* appx packages with unblock tricks
$provisioned = get-appxprovisionedpackage -online; $appxpackage = get-appxpackage -allusers; $eol = @()
$store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
$users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }
foreach ($choice in $remove_appx) {
    if ('' -eq $choice.Trim()) { continue }
    foreach ($appx in $($provisioned | Where-Object { $_.PackageName -like "*$choice*" })) {
        $next = !1; foreach ($no in $skip) { if ($appx.PackageName -like "*$no*") { $next = !0 } } ; if ($next) { continue }
        $PackageName = $appx.PackageName; $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName 
        New-Item "$store\Deprovisioned\$PackageFamilyName" -force >$null ; $PackageFamilyName  
        foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageName" -force >$null } ; $eol += $PackageName
        dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >$null
        remove-appxprovisionedpackage -packagename $PackageName -online -allusers >$null
    }
    foreach ($appx in $($appxpackage | Where-Object { $_.PackageFullName -like "*$choice*" })) {
        $next = !1; foreach ($no in $skip) { if ($appx.PackageFullName -like "*$no*") { $next = !0 } } ; if ($next) { continue }
        $PackageFullName = $appx.PackageFullName; 
        New-Item "$store\Deprovisioned\$appx.PackageFamilyName" -force >$null ; $PackageFullName
        foreach ($sid in $users) { New-Item "$store\EndOfLife\$sid\$PackageFullName" -force >$null } ; $eol += $PackageFullName
        dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 >$null
        remove-appxpackage -package $PackageFullName -allusers >$null
    }
}
## -------------------------------------------------------------------------------------------------------------------------------

## 5 run found *Edge* setup.exe with uninstall args and wait in-between
foreach ($setup in $edges) {
    if (-not (test-path $setup)) { continue }
    if ($setup -like '*EdgeWebView*') { $target = '--msedgewebview' } else { $target = '--msedge' }
    $sulevel = ('--system-level', '--user-level')[$setup -like '*\AppData\Local\*']
    $removal = "--uninstall $target $sulevel --verbose-logging --force-uninstall"
    try { Start-Process -wait $setup -args $removal } catch {}
    do { Start-Sleep 3 } while ((get-process -name 'setup', 'MicrosoftEdge*' -ea 0).Path -like '*\Microsoft\Edge*')
}
## -------------------------------------------------------------------------------------------------------------------------------



## 6 edgeupdate graceful cleanup
if ($WEBV) {
    foreach ($sw in $ALLHIVES) { Remove-Item "$sw\Microsoft\EdgeUpdate" -recurse -force -ErrorAction SilentlyContinue }  
    foreach ($UPDT in $edgeupdates) { 
        if (test-path $UPDT) { Start-Process -wait $UPDT -args '/unregsvc' }
        do { Start-Sleep 3 } while ((get-process -name 'setup', 'MicrosoftEdge*' -ea 0).Path -like '*\Microsoft\Edge*')
        if (test-path $UPDT) { Start-Process -wait $UPDT -args '/uninstall' }
        do { Start-Sleep 3 } while ((get-process -name 'setup', 'MicrosoftEdge*' -ea 0).Path -like '*\Microsoft\Edge*')
    }
    Unregister-ScheduledTask -TaskName MicrosoftEdgeUpdate* -Confirm:$false -ea 0; Remove-Item "$PROGRAMS\Microsoft\Temp" -recurse -force -ErrorAction SilentlyContinue
} 


## undo eol unblock trick to prevent latest cumulative update (LCU) failing 
foreach ($sid in $users) { foreach ($PackageName in $eol) { Remove-Item "$store\EndOfLife\$sid\$PackageName" -force -ErrorAction SilentlyContinue >$null } }


## -------------------------------------------------------------------------------------------------------------------------------

if (!(get-process -name 'explorer' -ea 0)) { Start-Process explorer }