function Remove-Locked {
    param(
        [string]$selectedLockedPackage
    )

    $provisioned = get-appxprovisionedpackage -online 
    $appxpackage = get-appxpackage -allusers
    $eol = @()
    $store = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
    $users = @('S-1-5-18'); if (test-path $store) { $users += $((Get-ChildItem $store -ea 0 | Where-Object { $_ -like '*S-1-5-21*' }).PSChildName) }

    #uninstall packages
       
    foreach ($appx in $($provisioned | Where-Object { $_.PackageName -like "*$selectedLockedPackage*" })) {

        $PackageName = $appx.PackageName 
        $PackageFamilyName = ($appxpackage | Where-Object { $_.Name -eq $appx.DisplayName }).PackageFamilyName

        New-Item "$store\Deprovisioned\$PackageFamilyName" -force | Out-Null
        dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 | Out-Null

        foreach ($sid in $users) { 
            New-Item "$store\EndOfLife\$sid\$PackageName" -force | Out-Null 
        }  
        $eol += $PackageName
            
        remove-appxprovisionedpackage -packagename $PackageName -online -allusers | Out-Null
    }
    foreach ($appx in $($appxpackage | Where-Object { $_.PackageFullName -like "*$selectedLockedPackage*" })) {

        $PackageFullName = $appx.PackageFullName
        $PackageFamilyName = $appx.PackageFamilyName
        New-Item "$store\Deprovisioned\$PackageFamilyName" -force | Out-Null
        dism /online /set-nonremovableapppolicy /packagefamily:$PackageFamilyName /nonremovable:0 | Out-Null

        #remove inbox apps
        $inboxApp = "$store\InboxApplications\$PackageFullName"
        Remove-Item -Path $inboxApp -Force -ErrorAction SilentlyContinue

        #get all installed user sids for package due to not all showing up in reg
        foreach ($user in $appx.PackageUserInformation) { 
            $sid = $user.UserSecurityID.SID
            if ($users -notcontains $sid) {
                $users += $sid
            }
            New-Item "$store\EndOfLife\$sid\$PackageFullName" -force | Out-Null
            remove-appxpackage -package $PackageFullName -User $sid -ErrorAction SilentlyContinue
        } 

        $eol += $PackageFullName
            
        remove-appxpackage -package $PackageFullName -allusers | Out-Null
    }
    

    ## undo eol unblock trick to prevent latest cumulative update (LCU) failing 
    foreach ($sid in $users) { foreach ($PackageName in $eol) { Remove-Item "$store\EndOfLife\$sid\$PackageName" -force -ErrorAction SilentlyContinue >'' } }

}