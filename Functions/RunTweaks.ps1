function RunTweaks($enabledSettings){
    #dot sourcing for functions
    $folder = Get-ChildItem -path C:\ -Filter _FOLDERMUSTBEONCDRIVE -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; }
    $functions = Get-ChildItem "$folder\Functions" -Filter *.ps1 -Recurse -Force
    foreach($func in $functions){
      .$func.FullName
    }
Write-Host "Running Tweaks..."
foreach($setting in $enabledSettings){

    if($setting -like "installPackages"){
        install-packs -Autorun 1
    }
    elseif($setting -like "registryTweaks"){
        import-reg -Autorun 1 
    }
    elseif($setting -like "scheduledTasks"){
        remove-tasks -Autorun 1
    }
    elseif($setting -like "disableServices"){
        disable-services -Autorun 1
    }
    elseif($setting -like "gp*"){
        $command = "gpTweaks -Autorun 1 -$setting 1"
        Invoke-Expression $command 
    }
    elseif($setting -like "debloat*"){
        $command = "debloat -Autorun 1 -$setting 1"
        Invoke-Expression $command 
    }
    elseif($setting -like "usePowerPlan"){
        import-powerplan -Autorun 1 -importPPlan 1
    }
    elseif($setting -like "removeallPlans"){
        import-powerplan -Autorun 1 -removeAllPlans 1
    }
    elseif($setting -like "rPowersaver") {
        import-powerplan -Autorun 1 -rPowersaver 1
    }
    elseif($setting -like "rBalanced") {
        import-powerplan -Autorun 1 -rBalanced 1
    }
    elseif($setting -like "rHighPerformance") {
        import-powerplan -Autorun 1 -rHighPerformance 1
    }
    elseif($setting -like "op*"){
        Write-Host "Running Optional Tweak..."
        $command = "OptionalTweaks -Autorun 1 -$setting 1"
        Invoke-Expression $command 
    }
    elseif($setting -like "con*"){
        Write-Host "Running Context Menu Tweak..."
        $command = "OptionalTweaks -Autorun 1 -$setting 1"
        Invoke-Expression $command 
    }
    elseif($setting -like "legacy*"){
        Write-Host "Running Legacy Tweak..."
        $command = "OptionalTweaks -Autorun 1 -$setting 1"
        Invoke-Expression $command 
    }
    elseif($setting -like "removeEdges"){
        W11Tweaks -Autorun 1 -removeEdges 1
    }
    elseif($setting -like "10TaskbarStartmenu"){
        W11Tweaks -Autorun 1 -win10taskbar 1
    }
    elseif($setting -like "10Explorer"){
        W11Tweaks -Autorun 1 -win10explorer 1
    }
    elseif($setting -like "servicesManual"){
        W11Tweaks -Autorun 1 -servicesManual 1
    }
}

Write-Host "Tweaks Completed... Restart to Apply ALL Changes"


}