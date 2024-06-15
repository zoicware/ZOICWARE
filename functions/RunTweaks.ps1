function RunTweaks($enabledSettings) {
    
    Write-Host '-------------- Applying Tweaks --------------'
    foreach ($setting in $enabledSettings) {

        Write-Host "Running Option : [$setting]" -ForegroundColor Green

        switch -Wildcard ($setting) {
            'installPackages' {
                install-packs -Autorun 1
            }
            'registryTweaks' {
                import-reg -Autorun 1 
            }
            'scheduledTasks' {
                remove-tasks -Autorun 1
            }
            'disableServices' {
                disable-services -Autorun 1
            }
            'gp*' {
                $command = "gpTweaks -Autorun 1 -$setting 1"
                Invoke-Expression $command 
            }
            'debloat*' {
                $command = "debloat -Autorun 1 -$setting 1"
                Invoke-Expression $command 
            }
            'usePowerPlan' {
                import-powerplan -Autorun 1 -importPPlan 1
            }
            'removeallPlans' {
                import-powerplan -Autorun 1 -removeAllPlans 1
            }
            'rPowersaver' {
                import-powerplan -Autorun 1 -rPowersaver 1
            }
            'rBalanced' {
                import-powerplan -Autorun 1 -rBalanced 1
            }
            'rHighPerformance' {
                import-powerplan -Autorun 1 -rHighPerformance 1
            }
            'op*' {
                $command = "OptionalTweaks -Autorun 1 -$setting 1"
                Invoke-Expression $command 
            }
            'con*' {
                $command = "OptionalTweaks -Autorun 1 -$setting 1"
                Invoke-Expression $command 
            }
            'legacy*' {
                $command = "OptionalTweaks -Autorun 1 -$setting 1"
                Invoke-Expression $command 
            }
            'removeEdges' {
                W11Tweaks -Autorun 1 -removeEdges 1
            }
            'win10*' {
                $command = "W11Tweaks -Autorun 1 -$setting 1"
                Invoke-Expression $command
            }
            'servicesManual' {
                W11Tweaks -Autorun 1 -servicesManual 1
            }
            'showTrayIcons' {
                W11Tweaks -Autorun 1 -showTrayIcons 1
            }
            'enableOpenShell' {
                W11Tweaks -Autorun 1 -enableOpenShell 1
            }
            'disableBellIcon' {
                W11Tweaks -Autorun 1 -disableBell
            }
        }

    }

    Write-Host 'Tweaks Completed... Restart to Apply ALL Changes'


}