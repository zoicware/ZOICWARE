function RunTweaks($enabledSettings) {
    
    Write-Host '-------------- Applying Tweaks --------------'
    foreach ($setting in $enabledSettings) {

        Write-Host "Running Option : [$setting]" -ForegroundColor Green

        switch -Wildcard ($setting) {
            'installPackages' {
                install-packs -Autorun 1
                break
            }
            'registryTweaks' {
                import-reg -Autorun 1 
                break
            }
            'scheduledTasks' {
                remove-tasks -Autorun 1
                break
            }
            'disableServices' {
                disable-services -Autorun 1
                break
            }
            'gp*' {
                $command = "gpTweaks -Autorun 1 -$setting 1"
                Invoke-Expression $command 
                break
            }
            'debloat*' {
                $command = "debloat -Autorun 1 -$setting 1"
                Invoke-Expression $command 
                break
            }
            'usePowerPlan' {
                import-powerplan -Autorun 1 -importPPlan 1
                break
            }
            'usePowerPlanAMD' {
                import-powerplan -Autorun 1 -importPPlanAMD 1
                break
            }
            'removeallPlans' {
                import-powerplan -Autorun 1 -removeAllPlans 1
                break
            }
            'enableUltimate' {
                import-powerplan -Autorun 1 -enableUltimate 1
                break
            }
            'enableMaxOverlay' {
                import-powerplan -Autorun 1 -enableMaxOverlay 1
                break
            }
            'enableHighOverlay' {
                import-powerplan -Autorun 1 -enableHighOverlay 1
                break
            }
            'op*' {
                $command = "OptionalTweaks -Autorun 1 -$setting 1"
                Invoke-Expression $command 
                break
            }
            'con*' {
                $command = "OptionalTweaks -Autorun 1 -$setting 1"
                Invoke-Expression $command 
                break
            }
            'removeEdges' {
                W11Tweaks -Autorun 1 -removeEdges 1
                break
            }
            'win10*' {
                $command = "W11Tweaks -Autorun 1 -$setting 1"
                Invoke-Expression $command
                break
            }
            'servicesManual' {
                W11Tweaks -Autorun 1 -servicesManual 1
                break
            }
            'showTrayIcons' {
                W11Tweaks -Autorun 1 -showTrayIcons 1
                break
            }
            'enableOpenShell' {
                W11Tweaks -Autorun 1 -enableOpenShell 1
                break
            }
            'darkWinver' {
                W11Tweaks -Autorun 1 -darkWinver 1
                break
            }
            'removeQuickSettingTiles' {
                W11Tweaks -Autorun 1 -removeQuickSettingTiles 1
                break
            }
            'removeSystemLabel' {
                W11Tweaks -Autorun 1 -removeSystemLabel 1
                break
            }
            'disableNotepadTabs' {
                W11Tweaks -Autorun 1 -disableNotepadTabs 1
                break
            }
            'hideSettingsAds' {
                W11Tweaks -Autorun 1 -hideSettingsAds 1
                break
            }
            'disableResume' {
                W11Tweaks -Autorun 1 -disableResume 1
                break
            }
            'smallTaskbarIcons' {
                W11Tweaks -Autorun 1 -smallTaskbarIcons 1
                break
            }
            'maxMouseThrottle' {
                W11Tweaks -Autorun 1 -maxMouseThrottle 1
                break
            }
            'newStartMenu' {
                W11Tweaks -Autorun 1 -newStartMenu 1
                break
            }
            default {
                Write-Host "Tweak [$setting] Not Found!" -ForegroundColor Red
            }

        }

    }

    Write-Status -message 'Tweaks Completed... Restart to Apply ALL Changes' -type Output


}