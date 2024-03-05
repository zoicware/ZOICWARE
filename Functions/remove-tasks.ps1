function remove-tasks {

    param (
      [Parameter(mandatory=$false)] [bool]$Autorun = $false
     # ,[Parameter(mandatory=$false)] $setting 
    )
  

  #dot source update config function
    $path = Get-ChildItem -path C:\ -Filter update-config.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; }
    .$path


  if($Autorun){
    $msgBoxInput = 'Yes'
  }
  else{
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
    $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Remove Scheduled Tasks?','zoicware','YesNo','Question')
  }
  
  
  switch  ($msgBoxInput) {
  
    'Yes' {
    
    if(!($Autorun)){
      update-config -setting "scheduledTasks" -value 1
    }

    #removes all schd tasks 
  Get-ScheduledTask -TaskPath '*' | Stop-ScheduledTask
  Unregister-ScheduledTask -TaskPath '*' -Confirm:$false
  Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineCore*'} | Disable-ScheduledTask
  Get-ScheduledTask | Where-Object {$_.Taskname -match 'MicrosoftEdgeUpdateTaskMachineUA*'} | Disable-ScheduledTask
  
  #restoring two tasks that are needed
  New-Item -Path C:\Windows\System32\Tasks\Microsoft\Windows\'TextServicesFramework\MsCtfMonitor' -ItemType File -Force
  $content = '<?xml version="1.0" encoding="UTF-16"?>
  <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo>
      <SecurityDescriptor>D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)</SecurityDescriptor>
      <Source>$(@%systemRoot%\system32\MsCtfMonitor.dll,-1000)</Source>
      <Description>$(@%systemRoot%\system32\MsCtfMonitor.dll,-1001)</Description>
      <URI>Microsoft\Windows\TextServicesFramework\MsCtfMonitor</URI>
    </RegistrationInfo>
    <Principals>
      <Principal id="AnyUser">
        <GroupId>S-1-5-32-545</GroupId>
      </Principal>
    </Principals>
    <Settings>
      <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
      <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
      <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
      <Hidden>true</Hidden>
      <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>
      <Priority>5</Priority>
      <IdleSettings>
        <StopOnIdleEnd>true</StopOnIdleEnd>
        <RestartOnIdle>false</RestartOnIdle>
      </IdleSettings>
      <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    </Settings>
    <Triggers>
      <LogonTrigger />
    </Triggers>
    <Actions Context="AnyUser">
      <ComHandler>
        <ClassId>{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}</ClassId>
      </ComHandler>
    </Actions>
  </Task>' | out-file C:\Windows\System32\Tasks\Microsoft\Windows\TextServicesFramework\MsCtfMonitor
  
  schtasks /create /xml C:\Windows\System32\Tasks\Microsoft\Windows\TextServicesFramework\MsCtfMonitor /tn "\MyTasks\FixSearch"  
    
    #searches c drive for the xml and imports it to task schd
  $pathSPP = Get-ChildItem -Path C:\ -Filter SvcRestartTask.xml -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
  schtasks /create /xml ([String]$pathSPP) /tn "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" 
    if(!($Autorun)){
      [System.Windows.Forms.MessageBox]::Show('Scheduled Tasks have been removed.')
    }
  
   }
  
  'No'{}
  
  }
  
  
  
  }