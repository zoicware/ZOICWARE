
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

$host.ui.RawUI.WindowTitle = 'Firewall+ by Zoic'


#Removing any old rules
$firewallRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -eq "Block Bad IPs"} 

if ($firewallRules) {
    foreach ($rule in $firewallRules) {
        Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction SilentlyContinue
    }
  }



function Get-IPAddressesFromList1($csvString) {
    $ipAddresses = @()

    # Split the CSV string into lines
    $lines = $csvString -split "\r?\n"

    # Extract IP addresses
    foreach ($line in $lines) {
        # Skip empty lines and comment lines
        if ($line -notmatch "^\s*(#|$)") {
            # Extract the IP address from the appropriate field
            if ($line -match '"[^"]*","([^"]+)"') {
                $ip = $matches[1].Trim()
                $ipAddresses += $ip
            }
        }
    }
    $ipAddresses = $ipAddresses | Select-Object -Skip 1
    return $ipAddresses
}

function Get-IPAddressesFromList2($csvString) {
    $ipAddresses = @()

    # Split the CSV string into lines
    $lines = $csvString -split "\r?\n"

    # Extract IP addresses
    foreach ($line in $lines) {
        # Skip empty lines and comment lines
        if ($line -notmatch "^\s*(#|$)") {
            # Extract the IP address from the appropriate field
            if ($line -match 'http://([\d.]+):') {
                $ip = $matches[1].Trim()
                $ipAddresses += $ip
            }
        }
    }

    return $ipAddresses
}



function Get-IPAddressesFromList3($list){

$pattern = '\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'

$matches = [regex]::Matches($list, $pattern)
$ipAddresses = $matches | ForEach-Object { $_.Value }
return $ipAddresses


}


# Function to create a firewall rule to block multiple IP addresses
function New-FirewallRule($ipAddresses, $direction) {
    $action = "Block"
    $ruleName = "Block Bad IPs"

    

    # Create the rule
    $rule = New-NetFirewallRule -DisplayName $ruleName -Direction $direction -LocalPort Any -Protocol Any -Action $action -RemoteAddress $ipAddresses -Enabled True -Profile Any -Description "Blocking multiple IP addresses"

    # Apply the rule immediately
    $rule | Set-NetFirewallRule -PassThru
}

# URLs to query
$url1 = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
$url2 = "https://urlhaus.abuse.ch/downloads/csv_online/"
$url3 = "https://www.spamhaus.org/drop/drop.txt"

# Query the URLs and get the CSV content
$csvContent1 = Invoke-WebRequest -Uri $url1 -UseBasicParsing | Select-Object -ExpandProperty Content 
$csvContent2 = Invoke-WebRequest -Uri $url2 -UseBasicParsing | Select-Object -ExpandProperty Content 
$txtContent = Invoke-WebRequest -Uri $url3 -UseBasicParsing | Select-Object -ExpandProperty Content

# Extract IP addresses from CSV content
$ipAddresses1 = Get-IPAddressesFromList1 $csvContent1
$ipAddresses2 = Get-IPAddressesFromList2 $csvContent2
$ipAddresses3 = Get-IPAddressesFromList3 $txtContent



# Create inbound and outbound rules for list 1
New-FirewallRule $ipAddresses1 "Inbound"
New-FirewallRule $ipAddresses1 "Outbound"


# Create inbound and outbound rules for list 2
New-FirewallRule $ipAddresses2 "Inbound"
New-FirewallRule $ipAddresses2 "Outbound"

# Create inbound and outbound rules for list 3
New-FirewallRule $ipAddresses3 "Inbound"
New-FirewallRule $ipAddresses3 "Outbound"


#Creating updater file
$url = "https://raw.githubusercontent.com/zoicware/FirewallUpdater/main/FirewallUpdater.ps1"
$content = Invoke-WebRequest -Uri $url -UseBasicParsing 
New-Item -Path "C:\FirewallUpdater.ps1" -Force
Set-Content -Path "C:\FirewallUpdater.ps1" -Value $content



#create schd task to run updater at 4am everyday and if not ran then run when the pc starts


$taskName = "FirewallUpdater"


# Check if the task already exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue

if ($existingTask -eq $null) {
# Get the current user's username
$currentUserName = $env:COMPUTERNAME + "\" + $env:USERNAME
$username = Get-LocalUser -Name $env:USERNAME | Select-Object -ExpandProperty sid


New-Item -Path C:\FirewallUpdater -ItemType File -Force
$content = '<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>'+$currentUserName+'</Author>
    <URI>\FirewallUpdater</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2023-06-28T04:00:00</StartBoundary>
      <ExecutionTimeLimit>PT15M</ExecutionTimeLimit>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>'+$username+'</UserId>
      <LogonType>S4U</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>PowerShell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\FirewallUpdater.ps1"</Arguments>
    </Exec>
  </Actions>
</Task>' | out-file C:\FirewallUpdater


schtasks /Create /XML "C:\FirewallUpdater" /TN "\FirewallUpdater" /F 



Remove-Item -Path "C:\FirewallUpdater" -Force

    
} else {
    Write-Host "Scheduled task already exists."
}


