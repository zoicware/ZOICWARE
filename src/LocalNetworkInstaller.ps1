If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	
}


#check for internet connection
try {
    Invoke-WebRequest -Uri 'https://www.google.com' -Method Head -DisableKeepAlive -UseBasicParsing | Out-Null

    Write-Host 'Internet Connected...Searching Google for Network Driver'

    # Get all network adapters
    $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }
    $intel = $false
    $realtek = $false
    $gigabit = $false
    $wifi = $false
    # Loop through each adapter
    foreach ($adapter in $adapters) {
        if ($adapter.Description -like '*Intel*' -and $adapter.Description -like '*Ethernet*') {
            $intel = $true
            Start-Process 'https://www.intel.com/content/www/us/en/download/18293/intel-network-adapter-driver-for-windows-10.html'
        }
        elseif ($adapter.Description -like '*Realtek*') {
            $realtek = $true
            Start-Process 'https://www.realtek.com/en/component/zoo/category/network-interface-controllers-10-100-1000m-gigabit-ethernet-pci-express-software' 

        }
        elseif ($adapter.Description -like '*Intel*' -and $adapter.Description -like '*Gigabit*') {
            $gigabit = $true
            Start-Process 'https://www.intel.com/content/www/us/en/download/18652/intel-gigabit-ethernet-network-connection-driver-for-windows-10-for-legacy-intel-nuc.html' 

        }
        elseif ($adapter.Description -like '*Intel*' -and $adapter.Description -like '*Wi-Fi*') {
            $wifi = $true
            Start-Process 'https://www.intel.com/content/www/us/en/download/19351/windows-10-and-windows-11-wi-fi-drivers-for-intel-wireless-adapters.html' 

        }
        else {

            Write-Host 'Not Supported'

        }
        
    }
      
    #adapter not supported searching google with adapter name + driver
    if ($intel -ne $true -and $realtek -ne $true -and $gigabit -ne $true -and $wifi -ne $true) {
        foreach ($adapter in $adapters) {
            $adapterSearch = $adapter.Description -replace ' ' , '+'
            $url = "https://www.google.com/search?q=$adapterSearch+driver"
            Start-Process $url 
        }
    }
}
catch [System.Net.WebException] {
    Write-Host 'No Internet Connection...Running Local Installer'


    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
    [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Drawing')
    [System.Windows.Forms.Application]::EnableVisualStyles()
    
    # Set the size of your form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Install Network Driver'
    $form.Size = New-Object System.Drawing.Size(300, 300)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

    $checkbox2 = new-object System.Windows.Forms.RadioButton
    $checkbox2.Location = new-object System.Drawing.Size(10, 30)
    $checkbox2.AutoSize = $true
    $checkbox2.Text = 'Realtek Lan'
    $checkbox2.ForeColor = 'White'
    $checkbox2.Checked = $false
    $Form.Controls.Add($checkbox2)  
    

    $checkbox3 = new-object System.Windows.Forms.RadioButton
    $checkbox3.Location = new-object System.Drawing.Size(10, 60)
    $checkbox3.Text = 'Intel Lan'
    $checkbox3.AutoSize = $true
    $checkbox3.ForeColor = 'White'
    $checkbox3.Checked = $false
    $Form.Controls.Add($checkbox3)
     

    $checkbox4 = new-object System.Windows.Forms.RadioButton
    $checkbox4.Location = new-object System.Drawing.Size(10, 90)
    $checkbox4.AutoSize = $true
    $checkbox4.Text = 'Killer Lan'
    $checkbox4.ForeColor = 'White'
    $checkbox4.Checked = $false
    $Form.Controls.Add($checkbox4)
    

    $checkbox5 = new-object System.Windows.Forms.RadioButton
    $checkbox5.Location = new-object System.Drawing.Size(10, 120)
    $checkbox5.AutoSize = $true
    $checkbox5.Text = 'Intel Wifi'
    $checkbox5.ForeColor = 'White'
    $checkbox5.Checked = $false
    $Form.Controls.Add($checkbox5)
    

    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(50, 210)
    $OKButton.Size = New-Object System.Drawing.Size(100, 23)
    $OKButton.Text = 'OK'
    $OKButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $OKButton.ForeColor = [System.Drawing.Color]::White
    $OKButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $OKButton.FlatAppearance.BorderSize = 0
    $OKButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $OKButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(150, 210)
    $CancelButton.Size = New-Object System.Drawing.Size(100, 23)
    $CancelButton.Text = 'Cancel'
    $CancelButton.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $CancelButton.ForeColor = [System.Drawing.Color]::White
    $CancelButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $CancelButton.FlatAppearance.BorderSize = 0
    $CancelButton.FlatAppearance.MouseOverBackColor = [System.Drawing.Color]::FromArgb(62, 62, 64)
    $CancelButton.FlatAppearance.MouseDownBackColor = [System.Drawing.Color]::FromArgb(27, 27, 28)
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)
    
    # Activate the form
    $Form.Add_Shown({ $Form.Activate() })
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {

        if ($checkbox2.Checked) {
            #get os version
            $OS = Get-CimInstance Win32_OperatingSystem
            
            #installing realtek lan driver
            Write-Host 'Installing Realtek Lan Driver...'
            $path = Search-Directory '*RealtekLan'
            #adds a wild card for inf files so that any files that arent inf are ignored
            if ($OS.Caption -like '*Windows 11*') {
                $path = $path + '\WIN11\*.inf'
            }
            else {
                $path = $path + '\WIN10\*.inf'
            }
           
            #installs any inf files that are in the realtek folder
            pnputil /add-driver $path /subdirs /install | Out-Null 
            #update connected devices
            pnputil.exe /scan-devices | Out-Null
            
        }

    


        if ($checkbox3.Checked) {
            #install intel lan
            Write-Host 'Installing Intel Lan Driver...'
            $path = Search-Directory '*IntelLan'
            $path = $path + '\*.inf'
            pnputil /add-driver $path /subdirs /install | Out-Null
            #update connected devices
            pnputil.exe /scan-devices | Out-Null
        
        }



        if ($checkbox4.Checked) {
            #killer lan (not possible to get inf for drivers)
            #using installer in silent mode instead
            Write-Host 'Installing Killer Network Driver...'
            $killerInstaller = Search-File '*KillerPerformanceSuite.exe' 
            Start-Process $killerInstaller -ArgumentList '/S /v /qn' -Wait

        }



        if ($checkbox5.Checked) {
            #install intel wifi driver
            Write-Host 'Installing Intel Wifi Driver...'
            $intelWifi = Search-File '*IntelWiFi.exe'
            Start-Process $intelWifi -ArgumentList '-q' -Wait
            
        }


    }

}
