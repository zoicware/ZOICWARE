function import-powerplan {

    param (
      [Parameter(mandatory=$false)] [bool]$Autorun = $false
      ,[Parameter(mandatory=$false)] [bool]$importPPlan = $false
      ,[Parameter(mandatory=$false)] [bool]$removeAllPlans = $false
      ,[Parameter(mandatory=$false)] [bool]$rPowersaver = $false
      ,[Parameter(mandatory=$false)] [bool]$rBalanced = $false
      ,[Parameter(mandatory=$false)] [bool]$rHighPerformance = $false
    )
  
    $checkbox1 = New-Object System.Windows.Forms.CheckBox
    $checkbox2 = New-Object System.Windows.Forms.CheckBox
    $checkbox3 = New-Object System.Windows.Forms.CheckBox
    $checkbox4 = New-Object System.Windows.Forms.CheckBox

    #hashtable to loop through
    $settings = @{}
    $settings["removeallPlans"] = $checkbox1
    $settings["rPowersaver"] = $checkbox2
    $settings["rBalanced"] = $checkbox3
    $settings["rHighPerformance"] = $checkbox4

    #dot source update config function
    $path = Get-ChildItem -path C:\ -Filter update-config.ps1 -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; }
    .$path


    if($Autorun){
      if($importPPlan){
        $msgBoxInput = 'Yes'
      }
      $result = [System.Windows.Forms.DialogResult]::OK
      $checkbox1.Checked = $removeAllPlans
      $checkbox2.Checked = $rPowersaver
      $checkbox3.Checked = $rBalanced
      $checkbox4.Checked - $rHighPerformance
    }
    else{
      [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
      $msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Import Zoics Ultimate Performance Power Plan?','zoicware','YesNo','Question')
  
  
      Add-Type -AssemblyName System.Windows.Forms
  
  # Create the form
  $form = New-Object System.Windows.Forms.Form
  $form.Text = "Remove Unwanted Plans"
  $form.Size = New-Object System.Drawing.Size(300, 200)
  $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
  $form.MaximizeBox = $false
  $form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen
  
  # Create the checkboxes
  
  $checkbox1.Text = "Remove ALL"
  $checkbox1.Location = New-Object System.Drawing.Point(20, 20)
  $form.Controls.Add($checkbox1)
  
  
  $checkbox2.Text = "Power Saver"
  $checkbox2.Location = New-Object System.Drawing.Point(20, 50)
  $form.Controls.Add($checkbox2)
  
  
  $checkbox3.Text = "Balanced"
  $checkbox3.Location = New-Object System.Drawing.Point(20, 80)
  $form.Controls.Add($checkbox3)
  
  
  $checkbox4.Text = "High Performance"
  $checkbox4.Location = New-Object System.Drawing.Point(20, 110)
  $checkbox4.AutoSize = $true
  $form.Controls.Add($checkbox4)
  
  # Create the OK button
  $okButton = New-Object System.Windows.Forms.Button
  $okButton.Text = "OK"
  $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
  $okButton.Location = New-Object System.Drawing.Point(70, 140)
  $form.Controls.Add($okButton)
  
  # Create the Cancel button
  $cancelButton = New-Object System.Windows.Forms.Button
  $cancelButton.Text = "Cancel"
  $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
  $cancelButton.Location = New-Object System.Drawing.Point(150, 140)
  $form.Controls.Add($cancelButton)
  
  
  # Show the form and wait for user input
  $result = $form.ShowDialog()
  
    }
  
  
  
  switch  ($msgBoxInput) {
  
    'Yes' {
          
          if(!($Autorun)){
          #update config
          update-config -setting "usePowerPlan" -value 1
          }
          
          #imports power plan
          $p = Get-ChildItem -path C:\ -Filter zoicsultimateperformance.pow -Erroraction SilentlyContinue -Recurse |select-object -first 1 | % { $_.FullName; } 
  
          powercfg -import ([string]$p ) 88888888-8888-8888-8888-888888888888     
          powercfg /setactive 88888888-8888-8888-8888-888888888888 
          powercfg -h off 
  if(!($Autorun)){
    [System.Windows.Forms.MessageBox]::Show('Zoics Ultimate Performance is successfully enabled.')
  }
      
     }
  
  'No'{}
  
  }
  
  
  
  # Check the selected checkboxes
  if ($result -eq [System.Windows.Forms.DialogResult]::OK) {

if(!($Autorun)){
    #loop through checkbox hashtable to update config
    $settings.GetEnumerator() | ForEach-Object {
      
      $settingName = $_.Key
      $checkbox = $_.Value
  
      if ($checkbox.Checked) {
          update-config -setting $settingName -value 1
      }
  }
}

  if($checkbox1.Checked){
  #deletes balanced, high performance, and power saver
  powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
  powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
  powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a 
  
  
  }
  if($checkbox2.Checked){
  powercfg -delete a1841308-3541-4fab-bc81-f71556f20b4a
  
  }    
  if($checkbox3.Checked){
  powercfg -delete 381b4222-f694-41f0-9685-ff5bb260df2e
  
  }    
  if($checkbox4.Checked){
  powercfg -delete 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
  
  }    
      
  }
  
  }