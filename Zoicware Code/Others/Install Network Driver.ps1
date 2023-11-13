If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}


[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
    
    # Set the size of your form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Install Network Driver'
    $form.Size = New-Object System.Drawing.Size(400,300)
    $form.StartPosition = 'CenterScreen'

    $checkbox2 = new-object System.Windows.Forms.checkbox
    $checkbox2.Location = new-object System.Drawing.Size(10,30)
    $checkbox2.Size = new-object System.Drawing.Size(150,20)
    $checkbox2.Text = "Realtek"
    $checkbox2.Checked = $false
    $Form.Controls.Add($checkbox2)  
    

    $checkbox3 = new-object System.Windows.Forms.checkbox
    $checkbox3.Location = new-object System.Drawing.Size(10,60)
    $checkbox3.Size = new-object System.Drawing.Size(150,20)
    $checkbox3.Text = "Intel Lan"
    $checkbox3.Checked = $false
    $Form.Controls.Add($checkbox3)
     

    $checkbox4 = new-object System.Windows.Forms.checkbox
    $checkbox4.Location = new-object System.Drawing.Size(10,90)
    $checkbox4.Size = new-object System.Drawing.Size(150,20)
    $checkbox4.Text = "Killer"
    $checkbox4.Checked = $false
    $Form.Controls.Add($checkbox4)
    

    $checkbox5 = new-object System.Windows.Forms.checkbox
    $checkbox5.Location = new-object System.Drawing.Size(10,120)
    $checkbox5.Size = new-object System.Drawing.Size(150,20)
    $checkbox5.Text = "Install All"
    $checkbox5.Checked = $false
    $Form.Controls.Add($checkbox5)
    

    $OKButton = New-Object System.Windows.Forms.Button
$OKButton.Location = New-Object System.Drawing.Point(100,210)
$OKButton.Size = New-Object System.Drawing.Size(100,23)
$OKButton.Text = 'OK'
$OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $OKButton
$form.Controls.Add($OKButton)

$CancelButton = New-Object System.Windows.Forms.Button
$CancelButton.Location = New-Object System.Drawing.Point(200,210)
$CancelButton.Size = New-Object System.Drawing.Size(100,23)
$CancelButton.Text = 'Cancel'
$CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.CancelButton = $CancelButton
$form.Controls.Add($CancelButton)

$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10,10)
$label.Size = New-Object System.Drawing.Size(200,20)
$label.Text = 'Choose Install All If Youre Not Sure:'
$form.Controls.Add($label)
  
 
    
    # Activate the form
    $Form.Add_Shown({$Form.Activate()})
    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
{

if($checkbox2.Checked){

#searches c drive for "RealtekLan" folder and adds the full path to the folder variable
$folder = Get-ChildItem -Path C:\ -Filter RealtekLan -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
#adds a wild card for inf files so that any files that arent inf are ignored
$folder = $folder+"\*.inf"
#installs any inf files that are in the realtek folder
pnputil /add-driver $folder /subdirs /install
pnputil /scan-devices



}


if($checkbox3.Checked){

$folder = Get-ChildItem -Path C:\ -Filter IntelLan -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
$folder = $folder+"\*.inf"
pnputil /add-driver $folder /subdirs /install
pnputil /scan-devices

}



if($checkbox4.Checked){

$folder = Get-ChildItem -Path C:\ -Filter KillerLan -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
$folder = $folder+"\*.inf"
pnputil /add-driver $folder /subdirs /install
pnputil /scan-devices



}






if($checkbox5.Checked){

$folder = Get-ChildItem -Path C:\ -Filter ChooseMe -Recurse -ErrorAction SilentlyContinue -Force |select-object -first 1 | % { $_.FullName; }
$folder = $folder+"\*.inf"
pnputil /add-driver $folder /subdirs /install
pnputil /scan-devices

}


}




