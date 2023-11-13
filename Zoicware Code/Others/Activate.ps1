If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{	Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath) -Verb RunAs
    Exit	}

[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Activate Windows?','Zoic','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {

    slmgr /ipk W269N-WFGWX-YVC9B-4J6C9-T83GX
    sleep 2
    Wait-Process wscript -ErrorAction SilentlyContinue 
    slmgr /skms kms8.msguides.com
    sleep 2
    Wait-Process wscript -ErrorAction SilentlyContinue
    slmgr /ato
    sleep 2
    Wait-Process wscript -ErrorAction SilentlyContinue
      
  [System.Windows.Forms.MessageBox]::Show('Activated Successfully.')
 }

'No'{}

}
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null 
$msgBoxInput = [System.Windows.Forms.MessageBox]::Show('Restart Computer','Zoic','YesNo','Question')

switch  ($msgBoxInput) {

  'Yes' {

Restart-Computer
 }

'No'{}

}
