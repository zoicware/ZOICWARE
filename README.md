# ZOICWARE

USAGE DEMO:
https://youtu.be/lHeGY1YfUsQ?list=PLO1RBTJcd5_imH8o0A_Qjzsup1iIB481Z



JOIN THE DISCORD

[![Discord](https://discordapp.com/api/guilds/1173717737017716777/widget.png?style=banner1)](https://discord.gg/VsC7XS5vgA)






![usage](https://github.com/zoicware/ZOICWARE/assets/118035521/776dd4ba-f139-4171-a75f-969452a32427)





------- UPDATE NOTES --------






v1.0.8

- updated Install Pack script to allow the user to install the latest C++ Packages, DirectX, and Internet Driver
      Note: the pack has been moved to dropbox as it is no longer possible to download files from Google Drive with Powershell

- updated install packages option in main script to attempt to install them if they are not found

- updated disable defender option to properly disable SecurityHealthService and Smartscreen



----------------------------------------------------------------------------------------------



v1.0.9

ZOICWARE HAS BEEN UPDATED FOR WIN 11!

- removed firewall+

- added win 11 reg tweaks

- updated disable defender for win 11

- updated debloat for win 11
	 - added uninstall health update tools and installed windows updates
	 - added uninstall remote desktop connection for 23h2 builds
 
- added explorer patcher tweaks for win 11

- added set all services to manual tweak for win 11



----------------------------------------------------------------------------------------------




v1.1.0

- added config to speed up the install process

- each setting you choose will be tracked by the ZCONFIG.cfg file in your temp directory 

- use the export tweaks button to save your settings for next time

- importing tweaks will run all tweaks set to 1 in the config without any prompts

- install net 3.5 installer rewritten to powershell




----------------------------------------------------------------------------------------------



v1.1.1


- install pack script displays a progressbar and downloads much faster

- removed enable xbox game bar from optional tweaks (no longer needed)

- added slight translucent effect and welcome title to console window

- replaced all file searching functions with a faster custom file searching method

- functions now imported as a powershell module instead of using dot sourcing

- fixed snipping tool context menu on windows 11

- removed original snipping tool option from optional tweaks

- minor bug fixes and code improvement




----------------------------------------------------------------------------------------------

v1.1.2

- added winfetch to display system info in powershell console

- fixed defender removing/preventing explorer patcher setup from running

- added show all taskbar tray icons on windows 11 (only shows all currently installed apps will need to be ran again when new apps are installed)

- fixed search function finding files in recycle bin

- The script will now automatically update your current config with any new settings added

- added Open Shell to Windows 11 tweaks
  	 - applying this setting will disable windows search (indexing) and replace it with openshell
 	 - custom startmenu settings will be automatically imported and all shortcuts in the current windows startmenu directory will be moved to the openshell one
  	 - OpenShell pinned shortcut directory: [C:\Users\*USERNAME*\AppData\Roaming\OpenShell\Pinned]





----------------------------------------------------------------------------------------------



v1.1.3


- added restore windows 10 recycle bin icon to windows 11 tweaks

- improved file searching function to now search in _FOLDERMUSTBEONCDRIVE first

- changed all gui menus to dark theme

- added removed pinned items in windows 11 sound flyout
	- NOTE: if you have never opened the sound flyout (from the taskbar icon) the reg tweak will not apply, if this happens simply open the flyout and then run the reg file on your desktop again


----------------------------------------------------------------------------------------------


v.1.1.4


- switched zoicware.bat to exe file using ps2exe (powershell module)

- added following apps to debloat Microsoft.OutlookForWindows, MicrosoftCorporationII.MicrosoftFamily, Microsoft.Windows.DevHome, Microsoft.Services.Store.Engagement

- disabling rounded edges will now apply on startup 

- added disable show copilot button on taskbar (reg tweaks)

- added fix to dx installer bug 
	- if the command is not correct it will close the window immediately and run with other command 

- fixed Powershell File not showing up on Windows 11 in context menu when selecting additional files to new menu (optional tweaks)

----------------------------------------------------------------------------------------------

v1.1.5

- added minor gui style update

- added remove nofication bell icon from taskbar (Win 11)
	- NOTE: this will break the calendar flyout when clicking on the date and time

- added new tweaks to ultimate context menu in optional tweaks
	- add take ownership of any file/folder
	- remove from context menu : Add to favorites, Customize this folder, Give access to, Open in Terminal, Restore Previous Versions, Print, Send to, Share, Personalize and Display (Desktop Menu)

- removed remove backup app as its not possible to uninstall via dism anymore

- fixed remote desktop connection not uninstalling

- added revert registry tweaks to restore changes

--------------------------------------------------------------------------------------------------

v1.1.6

- zoicware will now work on systems using a letter other than C for their system drive 

- cleaned up errors at the end of debloating and fixed DISM from getting stuck

- added Network Installer to main script 
	- if the script detects no internet connection it will run the local installer
	- if there is internet connection the script will search google for your network adapter's driver

- added Nvidia Autoinstall to main script
	- this will require internet connection as the script will be downloaded from github

- added activate windows to main script
	- updated kms server
	- this will install a generic pro key that works with Windows 10 and 11 Pro

- script adds _FOLDERMUSTBEONCDRIVE and zoicwareOS to defender exclusions to evade false positive

- fixed disable defender
	- with the latest defender update tamper protection has to be turned off before disabling
	- the script will open the security app and automatically navigate to disable tamper protection
	- if you dont want or need the script to do it for you feel free to manually disable before runnning the tweak
	- updated enable defender 

- added ultimate cleanup to main script
	- this combines the old UltimateCleanup.bat and Clear Event Viewer Logs.bat

 --------------------------------------------------------------------------------------------------

 v1.1.7

 - added restore old snipping tool to windows 11 tweaks

 - removed nsudo to avoid defender detection

 - fixed edge not being uninstalled with newest windows 11 update

 - various other bug fixes
