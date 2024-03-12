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


