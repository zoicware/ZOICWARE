# ZOICWARE

USAGE DEMO:
https://youtu.be/lHeGY1YfUsQ?list=PLO1RBTJcd5_imH8o0A_Qjzsup1iIB481Z



JOIN THE DISCORD

[![Discord](https://discordapp.com/api/guilds/1173717737017716777/widget.png?style=banner1)](https://discord.gg/VsC7XS5vgA)




------- UPDATE NOTES --------



v1.0.3
- added the option to remove the windows backup app (warning this may break some other windows features/apps so for now it will be under optional tweaks)

![Captvcbvcbure](https://github.com/zoicware/ZOICWAREWIN10/assets/118035521/b87e729b-11a2-4f7d-b9ae-253f8eaf8ab5)


----------------------------------------------------------------------------------------------


v1.0.4
- added restore changes button to main script to restore Updates, Defender, Services, and install the store
![image](https://github.com/zoicware/ZOICWAREWIN10/assets/118035521/8289d168-ca65-4b4b-a525-ea5e23e8ace9)


----------------------------------------------------------------------------------------------


v1.0.5

- added AMD Plan script to other scripts folder
  this will give you the option to edit ur current power plan for amd settings to try and improve idle stablity when using an agressive undervolt
  
  you can also just import my plan made for amd 
  
- added the correct way to remove hello face and quick assist as well as steps recorder app and narrator app to all debloat options



----------------------------------------------------------------------------------------------


v1.0.6

- removed sound and mouse scheme being removed in registry tweaks and is now in optional tweaks

- added classic black theme option to give most windows a classic look
  
- added win 11 sounds option to optional tweaks, note this will create a backup of the windows 10 sounds on your desktop

Classic Theme Ex.

![image](https://github.com/zoicware/ZOICWAREWIN10/assets/118035521/bf41ca6e-9d5c-41b4-86d0-cd805ea9a8fa)




----------------------------------------------------------------------------------------------


v1.0.7

After installing packages:

  - added recomplie images that have been invalidated to speed up start up performance of some apps
  - added remove superseded components, this may take a minute or few please wait

- added remove recycle bin name to optional tweaks

![image](https://github.com/zoicware/ZOICWAREWIN10/assets/118035521/3c6486eb-09d4-4282-af06-8e3004efbd9a)


- removed gaming services from debloat (keep xbox) to avoid dependency issues

- fixed some code logic that was broken in a previous update



----------------------------------------------------------------------------------------------



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


