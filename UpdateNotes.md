# ------- UPDATE NOTES --------

**ALL Versions**  
		- [v1.0.8](#v108)  
		- [v1.0.9](#v109)  
		- [v1.1.0](#v110)  
		- [v1.1.1](#v111)  
		- [v1.1.2](#v112)  
		- [v1.1.3](#v113)  
		- [v1.1.4](#v114)  
		- [v1.1.5](#v115)  
		- [v1.1.6](#v116)  
		- [v1.1.7](#v117)  
		- [v1.1.8](#v118)  
		- [v1.1.9](#v119)  
		- [v1.2.0](#v120)  
		- [v1.2.1](#v121)   
		- [v1.2.2](#v122)  
		- [v1.2.3](#v123)   
 		- [v1.2.4](#v124)   
  		- [v1.2.5](#v125)   
    		- [v1.2.6](#v126)   
  		-  [v1.2.7](#v127)   
    		-  [v1.2.8](#v128)    
                -  [v1.2.9](#v129)   

---

### v1.0.8

- updated Install Pack script to allow the user to install the latest C++ Packages, DirectX, and Internet Driver
      Note: the pack has been moved to dropbox as it is no longer possible to download files from Google Drive with Powershell

- updated install packages option in main script to attempt to install them if they are not found

- updated disable defender option to properly disable SecurityHealthService and Smartscreen



----------------------------------------------------------------------------------------------


### v1.0.9

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




### v1.1.0

- added config to speed up the install process

- each setting you choose will be tracked by the ZCONFIG.cfg file in your temp directory 

- use the export tweaks button to save your settings for next time

- importing tweaks will run all tweaks set to 1 in the config without any prompts

- install net 3.5 installer rewritten to powershell




----------------------------------------------------------------------------------------------



### v1.1.1


- install pack script displays a progressbar and downloads much faster

- removed enable xbox game bar from optional tweaks (no longer needed)

- added slight translucent effect and welcome title to console window

- replaced all file searching functions with a faster custom file searching method

- functions now imported as a powershell module instead of using dot sourcing

- fixed snipping tool context menu on windows 11

- removed original snipping tool option from optional tweaks

- minor bug fixes and code improvement




----------------------------------------------------------------------------------------------

### v1.1.2

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



### v1.1.3


- added restore windows 10 recycle bin icon to windows 11 tweaks

- improved file searching function to now search in _FOLDERMUSTBEONCDRIVE first

- changed all gui menus to dark theme

- added removed pinned items in windows 11 sound flyout
	- NOTE: if you have never opened the sound flyout (from the taskbar icon) the reg tweak will not apply, if this happens simply open the flyout and then run the reg file on your desktop again


----------------------------------------------------------------------------------------------


### v1.1.4


- switched zoicware.bat to exe file using ps2exe (powershell module)

- added following apps to debloat Microsoft.OutlookForWindows, MicrosoftCorporationII.MicrosoftFamily, Microsoft.Windows.DevHome, Microsoft.Services.Store.Engagement

- disabling rounded edges will now apply on startup 

- added disable show copilot button on taskbar (reg tweaks)

- added fix to dx installer bug 
	- if the command is not correct it will close the window immediately and run with other command 

- fixed Powershell File not showing up on Windows 11 in context menu when selecting additional files to new menu (optional tweaks)

----------------------------------------------------------------------------------------------

### v1.1.5

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

### v1.1.6

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

 ### v1.1.7

 - added restore old snipping tool to windows 11 tweaks

 - removed nsudo to avoid defender detection

 - fixed edge not being uninstalled with newest windows 11 update

 - added security updates only in optional tweaks
   	- this tweak will prevent windows update from installing optional and feature updates

 - reworked debloat to dynamically attempt to uninstall all appx packages and speed up the amount of time the process takes
   	- the option "Debloat All" will now also remove some locked appx packages
   	- NOTE: the other debloat options have not been changed

 - various other bug fixes

--------------------------------------------------------------------------------------------------

 ### v1.1.8

 - updated show all app icons on windows 11 taskbar to update for new apps upon restarting
	- a scheduled task will be created to run at startup to show new apps by default 
	- any apps that are manually disabled from showing on the taskbar will be skipped

- fixed registry tweaks from breaking search indexer on windows 10

- updated debloat to allow users custom debloat options
	- legacy debloat options will be under "debloat presets"

	- NOTE: Locked Packages may break some features when removed use with caution
	- NOTE: the extra debloat options are apart of the debloat presets
	- NOTE: some appx packages are excluded from the list to preserve os functionality

--------------------------------------------------------------------------------------------------


### v1.1.9

- updated disable defender to no longer need to disable tamper protection before disabling

- added check for updates when launching zoicware, if an old version is detected it will prompt to install the newest version


--------------------------------------------------------
### v1.2.0

- updated ui to be more modern and improve readability 

- added end task in context menu when right clicking apps on the taskbar for windows 11 (registry tweaks)

- improved run zoicware.exe to launch the script much faster 

---------------------------------------------------------------

### v1.2.1

- further improved script startup speed

- added option to build a custom config to automate tweaks

- upgraded registry tweaks option to now allow you to remove any tweaks before running

---

### v1.2.2

- fixed remote desktop not uninstalling on newer builds  
   
- replaced trusted installer function with Run-Trusted  
- fixed disable defender not working  
- added list of current power plans to remove  
- added built-in hidden powerplans to enable *[Ultimate Performance, Max Performance Overlay, High Performance Overlay]*   

---

### v1.2.3

- upgraded ultimate cleanup:
added option to individually customize most hidden disk cleanup options, added clear windows logs, this will delete almost all log files in various locations


- switched the clean up process after installing necessary packages to background tasks, a notification will appear for both tasks when they start and complete


- added restore windows 10 task manager to windows 11 tweaks


- fixed takeownership context menu tweak


- added restore windows 10 notepad to windows 11 tweaks *Note: removing uwp notepad breaks ps1 file icons*


- fixed disable defender


- added various info icons at the top of menus to open the features readme to the specific tweak

---
### v1.2.4

- added progress bar to removing scheduled tasks

- added disable archive apps to registry tweaks

- explorer patcher is now downloaded from the latest github release to ensure it always works

- split up uninstall edge and edge webview since its needed for some other apps

- changed "restore windows 10 notepad" to use 21h2 W11 notepad because it has the W10 style, this also fixes various other bugs with removing uwp notepad

- added remove extract all context menu to zip,7z,rar,tar,gz files

- removed most of the folders from the pack and moved away from using a dropbox link instead just uploading the zip directly to github

- since download zoicware script is removed install packages requires internet connection 

- various bug fixes

---
### v1.2.5
- replaced all message boxes with custom WinForms dark theme message boxes
  
- added hide recommended section on Windows 11 Startmenu [**NOTE!** this will run a small script on startup to remove it]
  
- replaced default WinForms font with DM Mono for a cleaner look
  
- added feature to install my other scripts that will create a desktop shortcut running the code directly from github
  
- you can now drag and drop your config file onto the Import/Export window

---
### v1.2.6

- remade main menu ui to organize options better
  
- fixed snipping tool hotkey not working when using debloat all
  
- moved Clipchamp, Microsoft.BingSearch, Microsoft.Services.Store.Engagement, Microsoft.WidgetsPlatformRuntime to locked appxpackages since they can no longer be uninstalled with the normal method
 (NOTE) debloat all will remove these packages

- integrated nvidiaautoinstall into zoicware instead of downloading it from the repo
  
- changed RUN ZOICWARE.ps1 to be a batch script to fix debloating on 24h2 (NOTE: RUN ZOICWARE.exe is still there but instead compiled from a batch script)
  
- added disable windows spotlight to registry tweaks
  
- added disable snipping tool noti and disable share app experinces for windows 11 regitry tweaks
  
- updated disable defender and enable for 24h2
  
- some bug fixes for 24h2


### v1.2.7

---

- added dynamic functions to get app icons so its more clear as to what the app is **NOTE** : Not all AppxPackages have an icon
  
- split up registry tweaks to show windows 10 and 11 to make it easier to customize 
  
- added repair xbox apps to revert tweaks this will download and run the xbox game repair tool
  
- added browser installer to post install tweaks to install chrome,brave or firefox
  
- the zoicware launcher script will now cache the location of ZOICWARE.ps1 this way it will open instantly after the first time | Location of cache : [C:\Users\Username\zLocation.tmp]
  
- added offline mode so that zoicware will skip checking for updates if theres no internet 
  
- fixed add new files to context menu on 24h2


### v1.2.8

---

- added additional policies to disable telemetry
   
- added pause updates for 1 year to optional tweaks
  
- changed windows 10 file explorer tweak to use a registry hack instead of explorer patcher (win 11 tweaks)
  
- added restore windows 10 icons this will create a backup of the windows 11 icons on your desktop
  
- added dark winver to windows 11 tweaks to replace the standard winver


### v1.2.9

---

- added enable qos for upload to network driver installer, this will cap your upload bandwidth and apply settings to reduce latency under load [Credits @AveYo]
  
- revert qos tweak added to restore tweaks
  
- added remove troubleshoot compatibility and include in library to context menu tweaks
  
- added option to choose between rebar on and off in nvidia autoinstall
  
- added install DDU option to nvidia autoinstall, if you choose to run it in safemode the script will reboot you to safemode and ddu will run at startup
  
- added release highlights to each of the 4 drivers listed on nvidia autoinstall
  
- removed legacy win store from optional tweaks  

