# All zoicware features
### Table of Contents
  - [Registry Tweaks](#registry-tweaks)
  - [Group Policy Tweaks](#group-policy-tweaks)
    - [Disable Updates](#disable-updates)
    - [Disable Windows Defender](#disable-windows-defender)
    - [Disable Windows Telemetry](#disable-windows-telemetry)
  - [Remove Scheduled Tasks](#remove-scheduled-tasks)
  - [Disable Services](#disable-services)
      - [Services Disabled](#services-disabled)
  - [Debloat](#debloat)
    - [Debloat Presets](#debloat-presets)
    - [Features](#features)
    - [Custom Debloat](#custom-debloat)
  - [Optional Tweaks](#optional-tweaks)
    - [General](#general)
    - [Ultimate Context Menu](#ultimate-context-menu)
      - [Add to Menu](#add-to-menu)
      - [Remove from Menu](#remove-from-menu)
  - [Import and Remove Power Plans](#import-and-remove-power-plans)
    - [Import Plan](#import-plan)
    - [Remove Plans](#remove-plans)
    - [Enable Hidden Plans](#enable-hidden-plans)
  - [Windows 11 Tweaks](#windows-11-tweaks)
    - [Patch Explorer](#patch-explorer)
    - [Misc Tweaks](#misc-tweaks)
  - [Install Network Driver](#install-network-driver)
  - [Install Nvidia Driver](#install-nvidia-driver)
    - [Features](#features-1)
      - [Post Install Tweaks](#post-install-tweaks)
  - [Install Packages](#install-packages)
  - [Importing and Exporting Tweaks](#importing-and-exporting-tweaks)
    - [Features](#features-2)
  - [Restore Tweaks](#restore-tweaks)
    - [Enable Updates](#enable-updates)
    - [Enable Defender](#enable-defender)
    - [Enable Services](#enable-services)
    - [Install Microsoft Store](#install-microsoft-store)
    - [Revert Registry Tweaks](#revert-registry-tweaks)
  - [Ultimate Cleanup](#ultimate-cleanup)
    - [Features](#features-3)
  - [Activate Windows](#activate-windows)
  - [Install Other Scripts](#install-other-scripts)

## Registry Tweaks

<img width="582" height="519" alt="{6B267B8F-C411-46F3-9433-F6715A1B969C}" src="https://github.com/user-attachments/assets/2e4ea222-65ba-48c5-b89f-993ed51dbfe5" />




- Apply the registry tweaks to automate most windows quality of life and performance settings
- A registry file will be created on the desktop containing all the registry keys including a comment describing the function of each

- Use the Change Mode button to either remove tweaks from the total list of tweaks ran OR select a few tweaks to run 

**[Registry Tweaks List](registrytweaks.md)**
## Group Policy Tweaks
### Disable Updates
- This tweak will disable automatic windows updates and the related services
### Disable Windows Defender
- CAUTION: Disabling Windows Defender could leave you vulnerable to malicious attacks! 
- This tweak will disable windows defender and all related services
### Disable Windows Telemetry
- This tweak will disable telemetry with group policy however, this only applies to server and ltsc builds
- **Note:** other telemetry services and settings are disabled as well
## Remove Scheduled Tasks
- This tweak will remove all scheduled tasks except for SvcRestart and CtfMonitor to avoid issues

## Disable Services
- This tweak will disable some unwanted services
#### Services Disabled
- All Bluetooth Services
- Fax
- Printer Services
- Shared PC
- Remote Registry
- Phone 
- Defrag 
- Delivery Optimization 
- Radio Management 
- Windows Insider
- Tablet Input
- diagsvc
- DPS
- WdiServiceHost
- WdiSystemHost
- AssignedAccessManagerSvc
- MapsBroker
- lfsvc
- Netlogon
- WpcMonSvc
- SCardSvr
- ScDeviceEnum
- SCPolicySvc
- WbioSrvc
- WalletService

## Debloat

<img width="414" height="307" alt="{4B76C016-6329-4B16-9DCA-0779757ED34D}" src="https://github.com/user-attachments/assets/4c4227e2-6578-46c9-acb5-fa8d1a1764f2" />

<img width="414" height="307" alt="{E1589997-2182-4402-AD8F-79B31FF187D9}" src="https://github.com/user-attachments/assets/84255752-1c06-4c83-8aea-b79fbc65b08c" />

<img width="414" height="307" alt="{56231C9E-633D-4519-8DAF-7037EED2FFC4}" src="https://github.com/user-attachments/assets/d6fd5195-5264-40da-89a5-c4d5d9698bcf" />

<img width="414" height="307" alt="{D7D552DA-FA5E-4FC8-B3A8-68CF607F4A72}" src="https://github.com/user-attachments/assets/e6ac4726-381f-48ff-ae95-5ded0189b291" />


<img width="414" height="307" alt="{B0D5413E-FFC4-4B79-AAD1-68D7031ADA09}" src="https://github.com/user-attachments/assets/bd398a2d-b619-4e2e-a966-01735c4ab569" />






- This tweak will allow you to debloat all windows appx packages and other preinstalled apps
### Debloat Presets
- **Debloat All** 
- **Keep Store Xbox Edge** 
- **Keep Store Xbox**
- **Keep Edge**
- **Keep Store**

### Features
- Removes all bloat appx packages, Edge, Teams and OneDrive, Remote Desktop, Health Update tools, Quick Assist, Hello Face, and Steps Recorder
     - **Note:** All debloat presets will clean the start menu pinned icons

### Custom Debloat
- Choose specfic Appx Packages including locked packages 
  - **Note:** locked packages are locked for a reason be careful when removing these
- Select Additional Options
     - Edge
     - Health Update Tools
     - Teams and OneDrive
     - Remote Desktop Connection
     - Hello Face, Quick Assist, Steps Recorder
     - Clean Start Menu Icons
 
### Remove Optional Features
- Uninstall windows capabilities, optional features, and windows packages.

### zUninstaller
- Remove installed apps with additional brute force cleaning of leftovers.
    - The script will search for leftover files and folders after the uninstaller for the app has been ran, since the script could potentially find items that arent related to the app a popup will appear with the found         items allowing for manual selection.
    - If a item can not be removed with brute force methods and script will run upon the next reboot to remove the file
 
## Optional Tweaks

<img width="589" height="444" alt="{CA823F8D-7283-4868-AAF3-D3A3F3EBBA55}" src="https://github.com/user-attachments/assets/b3b2c54e-12f1-4ef6-83ab-6334fabd6615" />






### General
- **Black Theme** - apply a black color to the taskbar and startmenu
     - Classic theme will apply a old windows insider theme to enable a retro effect on some windows
- **Remove Open File Security Warning** - When disabling smart screen windows will default to the old file security warning when opening files from another pc
- **Remove Speech Recognition App** - removes the files associated with this app
- **Enable HAGS** - enable Hardware Accelerated GPU Scheduling, this setting is set to disabled by registry tweaks (recommended)
- **Transparent Taskbar** - makes the taskbar clear with TaskbarX

- **Remove Mouse and Sound Schemes** - set the pointer and sound schemes to "None", removes blue loading wheel next to pointer
- **Security Updates Only** - defers feature updates for 365 days and optional updates for 30 days [MAX]
- **Remove Quick Access From File Explorer** - remove the quick access icon from file explorer
 - **Block Razer and ASUS Donwload Servers** - this tweak adds all razer and ASUS servers to the hosts file to prevent the download of their bloat software
   - **Note:** the hosts file is located `[C:\Windows\System32\drivers\etc\hosts]`
- **Remove Network Icon From File Explorer** - remove the network icon from file explorer (bottom left)
 - **Apply PBO Curve on Startup** - this tweak will prompt you to enter your pbo curve oc and will apply this when your pc starts up using PBO Tuner
 - **Do Not Include Drivers in Windows Update** - prevent drivers from being downloaded when checking for updates
 - **Enable Windows 11 Sounds** - replace windows 10 default sounds with windows 11 sounds, a backup folder of the windows 10 sounds will be placed on your desktop 
   - **Note:** Sounds Folder `[C:\Windows\Media]`
- **Remove Recycle Bin Name** - remove the "Recycle Bin" text from under the icon on the desktop
- **Security Updates Only** - this will defer cumulative feature updates via group policy so that you only get security updates 
- **Pause Updates for 1 Year** - this will pause updates for a year as a good alternative to disabling updates completely 
- **Prevent OS Upgrade** - this will prevent windows update from updating to Windows 11 from Windows 10 or updating a version such as 23h2 -> 24h2
- **Disable PowerShell Logging** - by default everything put in the powershell terminal is saved in a file in your appdata directory, this will disable that "feature"
- **Enable No GUI Boot** - this will enable no gui boot in msconfig thus disabling the boot logo, spinning logo, and boot messages
- **Disable Windows Platform Binary Table** - this is useful for oem prebuilts or laptops where the manufacture has apps that run on startup and install themselves, disabling WPBT prevents this bloat from installing/running
- **Disable Game Bar Popup** - when uninstalling xbox apps if you plug in a xbox controller an annoying popup will occur, this tweak will disable that [Credit: @AveYo]
- **Enable Fast Shutdown and Restart** - this will decrease the delay before sevices and apps are killed to shutdown or restart as well as auto ending open foreground apps without asking
- **Remove Backup App** - this will disable the backup app that is bundled in the CBS package however you will not be able to use a microsoft account to sign into apps such as xbox
- **Hide User Tile In Start Menu** - this will hide the user icon in the bottom left of the start menu
- **User More Accurate Time Server** - this will set the w32tm service to use https://www.pool.ntp.org/ as its time server instead of the default one

### Ultimate Context Menu

#### Add to Menu
- **Additional Files to New Menu** - add the ability to create new Registry Files, Powershell Scripts, and Batch Files
- **Additional ps1 Options** - open powershell files with Powershell or Powershell ISE as Admin
- **Snipping Tool** - add a shortcut to open the snipping tool or instantly take a snip
- **Shutdown** - add shutdown button
- **Run as Admin for ps1,bat,vbs files** - ability to run listed scripts as admin
- **Powershell and CMD** - add open Powershell or CMD prompt
- **Kill not Responding Tasks** - add option to kill any not responding tasks
 - **Delete Permanently** - skip the recycle bin and delete file (only works on some files)
 - **Take Ownership** - allow full access to any folder or file that has locked permissions

 #### Remove from Menu
 - **Add to Favorites** - remove add to favorites option for files and folders
 - **Customize this Folder** - remove customize this folder option when right clicking in some folders
 - **Give Access to** - remove give access option from files and folders
 - **Open in Terminal** - removes windows 11 option when right clicking the desktop
 - **Restore to Previous Versions** - remove this option when right clicking some files
 - **Print** - remove the print option when right clicking some files
 - **Send to** - remove the send to option for files and folders
 - **Share** - remove the share option when right clicking some files
 - **Personalize** - remove the personalize option when right clicking the desktop
 - **Display** - remove the display option when right clicking the desktop

 

 ## Import and Remove Power Plans

 <img width="552" height="407" alt="{C47C20BE-F31F-4D8D-8966-B46980B0BA6B}" src="https://github.com/user-attachments/assets/95233c00-5efb-4a9b-bbca-f49550efa188" />


<img width="552" height="407" alt="{57E45D56-8025-4E6D-ABD0-05293850B913}" src="https://github.com/user-attachments/assets/e4e57ffa-b9ab-4831-a405-da0de78c6828" />


 ### Import Plan
  - Custom power plan for removing power saving features and core parking
  ### Remove Plans
  - A list of current power plans will allow you to remove any and prevent windows from switching back to balanced/other recommended plans
  
  ### Enable Hidden Plans
  - there are 3 hidden power plans in windows `Ultimate Performance`
  `Max Performance Overlay` and `High Performance Overlay` 
  - this tweak will allow you to enable any of these to try out

  ### USB Power Tweaks
  - this section will display the USB hubs and devices connected
  - Choose any or all devices to disable power saving

  ## Windows 11 Tweaks
 
<img width="402" height="317" alt="{7C5C31D0-67B6-4C5E-974F-8E92DAEAA77E}" src="https://github.com/user-attachments/assets/393e02c1-9920-4f99-b15f-a7ddc40c09b3" />

<img width="402" height="317" alt="{7BCEFFCF-19B3-4B61-ACD0-AA1C68153EB9}" src="https://github.com/user-attachments/assets/3b052d7e-71ec-44e6-86b1-00c18d9788bf" />

<img width="402" height="317" alt="{B015E844-CBB8-4300-B969-9F0174915998}" src="https://github.com/user-attachments/assets/7ef4dc2f-876a-4f71-ac95-6e0481715439" />


  ### Patch Explorer
  - **Remove Rounded Edges** - remove rounded edges using [toggle-rounded-corners](https://github.com/oberrich/win11-toggle-rounded-corners) and run at startup
  - **Enable Windows 10 Taskbar and Startmenu** - run ExplorerPatcher and automatically apply settings for windows 10 taskbar and startmenu
  - **Enable Windows 10 File Explorer** - this will use some registry hacks to enable the old Windows 10 File Explorer ribbon when combined with the Enable Windows 10 Icons the full Win10 File Explorer can be restored without having a third party app
  - **Remove Recommended Section** - this tweak will remove the recommended section from the startmenu by making windows think you are in an education enviroment
  - **Replace Startmenu and Search with OpenShell** - this tweak will disable windows search and indexing to replace it with OpenShell and import a custom config for a minimal black startmenu, any current pinned shortcuts will be moved to the OpenShell pinned directory

  ### Windows 10 Restore Tweaks
- **Restore Windows 10 Recycle Bin Icon** - this tweak will replace the windows 11 recycle bin icon with the old windows 10 icon

- **Restore Windows 10 Snipping Tool** - remove uwp snipping tool (screen sktech) and enable windows 10 snipping tool

- **Restore Windows 10 Notepad** - this will enable the legacy windows 10 notepad with the optional feature and automatically set it to be used by default

- **Restore Windows 10 Task Manager** - this will create a fake taskmgr.exe that runs task manager with the -d command thus disabling the new ui, NOTE this tweak works best with UAC disabled due to the fake wrapper needing to be ran as admin

- **Restore Windows 10 Icons** - this tweak will replace all the windows 11 icons in file explorer with windows 10, this tweak works best with the windows 10 file explorer making it look exactly like windows 10 without using a third party app

  ### Misc Tweaks
  - **Set all Services to Manual** - this tweak works well on windows 11 to clean up some unnecessary services
     - **Services Skipped:**
          - AudioEndpointBuilder
          - Audiosrv
          - EventLog
          - SysMain
          - Themes
          - WSearch
          - NVDisplay.ContainerLocalSystem
          - WlanSvc
- **Show all Taskbar Tray Icons** - windows 11 makes it diffcult to show all taskbar tray icons with this tweak all current apps will be shown and and new apps will be enabled upon restarting after installing the app
     - **Note:** this tweak uses a scheduled task to update the registry key responsible for showing the app in the taskbar


- **Disable Bell Icon on Taskbar** - hide the notification bell icon on the taskbar
     - **Note:** this will break the calendar flyout when clicking the date and time

- **Dark Winver** - this will replace winver.exe with a dark themed version view them here -> [Dark Winver](https://github.com/zoicware/WinverDark)

- **Enable  Edit Quick Setting Tiles** - starting in 24h2 for some reason microsoft disabled editing the quick setting tiles in the volume/network flyout, this tweak will enable the simplfy quick setting tiles setting removing all the useless tiles

- **Remove System Labels From Start Menu Apps** - this tweak will remove the small "System" lables from some apps in the start menu

## Install Network Driver

- The script will check for internet connection 
     - If there is then the script will search google for your network adapter's driver
     - If no internet then the script will use local drivers : 
          - Realtek Lan
          - Intel Lan
          - Killer Lan
          - Intel Wifi
- After installing the driver a popup will ask if you want to enable QoS for upload, this tweak will enable some network settings to attempt to prioritize game network traffic along with some other networks tweaks to help with bufferbloat [Credit: @AveYo], NOTE: this can be reverted in "Revert Tweaks" if needed

## Install Nvidia Driver

<img width="349" height="294" alt="{DF5532D1-089B-4690-891A-78DFF81512EE}" src="https://github.com/user-attachments/assets/8bfd705a-74ac-472c-b96d-a4c03f8ebfc5" />


### Features
- the script will get the 4 latest Nvidia Drivers for the user to choose
- install older drivers by typing in the version number 
- **Strip Driver** - remove geforce experience and all other bloat leaving only the bare driver
- **Disable Telemetry** - this tweak runs automatically deleting a dll file preventing telemetry to Nvidias Server
     - **Note:** Only applies to Strip Driver setting as this file will break geforce experience
- **Disable HDCP** - disable High-bandwidth Digital Content Protection applies automatically 


<img width="350" alt="image" src="https://github.com/user-attachments/assets/2a192877-122a-4fec-be83-c65ea6e03ab8">

<img width="350" alt="image" src="https://github.com/user-attachments/assets/139f87f3-382d-45a9-9540-59f5d0d5a3d7">

#### Post Install Tweaks
- Import Optimized Nvidia Control Panel Settings
- Enable Legacy Sharpen to use sharpen without gpu scaling enabled
- Enable MSI Mode, this tweak also applies when running registry tweaks
- Disable GPU Idle States only recomended for users that know they need this tweak
- Apply Digital Vibrance - a slider will allow you to setup digital vibrance on all your monitors, this tweak will apply once restarting
- Disable Monitor Speakers

## Install Packages
 - This will download the latest DirectX and C++ packages from their source
     - Included Packages
          - DirectX
          - All Visual C++ Redistributables and Runtimes
          - Net 3.5 from the bootable media used to install windows
- After they are finished Ngen.exe and DISM are ran to cleanup outdated assemblies
## Importing and Exporting Tweaks

<img width="365" height="205" alt="{C24651C6-F4FB-4921-A7F9-598E39D8A0EF}" src="https://github.com/user-attachments/assets/c34d7eb6-cf3b-410d-a649-9d073afef286" />

<img width="289" height="407" alt="{0EE377D2-F202-4FE5-AA26-89A21F9D0895}" src="https://github.com/user-attachments/assets/5e977d0d-960f-4964-9cdd-be04967508ef" />


- Upon launching the script for the first time a file ZCONFIG.cfg will be created in `[C:\Users\Username\]`

### Features
- Build Custom Config with Selected Tweaks
- All tweaks will be updated in the config upon selecting 
- Export the config for automated use
- Import configs and run tweaks automatically with no prompts
## Restore Tweaks

<img width="496" height="204" alt="{FC59C98B-4849-4066-87F1-AE409422BEC0}" src="https://github.com/user-attachments/assets/7726cd81-7cfc-4d18-ab04-ce3693170a27" />


### Enable Updates
- reverts disable updates tweak and enables all registry keys / services
### Enable Defender
- enables all disabled registry keys and services
### Enable Services
- enables services disabled by the disable services tweak
### Install Microsoft Store
- installs the windows 10 store for windows 11 use `wsreset -i`
### Revert Registry Tweaks
- this will revert most registry tweaks   
  **Note:** not all registry tweaks can be reverted/should be 
## Ultimate Cleanup
- cleans temp files and event logs

<img width="387" height="309" alt="{9C293C86-4968-4FA2-9B03-4E02564B29AC}" src="https://github.com/user-attachments/assets/fedbb99b-5985-4797-9fd7-f927ce891384" />



### Features
- clear all event viewer logs
- force deletes files in both temp directories
- clear all windows logs in places that disk cleanup misses
- clear nvidia driver shader cache
- remove the windows.old folder sometimes taking up quite a bit of storage
- remove old duplicate drivers
- runs windows disk cleanup util on all drives
     - **Items Cleaned**
          - Active Setup Temp Folders
          - Thumbnail Cache
          - Delivery Optimization Files
          - D3D Shader Cache
          - Downloaded Program Files
          - Internet Cache Files
          - Setup Log Files
          - Temporary Files
          - Windows Error Reporting Files
          - Offline Pages Files
          - Recycle Bin
          - Temporary Setup Files
          - Update Cleanup
          - Upgrade Discarded Files
          - Windows Defender
          - Windows ESD installation files
          - Windows Reset Log Files
          - Windows Upgrade Log Files
          - Previous Installations
          - Old ChkDsk Files
          - Feedback Hub Archive log files
          - Diagnostic Data Viewer database files
          - Device Driver Packages
## Activate Windows
- activates windows 10 and 11 with a generic pro key and public kms server for 180 days
- **Note:** recomend using [Massgravel](https://github.com/massgravel/Microsoft-Activation-Scripts) for permanent activation


## Install Other Scripts

<img width="252" height="294" alt="{BB7BC9F2-B230-4BBE-B4F6-F141E5C09F46}" src="https://github.com/user-attachments/assets/18757af6-1c7e-4078-a62d-cdd8ca20288a" />


- Create a desktop shortcut to some of my other useful scripts for windows tweaking and management 
  
- This shortcut will run the code directly from the github so it will always be up to date

- **NOTE: If you do not disable uac you will need to run the shortcuts as admin**
