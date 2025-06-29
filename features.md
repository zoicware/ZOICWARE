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

<img width="600" alt="image" src=https://github.com/user-attachments/assets/8fe2786c-b09c-4b51-b513-dda29a3a55b2> 


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

<img width="580" alt="image" src="https://github.com/user-attachments/assets/cc0eafa0-e5ab-4ea8-96b5-a99df57bbc7a">

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
 
## Optional Tweaks


<img width="500" alt="image" src="https://github.com/user-attachments/assets/bbf52610-7e97-47b6-aaf2-eca8f10fc9cc">



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

<img width="500" alt="image" src="https://github.com/user-attachments/assets/9aff0be3-62c9-4e04-8dda-c7c26cd256ac">

<img width="500" alt="image" src="https://github.com/user-attachments/assets/a50a358b-9ebc-4a74-939c-1224f38997ca">

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
  ![{9D9E947F-7893-4161-9E47-5439D18C0AA2}](https://github.com/user-attachments/assets/e530d31b-ffae-4bca-aa26-6cb1275374f6)


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

<img width="400" alt="image" src="https://github.com/user-attachments/assets/b8e7c6bb-b3dd-49a1-b861-e776347d1968">

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
<img width="330" alt="image" src="https://github.com/zoicware/ZOICWARE/assets/118035521/1979c64e-c67a-47a5-823d-2446eb9ba006">
<img width="250" alt="image" src="https://github.com/zoicware/ZOICWARE/assets/118035521/a7f90f3b-e0b1-4dbc-9ab9-35c6fbf279bf">

- Upon launching the script for the first time a file ZCONFIG.cfg will be created in `[C:\Users\Username\]`

### Features
- Build Custom Config with Selected Tweaks
- All tweaks will be updated in the config upon selecting 
- Export the config for automated use
- Import configs and run tweaks automatically with no prompts
## Restore Tweaks

![{A4B9511E-A337-41A2-BE46-7699A1DE773A}](https://github.com/user-attachments/assets/01100bfc-3af6-447f-a74c-15d7d903dd62)

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

![{A9CC91FB-ADEC-48B0-A17A-BBD0EB67CB22}](https://github.com/user-attachments/assets/b13643f9-017d-456e-81c1-10bdf8d413bb)


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

- Create a desktop shortcut to some of my other useful scripts for windows tweaking and management 
  
- This shortcut will run the code directly from the github so it will always be up to date

- **NOTE: If you do not disable uac you will need to run the shortcuts as admin**
