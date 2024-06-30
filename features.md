# All zoicware features
## Registry Tweaks
- Apply the registry tweaks to automate most windows quality of life and performance settings
- A registry file will be created on the desktop containing all the registry keys including a comment describing the function of each

[Registry Tweaks Listed](registrytweaks.md)
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

## Debloat

<img width="380" alt="image" src="https://github.com/zoicware/ZOICWARE/assets/118035521/f8f626c5-a16d-480d-8364-fa2447399272">

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
<img width="250" alt="image" src="https://github.com/zoicware/ZOICWARE/assets/118035521/5ccbda0e-0793-45b1-b41c-4819a3d59b16">

<img width="250" alt="image" src="https://github.com/zoicware/ZOICWARE/assets/118035521/8461f5a7-f565-45a8-ba79-bbe1713c694a">

<img width="250" alt="image" src="https://github.com/zoicware/ZOICWARE/assets/118035521/90973fd8-6ca3-4263-b9fe-63490edeb096">


### General
- **Black Theme** - apply a black color to the taskbar and startmenu
     - Classic theme will apply a old windows insider theme to enable a retro effect on some windows
- **Remove Open File Security Warning** - When disabling smart screen windows will default to the old file security warning when opening files from another pc
- **Remove Speech Recognition App** - removes the files associated with this app
- **Enable HAGS** - enable Hardware Accelerated GPU Scheduling, this setting is set to disabled by registry tweaks (recommended)
- **Transparent Taskbar** - makes the taskbar clear with TaskbarX
- **Add Double Click to Powershell Files** - enable the ability to double click to run powershell scripts (only works windows 10)
- **Remove Mouse and Sound Schemes** - set the pointer and sound schemes to "None", removes blue loading wheel next to pointer
- **Security Updates Only** - defers feature updates for 365 days and optional updates for 30 days [MAX]
- **Remove Quick Access From File Explorer** - remove the quick access icon from file explorer
 - **Block Razer and ASUS Donwload Servers** - this tweak adds all razer and ASUS servers to the hosts file to prevent the download of their bloat software
   - **Note:** the hosts file is located [C:\Windows\System32\drivers\etc\hosts]
- **Remove Network Icon From File Explorer** - remove the network icon from file explorer (bottom left)
 - **Apply PBO Curve on Startup** - this tweak will prompt you to enter your pbo curve oc and will apply this when your pc starts up using PBO Tuner
 - **Do Not Include Drivers in Windows Update** - prevent drivers from being downloaded when checking for updates
 - **Enable Windows 11 Sounds** - replace windows 10 default sounds with windows 11 sounds, a backup folder of the windows 10 sounds will be placed on your desktop 
   - **Note:** Sounds Folder [C:\Windows\Media]
- **Remove Recycle Bin Name** - remove the "Recycle Bin" text from under the icon on the desktop

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

 #### Legacy Windows Store
 - **Classic Photo Viewer** - enable the option to view photos when the old photo viewer
 - **Windows 7 Calculator** - enable the windows 7 calculator and remove the uwp one
 - **Windows 7 Task Manager** - enable the windows 7 task manager
 - **Classic Volume Flyout** - enable the old volume controls for Windows 10
 - **Classic Alt Tab** - enable the old Alt tab menu on Windows 10

 ## Import and Remove Power Plans

 ### Import Plan
  - Custom power plan for removing power saving features and core parking
  ### Remove Plans
  - Remove any default windows plans to prevent windows from automatically switching back to balanced

  ## Windows 11 Tweaks

<img width="300" alt="image" src="https://github.com/zoicware/ZOICWARE/assets/118035521/cb3213af-0677-43fd-9c26-9c05f5f5d67f">


  ### Patch Explorer
  - **Remove Rounded Edges** - remove rounded edges using [toggle-rounded-corners](https://github.com/oberrich/win11-toggle-rounded-corners) and run at startup
  - **Enable Windows 10 Taskbar and Startmenu** - run ExplorerPatcher and automatically apply settings for windows 10 taskbar and startmenu
  - **Enable Windows 10 File Explorer** - create windows 10 file explorer config on desktop and open explorer patcher menu to import config

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
- **Replace Startmenu and Search with OpenShell** - this tweak will disable windows search and indexing to replace it with OpenShell and import a custom config for a minimal black startmenu, any current pinned shortcuts will be moved to the OpenShell pinned directory
- **Restore Windows 10 Recycle Bin Icon** - this tweak will replace the windows 11 recycle bin icon with the old windows 10 icon
- **Disable Bell Icon on Taskbar** - hide the notification bell icon on the taskbar
     - **Note:** this will break the calendar flyout when clicking the date and time
- **Restore Windows 10 Snipping Tool** - remove uwp snipping tool (screen sktech) and enable windows 10 snipping tool

## Install Network Driver

- The script will check for internet connection 
     - If there is then the script will search google for your network adapter's driver
     - If no internet then the script will use local drivers : 
          - Realtek Lan
          - Intel Lan
          - Killer Lan
          - Intel Wifi

## Install Nvidia Driver
- This will use [Nvidia Auto Install](https://github.com/zoicware/NvidiaAutoinstall) 
### Features
- the script will get the 4 latest Nvidia Drivers for the user to choose
- install older drivers by typing in the version number 
- **Strip Driver** - remove geforce experience and all other bloat leaving only the bare driver
- **Disable Telemetry** - this tweak runs automatically deleting a dll file preventing telemetry to Nvidias Server
     - **Note:** Only applies to Strip Driver setting as this file will break geforce experience
- **Disable HDCP** - disable High-bandwidth Digital Content Protection applies automatically 

#### Post Install Tweaks
- Import Optimized Nvidia Control Panel Settings
- Enable Legacy Sharpen to use sharpen without gpu scaling enabled
- Enable MSI Mode, this tweak also applies when running registry tweaks
- Disable GPU Idle States only recomended for users that know they need this tweak
- Apply Digital Vibrance - a slider will allow you to setup digital vibrance on all your monitors, this tweak will apply once restarting

## Install Packages
 - When installing zoicware if you choose to install packages using the [Download Zoicware Script](https://github.com/zoicware/ZOICWARE/blob/main/Download%20Zoicware.ps1) the script will use the local files 
 - If the script can not find the packages it will attempt to install them from the internet
     - Included Packages
          - DirectX
          - All Visual C++ Redistributables and Runtimes
          - Net 3.5 from the bootable media used to install windows
- After they are finished Ngen.exe and DISM are ran to cleanup **Note:** this may take some time be patient
## Importing and Exporting Tweaks
- Upon launching the script for the first time a file ZCONFIG.cfg will be created in [C:\Users\Username\]

### Features
- All tweaks will be updated in the config upon selecting 
- Export the config for automated use
- Import configs and run tweaks automatically with no prompts
## Restore Tweaks
### Enable Updates
- reverts disable updates tweak and enables all registry keys / services
### Enable Defender
- enables all disabled registry keys and services
### Enable Services
- enables services disabled by the disable services tweak
### Install Microsoft Store
- installs the windows 10 store for windows 11 use `wsreset -i`
### Revert Registry Tweaks
- this will revert most registry tweaks **Note:** not all registry tweaks can be reverted/should be 
## Ultimate Cleanup
- cleans temp files and event logs

### Features
- prompt user to clear event viewer logs (yes/no)
- force deletes files in both temp directories
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
