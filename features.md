# All zoicware features
### Table of Contents
  - [Registry Tweaks](#registry-tweaks)
  - [Group Policy Tweaks](#group-policy-tweaks)
    - [Disable Updates](#disable-updates)
    - [Disable Defender](#disable-defender)
    - [Disable Telemetry](#disable-telemetry)
  - [Disable Services](#disable-services)
      - [Services Disabled](#services-disabled)
  - [Remove Scheduled Tasks](#remove-scheduled-tasks)
  - [Debloat](#debloat)
    - [Debloat Presets](#debloat-presets)
    - [Features](#features)
    - [Custom Debloat](#custom-debloat)
  - [Power Tweaks](#power-tweaks)
    - [Import Plan](#import-plan)
    - [Remove Plans](#remove-plans)
    - [Enable Hidden Plans](#enable-hidden-plans)
  - [Optional Tweaks](#optional-tweaks)
    - [General](#general)
    - [Ultimate Context Menu](#ultimate-context-menu)
      - [Add to Menu](#add-to-menu)
      - [Remove from Menu](#remove-from-menu)
  - [Windows 11 Tweaks](#windows-11-tweaks)
    - [Patch Explorer](#patch-explorer)
    - [Windows 10 Restore Tweaks](#windows-10-restore-tweaks)
    - [Misc Tweaks](#misc-tweaks)
  - [Install Packages](#install-packages)
  - [Install Browsers](#install-browsers)
  - [Install Nvidia Driver](#install-nvidia-driver)
    - [Features](#features-1)
      - [Post Install Tweaks](#post-install-tweaks)
  - [Install Network Driver](#install-network-driver)
  - [Ultimate Cleanup](#ultimate-cleanup)
    - [Features](#features-3)
  - [Activate Windows](#activate-windows)
  - [Import and Export Config](#import-and-export-config)
    - [Features](#features-2)
  - [Restore Tweaks](#restore-tweaks)
    - [Enable Updates](#enable-updates)
    - [Enable Defender](#enable-defender)
    - [Enable Services](#enable-services)
    - [Install Microsoft Store](#install-microsoft-store)
    - [Revert Registry Tweaks](#revert-registry-tweaks)
    - [Unpause Updates](#unpause-updates)
  - [Install Other Scripts](#install-other-scripts)

## Registry Tweaks

<img width="772" height="690" alt="Screenshot 2026-07-11 172949" src="https://github.com/user-attachments/assets/f94587e1-c96b-4724-a403-c8e71ea9a105" />




- Apply the registry tweaks to automate most Windows quality of life and performance settings
- A registry file will be created on the desktop containing all the registry keys including a comment describing the function of each

- Use the `Change Mode` button to either remove tweaks from the total list of tweaks ran OR select only specific tweaks to be applied

**[Registry Tweaks List](registrytweaks.md)**
## Group Policy Tweaks
### Disable Updates
- This tweak will disable automatic Windows updates and the related services
### Disable Defender
- CAUTION: Disabling Windows defender could leave you vulnerable to malicious attacks!
- This tweak will disable Windows defender and all related services
### Disable Telemetry
- This tweak will disable telemetry with group policy however, this only applies to server and enterprise builds
- Adds telemetry domains to be blocked via hosts file gathered from official microsoft sources
> [!NOTE]
> other telemetry services and settings are disabled as well

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
- Windows Health and Optimized Experiences (whesvc)
- WSAIFabricSvc
- Microsoft Usage and Quality Insights (wuqisvc)

## Remove Scheduled Tasks
- This tweak will remove all scheduled tasks except for SvcRestart and CtfMonitor to avoid issues

## Debloat

<img width="414" height="307" alt="Screenshot 2026-07-11 174153" src="https://github.com/user-attachments/assets/dd7b61ae-93d2-48e6-9d5c-9d1b32821e70" />

<img width="414" height="307" alt="{E1589997-2182-4402-AD8F-79B31FF187D9}" src="https://github.com/user-attachments/assets/84255752-1c06-4c83-8aea-b79fbc65b08c" />

<img width="414" height="307" alt="{56231C9E-633D-4519-8DAF-7037EED2FFC4}" src="https://github.com/user-attachments/assets/d6fd5195-5264-40da-89a5-c4d5d9698bcf" />

<img width="414" height="307" alt="Screenshot 2026-07-11 174239" src="https://github.com/user-attachments/assets/200c0c46-c5cc-4c7e-824d-d6f13344606f" />


<img width="414" height="307" alt="{B0D5413E-FFC4-4B79-AAD1-68D7031ADA09}" src="https://github.com/user-attachments/assets/bd398a2d-b619-4e2e-a966-01735c4ab569" />






- This tweak will allow you to debloat all Windows appx packages and other preinstalled apps
### Debloat Presets
- **Debloat All**
- **Keep Store, XBOX and Edge**
- **Keep Store and XBOX**
- **Keep Edge**
- **Keep Store**

### Features
- Removes all bloat appx packages, Edge, Teams, OneDrive, Remote Desktop, Health Update Tools, etc
> [!NOTE]
> All debloat presets will clean the start menu pinned icons and outdated versions of newer installed packages

### Custom Debloat
- Choose specific appx packages including locked packages
> [!NOTE]
> locked packages are locked for a reason be careful when removing these

### Remove Extras
- Microsoft Edge
- Edge WebView
- Teams and OneDrive
- Windows Update Tools
- Remote Desktop Connection
- Clean Start Menu Icons
- Clean Outdated Store Apps
- Remove Backup App and Get Started

### Remove Win 32 Apps
- Speech App
- Live Captions
- Magnifier
- Narrator
- On-Screen Keyboard
- Voice Access
- Steps Recorder
- Quick Assist
- Math Input Panel
 
### Remove Optional Features
- Uninstall windows capabilities, optional features and windows packages.

### zUninstaller
- Remove installed apps with additional brute force cleaning of leftovers.
    - The script will search for leftover files and folders after the uninstaller for the app has been ran, since the script could potentially find items that arent related to the app a popup will appear with the found         items allowing for manual selection.
    - If an item can not be removed with brute force methods a script will run upon the next reboot to remove the file



 ## Power Tweaks

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



## Optional Tweaks

<img width="784" height="590" alt="Screenshot 2026-07-11 181630" src="https://github.com/user-attachments/assets/5ae93627-e405-4e09-8888-99a1c4e1ae88" />






### General
- **Black Theme** - applies a black color to the taskbar and start menu as well as dark user picture and black themed cursors
- **Transparent Taskbar** - makes the taskbar clear with TranslucentTB
- **Remove Network Icon From File Explorer** - remove the network icon from file explorer (bottom left)
- **Remove Recycle Bin Name** - remove the "Recycle Bin" text from under the icon on the desktop
- **Remove Mouse and Sound Schemes** - set the pointer and sound schemes to "None", this will disable all Windows sound effects and use the original Windows XP cursor scheme
- **Hide User Tile In Start Menu** - this will hide the user icon in the bottom left of the start menu
- **Modern Cursor Scheme** - this will add the fluent cursor design from Rectify11
- **Enable Dark Accents** - this will fix the default blue accents in win32 app controls to match your theme color
- **Enable Classic Accents** - applies the Windows XP/2000 classic navy blue to win32 app controls like menus, highlights and hover states
- **Do Not Include Drivers in Windows Update** - prevent drivers from being downloaded when checking for updates
- **Security Updates Only** - defers feature updates for 365 days and optional updates for 30 days [MAX]
- **Pause Updates for 1 Year** - this will pause updates for a year as a good alternative to disabling updates completely
- **Prevent OS Upgrade** - this will prevent Windows update from updating Windows 10 -> Windows 11 or updating a version such as 24h2 -> 25h2
- **Remove Open File Security Warning** - When disabling smart screen windows will default to the old file security warning when opening files from another pc
- **Block Razer and ASUS Download Servers** - this tweak adds all razer and ASUS servers to the hosts file to prevent the download of their bloat software
> [!NOTE]
> the hosts file is located `[C:\Windows\System32\drivers\etc\hosts]`
- **Apply PBO Curve on Startup** - this tweak will prompt you to enter your pbo curve oc and will apply this when your pc starts up using PBO Tuner
- **Disable PowerShell Logging** - by default everything put in the powershell terminal is saved in a file in your appdata directory, this will disable that "feature"
- **Enable No GUI Boot** - this will enable no gui boot in msconfig thus disabling the boot logo, spinning logo and boot messages
- **Create Shortcut to Start Menu Locations** - creates a shortcut in the start menu that lets you access both start menu shortcut folders directly to customize the listed apps shown in the start menu
- **Disable Game Bar Popup** - when uninstalling xbox apps if you plug in a xbox controller an annoying popup will occur, this tweak will disable that [Credit: @AveYo]
- **Enable Fast Shutdown/Restart** - this will decrease the delay before services and apps are killed to shutdown or restart as well as auto ending open foreground apps without asking
- **Use More Accurate Time Server for System Clock** - this will set the w32tm service to use https://www.pool.ntp.org/ as its time server instead of the default one
- **No Mouse Accel on Desktop** - removes mouse acceleration on the desktop when using scaling above 100% [Credit: @MarkC]
- **Disable Device Encryption** - this will disable BitLocker and prevent device encryption from being re-enabled
- **Cleanup 3rd Party App Start Menu Shortcuts** - takes the added 3rd party app shortcuts in the start menu out of their folders and leaves only the shortcut directly

### Ultimate Context Menu

#### Add to Menu
- **Additional Files to New Menu** - add the ability to create new registry files, PowerShell scripts and batch files
- **Additional ps1 Options** - open PowerShell files with PowerShell or PowerShell ISE as admin
- **Snipping Tool** - add a shortcut to open the snipping tool or instantly take a snip
- **Shutdown** - add a `Shutdown` button
- **Run as Admin for ps1,bat,vbs files** - add the ability to run listed scripts as admin
- **Powershell and CMD** - add open PowerShell or CMD prompt
- **Kill not Responding Tasks** - add option to kill any not responding tasks
- **Delete Permanently** - skip the recycle bin and delete files directly (only works on some files)
- **Take Ownership** - allow full access to any folder or file that has locked permissions
- **Legacy Control Panel Settings** - add a `Legacy settings` flyout to the desktop context menu with quick access to classic Control Panel applets [Credit: @iFryno]

#### Remove from Menu
- **Add to Favorites** - remove the `Add to Favorites` option for files and folders
- **Customize this Folder** - remove the `Customize this Folder` option when right clicking in some folders
- **Give Access to** - remove the `Give access to` option from files and folders
- **Open in Terminal** - remove the `Open in Terminal` option when right clicking the desktop
- **Restore to Previous Versions** - remove the `Restore Previous Versions` option after editing a file
- **Print** - remove the `Print` option when right clicking some files
- **Send to** - remove the `Send to` option for files and folders
- **Share** - remove the `Share` option when right clicking some files
- **Personalize** - remove the `Personalize` option when right clicking the desktop
- **Display** - remove the `Display settings` option when right clicking the desktop
- **Extract All for Archive Files** - remove the `Extract all` option when right clicking archive files such as .zip
- **Troubleshoot Compatibility** - remove the `Troubleshoot compatibility` option when right clicking executable files
- **Include in Library** - remove the `Include in Library` option when right clicking folders
- **Scan with Defender** - remove the `Scan with Microsoft Defender` option for downloaded files

 

  ## Windows 11 Tweaks
 
<img width="500" height="500" alt="Screenshot 2026-07-11 184643" src="https://github.com/user-attachments/assets/6a06ca9a-86fb-4be5-b0aa-5ba95a83067f" />

<img width="500" height="500" alt="Screenshot 2026-07-11 184656" src="https://github.com/user-attachments/assets/d0e91933-d65a-4421-87fd-1fdf4be592b6" />

<img width="500" height="500" alt="Screenshot 2026-07-11 184709" src="https://github.com/user-attachments/assets/a7b18565-c6ff-4194-828b-7db277e12349" />


  ### Patch Explorer
  - **Remove Rounded Edges** - remove rounded edges using [toggle-rounded-corners](https://github.com/oberrich/win11-toggle-rounded-corners) and run at startup
  - **Enable Windows 10 Taskbar and Start Menu** - run ExplorerPatcher and automatically apply settings for windows 10 taskbar and startmenu
  - **Enable Windows 10 File Explorer** - this will use some registry hacks to enable the old Windows 10 File Explorer ribbon when combined with the Enable Windows 10 Icons the full Win10 File Explorer can be restored without having a third party app
  - **Replace Startmenu and Search with OpenShell** - this tweak will disable windows search and indexing to replace it with OpenShell and import a custom config for a minimal black startmenu, any current pinned shortcuts will be moved to the OpenShell pinned directory

  ### Windows 10 Restore Tweaks
- **Restore Windows 10 Recycle Bin Icon** - this tweak will replace the windows 11 recycle bin icon with the old windows 10 icon
- **Restore Windows 10 Snipping Tool** - remove uwp snipping tool (screen sketch) and enable windows 10 snipping tool
- **Restore Windows 10 Task Manager** - this will create a fake taskmgr.exe that runs task manager with the -d command thus disabling the new ui
> [!NOTE]
> this tweak works best with UAC disabled due to the fake wrapper needing to be ran as admin
- **Restore Windows 10 Notepad** - this will enable the legacy windows 10 notepad with the optional feature and automatically set it to be used by default
- **Restore Windows 10 Icons** - this tweak will replace all the windows 11 icons in file explorer with windows 10, this tweak works best with the windows 10 file explorer making it look exactly like windows 10 without using a third party app
- **Restore Windows 10 Sounds** - replaces the windows 11 sound scheme with the old windows 10 sounds

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
- **Show all Taskbar Tray Icons** - windows 11 makes it difficult to show all taskbar tray icons with this tweak all current apps will be shown and new apps will be enabled upon restarting after installing the app
> [!NOTE]
> this tweak uses a scheduled task to update the registry key responsible for showing the app in the taskbar


- **Dark Winver** - this will replace winver.exe with a dark themed version view them here -> [Dark Winver](https://github.com/zoicware/WinverDark)

- **Remove Quick Settings Tiles** - this tweak removes the additional options in the quick settings menu on the taskbar and leaves just the volume slider

- **Disable Notepad Tabs and Rewrite** - this will disable the annoying `Continue previous session` and `Rewrite` features from the modern notepad making it feel more like the legacy one

- **Hide Ads in Settings** - this tweak removes the useless tiles in the settings app

- **Small Taskbar Icons** - makes the icons on the taskbar smaller

- **Set Background Mouse Throttle to 50hz** - by default Windows 11 throttles the polling rate for background listeners to 125hz to reduce unnecessary CPU overhead this tweak lowers that throttle further to 50hz

- **Enable New Start Menu** - this will enable the new start menu layout that has been added to 26200 (25H2) builds

- **Revert New Start Menu** - this restores the old 24H2 start menu layout for those who want to revert the tweak above or simply prefer to use the old layout on 25H2

## Install Packages
 - This will download the latest DirectX and C++ packages from their source
     - Included Packages
          - DirectX
          - All Visual C++ Redistributables and Runtimes
          - Net 3.5 from the bootable media used to install windows
- After they are finished Ngen.exe is ran to cleanup outdated assemblies speeding up some apps launch time

## Install Browsers
- gives you the option to install a web browser such as Chrome, Firefox or Brave
- this installer will also apply policies to pre-configure recommended browser settings
> [!NOTE]
> these policies can be removed by running their associated command below in PowerShell
> ```powershell
> Reg.exe delete 'HKLM\SOFTWARE\Policies\Google\Chrome' /f
> ```
> ```powershell
> Reg.exe delete 'HKLM\SOFTWARE\Policies\Mozilla\Firefox' /f
> ```
> ```powershell
> Reg.exe delete 'HKLM\SOFTWARE\Policies\BraveSoftware\Brave' /f
> ```


## Install Nvidia Driver

<img width="533" height="457" alt="image" src="https://github.com/user-attachments/assets/46d84ef6-236c-45ad-9181-bd035b76d3b6" />



### Features
- the script will get the 4 latest Nvidia Drivers for the user to choose
- install older drivers by typing in the version number (add "hf" to the end if its a hotfix driver)
- alternatively you can choose an already downloaded driver file
- **Strip Driver** - remove the nvidia app and all other bloat leaving only the bare driver
- **Disable Telemetry** - this tweak runs automatically deleting dll files preventing telemetry to Nvidias Server and reduces memory usage 
> [!NOTE]
> Only applies to Strip Driver setting as this file will break the nvidia app
- **Disable HDCP** - disable High-bandwidth Digital Content Protection


<img width="383" height="419" alt="Screenshot 2026-07-11 200228" src="https://github.com/user-attachments/assets/369e7cdb-7b0c-4ed5-95ca-987d0b98b815" />

<img width="383" height="421" alt="Screenshot 2026-07-11 200154" src="https://github.com/user-attachments/assets/23c6f8ff-69f2-43b5-8142-4155a2ed915f" />

#### Post Install Tweaks
- Import optimized Nvidia Control Panel settings and optionally choose to enable GSync,Rebar and/or force latest DLSS version
> [!NOTE]
> You can also choose your own NIP file to import
- Replace the modern `Image Scaling` option with the much more useful `Image Sharpening`
- Enable MSI Mode to switch supported devices from legacy line-based interrupts to Message Signaled Interrupts (MSI)
- Disable GPU Idle States only recommended for users that know they need this tweak
- Apply Digital Vibrance - a slider will allow you to setup digital vibrance on all your monitors, this tweak will apply once restarting
- Disable Monitor Speakers
- Enable Nvidia colors to ensure your monitor(s) are running at the highest color depth


## Install Network Driver

- The script will check for internet connection 
     - If there is then the script will search google for your network adapter's driver
     - If no internet then the script will use local drivers : 
          - Realtek Lan
          - Intel Lan
          - Killer Lan
          - Intel Wifi
- After installing the driver a popup will ask if you want to enable QoS for upload, this tweak will enable some network settings to attempt to prioritize game network traffic along with some other network tweaks to help with bufferbloat [Credit: @AveYo]
> [!NOTE]
> this can be reverted in "Revert Tweaks" if needed


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
> [!NOTE]
> recommend using [Massgravel](https://github.com/massgravel/Microsoft-Activation-Scripts) for permanent activation



## Import and Export Config

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
> [!NOTE]
> not all registry tweaks can/should be reverted
### Unpause Updates
- resumes Windows updates and re-enables driver updates  
> [!NOTE]
> to resume updates but keep driver updates disabled, use `Resume updates` in Windows Update settings instead






## Install Other Scripts

<img width="252" height="294" alt="{BB7BC9F2-B230-4BBE-B4F6-F141E5C09F46}" src="https://github.com/user-attachments/assets/18757af6-1c7e-4078-a62d-cdd8ca20288a" />


- Create a desktop shortcut to some of my other useful scripts for windows tweaking and management 
  
- This shortcut will run the code directly from the github so it will always be up to date
