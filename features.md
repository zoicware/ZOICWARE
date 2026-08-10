# All Zoicware Features

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
  - [Remove Extras](#remove-extras)
    - [Remove Win32 Apps](#remove-win32-apps)
    - [Remove Miscellaneous Apps](#remove-miscellaneous-apps)
  - [Remove Optional Features](#remove-optional-features)
  - [zUninstaller](#zuninstaller)
- [Power Tweaks](#power-tweaks)
  - [Import Plan](#import-plan)
  - [Remove Plans](#remove-plans)
  - [Enable Hidden Plans](#enable-hidden-plans)
  - [USB Power Tweaks](#usb-power-tweaks)
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
    - [General](#general)
    - [Monitor](#monitor)
- [Install Network Driver](#install-network-driver)
- [Ultimate Cleanup](#ultimate-cleanup)
  - [Features](#features-2)
- [Activate Windows](#activate-windows)
- [Import and Export Config](#import-and-export-config)
  - [Features](#features-3)
- [Restore Tweaks](#restore-tweaks)
  - [Enable Updates](#enable-updates)
  - [Enable Defender](#enable-defender)
  - [Enable Services](#enable-services)
  - [Install Microsoft Store](#install-microsoft-store)
  - [Revert Registry Tweaks](#revert-registry-tweaks)
  - [Unpause Updates](#unpause-updates)
- [Install Other Scripts](#install-other-scripts)



## Registry Tweaks

<img width="772" height="689" alt="1 Registry Tweaks" src="https://github.com/user-attachments/assets/b29ab392-cf2f-447d-88be-ed90439ce9b2" />

- Apply the registry tweaks to automate most Windows quality-of-life and performance settings.
- A registry file will be created on the desktop containing all the registry keys, including a comment describing the function of each.
- Use the `Change Mode` button to either remove tweaks from the full list of tweaks that ran or select only specific tweaks to be applied.

[Registry Tweaks List](registrytweaks.md)



## Group Policy Tweaks

<img width="280" height="187" alt="2 Group Policy Tweaks" src="https://github.com/user-attachments/assets/7d12c938-c895-4d77-a4e8-2ebf10e4126d" />


### Disable Updates
- This tweak will disable automatic Windows updates and the related services.

### Disable Defender
- This tweak will disable Windows Defender and all related services.
> [!CAUTION]
> Disabling Windows Defender will leave you vulnerable to malicious attacks!

### Disable Telemetry
- This tweak will disable telemetry via Group Policy; however, this only applies to Server and Enterprise builds.
- Adds telemetry domains to be blocked via the hosts file, gathered from official Microsoft sources.
> [!NOTE]
> Other telemetry services and settings are disabled as well.



## Disable Services
- This tweak will disable some unwanted services.

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
- This tweak will remove all scheduled tasks except for SvcRestart and CtfMonitor, to avoid issues.



## Debloat

- This tweak will allow you to debloat all Windows appx packages and other preinstalled apps.

### Debloat Presets

<img width="681" height="540" alt="3 Debloat Presets" src="https://github.com/user-attachments/assets/2a72742e-e4bf-4e37-95d2-6887261c3f9e" />

- Debloat All
- Keep Store, Xbox and Edge
- Keep Store and Xbox
- Keep Edge
- Keep Store

### Features
- Removes all bloat appx packages, Edge, Teams, OneDrive, Remote Desktop, Health Update Tools, etc.
> [!NOTE]
> All debloat presets will clean the Start Menu pinned icons and remove outdated versions of newly installed packages.

### Custom Debloat

<img width="681" height="537" alt="4 Debloat Appx" src="https://github.com/user-attachments/assets/69ce13d1-ad0d-435a-83f6-be6d8e12490b" />


- Choose specific appx packages, including locked packages.
> [!CAUTION]
> Locked packages are locked for a reason; be careful when removing these.

### Remove Optional Features

<img width="680" height="537" alt="5 Debloat Optional Features" src="https://github.com/user-attachments/assets/6aeeec07-7486-4516-b121-6f10532f9412" />

- Uninstall Windows capabilities, optional features and Windows packages.

### Remove Extras

<img width="680" height="537" alt="6 Debloat Extras" src="https://github.com/user-attachments/assets/04abe853-ed29-4373-94c8-0a388ea5d578" />

#### Remove Win32 Apps
- Speech App
- Live Captions
- Magnifier
- Narrator
- On-Screen Keyboard
- Voice Access
- Steps Recorder
- Quick Assist
- Math Input Panel

#### Remove Miscellaneous Apps
- Microsoft Edge
- Edge WebView
- Teams and OneDrive
- Windows Update Tools
- Remote Desktop Connection
- Clean Start Menu Icons
- Clean Outdated Store Apps
- Remove Backup App and Get Started

### zUninstaller

<img width="680" height="536" alt="7 Debloat App Uninstaller" src="https://github.com/user-attachments/assets/b819baaa-f4a4-4d31-b25c-2f0a0843ac68" />

- Remove installed apps with additional brute-force cleaning of leftovers.
  - The script will search for leftover files and folders after the app's uninstaller has run. Since the script could potentially find items that aren't related to the app, a popup will appear with the found items, allowing for manual selection.
  - If an item cannot be removed with brute-force methods, a script will run upon the next reboot to remove the file.



## Power Tweaks

<img width="733" height="540" alt="{86C425ED-62FD-4280-9514-AA5DB0C05DA0}" src="https://github.com/user-attachments/assets/7fdb1b4e-da64-41f6-b93a-44639052fb9a" />

### Import Plan
- Custom power plan for removing power-saving features and core parking.

### Remove Plans
- A list of current power plans will allow you to remove any and prevent Windows from switching back to Balanced or other recommended plans.

### Enable Hidden Plans
- There are three hidden power plans in Windows: Ultimate Performance, High Performance Overlay and Max Performance Overlay.
- This tweak will allow you to enable any of these to try out.

### USB Power Tweaks

<img width="730" height="538" alt="9 USB Power" src="https://github.com/user-attachments/assets/08ca1359-b443-4eb3-88ef-70cfebd8a07d" />


- This section will display the USB hubs and devices connected.
- Choose any or all devices to disable power saving.



## Optional Tweaks

### General

<img width="780" height="587" alt="10 Opt General" src="https://github.com/user-attachments/assets/680d80fb-904f-4139-94cf-2d9b69727949" />

- **Black Theme** - Applies a black color to the taskbar and Start Menu, as well as a dark user picture and black-themed cursors.
- **Transparent Taskbar** - Makes the taskbar transparent using TranslucentTB.
- **Remove Network Icon From File Explorer** - Removes the network icon from the File Explorer navigation pane.
- **Remove Recycle Bin Name** - Removes the "Recycle Bin" label from the icon.
- **Remove Mouse and Sound Schemes** - Sets the pointer and sound schemes to `None`; this will disable all Windows sound effects and use the original Windows XP cursor scheme.
- **Hide User Tile In Start Menu** - Hides the user icon in the bottom left of the Start Menu.
- **Modern Cursor Scheme** - Adds the Fluent cursor design from Rectify11.
- **Enable Dark Accents** - Fixes the default blue accents in Win32 app controls to match your theme color.
- **Enable Classic Accents** - Applies the classic Windows XP/2000 navy blue to Win32 app controls like menus, highlights and hover states.
- **Do Not Include Drivers in Windows Update** - Prevents drivers from being downloaded when checking for updates.
- **Security Updates Only** - Defers feature updates for 365 days and optional updates for 30 days [MAX].
- **Pause Updates for 1 Year** - Pauses updates for a year as a good alternative to disabling updates completely.
- **Prevent OS Upgrade** - Prevents Windows Update from upgrading your Windows version such as 24H2 -> 25H2.
- **Remove Open File Security Warning** - When disabling SmartScreen, Windows will default to the old file security warning when opening files from another PC.
- **Block Razer and ASUS Download Servers** - Adds all Razer and ASUS servers to the hosts file to prevent the download of their bloat software.
> [!NOTE]
> The hosts file is located at `C:\Windows\System32\drivers\etc\hosts`
- **Apply PBO Curve on Startup** - Prompts you to enter your PBO curve OC and applies it when your PC starts up, using PBO Tuner.
- **Disable PowerShell Logging** - By default, everything entered into the PowerShell console is saved to a file in your AppData directory; this will disable that "feature".
- **Enable No GUI Boot** - Enables No GUI Boot in msconfig, disabling the boot logo, spinning logo and boot messages.
- **Create Shortcut to Start Menu Locations** - Creates a shortcut in the Start Menu that lets you access both Start Menu shortcut folders directly, to customize the apps listed in the Start Menu.
- **Disable Game Bar Popup** - When uninstalling Xbox apps, plugging in an Xbox controller triggers an annoying popup; this tweak disables that [Credit: @AveYo].
- **Enable Fast Shutdown/Restart** - Decreases the delay before services and apps are killed to shut down or restart, as well as auto-ending open foreground apps without asking.
- **Use More Accurate Time Server for System Clock** - Sets the w32tm service to use https://www.pool.ntp.org/ as its time server instead of the default one.
- **No Mouse Accel on Desktop** - Removes mouse acceleration on the desktop when using scaling above 100% [Credit: @MarkC].
- **Disable Device Encryption** - Disables BitLocker and prevents device encryption from being re-enabled.
- **Cleanup Third-Party App Start Menu Shortcuts** - Takes third-party app shortcuts out of their folders in the Start Menu and leaves only the shortcut directly.

### Ultimate Context Menu

<img width="780" height="587" alt="11 Opt Context Menu" src="https://github.com/user-attachments/assets/ecab5303-6038-499e-881f-ba6c7e4f762b" />

#### Add to Menu
- **Additional Files to New Menu** - Adds the ability to create new registry files, PowerShell scripts and batch files.
- **Additional ps1 Options** - Opens PowerShell files with PowerShell or PowerShell ISE as admin.
- **Snipping Tool** - Adds a shortcut to open the Snipping Tool or instantly take a snip.
- **Shutdown** - Adds a `Shutdown` button to turn off your PC.
- **Run as Admin for ps1, bat, vbs files** - Adds the ability to run listed scripts as admin.
- **PowerShell and CMD** - Adds the option to open a PowerShell or CMD prompt.
- **Kill Not Responding Tasks** - Adds an option to kill any not-responding tasks.
- **Delete Permanently** - Skips the Recycle Bin and deletes files directly (only works on some files).
- **Take Ownership** - Allows full access to any folder or file that has locked permissions.
- **Legacy Control Panel Settings** - Adds a `Legacy settings` flyout to the desktop context menu with quick access to classic Control Panel applets [Credit: @iFryno].

#### Remove from Menu
- **Add to Favorites** - Removes the `Add to Favorites` option for files and folders.
- **Customize this Folder** - Removes the `Customize this Folder` option when right-clicking in some folders.
- **Give Access to** - Removes the `Give access to` option from files and folders.
- **Open in Terminal** - Removes the `Open in Terminal` option when right-clicking the desktop.
- **Restore to Previous Versions** - Removes the `Restore Previous Versions` option after editing a file.
- **Print** - Removes the `Print` option when right-clicking some files.
- **Send to** - Removes the `Send to` option for files and folders.
- **Share** - Removes the `Share` option when right-clicking some files.
- **Personalize** - Removes the `Personalize` option when right-clicking the desktop.
- **Display** - Removes the `Display settings` option when right-clicking the desktop.
- **Extract All for Archive Files** - Removes the `Extract all` option when right-clicking archive files such as .zip.
- **Troubleshoot Compatibility** - Removes the `Troubleshoot compatibility` option when right-clicking executable files.
- **Include in Library** - Removes the `Include in Library` option when right-clicking folders.
- **Scan with Defender** - Removes the `Scan with Microsoft Defender` option for downloaded files.



## Windows 11 Tweaks

### Patch Explorer

<img width="529" height="507" alt="12 Win11 Tweaks Patch Explorer" src="https://github.com/user-attachments/assets/9613a23e-59e5-48b0-8c3a-14e4ff516a37" />

- **Remove Rounded Edges** - Removes rounded edges using [toggle-rounded-corners](https://github.com/oberrich/win11-toggle-rounded-corners) and runs at startup.
- **Enable Windows 10 Taskbar and Start Menu** - Runs ExplorerPatcher and automatically applies settings for the Windows 10 taskbar and Start Menu.
- **Enable Windows 10 File Explorer** - This will use some registry hacks to enable the old Windows 10 File Explorer ribbon; when combined with Enable Windows 10 Icons, the full Windows 10 File Explorer look can be restored without a third-party app.
- **Replace Start Menu and Search with OpenShell** - This tweak will disable Windows Search and indexing to replace it with OpenShell and import a custom config for a minimal black Start Menu; any current pinned shortcuts will be moved to the OpenShell pinned directory.

### Windows 10 Restore Tweaks

<img width="530" height="506" alt="13 Win11 Tweaks Win10" src="https://github.com/user-attachments/assets/91bfbb1c-133f-4829-9613-0c8fe1e8b1a3" />

- **Restore Windows 10 Recycle Bin Icon** - This tweak will replace the Windows 11 Recycle Bin icon with the old Windows 10 icon.
- **Restore Windows 10 Snipping Tool** - Removes the UWP Snipping Tool (Screen Sketch) and enables the Windows 10 Snipping Tool.
- **Restore Windows 10 Task Manager** - This will create a fake taskmgr.exe that runs Task Manager with the -d command, disabling the new UI.
> [!TIP]
> This tweak works best with UAC disabled, since the fake wrapper needs to be run as admin.
- **Restore Windows 10 Notepad** - This will enable the legacy Windows 10 Notepad via the optional feature and automatically set it as the default.
- **Restore Windows 10 Icons** - This tweak will replace all the Windows 11 icons in File Explorer with Windows 10 icons; this tweak works best with the Windows 10 File Explorer, making it look exactly like Windows 10 without using a third-party app.
- **Restore Windows 10 Sounds** - Replaces the Windows 11 sound scheme with the old Windows 10 sounds.

### Misc Tweaks

<img width="530" height="506" alt="14 Win11 Tweaks Misc" src="https://github.com/user-attachments/assets/42892289-e417-4557-bd66-8967283de550" />

- **Set all Services to Manual** - This tweak sets the startup type to Manual for non-essential Windows services.
  - **Services Skipped:**
    - AudioEndpointBuilder
    - Audiosrv
    - EventLog
    - SysMain
    - Themes
    - WSearch
    - NVDisplay.ContainerLocalSystem
    - WlanSvc
- **Show all Taskbar Tray Icons** - Windows 11 makes it difficult to show all taskbar tray icons; with this tweak, all current apps will be shown and new apps will be enabled automatically after a restart following installation.
> [!NOTE]
> This tweak uses a scheduled task to update the registry key responsible for showing the app in the taskbar.
- **Dark Winver** - This will replace winver.exe with a dark-themed version. View it here -> [Dark Winver](https://github.com/zoicware/WinverDark)
- **Remove Quick Settings Tiles** - This tweak removes the additional options in the Quick Settings menu on the taskbar and leaves just the volume slider.
- **Disable Notepad Tabs and Rewrite** - This will disable the annoying `Continue previous session` and `Rewrite` features from the modern Notepad, making it feel more like the legacy one.
- **Hide Ads in Settings** - This tweak removes the useless tiles in the Settings app.
- **Small Taskbar Icons** - Makes the icons on the taskbar smaller.
- **Set Background Mouse Throttle to 50hz** - By default, Windows 11 throttles the polling rate for background listeners to 125hz to reduce unnecessary CPU overhead; this tweak lowers that throttle further, to 50hz.
- **Enable New Start Menu** - This will enable the new Start Menu layout that has been added to 26200 (25H2) builds.
- **Revert New Start Menu** - This restores the old 24H2 Start Menu layout for those who want to revert the tweak above or simply prefer to use the old layout on 25H2.



## Install Packages
- This will download the latest DirectX and C++ packages from their source.
  - Included Packages
    - DirectX
    - All Visual C++ Redistributables and Runtimes
    - .NET 3.5 from the bootable media used to install Windows
- After they finish, Ngen.exe is run to clean up outdated assemblies, speeding up some apps' launch times.



## Install Browsers

<img width="281" height="189" alt="15 Browser Install" src="https://github.com/user-attachments/assets/948fc687-aa2b-4326-bb51-17182bca7717" />

- Lets you install a web browser such as Chrome, Firefox or Brave.
- This installer will also apply policies to pre-configure recommended browser settings.
> [!NOTE]
> These policies can be removed by running their associated command below in PowerShell.
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

<img width="530" height="456" alt="16 NV Install" src="https://github.com/user-attachments/assets/5db64d82-779e-4002-bbdf-182646eafc7e" />

### Features
- The script will get the four latest Nvidia drivers to choose from.
- Install older drivers by typing in the version number.
> [!NOTE]
> Add `hf` at the end if it's a hotfix driver.
- Alternatively, you can choose an already downloaded driver file.
- **Strip Driver** - Removes the Nvidia app and all other bloat, leaving only the bare driver.
- **Disable Telemetry** - This tweak runs automatically, deleting DLL files to prevent telemetry to Nvidia's servers and reduce memory usage.
> [!NOTE]
> Only applies to the Strip Driver setting, as this file will break the Nvidia app.

### Post Install Tweaks

#### General

<img width="386" height="423" alt="{FBB867DD-B916-4C37-A736-4FFD245F7D7A}" src="https://github.com/user-attachments/assets/c68d5b0c-1490-4756-a848-432aa90f9885" />


- Import optimized Nvidia Control Panel settings and optionally enable G-Sync, Resizable BAR and/or override DLSS models with the recommended presets.
> [!NOTE]
> You can also choose your own NIP file to import.
- Replace the modern `Image Scaling` option with the much more useful `Image Sharpening`.
- Enable MSI Mode to switch supported devices from legacy line-based interrupts to Message Signaled Interrupts (MSI).
- Disable GPU Idle States. Recommended only for users who know they need this tweak.
- Disable High-bandwidth Digital Content Protection.

#### Monitor

<img width="382" height="419" alt="18 NV Post Install Monitor" src="https://github.com/user-attachments/assets/882043eb-9ac0-41ee-8e73-dbe782019e59" />

- Apply Digital Vibrance - A slider will let you set digital vibrance for all your monitors. This tweak will apply after restarting.
- Disable Monitor Speakers.
- Enable Nvidia colors to ensure your monitor(s) are running at the highest color depth.



## Install Network Driver
- The script will check for an internet connection.
  - If there is, the script will search Google for your network adapter's driver.
  - If there's no internet, the script will use local drivers:
    - Realtek Lan
    - Intel Lan
    - Killer Lan
    - Intel Wifi
- After installing the driver, a popup will ask if you want to enable QoS for upload; this tweak will enable some network settings to attempt to prioritize game network traffic, along with some other network tweaks to help with bufferbloat [Credit: @AveYo].
> [!NOTE]
> This can be reverted in `Revert Tweaks` if needed.



## Ultimate Cleanup

<img width="511" height="409" alt="19 Ultimate Cleanup" src="https://github.com/user-attachments/assets/ca7e503c-452f-4ab3-b6e5-7da1fed9065f" />

- Cleans temp files and event logs.

### Features
- Clears all Event Viewer logs.
- Force deletes files in both temp directories.
- Clears all Windows logs in places that Disk Cleanup misses.
- Clears Nvidia driver shader cache.
- Removes the windows.old folder, sometimes taking up quite a bit of storage.
- Removes old duplicate drivers.
- Runs the Windows Disk Cleanup utility on all drives.
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
- Activates Windows with a generic Pro key and a public KMS server, for 180 days.
> [!TIP]
> Use [Microsoft Activation Scripts (MAS)](https://github.com/massgravel/Microsoft-Activation-Scripts) for permanent activation.



## Import and Export Config

<img width="480" height="267" alt="20 Import Export Config" src="https://github.com/user-attachments/assets/dc8679fa-ce9c-45ad-8ab7-3ab4ebb7f02b" />

<img width="383" height="539" alt="21 Build Config" src="https://github.com/user-attachments/assets/5359c880-cb10-4a61-95b5-e93b8f43f8fe" />

- Upon launching the script for the first time, a file named ZCONFIG.cfg will be created in `[C:\Users\Username\]`.

### Features
- Build custom config with selected tweaks.
- All tweaks will be updated in the config upon selection.
- Export the config for automated use.
- Import configs and run tweaks automatically with no prompts.



## Restore Tweaks

<img width="657" height="299" alt="22 Restore Tweaks" src="https://github.com/user-attachments/assets/349dcf30-e9dc-497a-a378-c8a3e194408e" />


### Enable Updates
- Reverts the `Disable Updates` tweak and enables all registry keys and services.

### Enable Defender
- Enables all disabled registry keys and services.

### Enable Services
- Enables services disabled by the `Disable Services` tweak.

### Install Microsoft Store
- Installs the Windows 10 Store; for Windows 11, use `wsreset -i`.

### Revert Registry Tweaks
- This will revert most registry tweaks.
> [!NOTE]
> Not all registry tweaks can/should be reverted.

### Unpause Updates
- Resumes Windows updates and re-enables driver updates.
> [!TIP]
> To resume updates but keep driver updates disabled, use `Resume updates` in Windows Update settings instead.



## Install Other Scripts

<img width="330" height="388" alt="23 Install Scripts" src="https://github.com/user-attachments/assets/9e6cbc49-8beb-4c42-bb5b-2b144da434a8" />

- Creates a desktop shortcut to some of my other useful scripts for Windows tweaking and management.
- This shortcut will run the code directly from GitHub, so it will always be up to date.
