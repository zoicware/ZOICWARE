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

<img width="773" height="690" alt="Screenshot 2026-07-22 213344" src="https://github.com/user-attachments/assets/8053881a-53fa-4575-b774-17de8cc98a95" />

- Apply the registry tweaks to automate most Windows quality-of-life and performance settings.
- A registry file will be created on the desktop containing all the registry keys, including a comment describing the function of each.
- Use the `Change Mode` button to either remove tweaks from the full list of tweaks that ran or select only specific tweaks to be applied.

[Registry Tweaks List](registrytweaks.md)



## Group Policy Tweaks

<img width="280" height="188" alt="image" src="https://github.com/user-attachments/assets/611e76e7-dec6-4f83-a1c6-0f4001134ce2" />

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

<img width="684" height="540" alt="Screenshot 2026-07-22 211743" src="https://github.com/user-attachments/assets/f1370a14-f33d-409e-a988-cfde68f276be" />

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

<img width="682" height="537" alt="Screenshot 2026-07-22 211837" src="https://github.com/user-attachments/assets/34031a9c-ea91-4192-9d47-3999384966fd" />

- Choose specific appx packages, including locked packages.
> [!CAUTION]
> Locked packages are locked for a reason; be careful when removing these.

### Remove Optional Features

<img width="683" height="539" alt="Screenshot 2026-07-22 211933" src="https://github.com/user-attachments/assets/12a4a175-1fd7-4e8e-8228-43716d547860" />

- Uninstall Windows capabilities, optional features and Windows packages.

### Remove Extras

<img width="681" height="539" alt="Screenshot 2026-07-22 212005" src="https://github.com/user-attachments/assets/d5f67855-6865-4776-9a25-ca0857aa6c8c" />

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

<img width="680" height="537" alt="Screenshot 2026-07-22 212119" src="https://github.com/user-attachments/assets/25a32f09-b5f4-4db6-ab24-e52a8bbe2e19" />

- Remove installed apps with additional brute-force cleaning of leftovers.
  - The script will search for leftover files and folders after the app's uninstaller has run. Since the script could potentially find items that aren't related to the app, a popup will appear with the found items, allowing for manual selection.
  - If an item cannot be removed with brute-force methods, a script will run upon the next reboot to remove the file.



## Power Tweaks

<img width="732" height="540" alt="Screenshot 2026-07-22 212208" src="https://github.com/user-attachments/assets/a3822942-d294-4d62-b472-0768a49dbe1a" />

### Import Plan
- Custom power plan for removing power-saving features and core parking.

### Remove Plans
- A list of current power plans will allow you to remove any and prevent Windows from switching back to Balanced or other recommended plans.

### Enable Hidden Plans
- There are three hidden power plans in Windows: Ultimate Performance, High Performance Overlay and Max Performance Overlay.
- This tweak will allow you to enable any of these to try out.

### USB Power Tweaks

<img width="730" height="538" alt="Screenshot 2026-07-22 212255" src="https://github.com/user-attachments/assets/aad9a856-6e49-4740-9daf-438663bb004e" />

- This section will display the USB hubs and devices connected.
- Choose any or all devices to disable power saving.



## Optional Tweaks

### General

<img width="783" height="590" alt="Screenshot 2026-07-22 212344" src="https://github.com/user-attachments/assets/1dc71127-ff36-422d-81d7-6d2ddcfa74da" />

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

<img width="782" height="588" alt="Screenshot 2026-07-22 212421" src="https://github.com/user-attachments/assets/9b7aeca0-460d-429e-9e46-5d258d4db821" />

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

<img width="531" height="509" alt="Screenshot 2026-07-22 212504" src="https://github.com/user-attachments/assets/03516b03-9c52-4134-8e1e-70a1257c104c" />

- **Remove Rounded Edges** - Removes rounded edges using [toggle-rounded-corners](https://github.com/oberrich/win11-toggle-rounded-corners) and runs at startup.
- **Enable Windows 10 Taskbar and Start Menu** - Runs ExplorerPatcher and automatically applies settings for the Windows 10 taskbar and Start Menu.
- **Enable Windows 10 File Explorer** - This will use some registry hacks to enable the old Windows 10 File Explorer ribbon; when combined with Enable Windows 10 Icons, the full Windows 10 File Explorer look can be restored without a third-party app.
- **Replace Start Menu and Search with OpenShell** - This tweak will disable Windows Search and indexing to replace it with OpenShell and import a custom config for a minimal black Start Menu; any current pinned shortcuts will be moved to the OpenShell pinned directory.

### Windows 10 Restore Tweaks

<img width="533" height="510" alt="Screenshot 2026-07-22 212533" src="https://github.com/user-attachments/assets/1711286b-258c-4578-a6e7-3800139dcbdc" />

- **Restore Windows 10 Recycle Bin Icon** - This tweak will replace the Windows 11 Recycle Bin icon with the old Windows 10 icon.
- **Restore Windows 10 Snipping Tool** - Removes the UWP Snipping Tool (Screen Sketch) and enables the Windows 10 Snipping Tool.
- **Restore Windows 10 Task Manager** - This will create a fake taskmgr.exe that runs Task Manager with the -d command, disabling the new UI.
> [!TIP]
> This tweak works best with UAC disabled, since the fake wrapper needs to be run as admin.
- **Restore Windows 10 Notepad** - This will enable the legacy Windows 10 Notepad via the optional feature and automatically set it as the default.
- **Restore Windows 10 Icons** - This tweak will replace all the Windows 11 icons in File Explorer with Windows 10 icons; this tweak works best with the Windows 10 File Explorer, making it look exactly like Windows 10 without using a third-party app.
- **Restore Windows 10 Sounds** - Replaces the Windows 11 sound scheme with the old Windows 10 sounds.

### Misc Tweaks

<img width="532" height="510" alt="Screenshot 2026-07-22 212600" src="https://github.com/user-attachments/assets/7136f6c7-8c3c-454f-b12a-40bb29109a59" />

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

<img width="283" height="190" alt="Screenshot 2026-07-22 212644" src="https://github.com/user-attachments/assets/1ba442d8-51d8-4402-bbfa-e8503b7fb192" />

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

<img width="533" height="459" alt="Screenshot 2026-07-22 212726" src="https://github.com/user-attachments/assets/695c5994-a061-4be7-8b9e-950301fa67ca" />

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

<img width="382" height="420" alt="Screenshot 2026-07-22 212759" src="https://github.com/user-attachments/assets/13e666d2-3324-4f6e-8724-32b149533f24" />

- Import optimized Nvidia Control Panel settings and optionally enable G-Sync, Resizable BAR and/or override DLSS models with the recommended presets.
> [!NOTE]
> You can also choose your own NIP file to import.
- Replace the modern `Image Scaling` option with the much more useful `Image Sharpening`.
- Enable MSI Mode to switch supported devices from legacy line-based interrupts to Message Signaled Interrupts (MSI).
- Disable GPU Idle States. Recommended only for users who know they need this tweak.
- Disable High-bandwidth Digital Content Protection.

#### Monitor

<img width="380" height="418" alt="Screenshot 2026-07-22 212849" src="https://github.com/user-attachments/assets/e8b9822e-29a5-4220-b48c-9fddc94a43f6" />

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

<img width="513" height="410" alt="Screenshot 2026-07-22 212927" src="https://github.com/user-attachments/assets/9a162b3b-97da-40ff-82da-bc2bfce1bbde" />

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

<img width="482" height="269" alt="Screenshot 2026-07-22 213105" src="https://github.com/user-attachments/assets/332d0d6e-f8bb-490d-aeb3-0c0e48acf3b1" />

<img width="383" height="540" alt="Screenshot 2026-07-22 213121" src="https://github.com/user-attachments/assets/73b171e3-641c-41df-9658-4616fb08c27b" />

- Upon launching the script for the first time, a file named ZCONFIG.cfg will be created in `[C:\Users\Username\]`.

### Features
- Build custom config with selected tweaks.
- All tweaks will be updated in the config upon selection.
- Export the config for automated use.
- Import configs and run tweaks automatically with no prompts.



## Restore Tweaks

<img width="657" height="299" alt="Screenshot 2026-07-22 213214" src="https://github.com/user-attachments/assets/bef9ec6a-a1f3-4976-8896-621afd7dde4f" />

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

<img width="332" height="390" alt="Screenshot 2026-07-22 213250" src="https://github.com/user-attachments/assets/ec9ea14c-b900-4f3e-9ea9-16c74da43c47" />

- Creates a desktop shortcut to some of my other useful scripts for Windows tweaking and management.
- This shortcut will run the code directly from GitHub, so it will always be up to date.
