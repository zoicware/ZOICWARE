function Optimize-BTImageSource {
    param (
        [Parameter(Mandatory)]
        [String] $Source,

        [Switch] $ForceRefresh
    )

    if ([bool]([System.Uri]$Source).IsUnc -or $Source -like 'http?://*') {
        $RemoteFileName = $Source -replace '/|:|\\', '-'

        $NewFilePath = '{0}\{1}' -f $Env:TEMP, $RemoteFileName

        if (!(Test-Path -Path $NewFilePath) -or $ForceRefresh) {
            if ([bool]([System.Uri]$Source).IsUnc) {
                Copy-Item -Path $Source -Destination $NewFilePath -Force
            } else {
                Invoke-WebRequest -Uri $Source -OutFile $NewFilePath
            }
        }

        $NewFilePath
    } else {
        try {
            (Get-Item -Path $Source -ErrorAction Stop).FullName
        } catch {
            Write-Warning -Message "The image source '$Source' doesn't exist, failed back to icon."
        }
    }
}
function Test-BTAudioPath {
    param (
        [Parameter(Mandatory)]
        [String] $Path
    )

    $Extension = [IO.Path]::GetExtension($Path)

    $ValidExtensions = @(
        '.aac'
        '.flac'
        '.m4a'
        '.mp3'
        '.wav'
        '.wma'
    )

    if ($Extension -in $ValidExtensions) {
        if (Test-Path -Path $Path) {
            $true
        } else {
            throw "The file '$Path' doesn't exist in the specified location. Please provide a valid path and try again."
        }
    } else {
        throw "The file extension '$Extension' is not supported. Please provide a valid path and try again."
    }
}
function Get-BTHistory {
    <#
        .SYNOPSIS
        Shows all toast notifications in the Action Center.

        .DESCRIPTION
        The Get-BTHistory function returns all toast notifications that are in the Action Center. Toasts that have been dismissed by the user will not be returned.

        The object returned includes tag and group information which can be used with the Remove-BTNotification function to clear specific notification from the Action Center.

        Using the ScheduledToast switch you can get all toast notifications that have been scheduled to display, whether by scheduling outright or snoozing.

        .INPUTS
        STRING

        .OUTPUTS
        ToastNotification
        ScheduledToastNotification

        .EXAMPLE
        Get-BTHistory

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/Get-BTHistory.md
    #>

    [cmdletBinding(HelpUri='https://github.com/Windos/BurntToast/blob/main/Help/Get-BTHistory.md')]
    param (
        # Specifies the AppId of the 'application' or process that spawned the toast notification.
        [string] $AppId = $Script:Config.AppId,

        # A string that uniquely identifies a toast notification. Submitting a new toast with the same identifier as a previous toast will replace the previous toast.
        #
        # This is useful when updating the progress of a process, using a progress bar, or otherwise correcting/updating the information on a toast.
        [string] $UniqueIdentifier,

        # Specified that you need to see scheduled toast notifications, rather the those in the Action Center.
        [switch] $ScheduledToast
    )

    if (!(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\$AppId")) {
        throw "The AppId $AppId is not present in the registry, please run New-BTAppId to avoid inconsistent Toast behaviour."
    } else {
        if ($Script:ActionsSupported) {
            Write-Warning -Message 'The output from this function in some versions of PowerShell is not useful. Unfortunately this is expected at this time.'
        }

        $Toasts = if ($ScheduledToast) {
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).GetScheduledToastNotifications()
        } else {
            [Windows.UI.Notifications.ToastNotificationManager]::History.GetHistory($AppId)
        }

        if ($UniqueIdentifier) {
            $Toasts | Where-Object {$_.Tag -eq $UniqueIdentifier -or $_.Group -eq $UniqueIdentifier}
        } else {
            $Toasts
        }
    }
}
function New-BTAction {
    <#
        .SYNOPSIS
        Creates an action object for a Toast Notification.

        .DESCRIPTION
        The New-BTAction function creates an 'action' object which contains defines the controls displayed at the bottom of a Toast Notification.

        Actions can either be system handeled and automatically localized Snooze and Dismiss buttons or a custom collection of inputs.

        .INPUTS
        None
            You cannot pipe input to this function.

        .OUTPUTS
        Microsoft.Toolkit.Uwp.Notifications.IToastActions

        .EXAMPLE
        New-BTAction -SnoozeAndDismiss

        This command creates an action element using the system handled snooze and dismiss modal.

        .EXAMPLE
        New-BTAction -Buttons (New-BTButton -Content 'Google' -Arguments 'https://google.com')

        This command creates an action element with a single clickable button.

        .EXAMPLE
        $Button = New-BTButton -Content 'Google' -Arguments 'https://google.com'
        $ContextMenuItem = New-BTContextMenuItem -Content 'Bing' -Arguments 'https://bing.com'
        New-BTAction -Buttons $Button -ContextMenuItems $ContextMenuItem

        This example creates an action elemnt with both a clickable button and a right click context menu item.

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTAction.md
    #>

    [CmdletBinding(DefaultParametersetName = 'Custom Actions',
                   SupportsShouldProcess   = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTAction.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.IToastActions])]
    param (
        # Button objects created with the New-BTButton function. Up to five can be included, or less if Context Menu Items are also included.
        [ValidateCount(0, 5)]
        [Parameter(ParameterSetName = 'Custom Actions')]
        [Microsoft.Toolkit.Uwp.Notifications.IToastButton[]] $Buttons,

        # Right click context menu item objects created with the New-BTContextMenuItem function. Up to five can be included, or less if Buttons are also included.
        [ValidateCount(0, 5)]
        [Parameter(ParameterSetName = 'Custom Actions')]
        [Microsoft.Toolkit.Uwp.Notifications.ToastContextMenuItem[]] $ContextMenuItems,

        # Input objects created via the New-BTText and New-BTSelectionBoxItem functions. Up to five can be included.
        [ValidateCount(0, 5)]
        [Parameter(ParameterSetName = 'Custom Actions')]
        [Microsoft.Toolkit.Uwp.Notifications.IToastInput[]] $Inputs,

        # Creates a system handeled snooze and dismiss action. Cannot be included inconjunction with custom actions.
        [Parameter(Mandatory,
                   ParameterSetName = 'SnoozeAndDismiss')]
        [switch] $SnoozeAndDismiss
    )

    begin {
        if (($ContextMenuItems.Length + $Buttons.Length) -gt 5) {
            throw "You have included too many buttons and context menu items. The maximum combined number of these elements is five."
        }
    }
    process {
        if ($SnoozeAndDismiss) {
            $ToastActions = [Microsoft.Toolkit.Uwp.Notifications.ToastActionsSnoozeAndDismiss]::new()
        } else {
            $ToastActions = [Microsoft.Toolkit.Uwp.Notifications.ToastActionsCustom]::new()

            if ($Buttons) {
                foreach ($Button in $Buttons) {
                    $ToastActions.Buttons.Add($Button)
                }
            }

            if ($ContextMenuItems) {
                foreach ($ContextMenuItem in $ContextMenuItems) {
                    $ToastActions.ContextMenuItems.Add($ContextMenuItem)
                }
            }

            if ($Inputs) {
                foreach ($Input in $Inputs) {
                    $ToastActions.Inputs.Add($Input)
                }
            }
        }

        if($PSCmdlet.ShouldProcess("returning: [$($ToastActions.GetType().Name)] with $($ToastActions.Inputs.Count) Inputs, $($ToastActions.Buttons.Count) Buttons, and $($ToastActions.ContextMenuItems.Count) ContextMenuItems")) {
            $ToastActions
        }
    }
}
function New-BTAppId {
    <#
        .SYNOPSIS
        Creates a new AppId Registry Key.

        .DESCRIPTION
        The New-BTAppId function create a new AppId registry key in the Current User's Registery Hive. If the desired AppId is already present in the Registry then no changes are made.

        If no AppId is specified then the AppId specified in the config.json file in the BurntToast module's root directory is used.

        .INPUTS
        System.String

        You cannot pipe input to this cmdlet.

        .OUTPUTS
        None

        .EXAMPLE
        New-BTAppId

        This command creates an AppId registry key using the value specified in the BurntToast module's config.json file, which is 'BurntToast' by default.

        .EXAMPLE
        New-BTAppId -AppId 'Script Checker'

        This command create an AppId registry key called 'Script Checker.'

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTAppId.md
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTAppId.md')]
    param (
        # Specifies the new AppId. You can use any alphanumeric characters.
        #
        # Defaults to the AppId specified in the config.json file in the BurntToast module's root directoy if not provided.
        [ValidateNotNullOrEmpty()]
        [string] $AppId = $Script:Config.AppId
    )

    $RegPath = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings'

    if (!(Test-Path -Path "$RegPath\$AppId")) {
        if($PSCmdlet.ShouldProcess("creating: '$RegPath\$AppId' with property 'ShowInActionCenter' set to '1' (DWORD)")) {
            $null = New-Item -Path "$RegPath\$AppId" -Force
            $null = New-ItemProperty -Path "$RegPath\$AppId" -Name 'ShowInActionCenter' -Value 1 -PropertyType 'DWORD'
        }
    } else {
        Write-Verbose -Message 'Specified AppId is already present in the registry.'
    }
}
function New-BTAudio {
    <#
        .SYNOPSIS
        Creates a new Audio object for Toast Notifications.

        .DESCRIPTION
        The New-BTAudio function creates a new Audio object for Toast Notifications.

        You can use the parameters of New-BTAudio to select an audio file or a standard notification sound (including alarms). Alternativly you can specify that a Toast Notification should be silent.

        .INPUTS
        None

        You cannot pipe input to this cmdlet.

        .OUTPUTS
        Microsoft.Toolkit.Uwp.Notifications.ToastAudio

        .EXAMPLE
        New-BTAudio -Source ms-winsoundevent:Notification.SMS

        Creates an Audio  which will cause a Toast Notification to play the standard Microsoft 'SMS' sound.

        .EXAMPLE
        New-BTAudio -Path 'C:\Music\FavSong.mp3'

        Creates an Audio  which will cause a Toast Notification to play the specified song.

        .EXAMPLE
        New-BTAudio -Silent

        Creates an Audio  which will cause a Toast Notification to be silent.

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTAudio.md
    #>

    [CmdletBinding(DefaultParameterSetName = 'StandardSound',
                   SupportsShouldProcess   = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTAudio.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastAudio])]
    param (
        # Specifies one of the built in Microsoft notification sounds.
        #
        # This paramater takes the full form of the sounds, in the form of a uri. The New-BurntToastNotification function simplifies this, so be aware of the difference.
        [Parameter(Mandatory,
                   ParameterSetName = 'StandardSound')]
        [ValidateSet('ms-winsoundevent:Notification.Default',
                     'ms-winsoundevent:Notification.IM',
                     'ms-winsoundevent:Notification.Mail',
                     'ms-winsoundevent:Notification.Reminder',
                     'ms-winsoundevent:Notification.SMS',
                     'ms-winsoundevent:Notification.Looping.Alarm',
                     'ms-winsoundevent:Notification.Looping.Alarm2',
                     'ms-winsoundevent:Notification.Looping.Alarm3',
                     'ms-winsoundevent:Notification.Looping.Alarm4',
                     'ms-winsoundevent:Notification.Looping.Alarm5',
                     'ms-winsoundevent:Notification.Looping.Alarm6',
                     'ms-winsoundevent:Notification.Looping.Alarm7',
                     'ms-winsoundevent:Notification.Looping.Alarm8',
                     'ms-winsoundevent:Notification.Looping.Alarm9',
                     'ms-winsoundevent:Notification.Looping.Alarm10',
                     'ms-winsoundevent:Notification.Looping.Call',
                     'ms-winsoundevent:Notification.Looping.Call2',
                     'ms-winsoundevent:Notification.Looping.Call3',
                     'ms-winsoundevent:Notification.Looping.Call4',
                     'ms-winsoundevent:Notification.Looping.Call5',
                     'ms-winsoundevent:Notification.Looping.Call6',
                     'ms-winsoundevent:Notification.Looping.Call7',
                     'ms-winsoundevent:Notification.Looping.Call8',
                     'ms-winsoundevent:Notification.Looping.Call9',
                     'ms-winsoundevent:Notification.Looping.Call10')]
        [uri] $Source,

        # The full path to an audio file. Supported file types include:
        #
        # *.aac
        # *.flac
        # *.m4a
        # *.mp3
        # *.wav
        # *.wma
        [Parameter(Mandatory,
                   ParameterSetName = 'CustomSound')]
        [ValidateScript({Test-BTAudioPath $_})]
        [Obsolete('Unfortunately, custom sounds no longer work and this parameter will be removed in v0.9.0. See: https://github.com/MicrosoftDocs/windows-uwp/issues/1593')]
        [string] $Path,

        # Specifies that the slected sound should play multiple times if its duration is shorter than that of the toast it accompanies.
        [Parameter(ParameterSetName = 'CustomSound')]
        [Parameter(ParameterSetName = 'StandardSound')]
        [switch] $Loop,

        # Specifies that the toast should be displayed without sound.
        [Parameter(Mandatory,
                   ParameterSetName = 'Silent')]
        [switch] $Silent
    )

    $Audio = [Microsoft.Toolkit.Uwp.Notifications.ToastAudio]::new()

    if ($Source) {
        $Audio.Src = $Source
    }

    if ($Path) {
        $Audio.Src = $Path
    }

    $Audio.Loop = $Loop
    $Audio.Silent = $Silent

    if($PSCmdlet.ShouldProcess("returning: [$($Audio.GetType().Name)]:Src=$($Audio.Src):Loop=$($Audio.Loop):Silent=$($Audio.Silent)")) {
        $Audio
    }
}
function New-BTBinding {
    <#
        .SYNOPSIS
        Creates a new Generic Toast Binding object.

        .DESCRIPTION
        The New-BTBinding function creates a new Generic Toast Binding, where you provide text, images, and other visual elements for your Toast notification.

        .INPUTS
        None

        .OUTPUTS
        ToastBindingGeneric

        .EXAMPLE
        $text1 = New-BTText -Content 'This is a test'
        $text2 = New-BTText
        $text3 = New-BTText -Content 'This more testing'
        $progress = New-BTProgressBar -Title 'Things are happening' -Status 'Working on it' -Value 0.01
        $image1 = New-BTImage -Source 'C:\BurntToast\Media\BurntToast.png'
        $image2 = New-BTImage -Source 'C:\BurntToast\Media\BurntToast.png' -AppLogoOverride -Crop Circle
        $image3 = New-BTImage -Source 'C:\BurntToast\Media\BurntToast.png' -HeroImage
        $binding1 = New-BTBinding -Children $text1, $text2, $text3, $image1, $progress -AppLogoOverride $image2 -HeroImage $image3

        This example uses various BurntToast functions to create a number of objects, and then create a Generic Toast Binding using them as inputs.

        .NOTES
        Credit for most of the help text for this function go to the authors of the UWPCommunityToolkit library that this module relies upon.

        Please see the originating repo here: https://github.com/Microsoft/UWPCommunityToolkit

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTBinding.md
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTBinding.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastBindingGeneric])]
    param (
        # The contents of the body of the Toast, which can include Text (New-BTText), Image (New-BTImage), Group (not yet implemented), and Progress Bar (New-BTProgressBar).
        #
        # Also, Text elements must come before any other elements. If a Text element is placed after any other element, an exception will be thrown when you try to retrieve the Toast XML content.
        #
        # And finally, certain Text properties like HintStyle aren't supported on the root children text elements, and only work inside a Group. If you use Group on devices without the Anniversary Update, the group content will simply be dropped.
        [Microsoft.Toolkit.Uwp.Notifications.IToastBindingGenericChild[]] $Children,

        # Specifies groups of content (text and images) created via New-BTColumn that are displayed as a column.
        #
        # Multiple columns can be provided and they will be displayed side by side.
        [Microsoft.Toolkit.Uwp.Notifications.AdaptiveSubgroup[]] $Column,

        # Set to "true" to allow Windows to append a query string to the image URI supplied in the Toast notification. Use this attribute if your server hosts images and can handle query strings, either by retrieving an image variant based on the query strings or by ignoring the query string and returning the image as specified without the query string. This query string specifies scale, contrast setting, and language.
        [switch] $AddImageQuery,

        # An optional override of the logo displayed on the Toast notification.
        #
        # Created using the New-BTImage function with the 'AppLogoOverride' switch.
        [Microsoft.Toolkit.Uwp.Notifications.ToastGenericAppLogo] $AppLogoOverride,

        # New in Anniversary Update: An optional text element that is displayed as attribution text.
        #
        # On devices without the Anniversary Update, this text will appear as if it's another Text element at the end of your Children list.
        [Microsoft.Toolkit.Uwp.Notifications.ToastGenericAttributionText] $Attribution,

        # A default base URI that is combined with relative URIs in image source attributes.
        [uri] $BaseUri,

        # New in Anniversary Update: An optional hero image (a visually impactful image displayed on the Toast notification).
        #
        # On devices without the Anniversary Update, the hero image will simply be ignored.
        [Microsoft.Toolkit.Uwp.Notifications.ToastGenericHeroImage] $HeroImage,

        # The target locale of the XML payload, specified as BCP-47 language tags such as "en-US" or "fr-FR". This locale is overridden by any locale specified in binding or text. If this value is a literal string, this attribute defaults to the user's UI language. If this value is a string reference, this attribute defaults to the locale chosen by Windows Runtime in resolving the string.
        [string] $Language
    )

    $Binding = [Microsoft.Toolkit.Uwp.Notifications.ToastBindingGeneric]::new()

    if ($Children) {
        foreach ($Child in $Children) {
            $Binding.Children.Add($Child)
        }
    }

    if ($Column) {
        $AdaptiveGroup = [Microsoft.Toolkit.Uwp.Notifications.AdaptiveGroup]::new()

        foreach ($Group in $Column) {
            $AdaptiveGroup.Children.Add($Group)
        }

        $Binding.Children.Add($AdaptiveGroup)
    }

    if ($AddImageQuery) {
        $Binding.AddImageQuery = $AddImageQuery
    }

    if ($AppLogoOverride) {
        $Binding.AppLogoOverride = $AppLogoOverride
    }

    if ($Attribution) {
        $Binding.Attribution = $Attribution
    }

    if ($BaseUri) {
        $Binding.BaseUri = $BaseUri
    }

    if ($HeroImage) {
        $Binding.HeroImage = $HeroImage
    }

    if ($Language) {
        $Binding.Language = $Language
    }

    if($PSCmdlet.ShouldProcess("returning: [$($Binding.GetType().Name)]:Children=$($Binding.Children.Count):AddImageQuery=$($Binding.AddImageQuery.Count):AppLogoOverride=$($Binding.AppLogoOverride.Count):Attribution=$($Binding.Attribution.Count):BaseUri=$($Binding.BaseUri.Count):HeroImage=$($Binding.HeroImage.Count):Language=$($Binding.Language.Count)")) {
        $Binding
    }
}
function New-BTButton {
    <#
        .SYNOPSIS
        Creates a new clickable button for a Toast Notification.

        .DESCRIPTION
        The New-BTButton function creates a new clickable button for a Toast Notification. Up to five buttons can be added to one Toast.

        Buttons can be fully customized with display text, images and arguments or system handled 'Snooze' and 'Dismiss' buttons.

        .INPUTS
        None
            You cannot pipe input to this function.

        .OUTPUTS
        Microsoft.Toolkit.Uwp.Notifications.ToastButton
        Microsoft.Toolkit.Uwp.Notifications.ToastButtonDismiss
        Microsoft.Toolkit.Uwp.Notifications.ToastButtonSnooze

        .EXAMPLE
        New-BTButton -Dismiss

        This command creates a button which mimmicks the act of 'swiping away' the Toast when clicked.

        .EXAMPLE
        New-BTButton -Snooze

        This command creates a button which will snooze the Toast for the system default snooze time (often 10 minutes).

        .EXAMPLE
        New-BTButton -Snooze -Content 'Sleep' -Id 'TimeSelection'

        This command creates a button which will snooze the Toast for the time selected in the SelectionBox with the ID 'TimeSelection'. The button will show the text 'Sleep' rather than 'Dismiss.'

        .EXAMPLE
        New-BTButton -Content 'Blog' -Arguments 'https://king.geek.nz'

        This command creates a button with the display text "Blog", which will launch a browser window to "http://king.geek.nz" when clicked.

        .EXAMPLE
        $Picture = 'C:\temp\example.png'
        New-BTButton -Content 'View Picture' -Arguments $Picture -ImageUri $Picture

        This example creates a button with the display text "View Picture" with a picture to the left, which will launch the default picture viewer application and load the picture when clicked.

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTButton.md
    #>

    [CmdletBinding(DefaultParametersetName = 'Button',
                   SupportsShouldProcess   = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTButton.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastButton], ParameterSetName = 'Button')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastButtonDismiss], ParameterSetName = 'Dismiss')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastButtonSnooze], ParameterSetName = 'Snooze')]

    param (
        # Specifies a system handled snooze button. When paired with a selection box the snooze time is customizable and user selectable, otherwise the system default snooze time is used.
        #
        # Display text defaults to a localized 'Snooze', but this can be overridden with the Content parameter.
        [Parameter(Mandatory,
                   ParameterSetName = 'Snooze')]
        [switch] $Snooze,

        # Specifies a system handled dismiss button. Clicking the resulting button has the same affect as 'swiping away' or otherwise dismissing the Toast.
        #
        # Display text defaults to a localized 'Dismiss', but this can be overridden with the Content parameter.
        [Parameter(Mandatory,
                   ParameterSetName = 'Dismiss')]
        [switch] $Dismiss,

        # Specifies the text to display on the button.
        [Parameter(Mandatory,
                   ParameterSetName = 'Button')]
        [Parameter(ParameterSetName = 'Dismiss')]
        [Parameter(ParameterSetName = 'Snooze')]
        [string] $Content,

        # Specifies an app defined string.
        #
        # For the purposes of BurntToast notifications this is generally the path to a file or URI and paired with the Protocol ActivationType.
        [Parameter(Mandatory,
                   ParameterSetName = 'Button')]
        [string] $Arguments,

        # Defines tne ActivationType that is trigger when the button is pressed.
        #
        # Defaults to Protocol which will open the file or URI specified in with the Arguments parameter in the rlevant system default application.
        [Parameter(ParameterSetName = 'Button')]
        [Microsoft.Toolkit.Uwp.Notifications.ToastActivationType] $ActivationType = [Microsoft.Toolkit.Uwp.Notifications.ToastActivationType]::Protocol,

        # Specifies an image icon to display on the button.
        [Parameter(ParameterSetName = 'Button')]
        [string] $ImageUri,

        # Specifies the ID of a relevant Toast control.
        #
        # Standard buttons can be paried with a text box which makes the button appear to the right of it.
        #
        # Snooze buttons can be paired with a selection box to select the ammount of time to snooze.
        [Parameter(ParameterSetName = 'Button')]
        [Parameter(ParameterSetName = 'Snooze')]
        [alias('TextBoxId', 'SelectionBoxId')]
        [string] $Id
    )

    switch ($PsCmdlet.ParameterSetName) {
        'Button' {
            $Button = [Microsoft.Toolkit.Uwp.Notifications.ToastButton]::new($Content, $Arguments)

            $Button.ActivationType = $ActivationType

            if ($Id) {
                $Button.TextBoxId = $Id
            }

            if ($ImageUri) {
                $Button.ImageUri = $ImageUri
            }
        }
        'Snooze' {

            if ($Content) {
                $Button = [Microsoft.Toolkit.Uwp.Notifications.ToastButtonSnooze]::new($Content)
            } else {
                $Button = [Microsoft.Toolkit.Uwp.Notifications.ToastButtonSnooze]::new()
            }

            if ($Id) {
                $Button.SelectionBoxId = $Id
            }
        }
        'Dismiss' {
            if ($Content) {
                $Button = [Microsoft.Toolkit.Uwp.Notifications.ToastButtonDismiss]::new($Content)
            } else {
                $Button = [Microsoft.Toolkit.Uwp.Notifications.ToastButtonDismiss]::new()
            }
        }
    }

    switch ($Button.GetType().Name) {
        ToastButton { if($PSCmdlet.ShouldProcess("returning: [$($Button.GetType().Name)]:Content=$($Button.Content):Arguments=$($Button.Arguments):ActivationType=$($Button.ActivationType):ImageUri=$($Button.ImageUri):TextBoxId=$($Button.TextBoxId)")) { $Button }}
        ToastButtonSnooze { if($PSCmdlet.ShouldProcess("returning: [$($Button.GetType().Name)]:CustomContent=$($Button.CustomContent):ImageUri=$($Button.ImageUri):SelectionBoxId=$($Button.SelectionBoxId)")) { $Button } }
        ToastButtonDismiss { if($PSCmdlet.ShouldProcess("returning: [$($Button.GetType().Name)]:CustomContent=$($Button.CustomContent):ImageUri=$($Button.ImageUri)")) { $Button } }
    }
}
function New-BTColumn {
    <#
        .SYNOPSIS
        Creates a new Column Element for Toast Notifications.

        .DESCRIPTION
        The New-BTColumn function creates a new Column Element, or Adaptive Subgroup, for Toast Notifications.

        Valid content for an Adaptive Subgroup include Adaptive Text (New-BTText) and Adaptive Images (New-BTImage).

        These columns are supplied to the Column parameter on either the New-BTBinding or New-BurntToastNotification functions.

        .INPUTS
        int
        Microsoft.Toolkit.Uwp.Notifications.IAdaptiveSubgroupChild
        Microsoft.Toolkit.Uwp.Notifications.AdaptiveSubgroupTextStacking

        You cannot pipe input to this function.

        .OUTPUTS
        Microsoft.Toolkit.Uwp.Notifications.AdaptiveSubgroup

        .EXAMPLE
        PS C:\>$HeadingText = New-BTText -Text 'Now Playing'

        PS C:\>$TitleLabel = New-BTText -Text 'Title:' -Style Base
        PS C:\>$AlbumLabel = New-BTText -Text 'Album:' -Style Base
        PS C:\>$ArtistLabel = New-BTText -Text 'Artist:' -Style Base

        PS C:\>$Title = New-BTText -Text 'soft focus' -Style BaseSubtle
        PS C:\>$Album = New-BTText -Text 'Birocratic' -Style BaseSubtle
        PS C:\>$Artist = New-BTText -Text 'beets 4 (2017)' -Style BaseSubtle

        PS C:\>$Column1 = New-BTColumn -Children $TitleLabel, $AlbumLabel, $ArtistLabel -Weight 4
        PS C:\>$Column2 = New-BTColumn -Children $Title, $Album, $Artist -Weight 6

        PS C:\>$Binding1 = New-BTBinding -Children $HeadingText -Column $Column1, $Column2
        PS C:\>$Visual1 = New-BTVisual -BindingGeneric $Binding1
        PS C:\>$Content1 = New-BTContent -Visual $Visual1

        PS C:\>Submit-BTNotification -Content $Content1

        This example results in a toast notification displaying hard coded music information.

        Two columns are created, the first containing three labels with the 'Base' text style,
        the second column contains the corresponding three peices of data that match the labels.

        These columns are have relative weights, making the label column smaller than the data column.

        The columns are added to the toast notification via the Column parameter of the New-BTBinding
        function.

        .EXAMPLE
        PS C:\>$TitleLabel = New-BTText -Text 'Title:' -Style Base
        PS C:\>$AlbumLabel = New-BTText -Text 'Album:' -Style Base
        PS C:\>$ArtistLabel = New-BTText -Text 'Artist:' -Style Base

        PS C:\>$Title = New-BTText -Text 'soft focus' -Style BaseSubtle
        PS C:\>$Album = New-BTText -Text 'Birocratic' -Style BaseSubtle
        PS C:\>$Artist = New-BTText -Text 'beets 4 (2017)' -Style BaseSubtle

        PS C:\>$Column1 = New-BTColumn -Children $TitleLabel, $AlbumLabel, $ArtistLabel -Weight 4
        PS C:\>$Column2 = New-BTColumn -Children $Title, $Album, $Artist -Weight 6

        PS C:\>New-BurntToastNotification -Text 'Now Playing' -Column $Column1, $Column2

        This example is similar to the first, except that the toast notification is created via the
        New-BurntToastNotification function rather than the component functions.

        .NOTES
        Credit for most of the help text for this function go to the authors of the WindowsCommunityToolkit library that this module relies upon.

        Please see the originating repo here: https://github.com/windows-toolkit/WindowsCommunityToolkit

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTColumn.md
    #>

    # [CmdletBinding(SupportsShouldProcess = $true)]
    [cmdletBinding(HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTColumn.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.AdaptiveSubgroup])]
    param (
        # The content to be contained within the column. Can contain text (New-BTText) and images (New-BTImage).
        [Parameter()]
        [Microsoft.Toolkit.Uwp.Notifications.IAdaptiveSubgroupChild[]] $Children,

        # Controls the width of this column in relation to other columns. A higher relative weight results in the wider column.
        [int] $Weight,

        # The vertical alignment of the content inside this column.
        [Microsoft.Toolkit.Uwp.Notifications.AdaptiveSubgroupTextStacking] $TextStacking
    )

    $AdaptiveSubgroup = [Microsoft.Toolkit.Uwp.Notifications.AdaptiveSubgroup]::new()

    if ($Children) {
        foreach ($Child in $Children) {
            $AdaptiveSubgroup.Children.Add($Child)
        }
    }

    if ($Weight) {
        $AdaptiveSubgroup.HintWeight = $Weight
    }

    if ($TextStacking) {
        $AdaptiveSubgroup.HintTextStacking = $TextStacking
    }

    #if($PSCmdlet.ShouldProcess("returning: [$($TextObj.GetType().Name)]:Text=$($TextObj.Text.BindingName):HintMaxLines=$($TextObj.HintMaxLines):HintMinLines=$($TextObj.HintMinLines):HintWrap=$($TextObj.HintWrap):HintAlign=$($TextObj.HintAlign):HintStyle=$($TextObj.HintStyle):Language=$($TextObj.Language)")) {
    $AdaptiveSubgroup
    #}
}
function New-BTContent {
    <#
        .SYNOPSIS
        Creates a new Toast Content object.

        .DESCRIPTION
        The New-BTContent function creates a new Toast Content object which is the Base Toast element, which contains at least a visual element.

        .INPUTS
        None

        .OUTPUTS
        ToastContent

        .EXAMPLE
        $binding1 = New-BTBinding -Children $text1, $text2 -AppLogoOverride $image2
        $visual1 = New-BTVisual -BindingGeneric $binding1
        $content1 = New-BTContent -Visual $visual1

        This example combines numerous objects created via BurntToast functions into a binding, then a visual element and finally into a content object.

        The resultant object can now be displayed using the Submit-BTNotification function.

        .EXAMPLE
        $content1 = New-BTContent -Visual $visual1 -ActivationType Protocol -Launch 'https://google.com'

        This command takes a pre-existing visual object and also specifies options required to launch a browser on the Google homepage when clicking the toast.

        .NOTES
        Credit for most of the help text for this function go to the authors of the UWPCommunityToolkit library that this module relies upon.

        Please see the originating repo here: https://github.com/Microsoft/UWPCommunityToolkit

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTContent.md
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTContent.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastContent])]
    param (
        # Optionally create custom actions with buttons and inputs (New-BTAction.)
        [Microsoft.Toolkit.Uwp.Notifications.IToastActions] $Actions,

        # Specifies what activation type will be used when the user clicks the body of this Toast.
        [Microsoft.Toolkit.Uwp.Notifications.ToastActivationType] $ActivationType,

        # Specify custom audio options (New-BTAudio.)
        [Microsoft.Toolkit.Uwp.Notifications.ToastAudio] $Audio,

        # The amount of time the Toast should display. You typically should use the Scenario attribute instead, which impacts how long a Toast stays on screen.
        [Microsoft.Toolkit.Uwp.Notifications.ToastDuration] $Duration,

        # New in Creators Update: Specifies an optional header for the toast notification (New-BTHeader.)
        [Microsoft.Toolkit.Uwp.Notifications.ToastHeader] $Header,

        # A string that is passed to the application when it is activated by the Toast. The format and contents of this string are defined by the app for its own use. When the user taps or clicks the Toast to launch its associated app, the launch string provides the context to the app that allows it to show the user a view relevant to the Toast content, rather than launching in its default way.
        [string] $Launch,

        # Specify the scenario, to make the Toast behave like an alarm, reminder, or more.
        [Microsoft.Toolkit.Uwp.Notifications.ToastScenario] $Scenario,

        # Specify the visual element object, created with the New-BTVisual function.
        [Parameter(Mandatory)]
        [Microsoft.Toolkit.Uwp.Notifications.ToastVisual] $Visual,

        [Microsoft.Toolkit.Uwp.Notifications.ToastPeople] $ToastPeople,

        [datetime] $CustomTimestamp
    )

    $ToastContent = [Microsoft.Toolkit.Uwp.Notifications.ToastContent]::new()

    if ($Actions) {
        $ToastContent.Actions = $Actions
    }

    if ($ActivationType) {
        $ToastContent.ActivationType = $ActivationType
    }

    if ($Audio) {
        $ToastContent.Audio = $Audio
    }

    if ($Duration) {
        $ToastContent.Duration = $Duration
    }

    if ($Header) {
        $ToastContent.Header = $Header
    }

    if ($Launch) {
        $ToastContent.Launch = $Launch
    }

    if ($Scenario) {
        $ToastContent.Scenario = $Scenario
    }

    if ($Visual) {
        $ToastContent.Visual = $Visual
    }

    if ($Actions) {
        $ToastContent.Actions = $Actions
    }

    if ($ToastPeople) {
        $ToastContent.HintPeople = $ToastPeople
    }

    if ($CustomTimestamp) {
        $ToastContent.DisplayTimestamp = $CustomTimestamp
    }

    if($PSCmdlet.ShouldProcess( "returning: [$($ToastContent.GetType().Name)] with XML: $($ToastContent.GetContent())" )) {
        $ToastContent
    }
}
function New-BTContextMenuItem {
    <#
        .SYNOPSIS
        Creates a Context Menu Item object.

        .DESCRIPTION
        The New-BTContextMenuItem function creates a Context Menu Item object.

        .INPUTS
        None

        .OUTPUTS
        ToastContextMenuItem

        .EXAMPLE
        New-BTContextMenuItem -Content 'Google' -Arguments 'https://google.com' -ActivationType Protocol

        This command creates a new Context Menu Item object with the specified properties.

        .NOTES
        Credit for most of the help text for this function go to the authors of the UWPCommunityToolkit library that this module relies upon.

        Please see the originating repo here: https://github.com/Microsoft/UWPCommunityToolkit

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTContextMenuItem.md
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTContextMenuItem.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastContextMenuItem])]

    param (
        # The text to display on the menu item.
        [Parameter(Mandatory)]
        [string] $Content,

        # App-defined string of arguments that the app can later retrieve once it is activated when the user clicks the menu item.
        [Parameter(Mandatory)]
        [string] $Arguments,

        # Controls what type of activation this menu item will use when clicked. Defaults to Foreground.
        [Parameter()]
        [Microsoft.Toolkit.Uwp.Notifications.ToastActivationType] $ActivationType
    )

    $MenuItem = [Microsoft.Toolkit.Uwp.Notifications.ToastContextMenuItem]::new($Content, $Arguments)

    if ($ActivationType) {
        $MenuItem.ActivationType = $ActivationType
    }

    if($PSCmdlet.ShouldProcess("returning: [$($MenuItem.GetType().Name)]:Content=$($MenuItem.Content):Arguments=$($MenuItem.Arguments):ActivationType=$($MenuItem.ActivationType)")) {
        $MenuItem
    }
}
function New-BTHeader {
    <#
        .SYNOPSIS
        Creates a new toast notification header.

        .DESCRIPTION
        The New-BTHeader function creates a new toast notification header for a Toast Notification.

        These headers are diaplyed at the top of a toast and are also used to categorize toasts in the Action Center.

        .INPUTS
        None
            You cannot pipe input to this function.

        .OUTPUTS
        Microsoft.Toolkit.Uwp.Notifications.ToastHeader

        .EXAMPLE
        New-BTHeader -Title 'First Category'

        This command creates a Toast Header object, which will be displayed with the text "First Category."

        .EXAMPLE
        New-BTHeader -Id '001' -Title 'Stack Overflow Questions' -Arguments 'http://stackoverflow.com/'

        This command creates a Toast Header object, which will be displayed with the text "First Category."

        Clicking the header will take the user to the Stack Overflow website.

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTHeader.md
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTHeader.md')]

    param (
        # Unique string that identifies a header. If a new Id is provided, the system will treat the header as a new header even if it has the same display text as a previous header.
        #
        # It is possible to update a header's display text by re-using the Id but changing the title.
        [Parameter()]
        [string] $Id = 'ID' + (New-Guid).ToString().Replace('-','').ToUpper(),

        # The header string that is displayed to the user.
        [Parameter(Mandatory)]
        [string] $Title,

        # Specifies an app defined string.
        #
        # For the purposes of BurntToast notifications this is generally the path to a file or URI and paired with the Protocol ActivationType.
        [Parameter()]
        [string] $Arguments,

        # Defines tne ActivationType that is trigger when the button is pressed.
        #
        # Defaults to Protocol which will open the file or URI specified in with the Arguments parameter in the relevant system default application.
        [Parameter()]
        [Microsoft.Toolkit.Uwp.Notifications.ToastActivationType] $ActivationType = [Microsoft.Toolkit.Uwp.Notifications.ToastActivationType]::Protocol
    )

    $Header = [Microsoft.Toolkit.Uwp.Notifications.ToastHeader]::new($Id, ($Title -replace '\x01'), $Arguments)

    if ($ActivationType) {
        $Header.ActivationType = $ActivationType
    }

    if($PSCmdlet.ShouldProcess("returning: [$($Header.GetType().Name)]:Id=$($Header.Id):Title=$($Header.Title):Arguments=$($Header.Arguments):ActivationType=$($Header.ActivationType)")) {
        $Header
    }
}
function New-BTImage {
    <#
        .SYNOPSIS
        Creates a new Image Element for Toast Notifications.

        .DESCRIPTION
        The New-BTImageElement function creates a new Image Element for Toast Notifications.

        You can use the parameters of New-BTImageElement to specify the source image, alt text, placement on the Toast Notification and crop shape.

        .INPUTS
        None

        .OUTPUTS
        AdaptiveImage
        ToastGenericAppLogo
        ToastGenericHeroImage

        .EXAMPLE
        $image1 = New-BTImage -Source 'C:\Media\BurntToast.png'

        This command creates a standard image object to be included in the main body of a toast.

        .EXAMPLE
        $image2 = New-BTImage -Source 'C:\Media\BurntToast.png' -AppLogoOverride -Crop Circle

        This command creates an image object to be used as the logo on a toast, cropped into the shape fo a circle.

        .EXAMPLE
        $image3 = New-BTImage -Source 'C:\Media\BurntToast.png' -HeroImage

        This command creates an inmage to be used as a toast's hero image.

        .NOTES
        Credit for most of the help text for this function go to the authors of the UWPCommunityToolkit library that this module relies upon.

        Please see the originating repo here: https://github.com/Microsoft/UWPCommunityToolkit

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTImage.md
    #>

    [CmdletBinding(DefaultParameterSetName = 'Image',
                   SupportsShouldProcess   = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTImage.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.AdaptiveImage], ParameterSetName = 'Image')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastGenericAppLogo], ParameterSetName = 'AppLogo')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastGenericHeroImage], ParameterSetName = 'Hero')]

    param (
        # The URI of the image. Can be from your application package, application data, or the internet. Internet images must be less than 200 KB in size.
        [string] $Source = $Script:DefaultImage,

        # A description of the image, for users of assistive technologies.
        [string] $AlternateText,

        # Specifies that the image is to be used as the logo on the toast.
        [Parameter(Mandatory,
            ParameterSetName = 'AppLogo')]
        [switch] $AppLogoOverride,

        # Specifies that the image is to be used as the hero image on the toast.
        [Parameter(Mandatory,
            ParameterSetName = 'Hero')]
        [switch] $HeroImage,

        # The horizontal alignment of the image. For Toast, this is only supported when inside a group (not yet implemented.)
        [Parameter(ParameterSetName = 'Image')]
        [Microsoft.Toolkit.Uwp.Notifications.AdaptiveImageAlign] $Align,

        # Control the desired cropping of the image. Supported on Toast since Anniversary Update.
        [Parameter(ParameterSetName = 'Image')]
        [Parameter(ParameterSetName = 'AppLogo')]
        [Microsoft.Toolkit.Uwp.Notifications.AdaptiveImageCrop] $Crop,

        # By default, images have an 8px margin around them. You can remove this margin by including this switch. Supported on Toast since Anniversary Update.
        [Parameter(ParameterSetName = 'Image')]
        [switch] $RemoveMargin,

        # Set to true to allow Windows to append a query string to the image URI supplied in the Tile notification. Use this attribute if your server hosts images and can handle query strings, either by retrieving an image variant based on the query strings or by ignoring the query string and returning the image as specified without the query string. This query string specifies scale, contrast setting, and language.
        [switch] $AddImageQuery,

        [switch] $IgnoreCache
    )

    switch ($PsCmdlet.ParameterSetName) {
        'Image' {
            $Image = [Microsoft.Toolkit.Uwp.Notifications.AdaptiveImage]::new()

            if ($Align) {
                $Image.HintAlign = $Align
            }

            if ($Crop) {
                $Image.HintCrop = $Crop
            }

            $Image.HintRemoveMargin = $RemoveMargin
        }
        'AppLogo' {
            $Image = [Microsoft.Toolkit.Uwp.Notifications.ToastGenericAppLogo]::new()

            if ($Crop) {
                $Image.HintCrop = $Crop
            }
        }
        'Hero' {
            $Image = [Microsoft.Toolkit.Uwp.Notifications.ToastGenericHeroImage]::new()
        }
    }

    if ($Source) {
        $Image.Source = if ($IgnoreCache) {
            Optimize-BTImageSource -Source $Source -ForceRefresh
        } else {
            Optimize-BTImageSource -Source $Source
        }

    }

    if ($AlternateText) {
        $Image.AlternateText = $AlternateText
    }

    if ($AddImageQuery) {
        $Image.AddImageQuery = $AddImageQuery
    }

    switch ($Image.GetType().Name) {
        AdaptiveImage { if($PSCmdlet.ShouldProcess("returning: [$($Image.GetType().Name)]:Source=$($Image.Source):AlternateText=$($Image.AlternateText):HintCrop=$($Image.HintCrop):HintRemoveMargin=$($Image.HintRemoveMargin):HintAlign=$($Image.HintAlign):AddImageQuery=$($Image.AddImageQuery)")) { $Image } }
        ToastGenericAppLogo { if($PSCmdlet.ShouldProcess("returning: [$($Image.GetType().Name)]:Source=$($Image.Source):AlternateText=$($Image.AlternateText):HintCrop=$($Image.HintCrop):AddImageQuery=$($Image.AddImageQuery)")) { $Image } }
        ToastGenericHeroImage { if($PSCmdlet.ShouldProcess("returning: [$($Image.GetType().Name)]:Source=$($Image.Source):AlternateText=$($Image.AlternateText):AddImageQuery=$($Image.AddImageQuery)")) { $Image } }
    }
}
function New-BTInput {
    <#
        .SYNOPSIS
        Creates an input element on a Toast notification.

        .DESCRIPTION
        The New-BTInput function creates an input element on a Toast notification.

        Returned object is either a TextBox for users to type text into or SelectionBox to users to select from a list of options.

        .INPUTS
        None

        .OUTPUTS
        ToastTextBox
        ToastSelectionBox

        .EXAMPLE
        New-BTInput -Id Reply001 -Title 'Type a reply:'

        This command creates a new text box for a user to type a reply. (n.b. this sort of functionality probably won't work through BurntToast as PowerShell cannot, currently, subscribe to WinRT events.)

        .EXAMPLE
        New-BTInput -Id 'Selection001' -DefaultSelectionBoxItemId 'Item5' -Items $Select1, $Select2, $Select3, $Select4, $Select5

        This command creates a new selection box containing five options and specifying the ID of one of the options as the default.

        .NOTES
        Credit for most of the help text for this function go to the authors of the UWPCommunityToolkit library that this module relies upon.

        Please see the originating repo here: https://github.com/Microsoft/UWPCommunityToolkit

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTInput.md
    #>

    [CmdletBinding(DefaultParametersetName = 'Text',
                   SupportsShouldProcess   = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTInput.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastTextBox], ParametersetName = 'Text')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastSelectionBox], ParametersetName = 'Text')]

    param (
        # Used so that developers can retrieve user input once the app is activated.
        [Parameter(Mandatory)]
        [string] $Id,

        # Title text to display above the element.
        [Parameter()]
        [string] $Title,

        # Placeholder text to be displayed on the text box when the user hasn't typed any text yet.
        [Parameter(ParametersetName = 'Text')]
        [string] $PlaceholderContent,

        # The initial text to place in the text box. Leave this null for a blank text box.
        [Parameter(ParametersetName = 'Text')]
        [string] $DefaultInput,

        # This controls which item is selected by default, and refers to the Id property of a Selection Box Item (New-BTSelectionBoxItem.)
        #
        # If you do not provide this, the default selection will be empty (user sees nothing).
        [Parameter(ParametersetName = 'Selection')]
        [string] $DefaultSelectionBoxItemId,

        # The selection items that the user can pick from in this SelectionBox. Only 5 items can be added.
        [Parameter(Mandatory,
                   ParametersetName = 'Selection')]
        [Microsoft.Toolkit.Uwp.Notifications.ToastSelectionBoxItem[]] $Items
    )

    switch ($PsCmdlet.ParameterSetName) {
        'Text' {
            $ToastInput = [Microsoft.Toolkit.Uwp.Notifications.ToastTextBox]::new($Id)

            if ($PlaceholderContent) {
                $ToastInput.PlaceholderContent = $PlaceholderContent
            }

            if ($DefaultInput) {
                $ToastInput.DefaultInput = $DefaultInput
            }
        }
        'Selection' {
            $ToastInput = [Microsoft.Toolkit.Uwp.Notifications.ToastSelectionBox]::new($Id)

            if ($DefaultSelectionBoxItemId) {
                $ToastInput.DefaultSelectionBoxItemId = $DefaultSelectionBoxItemId
            }

            foreach ($Item in $Items) {
                $ToastInput.Items.Add($Item)
            }
        }
    }

    if ($Title) {
        $ToastInput.Title = $Title
    }

    switch ($ToastInput.GetType().Name) {
        ToastTextBox { if($PSCmdlet.ShouldProcess("returning: [$($ToastInput.GetType().Name)]:Id=$($ToastInput.Id):Title=$($ToastInput.Title):PlaceholderContent=$($ToastInput.PlaceholderContent):DefaultInput=$($ToastInput.DefaultInput)")) { $ToastInput } }
        ToastSelectionBox { if($PSCmdlet.ShouldProcess("returning: [$($ToastInput.GetType().Name)]:Id=$($ToastInput.Id):Title=$($ToastInput.Title):DefaultSelectionBoxItemId=$($ToastInput.DefaultSelectionBoxItemId):DefaultInput=$($ToastInput.Items.Count)")) { $ToastInput } }
    }
}
function New-BTProgressBar {
    <#
        .SYNOPSIS
        Creates a new Progress Bar Element for Toast Notifications.

        .DESCRIPTION
        The New-BTProgressBar function creates a new Progress Bar Element for Toast Notifications.

        You must specify the status and value for the progress bar and can optionally give the bar a title and override the automatic text representiation of the progress.

        .INPUTS
        String

        You cannot pipe input to this cmdlet.

        .OUTPUTS
        Microsoft.Toolkit.Uwp.Notifications.AdaptiveProgressBar

        .EXAMPLE
        New-BTProgressBar -Status 'Copying files' -Value 0.2

        This command creates a Progress Bar that is 20% full with the current status of 'Copying files' and the (default) text 20% displayed underneath.

        .EXAMPLE
        New-BTProgressBar -Status 'Copying files' -Indeterminate

        This command creates a Progress Bar with an 'indeterminate' animation rather than a bar filled to a certain percentage.

        .EXAMPLE
        New-BTProgressBar -Status 'Copying files' -Value 0.2 -ValueDisplay '4/20 files complete'

        This command creates a Progress Bar that is 20% full with the current status of 'Copying files' and the default text displayed underneath overridden to '4/20 files complete.'

        .EXAMPLE
        New-BTProgressBar -Title 'File Copy' -Status 'Copying files' -Value 0.2

        This example creates a Progress Bar that is 20% full with the current status of 'Copying files' and the (default) text 20% displayed underneath.

        The Progress Bar is displayed under the title 'File Copy.'

        .EXAMPLE
        $Progress = New-BTProgressBar -Status 'Copying files' -Value 0.2
        New-BurntToastNotification -Text 'File copy script running', 'More details!' -ProgressBar $Progress

        This example creates a Toast Notification which will include a progress bar.

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTProgressBar.md
    #>

    [CmdletBinding(DefaultParameterSetName = 'Determinate',
                   SupportsShouldProcess   = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTProgressBar.md')]
    param (
        # The text displayed above the progress bar. Generally used to give context around what the bar represents.
        [string] $Title,

        # The text displayed under the progress bar. Used to show the current status of the operation being performed.
        #
        # Examples include: Running, Paused, Stopped, Finished.
        [Parameter(Mandatory)]
        [string] $Status,

        # Used where the percentage complete is unknown, the resulting progress bar displays a system generated animation rather than a filled bar.
        #
        # Cannot be used at the same time as a set Value.
        [Parameter(Mandatory,
                   ParameterSetName = 'Indeterminate')]
        [switch] $Indeterminate,

        # Specifies the percentage to fill the progress bar as represented by a double, between 0 and 1 (inclusive.)
        #
        # For example 0.4 is 40%, 1 is 100%.
        [Parameter(Mandatory,
                   ParameterSetName = 'Determinate')]
        #[ValidateRange(0.0, 1.0)]
        $Value,

        # A string that replaces the default text representation of the percentage complete.
        #
        # The default text for the value 0.2 would be '20%', this parameter replaces this text with something of your own choice.
        [string] $ValueDisplay
    )

    $ProgressBar = [Microsoft.Toolkit.Uwp.Notifications.AdaptiveProgressBar]::new()

    $ProgressBar.Status = $Status

    if ($PSCmdlet.ParameterSetName -eq 'Determinate') {
        $ProgressBar.Value = [Microsoft.Toolkit.Uwp.Notifications.BindableProgressBarValue]::new($Value)
    } else {
        $ProgressBar.Value = 'indeterminate'
    }


    if ($Title) {
        $ProgressBar.Title = $Title
    }

    if ($ValueDisplay) {
        $ProgressBar.ValueStringOverride = $ValueDisplay
    }

    if($PSCmdlet.ShouldProcess("returning: [$($ProgressBar.GetType().Name)]:Status=$($ProgressBar.Status.BindingName):Title=$($ProgressBar.Title.BindingName):Value=$($ProgressBar.Value.BindingName):ValueStringOverride=$($ProgressBar.ValueStringOverride.BindingName)")) {
        $ProgressBar
    }
}
function New-BTSelectionBoxItem {
    <#
        .SYNOPSIS
        Creates a selection box item.

        .DESCRIPTION
        The New-BTSelectionBoxItem function creates a selection box item, for inclusion in a selection box created with New-BTInput.

        .INPUTS
        None

        .OUTPUTS
        ToastSelectionBoxItem

        .EXAMPLE
        $Select1 = New-BTSelectionBoxItem -Id 'Item1' -Content 'First option in the list'

        This command creates a new Selection Box Item object which can now be used with the New-BTInput function.

        .NOTES
        Credit for most of the help text for this function go to the authors of the UWPCommunityToolkit library that this module relies upon.

        Please see the originating repo here: https://github.com/Microsoft/UWPCommunityToolkit

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTSelectionBoxItem.md
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTSelectionBoxItem.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastSelectionBoxItem])]

    param (
        # Developer-provided ID that the developer uses later to retrieve input when the Toast is interacted with.
        #
        # Can also be provided to a selection box to identify the default selection.
        [Parameter(Mandatory)]
        [string] $Id,

        # String that is displayed on the selection item. This is what the user sees.
        [Parameter(Mandatory)]
        [string] $Content
    )

    $SelectionBoxItem = [Microsoft.Toolkit.Uwp.Notifications.ToastSelectionBoxItem]::new($Id, $Content)

    if($PSCmdlet.ShouldProcess("returning: [$($SelectionBoxItem.GetType().Name)]:Id=$($SelectionBoxItem.Id):Content=$($SelectionBoxItem.Content)")) {
        $SelectionBoxItem
    }
}
function New-BTShoulderTapBinding {
    <#
        .SYNOPSIS
        Creates a new Shoulder Tap Binding object.

        .DESCRIPTION
        The New-BTShoulderTapBinding function creates a new Shoulder Tap Binding Object, with which you can specify the Image to be displayed.

        .INPUTS
        LOTS...

        .OUTPUTS
        ToastBindingShoulderTap

        .EXAMPLE
        $Image = New-BTShoulderTapImage -Source 'https://www.route66sodas.com/wp-content/uploads/2019/01/Alert.gif'
        New-BTShoulderTapBinding -Image $Image

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTShoulderTapBinding.md
    #>
    [CmdletBinding(HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTShoulderTapBinding.md')]
    [Obsolete('This cmdlet is being deprecated, it will be removed in v0.9.0')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastBindingShoulderTap])]
    param (
        # The image displayed in the Shoulder Tap notification, this object is created using the New-BTShoulderTapImage function.
        [Parameter(Mandatory)]
        [Microsoft.Toolkit.Uwp.Notifications.ToastShoulderTapImage] $Image,

        # Set to "true" to allow Windows to append a query string to the image URI supplied in the Toast notification. Use this attribute if your server hosts images and can handle query strings, either by retrieving an image variant based on the query strings or by ignoring the query string and returning the image as specified without the query string. This query string specifies scale, contrast setting, and language.
        [switch] $AddImageQuery,

        # A default base URI that is combined with relative URIs in image source attributes.
        [uri] $BaseUri,

        # The target locale of the XML payload, specified as BCP-47 language tags such as "en-US" or "fr-FR". This locale is overridden by any locale specified in binding or text. If this value is a literal string, this attribute defaults to the user's UI language. If this value is a string reference, this attribute defaults to the locale chosen by Windows Runtime in resolving the string.
        [string] $Language
    )

    $Binding = [Microsoft.Toolkit.Uwp.Notifications.ToastBindingShoulderTap]::new()

    $Binding.Image = $Image

    if ($AddImageQuery.IsPresent) {
        $Binding.AddImageQuery = $true
    }

    if ($BaseUri) {
        $Binding.BaseUri = $BaseUri
    }

    if ($Language) {
        $Binding.Language = $Language
    }

    $Binding
}
function New-BTShoulderTapImage {
    <#
        .SYNOPSIS
        Creates a new ToastShoulderTapImage object.

        .DESCRIPTION
        The New-BTShoulderTapImage function creates a new ToastShoulderTapImage object.

        The image can be a static image or anitmated gif, specified using the Source parameter. It can also be a spritesheet.

        This function is mainly used internally, as it is abstracted away when using New-BurntToastShoulderTap.

        .INPUTS
        LOTS

        .OUTPUTS
        ToastShoulderTapImage

        .EXAMPLE
        $Image = New-BTShoulderTapImage -Source 'https://www.route66sodas.com/wp-content/uploads/2019/01/Alert.gif'

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTShoulderTapImage.md
    #>

    [Obsolete('This cmdlet is being deprecated, it will be removed in v0.9.0')]
    [CmdletBinding(DefaultParameterSetName = 'Image',
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTShoulderTapImage.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastShoulderTapImage])]

    param (
        [Parameter(ParameterSetName = 'Image',
                   Mandatory)]
        [string] $Source,

        [Parameter(ParameterSetName = 'Sprite',
                   Mandatory)]
        [string] $SpriteSheet,

        [Parameter(ParameterSetName = 'Sprite',
                   Mandatory)]
        [uint32] $FrameHeight,

        [Parameter(ParameterSetName = 'Sprite',
                   Mandatory)]
        [uint32] $FPS,

        [Parameter(ParameterSetName = 'Sprite')]
        [uint32] $StartingFrame,

        [string] $AlternateText,

        [switch] $AddImageQuery
    )

    $ShoulderTapImage = [Microsoft.Toolkit.Uwp.Notifications.ToastShoulderTapImage]::new()

    if ($PSCmdlet.ParameterSetName -eq 'Sprite') {
        $Sprite = [Microsoft.Toolkit.Uwp.Notifications.ToastSpriteSheet]::new()

        $Sprite.Source = Optimize-BTImageSource -Source $SpriteSheet
        $Sprite.FrameHeight = $FrameHeight
        $Sprite.Fps = $FPS

        if ($StartingFrame) {
            $Sprite.StartingFrame = $StartingFrame
        }

        $ShoulderTapImage.SpriteSheet = $Sprite
    } else {
        $ShoulderTapImage.Source = Optimize-BTImageSource -Source $Source
    }

    if ($AddImageQuery.IsPresent) {
        $ShoulderTapImage.AddImageQuery = $true
    }

    if ($AlternateText) {
        $ShoulderTapImage.AlternateText = $AlternateText
    }

    $ShoulderTapImage
}
function New-BTShoulderTapPeople {
    <#
        .SYNOPSIS
        Creates a new ToastPeople object.

        .DESCRIPTION
        The New-BTShoulderTapPeople function creates a new ToastPeople object. This object identifies a user from the People app which has been pinned to the Windows Taskbar.

        This function is mainly used internally, as it is abstracted away when using New-BurntToastShoulderTap.

        .INPUTS
        STRING

        .OUTPUTS
        ToastPeople

        .EXAMPLE
        $Person = New-BTShoulderTapPeople -Email 'bob@example.com'

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTShoulderTapPeople.md
    #>

    [Obsolete('This cmdlet is being deprecated, it will be removed in v0.9.0')]
    [CmdletBinding(DefaultParameterSetName = 'Email',
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTShoulderTapPeople.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastPeople])]

    param (
        # The email address which matches a contact in the Contacts app.
        [Parameter(ParameterSetName = 'Email',
                   Mandatory)]
        [string] $Email,

        # The remote identifier which matches a contact in the Contacts app.
        [Parameter(ParameterSetName = 'RemoteId',
                   Mandatory)]
        [string] $RemoteId,

        # The phone number which matches a contact in the Contacts app.
        [Parameter(ParameterSetName = 'PhoneNumber',
                   Mandatory)]
        [string] $PhoneNumber
    )

    $ToastPeople = [Microsoft.Toolkit.Uwp.Notifications.ToastPeople]::new()

    switch ($PSCmdlet.ParameterSetName) {
        Email {$ToastPeople.EmailAddress = $Email}
        RemoteId {$ToastPeople.RemoteId = $RemoteId}
        PhoneNumber {$ToastPeople.PhoneNumber = $PhoneNumber}
    }

    $ToastPeople
}
function New-BTText {
    <#
        .SYNOPSIS
        Creates a new Text Element for Toast Notifications.

        .DESCRIPTION
        The New-BTText function creates a new Text Element for Toast Notifications.

        You can specify the text you want displayed in a Toast Notification as a string, or run the function without a paramter for a blank line.

        Each Text Element is the equivalent of one line in on a Toast Notification, long lines will wrap.

        .INPUTS
        String

        You cannot pipe input to this function.

        .OUTPUTS
        Text

        .EXAMPLE
        New-BTText -Content 'This is a line with text!'

        Creates a Text Element that will show the string 'This is a line with text!' on a Toast Notification.

        .EXAMPLE
        New-BTText

        Creates a Text Element that will show a blank line on a Toast Notification.

        .NOTES
        TODO: Implement hint-style (https://blogs.msdn.microsoft.com/tiles_and_toasts/2015/06/30/adaptive-tile-templates-schema-and-documentation/)

        Credit for most of the help text for this function go to the authors of the UWPCommunityToolkit library that this module relies upon.

        Please see the originating repo here: https://github.com/Microsoft/UWPCommunityToolkit

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTText.md
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTText.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.AdaptiveText])]
    param (
        # The text to display. Data binding support added in Creators Update, only works for toast top-level text elements (But appears to not be working via PowerShell yet.)
        [Parameter()]
        [alias('Content')]
        [string] $Text,

        # The maximum number of lines the text element is allowed to display. For Toasts, top-level text elements will have varying max line amounts (and in the Anniversary Update you can change the max lines).
        #
        # Text on a Toast inside a group (not yet implemented) will behave identically to Tiles (default to infinity).
        [int] $MaxLines,

        # The minimum number of lines the text element must display. Note that for Toast, this property will only take effect if the text is inside a group (not yet implemented.)
        [int] $MinLines,

        # Supply this switch to enable text wrapping. For Toasts, this is true on top-level text elements, and false inside a group (not yet implemented.)
        #
        # Note that for Toast, setting wrap will only take effect if the text is inside a group (you can use HintMaxLines = 1 to prevent top-level text elements from wrapping).
        [switch] $Wrap,

        # The horizontal alignment of the text. Note that for Toast, this property will only take effect if the text is inside a group (not yet implemented.)
        [Microsoft.Toolkit.Uwp.Notifications.AdaptiveTextAlign] $Align,

        # The style controls the text's font size, weight, and opacity. Note that for Toast, the style will only take effect if the text is inside a group (not yet implemented.)
        [Microsoft.Toolkit.Uwp.Notifications.AdaptiveTextStyle] $Style,

        # The target locale of the XML payload, specified as a BCP-47 language tags such as "en-US" or "fr-FR". The locale specified here overrides any other specified locale, such as that in binding or visual. If this value is a literal string, this attribute defaults to the user's UI language. If this value is a string reference, this attribute defaults to the locale chosen by Windows Runtime in resolving the string.
        [string] $Language,

        [switch] $Bind
    )

    $TextObj = [Microsoft.Toolkit.Uwp.Notifications.AdaptiveText]::new()

    if ($Text) {
        $TextObj.Text = $Text -replace '\x01'
    }

    if ($MaxLines) {
        $TextObj.HintMaxLines = $MaxLines
    }

    if ($MinLines) {
        $TextObj.HintMinLines = $MinLines
    }

    if ($Wrap) {
        $TextObj.HintWrap = $Wrap
    }

    if ($Align) {
        $TextObj.HintAlign = $Align
    }

    if ($Style) {
        $TextObj.HintStyle = $Style
    }

    if ($Language) {
        $TextObj.Language = $Language
    }

    if($PSCmdlet.ShouldProcess("returning: [$($TextObj.GetType().Name)]:Text=$($TextObj.Text.BindingName):HintMaxLines=$($TextObj.HintMaxLines):HintMinLines=$($TextObj.HintMinLines):HintWrap=$($TextObj.HintWrap):HintAlign=$($TextObj.HintAlign):HintStyle=$($TextObj.HintStyle):Language=$($TextObj.Language)")) {
        $TextObj
    }
}
function New-BTVisual {
    <#
        .SYNOPSIS
        Creates a new visual element for toast notifications.

        .DESCRIPTION
        The New-BTVisual function creates a new visual element for toast notifications, which defines all of the visual aspects of a toast.

        .INPUTS
        None

        .OUTPUTS
        ToastVisual

        .EXAMPLE
        New-BTVisual -BindingGeneric $Binding1

        This command creates a new Visual element taking a previously configured binding element as input.

        .NOTES
        Credit for most of the help text for this function go to the authors of the UWPCommunityToolkit library that this module relies upon.

        Please see the originating repo here: https://github.com/Microsoft/UWPCommunityToolkit

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BTVisual.md
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BTVisual.md')]
    [OutputType([Microsoft.Toolkit.Uwp.Notifications.ToastVisual])]
    param (
        # The generic Toast binding, which can be rendered on all devices. This binding is created using the New-BTBinding function.
        [Parameter(Mandatory)]
        [Microsoft.Toolkit.Uwp.Notifications.ToastBindingGeneric] $BindingGeneric,

        [Microsoft.Toolkit.Uwp.Notifications.ToastBindingShoulderTap] $BindingShoulderTap,

        # Specify this switch to allow Windows to append a query string to the image URI supplied in the Toast notification. Use this attribute if your server hosts images and can handle query strings, either by retrieving an image variant based on the query strings or by ignoring the query string and returning the image as specified without the query string. This query string specifies scale, contrast setting, and language.
        [switch] $AddImageQuery,

        # A default base URI that is combined with relative URIs in image source attributes.
        [uri] $BaseUri,

        # The target locale of the XML payload, specified as BCP-47 language tags such as "en-US" or "fr-FR". This locale is overridden by any locale specified in binding or text. If this value is a literal string, this attribute defaults to the user's UI language. If this value is a string reference, this attribute defaults to the locale chosen by Windows Runtime in resolving the string.
        [string] $Language
    )

    $Visual = [Microsoft.Toolkit.Uwp.Notifications.ToastVisual]::new()
    $Visual.BindingGeneric = $BindingGeneric

    $Visual.BindingShoulderTap = $BindingShoulderTap

    if ($AddImageQuery) {
        $Visual.AddImageQuery = $AddImageQuery
    }

    if ($BaseUri) {
        $Visual.BaseUri = $BaseUri
    }

    if ($Language) {
        $Visual.Language = $Language
    }

    if($PSCmdlet.ShouldProcess("returning: [$($Visual.GetType().Name)]:BindingGeneric=$($Visual.BindingGeneric.Children.Count):BaseUri=$($Visual.BaseUri):Language=$($Visual.Language)")) {
        $Visual
    }
}
function New-BurntToastNotification {
    <#
        .SYNOPSIS
        Creates and displays a Toast Notification.

        .DESCRIPTION
        The New-BurntToastNotification function creates and displays a Toast Notification on Microsoft Windows 10.

        You can specify the text and/or image displayed as well as selecting the sound that is played when the Toast Notification is displayed.

        You can optionally call the New-BurntToastNotification function with the Toast alias.

        .INPUTS
        None
            You cannot pipe input to this function.

        .OUTPUTS
        None
            New-BurntToastNotification displays the Toast Notification that is created.

        .EXAMPLE
        New-BurntToastNotification

        This command creates and displays a Toast Notification with all default values.

        .EXAMPLE
        New-BurntToastNotification -Text 'Example Script', 'The example script has run successfully.'

        This command creates and displays a Toast Notification with customized title and display text.

        .EXAMPLE
        New-BurntToastNotification -Text 'WAKE UP!' -Sound 'Alarm2'

        This command creates and displays a Toast Notification which plays a looping alarm sound and lasts longer than a default Toast.

        .EXAMPLE
        $BlogButton = New-BTButton -Content 'Open Blog' -Arguments 'https://king.geek.nz'
        New-BurntToastNotification -Text 'New Blog Post!' -Button $BlogButton

        This exmaple creates a Toast Notification with a button which will open a link to "https://king.geek.nz" when clicked.

        .EXAMPLE
        $ToastHeader = New-BTHeader -Id '001' -Title 'Stack Overflow Questions'
        New-BurntToastNotification -Text 'New Stack Overflow Question!', 'More details!' -Header $ToastHeader

        This example creates a Toast Notification which will be displayed under the header 'Stack Overflow Questions.'

        .EXAMPLE
        $Progress = New-BTProgressBar -Status 'Copying files' -Value 0.2
        New-BurntToastNotification -Text 'File copy script running', 'More details!' -ProgressBar $Progress

        This example creates a Toast Notification which will include a progress bar.

        .EXAMPLE
        New-BurntToastNotification -Text 'Professional Content', 'And gr8 spelling' -UniqueIdentifier 'Toast001'
        New-BurntToastNotification -Text 'Professional Content', 'And great spelling' -UniqueIdentifier 'Toast001'

        This example will show a toast with a spelling error, which is replaced by a second toast because they both shared a unique identifier.

        .NOTES
        I'm *really* sorry about the number of Parameter Sets. The best explanation is:

        * You cannot specify a sound and mark the toast as silent at the same time.
        * You cannot specify SnoozeAndDismiss and custom buttons at the same time.

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BurntToastNotification.md
    #>

    [Alias('Toast')]
    [CmdletBinding(DefaultParameterSetName = 'Sound',
                   SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BurntToastNotification.md')]
    param (
        # Specifies the text to show on the Toast Notification. Up to three strings can be displayed, the first of which will be embolden as a title.
        [ValidateCount(0, 3)]
        [String[]] $Text = 'Default Notification',

        # Specifies groups of content (text and images) created via New-BTColumn that are displayed as a column.
        #
        # Multiple columns can be provided and they will be displayed side by side.
        [Microsoft.Toolkit.Uwp.Notifications.AdaptiveSubgroup[]] $Column,

        #TODO: [ValidateScript({ Test-ToastImage -Path $_ })]

        # Specifies the AppId of the 'application' or process that spawned the toast notification.
        [string] $AppId = $Script:Config.AppId,

        # Specifies the path to an image that will override the default image displayed with a Toast Notification.
        [String] $AppLogo,

        # Specifies the path to an image that will be used as the hero image on the toast.
        [String] $HeroImage,

        # Selects the sound to acompany the Toast Notification. Any 'Alarm' or 'Call' tones will automatically loop and extent the amount of time that a Toast is displayed on screen.
        #
        # Cannot be used in conjunction with the 'Silent' switch.
        [Parameter(ParameterSetName = 'Sound')]
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Sound-SnD')]
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Sound-Button')]
        [ValidateSet('Default',
                     'IM',
                     'Mail',
                     'Reminder',
                     'SMS',
                     'Alarm',
                     'Alarm2',
                     'Alarm3',
                     'Alarm4',
                     'Alarm5',
                     'Alarm6',
                     'Alarm7',
                     'Alarm8',
                     'Alarm9',
                     'Alarm10',
                     'Call',
                     'Call2',
                     'Call3',
                     'Call4',
                     'Call5',
                     'Call6',
                     'Call7',
                     'Call8',
                     'Call9',
                     'Call10')]
        [String] $Sound = 'Default',

        # Indicates that the Toast Notification will be displayed on screen without an accompanying sound.
        #
        # Cannot be used in conjunction with the 'Sound' parameter.
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Silent')]
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Silent-SnD')]
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Silent-Button')]
        [Switch] $Silent,

        # Adds a default selection box and snooze/dismiss buttons to the bottom of the Toast Notification.
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'SnD')]
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Silent-SnD')]
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Sound-SnD')]
        [Switch] $SnoozeAndDismiss,

        # Allows up to five buttons to be added to the bottom of the Toast Notification. These buttons should be created using the New-BTButton function.
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Button')]
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Silent-Button')]
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Sound-Button')]
        [Microsoft.Toolkit.Uwp.Notifications.IToastButton[]] $Button,

        # Specify the Toast Header object created using the New-BTHeader function, for seperation/categorization of toasts from the same AppId.
        [Microsoft.Toolkit.Uwp.Notifications.ToastHeader] $Header,

        # Specify one or more Progress Bar object created using the New-BTProgressBar function.
        [Microsoft.Toolkit.Uwp.Notifications.AdaptiveProgressBar[]] $ProgressBar,

        # A string that uniquely identifies a toast notification. Submitting a new toast with the same identifier as a previous toast will replace the previous toast.
        #
        # This is useful when updating the progress of a process, using a progress bar, or otherwise correcting/updating the information on a toast.
        [string] $UniqueIdentifier,

        # A hashtable that binds strings to keys in a toast notification. In order to update a toast, the original toast needs to include a databinding hashtable.
        [hashtable] $DataBinding,

        # The time after which the notification is no longer relevant and should be removed from the Action Center.
        [datetime] $ExpirationTime,

        # Bypasses display to the screen and sends the notification directly to the Action Center.
        [switch] $SuppressPopup,

        # Sets the time at which Windows should consider the notification to have been created. If not specified the time at which the notification was recieved will be used.
        #
        # The time stamp affects sorting of notifications in the Action Center.
        [datetime] $CustomTimestamp,

        [scriptblock] $ActivatedAction,

        [scriptblock] $DismissedAction
    )

    $ChildObjects = @()

    foreach ($Txt in $Text) {
        $ChildObjects += New-BTText -Text $Txt -WhatIf:$false
    }

    if ($ProgressBar) {
        foreach ($Bar in $ProgressBar) {
            $ChildObjects += $Bar
        }
    }

    if ($AppLogo) {
        $AppLogoImage = New-BTImage -Source $AppLogo -AppLogoOverride -Crop Circle -WhatIf:$false
    } else {
        $AppLogoImage = New-BTImage -AppLogoOverride -Crop Circle -WhatIf:$false
    }

    if ($Silent) {
        $Audio = New-BTAudio -Silent -WhatIf:$false
    } else {
        if ($Sound -ne 'Default') {
            if ($Sound -like 'Alarm*' -or $Sound -like 'Call*') {
                $Audio = New-BTAudio -Source "ms-winsoundevent:Notification.Looping.$Sound" -Loop -WhatIf:$false
                $Long = $True
            } else {
                $Audio = New-BTAudio -Source "ms-winsoundevent:Notification.$Sound" -WhatIf:$false
            }
        }
    }

    $BindingSplat = @{
        Children        = $ChildObjects
        AppLogoOverride = $AppLogoImage
        WhatIf          = $false
    }

    if ($HeroImage) {
        $BTImageHero = New-BTImage -Source $HeroImage -HeroImage -WhatIf:$false
        $BindingSplat['HeroImage'] = $BTImageHero
    }

    if ($Column) {
        $BindingSplat['Column'] = $Column
    }

    $Binding = New-BTBinding @BindingSplat
    $Visual = New-BTVisual -BindingGeneric $Binding -WhatIf:$false

    $ContentSplat = @{
        'Audio'  = $Audio
        'Visual' = $Visual
    }

    if ($Long) {
        $ContentSplat.Add('Duration', [Microsoft.Toolkit.Uwp.Notifications.ToastDuration]::Long)
    }

    if ($SnoozeAndDismiss) {
        $ContentSplat.Add('Actions', (New-BTAction -SnoozeAndDismiss -WhatIf:$false))
    } elseif ($Button) {
        $ContentSplat.Add('Actions', (New-BTAction -Buttons $Button -WhatIf:$false))
    }

    if ($Header) {
        $ContentSplat.Add('Header', $Header)
    }

    if ($CustomTimestamp) {
        $ContentSplat.Add('CustomTimestamp', $CustomTimestamp)
    }

    $Content = New-BTContent @ContentSplat -WhatIf:$false

    $ToastSplat = @{
        Content = $Content
        AppId   = $AppId
    }

    if ($UniqueIdentifier) {
        $ToastSplat.Add('UniqueIdentifier', $UniqueIdentifier)
    }

    if ($ExpirationTime) {
        $ToastSplat.Add('ExpirationTime', $ExpirationTime)
    }

    if ($SuppressPopup.IsPresent) {
        $ToastSplat.Add('SuppressPopup', $true)
    }

    if ($DataBinding) {
        $ToastSplat.Add('DataBinding', $DataBinding)
    }

    # Toast events may not be supported, this check happens inside Submit-BTNotification
    if ($ActivatedAction) {
        $ToastSplat.Add('ActivatedAction', $ActivatedAction)
    }

    if ($DismissedAction) {
        $ToastSplat.Add('DismissedAction', $DismissedAction)
    }

    if ($PSCmdlet.ShouldProcess( "submitting: $($Content.GetContent())" )) {
        Submit-BTNotification @ToastSplat
    }
}
function New-BurntToastShoulderTap {
    <#
        .SYNOPSIS
        Creates and displays a Shoulder Tap notification.

        .DESCRIPTION
        The New-BurntToastShoulderTap function creates and displays a Shoulder Tap notification on Microsoft Windows 10.

        You can provide a static image or animated GIF, which will be displayed above the specified pinned contact.

        You must first pin a contact to the Taskbar using the Windows 10 People app.  Next, you can refer to the contact **by its e-mail address** to display a notification.

        If a matching contact cannot be found, Windows will fall back to a toast notification. This toast notification will also been seen in the Action Center (with or without a working Shoulder Tap.)

        You can optionally call the New-BurntToastShoulderTap function with the ShoulderTap alias.

        .INPUTS
        LOTS...

        .OUTPUTS
        None
            New-BurntToastShoulderTap displays the Shoulder Tap that is created.

        .EXAMPLE
        $Image = 'https://i.imgur.com/WKiNp5o.gif'
        $Contact = 'stormy@example.com'
        $Text = 'First Shoulder Tap', 'This is for the fallback toast.'

        New-BurntToastShoulderTap -Image $Image -Person $Contact -Text $Text

        .NOTES
        There's some manual steps required to create and pin a contact which matches the specified email address in the Person parameter.

        There will be a blog post about this on https://toastit.dev, and also further documented within this module in the next release.

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/New-BurntToastShoulderTap.md
    #>

    [Obsolete('This cmdlet is being deprecated, it will be removed in v0.9.0')]
    [Alias('ShoulderTap')]
    [CmdletBinding(SupportsShouldProcess   = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/New-BurntToastShoulderTap.md')]
    param (
        # The URI of the image. Can be a static image or animated GIF.
        [Parameter(Mandatory)]
        [string] $Image,

        # The email address of the "person" from which the Shoulder Tap is coming from.
        #
        # A contact with a matching email address must be pinned to the task bar.
        [Parameter(Mandatory)]
        [string] $Person,

        # Specifies the text to show on the Toast Notification. Up to three strings can be displayed, the first of which will be embolden as a title.
        #
        # The toast version will be shown on screen if the required contact is not pinned to the task bar, and will also appear in the Action Center.
        [ValidateCount(0, 3)]
        [string[]] $Text = 'Default Notification',

        # Specifies the path to an image that will override the default image displayed with a Toast Notification.
        [string] $AppLogo,

        # Allows up to five buttons to be added to the bottom of the Toast Notification. These buttons should be created using the New-BTButton function.
        [Microsoft.Toolkit.Uwp.Notifications.IToastButton[]] $Button,

        # Specify the Toast Header object created using the New-BTHeader function, for seperation/categorization of toasts from the same AppId.
        [Microsoft.Toolkit.Uwp.Notifications.ToastHeader] $Header,

        # Specify one or more Progress Bar object created using the New-BTProgressBar function.
        [Microsoft.Toolkit.Uwp.Notifications.AdaptiveProgressBar[]] $ProgressBar,

        # A string that uniquely identifies a toast notification. Submitting a new toast with the same identifier as a previous toast will replace the previous toast.
        #
        # This is useful when updating the progress of a process, using a progress bar, or otherwise correcting/updating the information on a toast.
        [string] $UniqueIdentifier,

        # The time after which the notification is no longer relevant and should be removed from the People notification and Action Center.
        [datetime] $ExpirationTime,

        # Bypasses display to the screen and sends the notification directly to the Action Center.
        [switch] $SuppressPopup,

        # Sets the time at which Windows should consider the notification to have been created. If not specified the time at which the notification was recieved will be used.
        #
        # The time stamp affects sorting of notifications in the Action Center.
        [datetime] $CustomTimestamp,

        # Specifies the AppId of the 'application' or process that spawned the toast notification.
        #
        # Defaults to the People App, rather than the configured default.
        [string] $AppId = 'Microsoft.People_8wekyb3d8bbwe!x4c7a3b7dy2188y46d4ya362y19ac5a5805e5x'
    )

    $ChildObjects = @()

    foreach ($Txt in $Text) {
        $ChildObjects += New-BTText -Text $Txt -WhatIf:$false
    }

    if ($ProgressBar) {
        foreach ($Bar in $ProgressBar) {
            $ChildObjects += $Bar
        }
    }

    if ($AppLogo) {
        $AppLogoImage = New-BTImage -Source $AppLogo -AppLogoOverride -Crop Circle -WhatIf:$false
    } else {
        $AppLogoImage = New-BTImage -AppLogoOverride -Crop Circle -WhatIf:$false
    }

    $Binding = New-BTBinding -Children $ChildObjects -AppLogoOverride $AppLogoImage -WhatIf:$false

    $ShoulderTapBinding = New-BTShoulderTapBinding -Image (New-BTShoulderTapImage -Source $Image)

    $Visual = New-BTVisual -BindingGeneric $Binding -BindingShoulderTap $ShoulderTapBinding -WhatIf:$false

    $ContentSplat = @{
        'Visual' = $Visual
        'ToastPeople' = (New-BTShoulderTapPeople -Email $Person)
    }

    if ($Header) {
        $ContentSplat.Add('Header', $Header)
    }

    if ($CustomTimestamp) {
        $ContentSplat.Add('CustomTimestamp', $CustomTimestamp)
    }

    $Content = New-BTContent @ContentSplat -WhatIf:$false

    $ToastSplat = @{
        Content = $Content
        AppId = $AppId
    }

    if ($UniqueIdentifier) {
        $ToastSplat.Add('UniqueIdentifier', $UniqueIdentifier)
    }

    if ($ExpirationTime) {
        $ToastSplat.Add('ExpirationTime', $ExpirationTime)
    }

    if ($SuppressPopup.IsPresent) {
        $ToastSplat.Add('SuppressPopup', $true)
    }

    if($PSCmdlet.ShouldProcess( "submitting: $($Content.GetContent())" )) {
        Submit-BTNotification @ToastSplat
    }
}
function Remove-BTNotification {
    <#
        .SYNOPSIS
        Removes toast notifications from the Action Center.

        .DESCRIPTION
        The Remove-BTNotification function removes toast notifications from the Action Center.

        If no parameters are specified, all toasts (for the default AppId) will be removed.

        Tags and Groups for Toasts can be found using the Get-BTHistory function.

        .INPUTS
        LOTS

        .OUTPUTS
        NONE

        .EXAMPLE
        Remove-BTNotification

        .EXAMPLE
        Remove-BTNotification -Tag 'UniqueIdentifier'

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/Remove-BTNotification.md
    #>

    [CmdletBinding(DefaultParameterSetName = 'Individual',
                   SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/Remove-BTNotification.md')]
    param (
        # Specifies the AppId of the 'application' or process that spawned the toast notification.
        [string] $AppId = $Script:Config.AppId,

        # Specifies the tag, which identifies a given toast notification.
        [Parameter(ParameterSetName = 'Individual')]
        [string] $Tag,

        # Specifies the group, which helps to identify a given toast notification.
        [Parameter(ParameterSetName = 'Individual')]
        [string] $Group,

        # A string that uniquely identifies a toast notification. Represents both the Tag and Group for a toast.
        [Parameter(Mandatory = $true,
                   ParameterSetName = 'Combo')]
        [string] $UniqueIdentifier
    )

    if ($UniqueIdentifier) {
        if($PSCmdlet.ShouldProcess("Tag: $UniqueIdentifier, Group: $UniqueIdentifier, AppId: $AppId", 'Selectively removing notifications')) {
            [Windows.UI.Notifications.ToastNotificationManager]::History.Remove($UniqueIdentifier, $UniqueIdentifier, $AppId)
        }
    } elseif (!(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\$AppId")) {
        Write-Warning -Message "The AppId $AppId is not present in the registry, please run New-BTAppId to avoid inconsistent Toast behaviour."
    }

    if ($Tag -and $Group) {
        if($PSCmdlet.ShouldProcess("Tag: $Tag, Group: $Group, AppId: $AppId", 'Selectively removing notifications')) {
            [Windows.UI.Notifications.ToastNotificationManager]::History.Remove($Tag, $Group, $AppId)
        }
    } elseif ($Tag) {
        if($PSCmdlet.ShouldProcess("Tag: $Tag, AppId: $AppId", 'Selectively removing notifications')) {
            [Windows.UI.Notifications.ToastNotificationManager]::History.Remove($Tag, $AppId)
        }
    } elseif ($Group) {
        if($PSCmdlet.ShouldProcess("Group: $Group, AppId: $AppId", 'Selectively removing notifications')) {
            [Windows.UI.Notifications.ToastNotificationManager]::History.RemoveGroup($Group, $AppId)
        }
    } else {
        if($PSCmdlet.ShouldProcess("AppId: $AppId", 'Clearing all notifications')) {
            [Windows.UI.Notifications.ToastNotificationManager]::History.Clear($AppId)
        }
    }
}
function Submit-BTNotification {
    <#
        .SYNOPSIS
        Submits a completed toast notification for display.

        .DESCRIPTION
        The Submit-BTNotification function submits a completed toast notification to the operating systems' notification manager for display.

        .INPUTS
        None

        .OUTPUTS
        None

        .EXAMPLE
        Submit-BTNotification -Content $Toast1 -UniqueIdentifier 'Toast001'

        This command submits the complete toast content object $Toast1, from the New-BTContent function, and tags it with a unique identifier so that it can be replaced/updated.

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/Submit-BTNotification.md
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/Submit-BTNotification.md')]
    param (
        # A Toast Content object which is the Base Toast element, created using the New-BTContent function.
        [Microsoft.Toolkit.Uwp.Notifications.ToastContent] $Content,

        # When updating toasts (not curently working) rapidly, the sequence number helps to ensure that toasts recieved out of order will not be displayed in a manner that may confuse.
        #
        # A higher sequence number indicates a newer toast.
        [uint64] $SequenceNumber,

        # A string that uniquely identifies a toast notification. Submitting a new toast with the same identifier as a previous toast will replace the previous toast.
        #
        # This is useful when updating the progress of a process, using a progress bar, or otherwise correcting/updating the information on a toast.
        [string] $UniqueIdentifier,

        # Specifies the AppId of the 'application' or process that spawned the toast notification.
        [string] $AppId = $Script:Config.AppId,

        # A hashtable that binds strings to keys in a toast notification. In order to update a toast, the original toast needs to include a databinding hashtable.
        [hashtable] $DataBinding,

        # The time after which the notification is no longer relevant and should be removed from the Action Center.
        [datetime] $ExpirationTime,

        # Bypasses display to the screen and sends the notification directly to the Action Center.
        [switch] $SuppressPopup,

        [scriptblock] $ActivatedAction,

        [scriptblock] $DismissedAction,

        [scriptblock] $FailedAction
    )

    if (!(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\$AppId")) {
        Write-Warning -Message "The AppId $AppId is not present in the registry, please run New-BTAppId to avoid inconsistent Toast behaviour."
    }

    if (-not $IsWindows) {
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    }

    $ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::new()

    if (-not $DataBinding) {
        $CleanContent = $Content.GetContent() -Replace '<text(.*?)>{', '<text$1>'
        $CleanContent = $CleanContent.Replace('}</text>', '</text>')
        $CleanContent = $CleanContent.Replace('="{', '="')
        $CleanContent = $CleanContent.Replace('}" ', '" ')

        $ToastXml.LoadXml($CleanContent)
    } else {
        $ToastXml.LoadXml($Content.GetContent())
    }

    $Toast = [Windows.UI.Notifications.ToastNotification]::new($ToastXml)

    if ($DataBinding) {
        $DataDictionary = New-Object 'system.collections.generic.dictionary[string,string]'

        if ($DataBinding) {
            foreach ($Key in $DataBinding.Keys) {
                $DataDictionary.Add($Key, $DataBinding.$Key)
            }
        }

        foreach ($Child in $Content.Visual.BindingGeneric.Children) {
            if ($Child.GetType().Name -eq 'AdaptiveText') {
                $BindingName = $Child.Text.BindingName

                if (!$DataDictionary.ContainsKey($BindingName)) {
                    $DataDictionary.Add($BindingName, $BindingName)
                }
            } elseif ($Child.GetType().Name -eq 'AdaptiveProgressBar') {
                if ($Child.Title) {
                    $BindingName = $Child.Title.BindingName

                    if (!$DataDictionary.ContainsKey($BindingName)) {
                        $DataDictionary.Add($BindingName, $BindingName)
                    }
                }

                if ($Child.Value) {
                    $BindingName = $Child.Value.BindingName

                    if (!$DataDictionary.ContainsKey($BindingName)) {
                        $DataDictionary.Add($BindingName, $BindingName)
                    }
                }

                if ($Child.ValueStringOverride) {
                    $BindingName = $Child.ValueStringOverride.BindingName

                    if (!$DataDictionary.ContainsKey($BindingName)) {
                        $DataDictionary.Add($BindingName, $BindingName)
                    }
                }

                if ($Child.Status) {
                    $BindingName = $Child.Status.BindingName

                    if (!$DataDictionary.ContainsKey($BindingName)) {
                        $DataDictionary.Add($BindingName, $BindingName)
                    }
                }
            }
        }

        $Toast.Data = [Windows.UI.Notifications.NotificationData]::new($DataDictionary)
    }

    if ($UniqueIdentifier) {
        $Toast.Group = $UniqueIdentifier
        $Toast.Tag = $UniqueIdentifier
    }

    if ($ExpirationTime) {
        $Toast.ExpirationTime = $ExpirationTime
    }

    if ($SuppressPopup.IsPresent) {
        $Toast.SuppressPopup = $SuppressPopup
    }

    if ($SequenceNumber) {
        $Toast.Data.SequenceNumber = $SequenceNumber
    }

    if ($ActivatedAction -or $DismissedAction -or $FailedAction) {
        if ($Script:ActionsSupported) {
            if ($ActivatedAction) {
                Register-ObjectEvent -InputObject $Toast -EventName Activated -Action $ActivatedAction |Out-Null
            }
            if ($DismissedAction) {
                Register-ObjectEvent -InputObject $Toast -EventName Dismissed -Action $DismissedAction | Out-Null
            }
            if ($FailedAction) {
                Register-ObjectEvent -InputObject $Toast -EventName Failed -Action $FailedAction | Out-Null
            }
        } else {
            Write-Warning $Script:UnsupportedEvents
        }
    }

    if($PSCmdlet.ShouldProcess( "submitting: [$($Toast.GetType().Name)] with AppId $AppId, Id $UniqueIdentifier, Sequence Number $($Toast.Data.SequenceNumber) and XML: $($Content.GetContent())")) {
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($Toast)
    }
}
function Update-BTNotification {
    <#
        .SYNOPSIS
        Updates a toast notification for display.

        .DESCRIPTION
        The Update-BTNotification function updates a toast notification in the operating systems' notification manager.

        .INPUTS
        LOTS...

        .OUTPUTS
        NONE

        .EXAMPLE
        $FirstDataBinding = @{
            FirstLine = 'Example Toast Heading'
            SecondLine = 'This toast is still the original'
        }

        New-BurntToastNotification -Text 'FirstLine', 'SecondLine' -UniqueIdentifier 'ExampleToast' -DataBinding $FirstDataBinding

        $SecondDataBinding = @{
            SecondLine = 'This toast has been updated!'
        }

        Update-BTNotification -UniqueIdentifier 'ExampleToast' -DataBinding $SecondDataBinding

        .LINK
        https://github.com/Windos/BurntToast/blob/main/Help/Update-BTNotification.md
    #>

    [CmdletBinding(SupportsShouldProcess = $true,
                   HelpUri = 'https://github.com/Windos/BurntToast/blob/main/Help/Update-BTNotification.md')]
    [CmdletBinding()]
    param (
        # When updating toasts (not curently working) rapidly, the sequence number helps to ensure that toasts recieved out of order will not be displayed in a manner that may confuse.
        #
        # A higher sequence number indicates a newer toast.
        [uint64] $SequenceNumber,

        # A string that uniquely identifies a toast notification. Submitting a new toast with the same identifier as a previous toast will replace the previous toast.
        #
        # This is useful when updating the progress of a process, using a progress bar, or otherwise correcting/updating the information on a toast.
        [string] $UniqueIdentifier,

        # Specifies the AppId of the 'application' or process that spawned the toast notification.
        [string] $AppId = $Script:Config.AppId,

        # A hashtable that binds strings to keys in a toast notification. In order to update a toast, the original toast needs to include a databinding hashtable.
        [hashtable] $DataBinding
    )

    if (!(Test-Path -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\$AppId")) {
        Write-Warning -Message "The AppId $AppId is not present in the registry, please run New-BTAppId to avoid inconsistent Toast behaviour."
    }

    if (-not $IsWindows) {
        $null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    }

    if ($DataBinding) {
        $DataDictionary = New-Object 'system.collections.generic.dictionary[string,string]'

        foreach ($Key in $DataBinding.Keys) {
            $DataDictionary.Add($Key, $DataBinding.$Key)
        }
    }

    $ToastData = [Windows.UI.Notifications.NotificationData]::new($DataDictionary)

    if ($SequenceNumber) {
        $ToastData.SequenceNumber = $SequenceNumber
    }

    if($PSCmdlet.ShouldProcess("AppId: $AppId, UniqueId: $UniqueIdentifier", 'Updating notification')) {
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Update($ToastData, $UniqueIdentifier, $UniqueIdentifier)
    }
}
$PublicFunctions = 'Get-BTHistory', 'New-BTAction', 'New-BTAppId', 'New-BTAudio', 'New-BTBinding', 'New-BTButton', 'New-BTColumn', 'New-BTContent', 'New-BTContextMenuItem', 'New-BTHeader', 'New-BTImage', 'New-BTInput', 'New-BTProgressBar', 'New-BTSelectionBoxItem', 'New-BTShoulderTapBinding', 'New-BTShoulderTapImage', 'New-BTShoulderTapPeople', 'New-BTText', 'New-BTVisual', 'New-BurntToastNotification', 'New-BurntToastShoulderTap', 'Remove-BTNotification', 'Submit-BTNotification', 'Update-BTNotification'

$WinMajorVersion = (Get-CimInstance -ClassName Win32_OperatingSystem -Property Version).Version.Split('.')[0]

if ($WinMajorVersion -ge 10) {
    $Library = @( Get-ChildItem -Path $PSScriptRoot\lib\Microsoft.Toolkit.Uwp.Notifications\*.dll -Recurse -ErrorAction SilentlyContinue )

    if ($IsWindows) {
        $Library += @( Get-ChildItem -Path $PSScriptRoot\lib\Microsoft.Windows.SDK.NET\*.dll -Recurse -ErrorAction SilentlyContinue )
    }

    # Add one class from each expected DLL here:
    $LibraryMap = @{
        'Microsoft.Toolkit.Uwp.Notifications.dll' = 'Microsoft.Toolkit.Uwp.Notifications.ToastContent'
    }

    $Script:Config = Get-Content -Path $PSScriptRoot\config.json -ErrorAction SilentlyContinue | ConvertFrom-Json
    $Script:DefaultImage = if ($Script:Config.AppLogo -match '^[.\\]') {
        "$PSScriptRoot$($Script:Config.AppLogo)"
    } else {
        $Script:Config.AppLogo
    }

    foreach ($Type in $Library) {
        try {
            if (-not ($LibraryMap[$Type.Name]  -as [type])) {
                Add-Type -Path $Type.FullName -ErrorAction Stop
            }
        } catch {
            Write-Error -Message "Failed to load library $($Type.FullName): $_"
        }
    }

    $Script:ActionsSupported = 'System.Management.Automation.SemanticVersion' -as [type] -and
        $PSVersionTable.PSVersion -ge [System.Management.Automation.SemanticVersion] '7.1.0-preview.4'

    $Script:UnsupportedEvents = 'Toast events are only supported on PowerShell 7.1.0 and above. ' +
        'Your notification will still be displayed, but the actions will be ignored.'

    Export-ModuleMember -Alias 'Toast'
    Export-ModuleMember -Function $PublicFunctions

    # Register default AppId
    New-BTAppId

    if (-not $IsWindows) {
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    }
} else {
    throw 'This version of BurntToast will only work on Windows 10. If you would like to use BurntToast on Windows 8, please use version 0.4'
}
