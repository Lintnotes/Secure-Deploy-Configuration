<#
.SYNOPSIS
    Applies Secure Deploy Configuration for Windows 10,11, and Windows Server 2012,2016,2019,2022
.DESCRIPTION
    This script will verify Supported Operating Systems and configure the OS Security Settings based off of DoD STIGS, Remove Features, Uninstall Appx Applications, Apply ADMX Templates and any other settings required for a secure deployment.
.EXAMPLE
    Apply-SDC.ps1
.NOTES
    FileName:   Apply-SDC.ps1
    Author:     Brandon Linton
    Contact:    @Lintnotes
    Created:    2022-11-28
    Updated:
    Version History:
        1.0.0 - (2022-11-28) - Script Created

Disclaimer. The sample scripts are not supported under any Microsoft standard support program or service.
The sample scripts are provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#>
[CmdletBinding()]
param(
    [parameter(Mandatory = $False, HelpMessage = "Define URI to download content or leave blank if local.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$Uri = "https://YOURURL",

    [parameter(Mandatory = $False, HelpMessage = "Remove Appx Applications from system.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$RemoveAppX = $True,

    [parameter(Mandatory = $False, HelpMessage = "Office Version to STIG")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("365", "2016", "2013")]
    [string]$OfficeVersion = "365",

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Start Menu Layout.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$StartLayout = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Taskbar Layout.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$TaskbarLayout = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Lockscreen.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$LockScreen = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Desktop Wallpaper.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$Wallpaper = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Theme.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$Theme = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Desktop Icons.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$DesktopIcons = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure This PC Desktop Icon to Show Computername")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$ThisPCToComputerName = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure OEM Branding Information.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$OEMBranding = $True,

    [parameter(Mandatory = $False, HelpMessage = "Enter OEM Branding Company Name")]
    [ValidateNotNullOrEmpty()]
    [string]$Manufacturer = "U.S Department of Defense",

    [parameter(Mandatory = $False, HelpMessage = "Enter OEM Branding Company Support #")]
    [ValidateNotNullOrEmpty()]
    [string]$SupportPhone = "Enterprise Help Desk - Commercial:855-352-0001",

    [parameter(Mandatory = $False, HelpMessage = "Enter OEM Branding Company Support URL")]
    [ValidateNotNullOrEmpty()]
    [string]$SupportURL = "https://software.forge.mil/sf/go/proj2467",

    [parameter(Mandatory = $False, HelpMessage = "Configure HKCU Registry Settings.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$RegistryHKCU = $True,

    [parameter(Mandatory = $False, HelpMessage = "Disable Teams Consumer Experience")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$DisableTeams = $True
)

Function Write-CMLogEntry() {
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        [Parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("0", "1", "2", "3")]
        [string]$Severity,

        [Parameter(Mandatory = $false, HelpMessage = "Name of the component that the entry will be written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$Component = "Powershell",

        [Parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will be written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$FileName = "Apply-SDC.log"
    )

    Try {
        #Set the Location of the Log
        If (!(Test-Path $ENV:WINDIR\Logs\Software)) {
            New-Item -ItemType Directory -Path $ENV:WINDIR\Logs\Software -Force | Out-Null
        }

        $Script:LogFilePath = Join-Path  -Path "$ENV:WINDIR\Logs\Software" -ChildPath $FileName

        # Construct time stamp for log entry
        if (-not (Test-Path -Path 'variable:global:TimezoneBias')) {
            [string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
            if ($TimezoneBias -match "^-") {
                $TimezoneBias = $TimezoneBias.Replace('-', '+')
            }
            else {
                $TimezoneBias = '-' + $TimezoneBias
            }
        }
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)

        #Get the current date
        $Date = (Get-Date -Format "MM-dd-yyyy")

        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($Component)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to Apply-SDC.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }

        Switch ($Severity) {
            0 { $Color = 'White' }
            1 { $Color = 'Green' }
            2 { $Color = 'Yellow' }
            3 { $Color = 'Red' }
        }
        Write-Host "Message: '$Value'" -ForegroundColor $Color
    }
    Catch {
        Write-Host -f Red "Error:" $_.Exception.Message
    }
}

# Relaunch script as sysnative if architecture is amd64
If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    Try {
        &"$ENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -File $PSCOMMANDPATH
    }
    Catch {
        Throw "Failed to start $PSCOMMANDPATH"
    }
    Exit
}

Clear-Host
Write-CMLogEntry -Value "Script Execution Started" -Severity 0
Write-CMLogEntry -Value "Script Logging: $($LogFilePath)" -Severity 0
Write-CMLogEntry -Value "Gathering Data Please be patient..." -Severity 0
# Define Variables
$Script:IsWorkstation = $False
$Script:IsDomainController = $False
$Script:IsServer = $False
$Script:IsMultiSession = $False
$Script:OS = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption).Caption
$Script:OSBuild = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object BuildNumber).BuildNumber
$Script:Model = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Model).Model
$Script:Is64Bit = [System.Environment]::Is64BitOperatingSystem
$Script:ProductType = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object ProductType).ProductType
switch ($ProductType) {
    1 { $Script:IsWorkstation = $True }
    2 { $Script:IsDomainController = $True }
    3 { If ($OS -like '*multi-session*') { $Script:IsWorkstation = $True; $Script:IsMultiSession = $True }Else { $Script:IsServer = $True } }
    default { "Unknown" }
}

$SDCRootPath = Join-Path -Path $env:WINDIR -ChildPath '\Resources\SDC'

If (!(Test-Path $SDCRootPath)) { New-Item -Path $SDCRootPath -ItemType Directory -Force | Out-Null }Else { Remove-Item  $SDCRootPath\* -Recurse -Force }

Write-CMLogEntry -Value "Attempting to download OS Branding Pack" -Severity 0
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$SDCPackage = "$PSScriptRoot\SDC.zip"

try {
    Invoke-WebRequest -Uri $Uri -OutFile $SDCPackage
    Write-CMLogEntry -Value "Succesfully Downloaded SDC from $($Uri)" -Severity 1
}
catch {
    Write-CMLogEntry -Value "Failed to download SDC from $($Uri)" -Severity 2
}

If (Test-Path $PSScriptRoot\SDC.zip) {
    Write-CMLogEntry -Value "Extracting files to local storage:$SDCRootPath." -Severity 0
    Expand-Archive -LiteralPath $SDCPackage -DestinationPath $SDCRootPath
}
else {
    Write-CMLogEntry -Value "OS Branding Pack not found..." -Severity 2
    Break
}

Write-CMLogEntry -Value "Detected Operating System:$OS" -Severity 0

If ($OS -match "Windows 10|Windows 11|2012|2016|2019|2022") {
    Write-CMLogEntry -Value "Operating System Supported" -Severity 0
}
Else {
    Write-CMLogEntry -Value "Operating System NOT Supported" -Severity 0
    Break
}

If ($OS -notmatch 'Windows 10') {
    Get-ChildItem $SDCRootPath\Policy\01_STIGS -ErrorAction SilentlyContinue | Where-Object { $_.PSisContainer -and ($_.Name -like '*Windows 10*') } | Remove-Item -Recurse -Force
}
If ($OS -notmatch 'Windows 11') {
    Get-ChildItem $SDCRootPath\Policy\01_STIGS -ErrorAction SilentlyContinue | Where-Object { $_.PSisContainer -and ($_.Name -like '*Windows 11*') } | Remove-Item -Recurse -Force
}
If ($OS -notmatch '2012') {
    Get-ChildItem $SDCRootPath\Policy\01_STIGS -ErrorAction SilentlyContinue | Where-Object { $_.PSisContainer -and ($_.Name -like '*Server 2012*') } | Remove-Item -Recurse -Force
}
If ($OS -notmatch '2016') {
    Get-ChildItem $SDCRootPath\Policy\01_STIGS -ErrorAction SilentlyContinue | Where-Object { $_.PSisContainer -and ($_.Name -like '*Server 2016*') } | Remove-Item -Recurse -Force
}
If ($OS -notmatch '2019') {
    Get-ChildItem $SDCRootPath\Policy\01_STIGS -ErrorAction SilentlyContinue | Where-Object { $_.PSisContainer -and ($_.Name -like '*Server 2019*') } | Remove-Item -Recurse -Force
}
if ($OS -notmatch '2022') {
    Get-ChildItem $SDCRootPath\Policy\01_STIGS -ErrorAction SilentlyContinue | Where-Object { $_.PSisContainer -and ($_.Name -like '*Server 2022*') } | Remove-Item -Recurse -Force
}

If (($OS -match 'Windows 10|Windows 11' -and $OfficeVersion -ne "365") -or ($OS -match 'Server')) {
    Get-ChildItem $SDCRootPath\Policy\01_STIGS -ErrorAction SilentlyContinue | Where-Object { $_.PSisContainer -and ($_.Name -like '*Office 2019-M365*') } | Remove-Item -Recurse -Force
}
if (($OS -match 'Windows 10|Windows 11' -and $OfficeVersion -ne "2016") -or ($OS -match 'Server')) {
    Get-ChildItem $SDCRootPath\Policy\01_STIGS -ErrorAction SilentlyContinue | Where-Object { $_.PSisContainer -and ($_.Name -like '*Office System 2016*') } | Remove-Item -Recurse -Force
}
if (($OS -match 'Windows 10|Windows 11' -and $OfficeVersion -ne "2013") -or ($OS -match 'Server')) {
    Get-ChildItem $SDCRootPath\Policy\01_STIGS -ErrorAction SilentlyContinue | Where-Object { $_.PSisContainer -and ($_.Name -like '*Office System 2013*') } | Remove-Item -Recurse -Force
}

# Define LGPO Location
If (Test-Path $SDCRootPath\LGPO\LGPO.exe) {
    $LGPO = "$SDCRootPath\LGPO\LGPO.exe"
    Write-CMLogEntry -Value "LGPO Utility Found: $LGPO " -Severity 0
}
Else {
    Write-CMLogEntry -Value "LGPO Utility Not Found Exiting." -Severity 0
    Break
}

# Appx Removal
$AppxPackages = @(
    "Microsoft.BingWeather",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.MicrosoftOfficeHub",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MixedReality.Portal",
    "Microsoft.Office.OneNote",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "microsoft.windowscommunicationsapps",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGamingOverlay",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.YourPhone",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Clipchamp.Clipchamp",
    "Microsoft.GamingApp"
)
# Remove Appx Packages
If (($OS -match 'Windows 10|Windows 11') -and $RemoveAppX -eq $True) {
    #Get list of installed Appx package on local system
    $installedAppx = Get-AppxPackage | Select-Object -Property Name, PackageFullName | Sort-Object -Property Name
    Foreach ($App in $AppxPackages) {
        Write-CMLogEntry -Value "Processing Appx Package:$App" -Severity 0 -Component "Apps"
        # Gather package names
        $AppPackageFullName = Get-AppxPackage -Name $App -AllUsers | Select-Object -ExpandProperty PackageFullName
        $AppProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $App } | Select-Object -ExpandProperty PackageName
        #Does Applications exist on system
        if ($AppPackageFullName -eq $null) {
            Write-CMLogEntry -Value  "Application $($App) is not installed on system" -Severity 2 -Component "Apps"
            continue
        }

        #app to be removed is installed on system
        Write-CMLogEntry -Value "Processing Appx Package: $($App).  Package is installed.  Attempting to remove package." -Severity 1 -Component "Apps"
        # Attempt to remove AppxPackage
        try {
            Write-CMLogEntry -Value "Removing Appx Package: $AppPackageFullName" -Severity 0 -Component "Apps"
            Remove-AppxPackage -Package $AppPackageFullName -ErrorAction SilentlyContinue | Out-Null
        }
        catch [System.Exception] {
            Write-CMLogEntry -Value ($_.Exception.Message) -Severity 3 -Component "Apps"
        }

        # Attempt to remove AppxProvisioningPackage
        try {
            Write-CMLogEntry -Value "Removing AppxProvisioningPackage: $AppProvisioningPackageName" -Severity 0 -Component "Apps"
            Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online  -ErrorAction SilentlyContinue | Out-Null
        }
        catch [System.Exception] {
            Write-CMLogEntry -Value ($_.Exception.Message) -Severity 3 -Component "Apps"
        }
        #Verify Appx was removed
        if ((Get-AppxPackage -Name $App -AllUsers) -ne $null) {
            Write-CMLogEntry -Value "Application: $($App) failed to be removed" -Severity 3 -Component "Apps"
        }
        else {
            Write-CMLogEntry -Value "Application: $($App) successfully uninstalled" -Severity 1 -Component "Apps"
        }
    }
}

# Remove Features
$Features = @(
    "MicrosoftWindowsPowerShellV2Root", #The Windows PowerShell 2.0 feature must be disabled on the system. (Vuln ID: V-70637)
    "MicrosoftWindowsPowerShellV2", #The Windows PowerShell 2.0 feature must be disabled on the system. (Vuln ID: V-70637)
    "SMB1Protocol", #The Server Message Block (SMB) v1 protocol must be disabled on the system (Vuln ID: V-70639)
    "SNMP" #The SNMP protocol must be disabled on the system (Vuln ID: V-63381)
)

Foreach ($Feature in $Features) {
    Write-CMLogEntry -Value "Processing Feature: $($Feature)" -Severity 1 -Component "Features"
    $InstalledFeature = Get-WindowsOptionalFeature -Online -FeatureName $Feature
    if ($InstalledFeature -eq $null) {
        Write-CMLogEntry -Value "Feature: $($Feature) is not installed on system" -Severity 2 -Component "Features"
        continue
    }
    # Feature is installed
    Write-CMLogEntry -Value "Feature: $($Feature) is available on system. Attempting to remove $($Feature)" -Severity 1 -Component "Features"
    Disable-WindowsOptionalFeature -FeatureName $Feature -Online -NoRestart -ErrorAction SilentlyContinue | Out-Null
    #Verify feature was removed
    if ((Get-WindowsOptionalFeature -FeatureName $Feature -Online).State -match "Disable") {
        Write-CMLogEntry -Value "Feature: $($Feature) has been successfully removed" -Severity 1 -Component "Features"
    }
    else {
        Write-CMLogEntry -Value "Feature: $($Feature) has failed to be removed. Check to make sure the feature is not being used by another process or you have necessary rights" -Severity 3 -Component "Features"
    }
}

# Client Side Extensions
$CSEs = @(
    "zone", #Internet Explorer zone mapping extension; needed for Site-To-Zone Assignment List policy
    "mitigation", #Mitigation Options extension; needed for the Untrusted Font Blocking policy
    "audit", #Advanced Audit Policy Configuration; ensures that GpUpdate.exe applies advanced audit policy settings.
    "LAPS", #Local Administrator Password Solution (LAPS) extension
    "DGVBS", #Device Guard Virtualiztion-Based Security extension; needed for Credential Guard and for Device Guard (Windows 10)
    "DGCI" #Device Guard Code Integrity policy extension; needed for Device Guard (Windows 10)
)

Foreach ($CSE in $CSEs) {
    Write-CMLogEntry -Value "Processing Client Side Extension: $($CSE)" -Severity 1 -Component "LGPO"
    & $LGPO "/e" $CSE "/v"
}

# ADMX/L Templates
Write-CMLogEntry -Value "Processing ADMX/L Templates" -Severity 0 -Component "Files"
Get-ChildItem "$SDCRootPath\Templates" -Recurse -File | Where-Object { $_.Name -like "*.admx" } | Copy-Item -Destination $env:WINDIR\PolicyDefinitions -Recurse -Force
Get-ChildItem "$SDCRootPath\Templates" -Recurse -File | Where-Object { $_.Name -like "*.adml" } | Copy-Item -Destination $env:WINDIR\PolicyDefinitions\en-us -Recurse -Force

Write-CMLogEntry -Value "Processing LGPO Policy" -Severity 0 -Component "LGPO"
& $LGPO "/g" "$SDCRootPath\Policy" "/v"

Write-CMLogEntry -Value "Processing Registry Changes" -Severity 0 -Component "Registry"
#NET Framework 4.0 STIG (V-30935) - Validation of Strong Names
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework" -Name AllowStrongNameBypass -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
New-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" -Name AllowStrongNameBypass -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
#Update for Disabling TLS RC4 cipher in .NET (ACAS)
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" -Name SchUseStrongCrypto -Value 1 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
New-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727" -Name SchUseStrongCrypto -Value 1 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
#NET Framework 4.0 STIG (V-81495) - Disable TLS RC4 cipher in .Net -- (Added in v1r6 STIG)
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto -Value 1 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
New-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name SchUseStrongCrypto -Value 1 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
#MS15-124 - IE 11 User32 Exception Handler Hardening (ACAS)
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Name 'iexplore.exe' -Value 1 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
New-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -Name 'iexplore.exe' -Value 1 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
#CVE-2017-8529 - Critical - IE 11 iFrame Printing Vulnerability (ACAS)
New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" -Name 'iexplore.exe' -Value 1 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
New-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" -Name 'iexplore.exe' -Value 1 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
# Minimize Internet Connections
If ($OS -match 'Windows 10|Windows 11') {
    New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name 'fMinimizeConnections' -Value 1 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
}
# Local Accounts
Write-CMLogEntry -Value "Processing Local Account PasswordExpiration" -Severity 0
Get-LocalUser | Where-Object { $_.PasswordExpires -ne $True } | Set-LocalUser -PasswordNeverExpires:$False

# DEP Settings
If ($OS -match 'Windows 10|Windows 11') {
    Write-CMLogEntry -Value "Processing DEP Configuration" -Severity 0
    cmd.exe /c "bcdedit.exe /set {current} nx OptOut"
}

# Configure OS Drive Label
Write-CMLogEntry -Value "Renaming OS Drive Label" -Severity 0
Get-Volume -DriveLetter C | Set-Volume -NewFileSystemLabel OS

# Configure Start Layout Function
function Set-StartLayout {
    If ($StartLayout -ne $True) {
        Write-CMLogEntry -Value "Start Layout not enabled skipping routine." -Severity 2 -Component "Branding"
    }
    Else {
        Write-CMLogEntry -Value "Configuring Start Layout" -Severity 0 -Component "Branding"
        If ((Test-Path $SDCRootPath\Files\StartMenu\LayoutModification.json) -and ($OS -match 'Windows 11')) {
            $StartLayoutModification = "$SDCRootPath\Files\StartMenu\LayoutModification.json"
            Write-CMLogEntry -Value "Detected Start Layout File:$($StartLayoutModification) for $($OS)" -Severity 0 -Component "Branding"
            Copy-Item -Path $StartLayoutModification -Destination "$env:SystemDrive\Users\Default\Appdata\Local\Microsoft\Windows\Shell" -Force | Out-Null
        }
        ElseIf ((Test-Path $SDCRootPath\Files\StartMenu\LayoutModification.xml) -and ($OS -match 'Windows 10')) {
            $StartLayoutModification = "$SDCRootPath\Files\StartMenu\LayoutModification.xml"
            Write-CMLogEntry -Value "Detected Start Layout File:$($StartLayoutModification) for $($OS)" -Severity 0 -Component "Branding"
            Import-StartLayout -LayoutPath $StartLayoutModification -MountPath $env:SystemDrive\ -ErrorAction SilentlyContinue
        }
        ElseIf ($IsServer -eq $True) {
            Write-CMLogEntry -Value "Start Layout not supported on $($OS)." -Severity 2 -Component "Branding"
        }
        Else {
            Write-CMLogEntry -Value "StartLayout File Missing." -Severity 2 -Component "Branding"
        }
        Write-CMLogEntry -Value "Configuring Start Layout Completed Succesfully..." -Severity 1 -Component "Branding"
    }
}

# Configure Taskbar Layout Function
function Set-TaskbarLayout {
    If ($TaskbarLayout -ne $True) {
        Write-CMLogEntry -Value "Taskbar Layout not enabled skipping routine." -Severity 1 -Component "Branding"
    }
    Else {
        If ((Test-Path $SDCRootPath\Files\Taskbar\TaskbarLayoutModification.xml) -and ($OS -match 'Windows 11')) {
            Write-CMLogEntry -Value "Configuring Taskbar Layout" -Severity 0 -Component "Branding"
            $TaskbarLayoutModification = "$SDCRootPath\Files\Taskbar\TaskbarLayoutModification.xml"
            Write-CMLogEntry -Value "Detected Taskbar Layout File:$($TaskbarLayoutModification) for $($OS)" -Severity 0 -Component "Branding"
            If (!(Test-Path $env:WINDIR\OEM)) { New-Item -ItemType Directory -Path $env:WINDIR\OEM -Force | Out-Null }
            Copy-Item -Path $TaskbarLayoutModification -Destination $env:WINDIR\OEM -Force | Out-Null
            New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name LayoutXMLPath -Value $env:WINDIR\OEM\TaskbarLayoutModification.xml -Force | Out-Null
        }
        ElseIf ($OS -notmatch "Windows 11") {
            Write-CMLogEntry -Value "Taskbar Layout not supported on $($OS)." -Severity 2 -Component "Branding"
        }
        Else {
            Write-CMLogEntry -Value "Taskbar Layout File Missing." -Severity 2 -Component "Branding"
        }
        Write-CMLogEntry -Value "Configuring Taskbar Layout Completed Succesfully..." -Severity 1 -Component "Branding"
    }
}

function Set-DefaultTheme {
    If ($Theme -ne $True) {
        Write-CMLogEntry -Value "Theme not enabled skipping routine..." -Severity 0 -Component "Branding"
    }
    else {
        Write-CMLogEntry -Value "Configuring Default Windows Corporate Theme." -Severity 0 -Component "Branding"
        Copy-Item "$SDCRootPath\Files\Theme\CorporateTheme.theme" -Destination $env:WINDIR\Resources\Themes -Force | Out-Null
        $Null = New-Item -Path "HKLM:\Temp\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ItemType Directory -Force | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name ThemeFile -Value "$env:WINDIR\Resources\Themes\CorporateTheme.Theme" -PropertyType String -Force  | Out-Null
    }
}

function Set-DefaultWallpaper {
    If ($Wallpaper -ne $True) {
        Write-CMLogEntry -Value "Default Wallpaper not enabled skipping routine." -Severity 2 -Component "Branding"
    }
    Else {
        Write-CMLogEntry -Value "Configuring Default Wallpaper." -Severity 0 -Component "Branding"
        $Files = Get-ChildItem -Path "$env:WINDIR\Web\Wallpaper\Windows", "$env:WINDIR\Web\4K\Wallpaper\Windows" -Recurse | Where-Object { $_.Extension -eq ".jpg" }
        Write-CMLogEntry -Value "Replacing Default Wallpaper with Corporate Wallpaper." -Severity 0 -Component "Branding"
        foreach ($Item in $Files) {
            Write-CMLogEntry -Value "Taking Ownership of $($Item.FullName)" -Severity 0 -Component "Branding"
            takeown /f $Item.FullName
            Write-CMLogEntry -Value "Granting Full Control Permission to Administrators Group for $($Item.FullName)" -Severity 0 -Component "Branding"
            & icacls $Item.FullName /grant "Administrators:(F)"
            Remove-Item -Path $Item.FullName -Force -ErrorAction SilentlyContinue | Out-Null
            Write-CMLogEntry -Value "Deleting $($Item.Fullname)" -Severity 0 -Component "Branding"
        }
        Copy-Item "$SDCRootPath\Files\Wallpaper\CorporateWallpaper.jpg" -Destination $env:WINDIR\Web\Wallpaper\Windows\img0.jpg -Force | Out-Null
        Copy-Item "$SDCRootPath\Files\Wallpaper\CorporateWallpaper.jpg" -Destination $env:WINDIR\Web\4K\Wallpaper\Windows\img0.jpg -Force | Out-Null
        Copy-Item "$SDCRootPath\Files\Wallpaper\*" -Destination $env:WINDIR\Web\4K\Wallpaper\Windows -Recurse -Force
        Copy-Item "$SDCRootPath\Files\Wallpaper\CorporateWallpaper.jpg" -Destination $env:WINDIR\Web\Wallpaper -Force | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\Control Panel\Desktop" -Name Wallpaper -Value "$env:windir\Web\Wallpaper\CorporateWallpaper.jpg" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

function Set-DefaultLockscreen {
    If ($LockScreen -ne $True) {
        Write-CMLogEntry -Value "Default Lockscreen not enabled skipping routine." -Severity 2 -Component "Branding"
    }
    Else {
        Write-CMLogEntry -Value "Configuring Default Lockscreen." -Severity 0 -Component "Branding"
        $Files = Get-ChildItem -Path "$env:WINDIR\Web\Screen" -Recurse | Where-Object { $_.Name -eq "img100.jpg" -or $_.Name -eq "img105.jpg" }

        Write-CMLogEntry -Value "Replacing Default Lockscreen with Corporate Lockscreen." -Severity 0 -Component "Branding"
        foreach ($Item in $Files) {
            Write-CMLogEntry -Value "Taking Ownership of $($Item.FullName)" -Severity 0 -Component "Branding"
            takeown /f $Item.FullName
            Write-CMLogEntry -Value "Granting Full Control Permission to Administrators Group for $($Item.FullName)" -Severity 0 -Component "Branding"
            & icacls $Item.FullName /grant "Administrators:(F)"
            Remove-Item -Path $Item.FullName -Force -ErrorAction SilentlyContinue | Out-Null
            Write-CMLogEntry -Value "Deleting $($Item.Fullname)" -Severity 0 -Component "Branding"
        }
        Copy-Item "$SDCRootPath\Files\Lockscreen\CorporateLockScreen.jpg" -Destination $env:WINDIR\Web\Screen\img100.jpg -Force | Out-Null
        Copy-Item "$SDCRootPath\Files\Lockscreen\CorporateLockScreen.jpg" -Destination $env:WINDIR\Web\Screen\img105.jpg -Force | Out-Null

        If ($OS -notcontains 'Server') {
            Write-CMLogEntry -Value "Disabling Locksreen Tools Tips and Rotation" -Severity 0 -Component "Branding"
            If (!(Test-Path HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager)) { $Null = New-Item HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -ItemType Directory -Force | Out-Null }
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name RotatingLockScreenOverlayEnabled -Value "0" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name RotatingLockScreenEnabled -Value "0" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null

            Write-CMLogEntry -Value "Disabling Lockscreen Bing Rotation" -Severity 0 -Component "Branding"
            If (!(Test-Path "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative")) { $Null = New-Item "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -ItemType Directory -Force | Out-Null }
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name LockImageFlags -Value "0" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name LockScreenOptions -Value "0" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name CreativeId -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name DescriptionText -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name ActionText -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name ActionUri -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name PlacementId -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name ClickthroughToken -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name ImpressionToken -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name CreativeJson -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name PortraitAssetPath -Value "0" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name LandscapeAssetPath -Value "$env:WINDIR\Web\Screen\img100.jpg" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name LockImageFlags -Value "$env:WINDIR\Web\Screen\img100.jpg" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name HotspotImageFolderPath -Value "$env:WINDIR\Web\Screen\img100.jpg" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null

            Write-CMLogEntry -Value "Disabling Spotlight" -Severity 0 -Component "Branding"
            If (!(Test-Path HKLM:\Temp\SOFTWARE\Policies\Microsoft\Windows\CloudContent)) { $Null = New-Item HKLM:\Temp\SOFTWARE\Policies\Microsoft\Windows\CloudContent -ItemType Directory -Force | Out-Null }
            $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsSpotlightFeatures -Value "1" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
        }

        Write-CMLogEntry -Value "Disabling Windows LogonBackGroundImage" -Severity 0 -Component "Branding"
        $Null = New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\System" -Name DisableLogonBackgroundImage -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null

        Write-CMLogEntry -Value "Enforcing Lockscreen" -Severity 0 -Component "Branding"
        If (!(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization)) { $Null = New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Force | Out-Null }
        $Null = New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name LockScreenImage -Value "$env:WINDIR\Web\Screen\img100.jpg" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name UseDefaultTile -Value "1" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name UseDefaultTile -Value "1" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

function Set-DesktopIcons {
    If ($DesktopIcons -ne $True) {
        Write-CMLogEntry -Value "Desktop Icons not enabled skipping routine." -Severity 1 -Component "Branding"
    }
    Else {
        Write-CMLogEntry -Value "Configuring Default Windows Desktop Icons - Desktop,Documents,Control Panel,Recycle Bin" -Severity 0 -Component "Branding"
        # Desktop
        $Null = New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
        # Documents
        $Null = New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
        # Control Panel
        $Null = New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
        # Recycle Bin
        $Null = New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
        # Sort Desktop Icons by Type
        $Null = New-ItemProperty "HKLM:\Temp\Software\Microsoft\Windows\Shell\Bags\1\Desktop" -Name "FFlags" -Value '40200224' -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
    }
}

Function Set-ThisPCToComputerName {
    If ($ThisPCToComputerName -ne $True) {
        Write-CMLogEntry -Value "This PC to Computername not enabled skipping routine." -Severity 1 -Component "Branding"
    }
    Else {
        If ($IsServer -eq $True -or $OS -like '*Multi-Session*') {
            Write-CMLogEntry -Value "This PC To Computername not supported on $($OS)." -Severity 2 -Component "Branding"
        }
        Else {
            Write-CMLogEntry -Value "Configuring This PC to display $($env:computername) on the desktop." -Severity 0 -Component "Branding"
            function enable-privilege {
                param(
                    ## The privilege to adjust. This set is taken from
                    ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
                    [ValidateSet(
                        "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
                        "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
                        "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
                        "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
                        "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
                        "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
                        "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
                        "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
                        "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
                        "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
                        "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
                    $Privilege,
                    ## The process on which to adjust the privilege. Defaults to the current process.
                    $ProcessId = $pid,
                    ## Switch to disable the privilege, rather than enable it.
                    [Switch] $Disable
                )

                ## Taken from P/Invoke.NET with minor adjustments.
                $definition = @'
 using System;
 using System.Runtime.InteropServices;

 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }

  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

                $processHandle = (Get-Process -Id $ProcessId).Handle
                $type = Add-Type $definition -PassThru
                $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
            }

            #Take OwnerShip
            enable-privilege SeTakeOwnershipPrivilege
            $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::takeownership)
            # You must get a blank acl for the key b/c you do not currently have access
            $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
            $identity = "BUILTIN\Administrators"
            $me = [System.Security.Principal.NTAccount]$identity
            $acl.SetOwner($me)
            $key.SetAccessControl($acl)

            # After you have set owner you need to get the acl with the perms so you can modify it.
            $acl = $key.GetAccessControl()
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($identity, "FullControl", "Allow")
            $acl.SetAccessRule($rule)
            $key.SetAccessControl($acl)

            $key.Close()


            #Grant Rights to Admin & System
            # Set Adminstrators of Full Control of Registry Item
            $RegistryPath = "Registry::HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

            $identity = "BUILTIN\Administrators"
            $RegistrySystemRights = "FullControl"
            $type = "Allow"
            # Create new rule
            $RegistrySystemAccessRuleArgumentList = $identity, $RegistrySystemRights, $type
            $RegistrySystemAccessRule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList $RegistrySystemAccessRuleArgumentList
            # Apply new rule
            $NewAcl.SetAccessRule($RegistrySystemAccessRule)
            Set-Acl -Path $RegistryPath -AclObject $NewAcl


            # Set SYSTEM to Full Control of Registry Item
            $identity = "NT AUTHORITY\SYSTEM"
            $RegistrySystemRights = "FullControl"
            $type = "Allow"
            # Create new rule
            $RegistrySystemAccessRuleArgumentList = $identity, $RegistrySystemRights, $type
            $RegistrySystemAccessRule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList $RegistrySystemAccessRuleArgumentList
            # Apply new rule
            $NewAcl.SetAccessRule($RegistrySystemAccessRule)
            Set-Acl -Path $RegistryPath -AclObject $NewAcl


            #Set the Values to actually make this work
            Set-Item -Path $RegistryPath -Value $env:COMPUTERNAME -Force
            Set-ItemProperty -Path $RegistryPath -Name "LocalizedString" -Value  $env:COMPUTERNAME -Force
            #Enable the "This PC" Icon to show on Desktop
            $Null = Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Force
        }
    }
}

Function Set-OEMBranding {
    If ($OEMBranding -ne $True) {
        Write-CMLogEntry -Value "OEM Branding not enabled skipping routine." -Severity 2 -Component "Branding"
    }
    Else {
        Write-CMLogEntry -Value "Configuring OEM Branding Information" -Severity 0 -Component "Branding"
        $OEMLogo = "$SDCRootPath\Files\OEMLogo\OEMLogo.bmp"
        Copy-Item $OEMLogo $env:WINDIR\OEM -Force -ErrorAction SilentlyContinue | Out-Null
        Copy-Item "$SDCRootPath\Files\UserLogos\*" "$env:SystemDrive\ProgramData\Microsoft\User Account Pictures" -Recurse -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "UseDefaultTile" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
        $OEMKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
        Set-ItemProperty -Path $OEMKey -Name "Model" -Value $Script:Model -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "HelpCustomized" -Value 00000000 -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "SupportHours" -Value "24/7" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "Logo" -Value "$env:WINDIR\OEM\OEMLogo.bmp" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "Manufacturer" -Value $Manufacturer -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "SupportPhone" -Value $SupportPhone -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "SupportURL" -Value $SupportURL -ErrorAction SilentlyContinue | Out-Null
    }
}

Function Set-RegistryHKCU {
    If ($RegistryHKCU -ne $True) {
        Write-CMLogEntry -Value "Registry HKCU Settings not enabled skipping routine." -Severity 2 -Component "Branding"
    }
    Else {
        Write-CMLogEntry -Value "Configuring HKCU Registry Settings" -Severity 0 -Component "Branding"
        Write-CMLogEntry -Value "Configuring File Name Extensions" -Severity 0 -Component "Branding"
        If (!(Test-Path HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced)) { $Null = New-Item HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Force | Out-Null }
        New-ItemProperty -Path "HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
        If ($OS -Match "Windows 11" -and $DisableTeams -eq $True) {
            Write-CMLogEntry -Value "Disabling Teams" -Severity 0 -Component "Branding"
            New-ItemProperty -Path "HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" -Force -ErrorAction SilentlyContinue | Out-Null
            New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" -Name ChatIcon -Value 3 -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
            Get-AppxPackage -AllUsers -Name '*MicrosoftTeams*' | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        }
    }
}

Write-CMLogEntry -Value "Detected Operating System: $($OS)" -Severity 0
Write-CMLogEntry "Detected Operating System Version: $($OSBuild)" -Severity 0

If (Test-Path HKLM:\DefaultUser) {
    Write-CMLogEntry -Value "Unmounting Default User Hive - Leftover from previous process..." -Severity 3
    reg.exe unload 'HKLM\DefaultUser'
    Start-Sleep -Seconds 5
}
Write-CMLogEntry -Value "Mounting Default User Hive" -Severity 0
Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load HKLM\Temp $env:SystemDrive\Users\Default\NTUSER.dat" -WindowStyle Hidden -PassThru -Wait | Out-Null

Set-StartLayout
Set-TaskbarLayout
Set-DefaultWallpaper
Set-DefaultLockscreen
Set-DefaultTheme
Set-DesktopIcons
Set-ThisPCToComputerName
Set-OEMBranding
Set-RegistryHKCU


# Cleanup and dispose of variables.
Get-Variable Registry* | Remove-Variable
[gc]::Collect()
Start-Sleep -Seconds 5
Set-Location C:\
Write-CMLogEntry -Value "Unmounting Default User Hive" -Severity 0
reg.exe unload 'HKLM\Temp'