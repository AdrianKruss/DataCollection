########### Declaring variable #############
$FailedItems = @()

############### Collecting AntiSpyware setting ########################

$DisableAntiSpyware = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiSpyware"

############ Collecting Microsoft Defender Antimalware settings ################

$DefenderPolicies = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"

############ Collecting Microsoft Defender AntiVirus settings ################

$DisableAntiVirus = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender" -Name "DisableAntiVirus"

############ Collecting Microsoft Defender Antimalware signature settings ################

$Signature = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Signature Updates"


############ Collecting Microsoft Firewall  settings ################

$WindowsFWEnabled = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"

############ Collecting Microsoft OS Minimum version settings ################

$OSCurrentVersion = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

############ Collecting Microsoft Real Time protection settings ################

$RTProtection = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"






################ Collecting Password Settings ###################

# Collecting Password Complexity settings 
# Collecting Password Expiration (days) settings
# Collecting Number of previous password to prevent reuse
# Collecting minimum password length
# Collecting maximum munites of inactivity before password is required
# Collecting Password type
# Collecting simple password
# Collecting require a password to unlock mobile device

############ Collecting Munber of previous passwords  settings ################


$DeviceLock = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\DeviceLock"
$AllowScreenTimeoutWhileLockedUserConfig = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\AllowScreenTimeoutWhileLockedUserConfig"
#$AlphanumericDevicePasswordRequired = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\AlphanumericDevicePasswordRequired"
#$DevicePasswordEnabled = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\DeviceLock\DevicePasswordEnabled"

################ Collecting Local Security Policy Settings ###################
SecEdit /export /cfg .\cfg.ini

$PasswordPolicyComplexity = (Cat .\cfg.ini | Select-String –Pattern "PasswordComplexity" | Select-Object -First 1 ) -split "=" | Select-Object -Skip 1
$PasswordPolicyExpiration = (Cat .\cfg.ini | Select-String –Pattern "MaximumPasswordAge" | Select-Object -First 1 ) -split "=" | Select-Object -Skip 1
$PasswordHistorySize = (Cat .\cfg.ini | Select-String –Pattern "PasswordHistorySize" | Select-Object -First 1 ) -split "=" | Select-Object -Skip 1


##################### Main #####################

if($WindowsFWEnabled -eq "0")
{
    Write-Output "Windows Firewall is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/you-need-to-enable-defender-firewall-windows"
    $FailedItems += "Windows Firewall is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/you-need-to-enable-defender-firewall-windows"
}

if($DisableAntiSpyware.DisableAntiSpyware -eq "1")
{
    Write-Output "Windows Defender Anti-Spyware Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
    $FailedItems += "Windows Defender Anti-Spyware Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
}

if($DisableAntiVirus.DisableAntiVirus -eq "1")
{
    Write-Output "Windows Defendput er Anti-Virus Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
    $FailedItems += "Windows Defendput er Anti-Virus Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
}

if($RTProtection.DpaDisabled -eq "1")
{
    Write-Output "Windows Defender Anti-Virus Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
    $FailedItems += "Windows Defender Anti-Virus Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
}

if($Signature -eq "1")
{
    Write-Output "AntiVirus Signatures and or Definitions are out of Date"
    $FailedItems += "AntiVirus Signatures and or Definitions are out of Date"
}

if($DefenderPolicies -ne $null)
{
    Write-Output "Conflicting Anti-Virus Policies, see HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
    $FailedItems += "Conflicting Anti-Virus Policies, see HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
}

############### OS #######################

if($OSCurrentVersion.CurrentMajorVersionNumber -ge "10")
{

    if($OSCurrentVersion.CurrentBuildNumber -lt "17738")
    {
      $FailedItems += "Windows OS version is Windows 10 or greater but build is less than 17738, see https://docs.microsoft.com/en-us/windows/release-information/ for Windows 10 release information"  
    }

}

if($OSCurrentVersion.CurrentMajorVersionNumber -lt "10")
{

    $FailedItems += "Windows OS version is not Windows 10 or greater"

}

##################### Password ####################


if($DeviceLock.MinDevicePasswordComplexCharacters -ne "3")
{
    Write-Output "The number of complex element types (uppercase and lowercase letters, numbers, and punctuation) required for a strong PIN or password is not set"
    $FailedItems += "The number of complex element types (uppercase and lowercase letters, numbers, and punctuation) required for a strong PIN or password is not set"
}

if($DeviceLock.DevicePasswordExpiration -lt "180")
{
    Write-Output "Device doesn't meet Intune Password Policy Expiration.For Intune Device Policy Settings please visit https://dev.azure.com/Supportability/Rave%20Desk/_wiki/wikis/Rave%20Desk/327435/Intune-Policy-Settings"
    $FailedItems += "Device doesn't meet Intune Password Policy Expiration.For Intune Device Policy Settings please visit https://dev.azure.com/Supportability/Rave%20Desk/_wiki/wikis/Rave%20Desk/327435/Intune-Policy-Settings"
}


if($DeviceLock.DevicePasswordHistory -lt "5")
{
    Write-Output "Device doesn't meet Intune Password Policy History.For Intune Device Policy Settings please visit https://dev.azure.com/Supportability/Rave%20Desk/_wiki/wikis/Rave%20Desk/327435/Intune-Policy-Settings"
    $FailedItems += "Device doesn't meet Intune Password Policy History.For Intune Device Policy Settings please visit https://dev.azure.com/Supportability/Rave%20Desk/_wiki/wikis/Rave%20Desk/327435/Intune-Policy-Settings"
}

if($DeviceLock.MinDevicePasswordLength -lt "8")
{
    Write-Output "Device password length is less than 8 characters"
    $FailedItems += "Device password length is less than 8 characters"
}

if($DeviceLock.AlphanumericDevicePasswordRequired -ne "0")
{
    Write-Output "Device must support alpha numeric passwords"
    $FailedItems += "Device must support alpha numeric passwords"
}


if($DeviceLock.AllowSimpleDevicePassword -eq "1")
{
    Write-Output "Device simple Password is enable"
    $FailedItems += "Device simple Password is enable"
}

if($DeviceLock.DevicePasswordEnabled -eq "1")
{
    Write-Output "Device Password is disable"
    $FailedItems += "Device Password is disable"
}


#######################################################

if(!$FailedItems){

    $FailedItems = "Device settings match required Intune compliance settings"

}
New-HTML {

    New-HTMLTab -Name "Intune results"{
            New-HTMLTable -DataTable $FailedItems{
            }
        }
                
} -FilePath $PSScriptRoot\Intune.Html -UseCssLinks -UseJavaScriptLinks -TitleText 'Intune results' -ShowHTML