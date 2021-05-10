##################### ReadMe ###########################################################
#
# Please review the instructions:
#
# Text: https://github.com/AdrianKruss/DataCollection/blob/master/README.md
#
# Word : https://github.com/AdrianKruss/DataCollection/blob/master/Read-Me.docx
#
#######################################################################################

########### Importing HTML Module ##############
 if (Get-Module -ListAvailable -Name PSWriteHTML) {
          Write-Host "Module exists"
      } 
      else {
          Install-Module PSWriteHTML -Force
      }

########### Declaring variable #############
$FailedItems = @()
$Goodvalues = @{}
$Badvalues = @{}

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
$WindowsPFWEnabled = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"

############ Collecting Microsoft OS Minimum version settings ################

$OSCurrentVersion = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

############ Collecting Microsoft Real Time protection settings ################

$RTProtection = Get-ItemProperty -Path "HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection"

############ Collecting Event Viewer data (Admin) ################################

$EVAdmin = Get-WinEvent Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin | where {($_.id -eq "404") -or ($_.id -eq "809") -or ($_.id -eq "820")}

############ Collecting Event Viewer data (Operational) ################################

$EVOperational = Get-WinEvent Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational | where {($_.id -eq "404") -or ($_.id -eq "809") -or ($_.id -eq "820")}


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

################ Collecting Local Security Policy Settings ###################
SecEdit /export /cfg .\cfg.ini

$PasswordPolicyComplexity = (Cat .\cfg.ini | Select-String –Pattern "PasswordComplexity" | Select-Object -First 1 ) -split "=" | Select-Object -Skip 1
$PasswordPolicyExpiration = (Cat .\cfg.ini | Select-String –Pattern "MaximumPasswordAge" | Select-Object -First 1 ) -split "=" | Select-Object -Skip 1
$PasswordHistorySize = (Cat .\cfg.ini | Select-String –Pattern "PasswordHistorySize" | Select-Object -First 1 ) -split "=" | Select-Object -Skip 1


##################### Main #####################

if($WindowsFWEnabled.EnableFirewall -eq "0" -and $WindowsPFWEnabled.EnableFirewall -eq "0")
{
    Write-Output "Windows Firewall is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/you-need-to-enable-defender-firewall-windows"
    $FailedItems += "Windows Firewall is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/you-need-to-enable-defender-firewall-windows"
    $Badvalues.Firewall =  $WindowsFWEnabled.EnableFirewall
}

else
{
$Goodvalues.Firewall =  $WindowsFWEnabled.EnableFirewall
}

if($DisableAntiSpyware.DisableAntiSpyware -eq "1")
{
    Write-Output "Windows Defender Anti-Spyware Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
    $FailedItems += "Windows Defender Anti-Spyware Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
    $Badvalues.DisableAntiSpyware = $DisableAntiSpyware.DisableAntiSpyware
}

else
{
$Goodvalues.DisableAntiSpyware = $DisableAntiSpyware.DisableAntiSpyware

}

if($DisableAntiVirus.DisableAntiVirus -eq "1")
{
    Write-Output "Windows Defendput er Anti-Virus Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
    $FailedItems += "Windows Defendput er Anti-Virus Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
    $Badvalues.DisableAntiVirus = $DisableAntiVirus.DisableAntiVirus
}
else
{
$Goodvalues.DisableAntiVirus = $DisableAntiVirus.DisableAntiVirus
}

if($RTProtection.DpaDisabled -eq "1")
{
    Write-Output "Windows Defender Anti-Virus Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
    $FailedItems += "Windows Defender Anti-Virus Protection is disabled but needs to be enabled for compliance https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows"
    $Badvalues.RTPProtection = $RTProtection.DpaDisabled
}

else
{
$Goodvalues.RTPProtection = $RTProtection.DpaDisabled
}

if($Signature -eq "1")
{
    Write-Output "AntiVirus Signatures and or Definitions are out of Date"
    $FailedItems += "AntiVirus Signatures and or Definitions are out of Date"
    $Badvalues.signature = $Signature.DisableDefaultSigs
}

else
{
$Goodvalues.signature = $Signature.DisableDefaultSigs
}

if($DefenderPolicies -ne $null)
{
    Write-Output "Conflicting Anti-Virus Policies, see HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
    $FailedItems += "Conflicting Anti-Virus Policies, see HKLM:\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender"
    $Badvalues.DefenderPolicies = $DefenderPolicies
}

else
{
$GoodValues.DefenderPolicies = $DefenderPolicies
}

if($EVAdmin)
{
    Write-Output "Errors related to Password Days expiration in event vwr logs(Admin):"
    $FailedItems += "Errors related to Password Days expiration in event vwr logs(Admin):"
}


if($EVOperational)
{
    Write-Output "Errors related to Password Days expiration in event vwr logs(Opertional):"
    $FailedItems += "Errors related to Password Days expiration in event vwr logs(Opertional):"
}

############### OS #######################

if($OSCurrentVersion.CurrentMajorVersionNumber -ge "10")
{

    if($OSCurrentVersion.CurrentBuildNumber -lt "17738")
    {
      $FailedItems += "Windows OS version is Windows 10 or greater but build is less than 17738, see https://docs.microsoft.com/en-us/windows/release-information/ for Windows 10 release information"  
      $Badvlaues.CurrentBuildNumber = $OSCurrentVersion.CurrentBuildNumber
    }
    else
    {
    $Goodvalues.CurrentBuildNumber = $OSCurrentVersion.CurrentBuildNumber
    }


}

if($OSCurrentVersion.CurrentMajorVersionNumber -lt "10")
{

    $FailedItems += "Windows OS version is not Windows 10 or greater"
    $BadValues.OSCurrentMajorVersion = $OSCurrentVersion.CurrentMajorVersionNumber

}
else
{
$Goodvalues.OSCurrentMajorVersion = $OSCurrentVersion.CurrentMajorVersionNumber
}

##################### Password ####################


if($DeviceLock.MinDevicePasswordComplexCharacters -ne "2" -and $PasswordPolicyComplexity -ne 1)
{
    Write-Output "The number of complex element types (uppercase and lowercase letters, numbers, and punctuation) required for a strong PIN or password is not set"
    $FailedItems += "The number of complex element types (uppercase and lowercase letters, numbers, and punctuation) required for a strong PIN or password is not set"
    $BadValues.MinDevicePasswordComplexCharacters = $DeviceLock.MinDevicePasswordComplexCharacters
}

else
{
$Goodvalues.MinDevicePasswordComplexCharacters = $DeviceLock.MinDevicePasswordComplexCharacters
}

if($DeviceLock.DevicePasswordExpiration -lt "180" -and $PasswordPolicyExpiration -lt "180")
{
    Write-Output "Device doesn't meet Intune Password Policy Expiration.The device password expiration is less than 180 days"
    $FailedItems += "Device doesn't meet Intune Password Policy Expiration. The device password expiration is less than 180 days"
    $Badvalues.DevicePasswordExpiration = $DeviceLock.DevicePasswordExpiration
}

else
{
$Goodvalues.DevicePasswordExpiration = $DeviceLock.DevicePasswordExpiration
}

if($DeviceLock.DevicePasswordHistory -lt "5" -and $PasswordHistorySize -lt "5")
{
    Write-Output "Device doesn't meet Intune Password Policy History. The Device Password History is less than 5"
    $FailedItems += "Device doesn't meet Intune Password Policy History.The Device Password History is less than 5"
    $BadValues.DevicePasswordHistory = $DeviceLock.DevicePasswordHistory
}
else
{
$Goodvalues.DevicePasswordHistory = $DeviceLock.DevicePasswordHistory
}

if($DeviceLock.MinDevicePasswordLength -lt "8")
{
    Write-Output "Device password length is less than 8 characters"
    $FailedItems += "Device password length is less than 8 characters"
    $BadValues.MinDevicePasswordLength = $DeviceLock.MinDevicePasswordLength
}

else
{
$Goodvalues.MinDevicePasswordLength = $DeviceLock.MinDevicePasswordLength
}
if($DeviceLock.AlphanumericDevicePasswordRequired -ne "0")
{
    Write-Output "Device must support alpha numeric passwords"
    $FailedItems += "Device must support alpha numeric passwords"
    $BadValues.AlphanumericDevicePasswordRequired = $DeviceLock.AlphanumericDevicePasswordRequired
}

else
{
$Goodvalues.AlphanumericDevicePasswordRequired = $DeviceLock.AlphanumericDevicePasswordRequired
}

if($DeviceLock.AllowSimpleDevicePassword -eq "1")
{
    Write-Output "Device simple Password is enable"
    $FailedItems += "Device simple Password is enable"
    $BadValues.AllowSimpleDevicePassword = $DeviceLock.AllowSimpleDevicePassword
}

else
{
$Goodvalues.AllowSimpleDevicePassword = $DeviceLock.AllowSimpleDevicePassword
}

if($DeviceLock.DevicePasswordEnabled -eq "1")
{
    Write-Output "Device Password is disable"
    $FailedItems += "Device Password is disable"
    $BadValues.DevicePasswordEnabled = $DeviceLock.DevicePasswordEnabled
}

else
{
$Goodvalues.DevicePasswordEnabled = $DeviceLock.DevicePasswordEnabled
}


##################### Adding Expected Values ##################################

$ExpectedValues = @( 

New-Object PSObject -property @{ Name='Firewall'; Value='1' ;Reference = 'https://docs.microsoft.com/en-us/mem/intune/user-help/you-need-to-enable-defender-firewall-windows';}
New-Object PSObject -property @{ Name='Minimum-OSBuildNumber'; Value='17738';Reference = 'https://docs.microsoft.com/en-us/windows/release-information/ for Windows 10 release information'}
New-Object PSObject -property @{ Name='DefenderPolicies'; Value='1';Reference = 'https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows'}
New-Object PSObject -property @{ Name='DevicePasswordEnabled'; Value='0'; Reference = 'https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock#devicelock-devicepasswordenabled' }
New-Object PSObject -property @{ Name='DisableAntiSpyware'; Value='0';Reference = 'https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-window'}
New-Object PSObject -property @{ Name='DisableAntiVirus'; Value='0'; Reference = 'https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows'}
New-Object PSObject -property @{ Name='OSMajorVersion'; Value='10'}
New-Object PSObject -property @{ Name='RTPProtection'; Value='0'; Reference = 'https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows'}
New-Object PSObject -property @{ Name='Signature'; Value='0'; Reference = 'https://docs.microsoft.com/en-us/mem/intune/user-help/turn-on-defender-windows' }
New-Object PSObject -property @{ Name='AlphanumericDevicePasswordRequired'; Value='0'; Reference = 'https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock#devicelock-alphanumericdevicepasswordrequired'}
New-Object PSObject -property @{ Name='DevicePasswordExpiration'; Value='180'; Reference = 'https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock#devicelock-devicepasswordexpiration'}
New-Object PSObject -property @{ Name='DevicePasswordHistory'; Value='5'; Reference = 'https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock#devicelock-minimumpasswordage'}
New-Object PSObject -property @{ Name='MinDevicePasswordComplexCharacters'; Value='2'; Reference = 'https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock#devicelock-mindevicepasswordcomplexcharacters'}
New-Object PSObject -property @{ Name='MinDevicePasswordLength'; Value='8' ; Reference = 'https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-devicelock#devicelock-mindevicepasswordlength'}
)

$ExpectedValues = $ExpectedValues|Select-Object Name,Value,Reference

#######################################################

if(!$FailedItems){

    $FailedItems = "Device settings match required Intune compliance settings"

}
New-HTML {

    Tab -Name "Intune results"{
            
            if ($null -eq $FailedItems) 
            {
                New-HTMLText -text 'Pass' -FontSize 34 -Color Green -BackGroundColor LightBlue -Alignment center
                #New-HTMLTableHeader -Title 'Failed' -FontSize 24 -Color Red -BackGroundColor Green
            }
            elseif ($null -ne $FailedItems) 
            {
                New-HTMLText -text 'Failed' -FontSize 34 -Color Red -BackGroundColor LightBlue -Alignment center
            }
        
            New-HTMLTable -DataTable $FailedItems{ }
    
              
            New-HTMLTable -DataTable $Badvalues -HideFooter  -AutoSize { New-HTMLTableHeader -Title 'BadValues' -FontSize 24 -Color Red -BackGroundColor LightBlue}
             
            New-HTMLTable -DataTable $Goodvalues -HideFooter -AutoSize { New-HTMLTableHeader -Title 'GoodValues' -FontSize 24 -Color green -BackGroundColor LightBlue}
            
            
       
    New-HTMLTable -DataTable $ExpectedValues -HideFooter { New-HTMLTableHeader -Title 'ExpectedValues' -FontSize 24 -Color Blue -BackGroundColor LightBlue} }
                
} -FilePath Intune.Html -online -TitleText 'Intune results' -ShowHTML

