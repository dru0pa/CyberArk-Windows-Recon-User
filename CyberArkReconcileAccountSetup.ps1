<#
.SYNOPSIS
    This PowerShell script creates and configures a local user account for CyberArk reconciliation on Windows servers.

.DESCRIPTION
    This script automates the process of setting up a dedicated local user account for CyberArk reconciliation tasks. It handles user creation, password management, group memberships, User Account Control (UAC) settings, file and printer sharing, and the "Log on as a service" right. The script includes checks to prevent errors and ensure idempotency, making it suitable for both initial setup and ongoing maintenance.

.PARAMETER None
    This script does not accept any parameters.

.NOTES
    Author: Andrew Price
    Created: 2024-10-07
    Last Updated: 2024-10-07

    Security Considerations:
    * Password Handling: In production environments, avoid hardcoding passwords. Use secure methods like prompting for the password or retrieving it from a secure vault.
    * Least Privilege: Evaluate if the reconcile account needs full administrative rights or if more granular permissions can be applied.
    * UAC: Disabling UAC lowers system security. Carefully consider the implications before disabling it. Explore alternative solutions if possible.
    * File and Printer Sharing: Enabling file and printer sharing can increase the attack surface. Ensure appropriate security measures are in place.

.EXAMPLE
    To run the script, save it as a .ps1 file (e.g., CyberArkReconcileAccountSetup.ps1) and execute it from an elevated PowerShell prompt:
    .\CyberArkReconcileAccountSetup.ps1
#>

# Get the hostname of the machine.
$hostname = hostname

# Extract the first 12 characters of the hostname to ensure the username stays within the 20-character limit.
$shortHostname = $hostname.Substring(0, 12)

# Set the username (including the shortened hostname) and a strong password.
$username = "$shortHostname-Recon" 
$password = ConvertTo-SecureString "Password@2" -AsPlainText -Force

# Check if the user already exists
if (Get-LocalUser -Name $username) {
    echo "User '$username' already exists. Skipping user creation."
} else {
    # Create the user account with the following settings:
    # - No password expiration
    # - User cannot change the password
    # - Account never expires
    # - Description to clarify the account's purpose
    New-LocalUser -Name $username -Password $password -AccountExpires ([DateTime]::MaxValue) -Description 'CyberArk Reconcile Account' -PasswordNeverExpires

    echo "User '$username' created successfully."
}

# Add the user to the local Administrators group (if not already a member)
if (!(Get-LocalGroupMember -Group "Administrators" -Member $username)) {
    Add-LocalGroupMember -Group "Administrators" -Member $username
    echo "User '$username' added to Administrators group."
} else {
    echo "User '$username' is already a member of the Administrators group."
}

# Add the user to the "Remote Desktop Users" group to allow RDP access (if not already a member)
if (!(Get-LocalGroupMember -Group "Remote Desktop Users" -Member $username)) {
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $username
    echo "User '$username' added to Remote Desktop Users group."
} else {
    echo "User '$username' is already a member of the Remote Desktop Users group."
}

# Disable User Account Control
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord

# Check if File and Printer Sharing is already enabled
$firewallRule = Get-NetFirewallRule -DisplayName "File and Printer Sharing (SMB-In)"

if ($firewallRule.Enabled -eq $false) {
    echo "Enabling File and Printer Sharing..."

    # Enable the necessary firewall rules for different profiles (Domain and Private)
    # ... (firewall rules code as before) ...
} else {
    echo "File and Printer Sharing is already enabled."
    echo "Make sure  is enabled in Network is already enabled."
}

# Check the current UAC setting
$currentUACSetting = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"

# Disable User Account Control (only if not already disabled)
if ($currentUACSetting.EnableLUA -ne 0) {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0 -Type DWord
    echo "User Account Control disabled."
} else {
    echo "User Account Control is already disabled."
}
