# CyberArk Reconcile Account Setup Script

This PowerShell script automates the creation and configuration of a local user account on Windows servers for CyberArk reconciliation purposes.

## Features

* **Creates a local user account:**  The script creates a new local user account with a username based on the server's hostname (e.g., `SERVERNAME-Recon`).
* **Sets a strong password:** The script sets a strong password for the user account (you can modify the password in the script).
* **Configures account settings:**
    * Sets the account to never expire.
    * Prevents the user from changing the password.
    * Adds a description to the account for clarity.
* **Adds to necessary groups:**
    * Adds the user to the local `Administrators` group for privileged access.
    * Adds the user to the `Remote Desktop Users` group to allow RDP access (if needed).
* **Disables User Account Control (UAC):** Disables UAC to prevent interference with CyberArk functionality.
* **Enables File and Printer Sharing:** Enables the necessary firewall rules for file and printer sharing (if needed).
* **Grants "Log on as a service" right:**  Grants the user the "Log on as a service" right to allow it to run services.
* **Checks for existing configurations:** The script checks if the user, group memberships, UAC settings, and file sharing are already configured before making changes, preventing errors and conflicts.

## Requirements

* **PowerShell:** The script requires PowerShell to be installed on the target Windows server.
* **Administrator Privileges:** The script must be executed with administrator privileges.

## Usage

1. **Save the script:** Save the script as a `.ps1` file (e.g., `CyberArkReconcileAccountSetup.ps1`).
2. **Modify the script (optional):**
    * Change the `$password` variable to your desired password.
    * Review the sections for UAC, file sharing, and "Log on as a service" and adjust them based on your specific requirements and security policies.
3. **Run the script:** Execute the script from an elevated PowerShell prompt:
   ```powershell
   .\CyberArkReconcileAccountSetup.ps1
