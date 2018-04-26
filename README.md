# Windows System Configuration Data Collection

This PowerShell script is designed to collect data about individual Windows Systems for audit purposes. This data includes:

* Local Users
* Group Memberships
* Group Policy Settings
* Installed Software (System level)
* General System Information
* Network Information
* Logical Disks
* Shares
* RDP Status
* Firewall Configuration

## Use

1. Download the [Get-WindowsSystemData.ps1](https://github.com/aentringer/WinSysData/Get-WindowsSystemData.ps1) script from this repository.
1. Copy the .ps1 script file to the system being audited
    * *You may also run the script via PowerShell remoting (Invoke-Command), but that is beyond the scope of this README.*
1. Open PowerShell Console (if admin privileges are available, run PowerShell as admin)
1. Change execution policy for current session, if necessary:
    * Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
1. Execute the script:
    * .\Path\to\Script\Get-WindowsSystemData.ps1
      * *Where \Path\to\Script\ is the actual path of the script on the system being audited.*

## Notes

The firewall configuration portion of the script is still being improved. The intention is to provide a merged file for most of the information in the future, but the current form is released just to gather the data.
