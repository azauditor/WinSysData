<#
.SYNOPSIS
This script is intended to gather information about Windows machines.
This can be run against workstations or servers and will gather
relevant information for auditing purposes.

.EXAMPLE
Single Machine Audit
PS C:\> Powershell.exe -ExecutionPolicy Bypass .\Get-WindowsSystemData.ps1
#>
[CmdletBinding()]
param (
    [Parameter(Position=0, ValueFromPipeline=$true)]
    [ValidateScript({Test-Path $_ -PathType 'Container'})]
    $Path
)

function Export-SecurityPolicy {
    $SecPol = "$Path\$ComputerName\$ComputerName-secpol.inf"
    $Gpo = "$Path\$ComputerName\$ComputerName-GPO.html"
    Write-Output "Exporting SecEdit Policy - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Start-Process -FilePath secedit.exe -ArgumentList "/export /cfg `"$SecPol`"" -WindowStyle Hidden -Wait
    Write-Output "Exporting Group Policy Resultant Set of Policy (RSOP) - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Start-Process -FilePath gpresult.exe -ArgumentList "/H `"$Gpo`"" -WindowStyle Hidden -Wait
    Start-Sleep -s 1
}

function Get-SharePermission ($ShareName) {
    <#
    .SYNOPSIS
    Use this script to export security settings of each share, including both share
    permissions and their associated NTFS permissions

    .DESCRIPTION
    This script will export existing Share permission, including NTFS permissions

    .NOTES
        Must be run locally if PowerShell Remoting is not enabled for target server.
        Must be an Administrator to run against remote machines (or appropriate WinRM exceptions granted).

        Original Authors: TonyF and Nohandle April 2013 on: http://powershell.com/cs/forums/t/12706.aspx?PageIndex=2
        Edited by: Alex Entringer 2/15/2015 to clean the code, add additional ACL
                                            Access Masks, function for multiple
                                            servers, Timestamp to result
                   Alex Entringer 2/16/2015 + Permit the omission of the parameter to
                                            scan local machine only
                   Phil Hanus 6/21/2018 + Modified check groups regiion to work with PS v2.0+
                   Phil Hanus 6/21/2018 + Modified OS Version check to work with PS v2.0+
    #>
    $Share = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "name='$ShareName'"
    if ($Share) {
        $Obj = @()
        $ACLS = $Share.GetSecurityDescriptor().Descriptor.DACL
        foreach ($ACL in $ACLS) {
            $User = $ACL.Trustee.Name
            if (-not $User) {
                $User = $ACL.Trustee.SID
            }
            $Domain = $ACL.Trustee.Domain
            switch ($ACL.AccessMask) {
                2032127     { $Perm = "Full Control" }
                1179785     { $Perm = "Read" }
                1180063     { $Perm = "Read, Write" }
                1179817     { $Perm = "ReadAndExecute" }
                1610612736  { $Perm = "ReadAndExecuteExtended" }
                1245631     { $Perm = "ReadAndExecute, Modify, Write" }
                1180095     { $Perm = "ReadAndExecute, Write" }
                268435456   { $Perm = "FullControl (Sub Only)" }
                default     { $Perm = "Unknown" }
            }
            $Obj = $Obj + "$Domain\$user | $Perm<br>"
        }
    }
    else {
        $Obj = " ERROR: cannot enumerate share permissions. "
    }
    return $Obj
} # End Get-SharePermissions Function

function Get-NTFSOwner ($Path) {
	try {
		$ACL = Get-Acl -Path $Path
		$A = $ACL.Owner.ToString()
		return $A
	}
	catch {
		$A = " NOTE: Do not have access to view permissions. "
		return $A
	}
} # End Get-NTFSOwner Function

function Get-NTFSPermission ($Path) {
	try {
		$ACL = Get-Acl -Path $Path
		$Obj = @()
		foreach($A in $ACL.Access){
			$AA = $A.FileSystemRights
			$AB = $A.AccessControlType
			$AC = $A.IdentityReference
			$Obj = $Obj + "$AC | $AB | $AA <br>"
		}
		return $Obj
	}
	catch {
		$Obj = " NOTE: Do not have access to view permissions. "
		return $Obj
	}
} # End Get-NTFSPerms Function

function Get-ShareReport {
    $CheckDate = Get-Date -format G
    # Create Webpage Header
    $z = "<!DOCTYPE html PUBLIC `"-//W3C//DTD XHTML 1.0 Strict//EN`"  `"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd`">"
    $z = $z + "<html xmlns=`"http://www.w3.org/1999/xhtml`">"
    $z = "<head><style>"
    $z = $z + "TABLE{border-width: 2px;border-style: solid;border-color: black;border-collapse: collapse;}"
    $z = $z + "TH{border-width: 2px;padding: 4px;border-style: solid;border-color: black;background-color:lightblue;text-align:left;font-size:14px}"
    $z = $z + "TD{border-width: 1px;padding: 4px;border-style: solid;border-color: black;font-size:12px}"
    $z = $z + "</style></head><body>"
    $z = $z + "<H3>Share Report for $ComputerName</H3>"
    $z = $z + "<H4>Report Ran on: $CheckDate</H4>"
    $z = $z + "<table><colgroup><col/><col/><col/><col/><col/><col/></colgroup>"
    $z = $z + "<tr><th>Share Name</th><th>Location</th><th>NTFS Permissions<br>User Identity | Access Control | Rights</th><th>NTFS Owner</th><th>Share Permissions<br>User Identity | Rights</th><th>Share Description</th></tr>"

    $MainShares = Get-WmiObject -Class Win32_Share -Filter "type=0"
    foreach ($MainShare in $MainShares) {
        $MainShareName = $MainShare.Name
        $MainLocation = $MainShare.Path
        $MainNTFSPermissions = Get-NTFSPermission -Path $MainLocation
        $MainNTFSOwner = Get-NTFSOwner -Path $MainLocation
        $MainSharePermissions = Get-SharePermission -ShareName $MainShareName
        $MainShareDescription = $MainShare.Description

        $Z = $Z + "<tr><td>$MainShareName</td><td>$MainLocation</td><td>$MainNTFSPermissions</td><td>$MainNTFSOwner</td><td>$MainSharePermissions</td><td>$MainShareDescription</td></tr>"
    }
    $z = $Z + "</table></body></html>"
    $OutFileName = $ComputerName + "-ShareReport.html"
    Out-File -FilePath "$Path\$ComputerName\$OutFileName" -InputObject $Z -Encoding ASCII

    if (-not (Test-Path -Path "$Path\$ComputerName\$OutFileName" -PathType 'Leaf')){
        Write-Error -Message 'Share Permissions Export Failed. Output file not found.'
    }
} # End Get-ShareReport Function

function Get-WindowsUpdate {
    <#
        .SYNOPSIS
        Collects information on the O365 Client on the remote computer.
        .DESCRIPTION
        Collects information on the O365 Client on the remote computer.
        .PARAMETER ComputerName
        Name of the computer to connect to.
        .NOTES
        By Tom Arbuthnot. Lyncdup.com
        http://lyncdup.com/2013/09/list-all-microsoftwindows-updates-with-powershell-sorted-by-kbhotfixid-get-microsoftupdate/

        Edited by Alex Entringer 3/16/15 to support file output and list install date
        If you want to output the collection as an object, just remove the two lines above and replace them with "$OutputCollection"

        http://blogs.technet.com/b/tmintner/archive/2006/07/07/440729.aspx
        http://www.gfi.com/blog/windows-powershell-extracting-strings-using-regular-expressions/
    #>
    $WU = New-Object -ComObject "Microsoft.Update.Searcher"
    $TotalUpdates = $WU.GetTotalHistoryCount()
    $All = $WU.QueryHistory(0,$totalupdates)

    $All | ForEach-Object {
        $Title = $_.title
        $KB = [regex]::match($Title,'(KB\w+)').Groups[1].Value
        $Result = $null
        switch ($_.ResultCode)
        {
            0 { $Result = 'NotStarted' }
            1 { $Result = 'InProgress' }
            2 { $Result = 'Succeeded' }
            3 { $Result = 'SucceededWithErrors' }
            4 { $Result = 'Failed' }
            5 { $Result = 'Aborted' }
            default { $Result = $_ }
        }

        New-Object -TypeName PSObject -Property @{
            'KB' = $KB
            'Date' = $_.Date
            'Result' = $Result
            'Title' = $Title
            'Description' = $_.Description
            'ClientApplicationID' = $_.ClientApplicationID
            'SupportURL' = $_.SupportUrl

        }
    } | Sort-Object Date | Select-Object KB,Date,Title,ClientApplicationID,Description,SupportURL |
    ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-Updates.csv" -Append

    if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-Updates.csv" -PathType 'Leaf')){
        Write-Error -Message 'Windows Update Export Failed. Output file not found.'
    }
} # End Get-WindowsUpdate Function

function ConvertFrom-NetStatus {
    param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        $Value
    )

    $StatusHash = @{
        [uint16]0 = "Disconnected"
        [uint16]1 = "Connecting"
        [uint16]2 = "Connected"
        [uint16]3 = "Disconnecting"
        [uint16]4 = "Hardware not present"
        [uint16]5 = "Hardware disabled"
        [uint16]6 = "Hardware malfunction"
        [uint16]7 = "Media Disconnected"
        [uint16]8 = "Authenticating"
        [uint16]9 = "Authentication Succeeded"
        [uint16]10 = "Authentication Failed"
        [uint16]11 = "Invalid Address"
        [uint16]12 = "Credentials Required"
    }

    if ($StatusHash.ContainsKey($Value)) {
        $NewValue = $StatusHash[$Value]
    }
    else {
        $NewValue = 'Unknown Network Connection Status'
    }
    return $NewValue
} # End ConvertFrom-NetStatus Function

function Get-Netstat
{
    netstat -ano | Select-Object -skip 4 |
    ForEach-Object {
        $Temp = ($_).Trim() -split "\s+"
        New-Object PSObject -Property @{
            Protocol         = $Temp[0]
            Local_Address    = $Temp[1]
            Foreign_Address  = $Temp[2]
            State            = $Temp[3]
            PID              = $Temp[4]
        }
    }
} #End Get-Netstat Function

function Get-FirewallRule {
    <#
    .SYNOPSIS
        Script to read firewall rules and output as an array of objects.

    .DESCRIPTION
        This script will gather the Windows Firewall rules from the registry and convert the information stored in the registry keys to PowerShell Custom Objects to enable easier manipulation and filtering based on this data.

    .PARAMETER Local
        By setting this switch the script will display only the local firewall rules

    .PARAMETER GPO
        By setting this switch the script will display only the firewall rules as set by group policy

    .NOTES
        Name: Get-FireWallRules.ps1
        Author: Jaap Brasser
        DateUpdated: 2013-01-10
        Version: 1.1

    .LINK
    http://www.jaapbrasser.com

    .EXAMPLE
        .\Get-FireWallRules.ps1

    Description
    -----------
    The script will output all the local firewall rules

    .EXAMPLE
        .\Get-FireWallRules.ps1 -GPO

    Description
    -----------
    The script will output all the firewall rules defined by group policies

    .EXAMPLE
        .\Get-FireWallRules.ps1 -GPO -Local

    Description
    -----------
    The script will output all the firewall rules defined by group policies as well as the local firewall rules
    #>
    param(
        [switch]$Local,
        [switch]$GPO
    )

    # If no switches are set the script will default to local firewall rules
    if ((-not $Local) -and (-not $Gpo)) {
        $Local = $true
    }

    $RegistryKeys = @()
    if ($Local) {$RegistryKeys += 'Registry::HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'}
    if ($GPO) {$RegistryKeys += 'Registry::HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules'}

    foreach ($Key in $RegistryKeys) {
        if (Test-Path -Path $Key) {
            (Get-ItemProperty -Path $Key).PSObject.Members |
            Where-Object {(@('PSPath','PSParentPath','PSChildName') -notcontains $_.Name) -and ($_.MemberType -eq 'NoteProperty') -and ($_.TypeNameOfValue -eq 'System.String')} |
            ForEach-Object {
                $HashProps = @{
                    NameOfRule = $_.Name
                    RuleVersion = ($_.Value -split '\|')[0]
                    Action = $null
                    Active = $null
                    Direction = $null
                    Protocol = $null
                    LocalPort = $null
                    Application = $null
                    Name = $null
                    Description = $null
                    EmbeddedContext = $null
                    Profile = $null
                    RA4 = $null
                    RA6 = $null
                    Service = $null
                    RemotePort = $null
                    ICMP6 = $null
                    Edge = $null
                    LA4 = $null
                    LA6 = $null
                    ICMP4 = $null
                    LPort2_10 = $null
                    RPort2_10 = $null
                }

                # Determine if this is a local or a group policy rule and display this in the hashtable
                if ($Key -match 'HKLM\\System\\CurrentControlSet') {
                    $HashProps.RuleType = 'Local'
                }
                else {
                    $HashProps.RuleType = 'GPO'
                }

                # Iterate through the value of the registry key and fill PSObject with the relevant data
                foreach ($FireWallRule in ($_.Value -split '\|')) {
                    switch (($FireWallRule -split '=')[0]) {
                        'Action' {$HashProps.Action = ($FireWallRule -split '=')[1]}
                        'Active' {$HashProps.Active = ($FireWallRule -split '=')[1]}
                        'Dir' {$HashProps.Direction = ($FireWallRule -split '=')[1]}
                        'Protocol' {$HashProps.Protocol = ($FireWallRule -split '=')[1]}
                        'LPort' {$HashProps.LocalPort = ($FireWallRule -split '=')[1]}
                        'App' {$HashProps.Application = ($FireWallRule -split '=')[1]}
                        'Name' {$HashProps.Name = ($FireWallRule -split '=')[1]}
                        'Desc' {$HashProps.Description = ($FireWallRule -split '=')[1]}
                        'EmbedCtxt' {$HashProps.EmbeddedContext = ($FireWallRule -split '=')[1]}
                        'Profile' {$HashProps.Profile = ($FireWallRule -split '=')[1]}
                        'RA4' {[array]$HashProps.RA4 += ($FireWallRule -split '=')[1]}
                        'RA6' {[array]$HashProps.RA6 += ($FireWallRule -split '=')[1]}
                        'Svc' {$HashProps.Service = ($FireWallRule -split '=')[1]}
                        'RPort' {$HashProps.RemotePort = ($FireWallRule -split '=')[1]}
                        'ICMP6' {$HashProps.ICMP6 = ($FireWallRule -split '=')[1]}
                        'Edge' {$HashProps.Edge = ($FireWallRule -split '=')[1]}
                        'LA4' {[array]$HashProps.LA4 += ($FireWallRule -split '=')[1]}
                        'LA6' {[array]$HashProps.LA6 += ($FireWallRule -split '=')[1]}
                        'ICMP4' {$HashProps.ICMP4 = ($FireWallRule -split '=')[1]}
                        'LPort2_10' {$HashProps.LPort2_10 = ($FireWallRule -split '=')[1]}
                        'RPort2_10' {$HashProps.RPort2_10 = ($FireWallRule -split '=')[1]}
                        default {}
                    }
                }
                # Create and output object using the properties defined in the hashtable
                New-Object -TypeName 'PSCustomObject' -Property $HashProps
            }
        }
    }
} # End Get-FirewallRule function

$ComputerName = $env:COMPUTERNAME

if (-not $Path) {
    if (-not $PSScriptRoot) {
        $PSScriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
    }
    $Path = $PSScriptRoot
}

#region Check Administrator Privileges
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $IsAdmin = $true
}
else {
    Write-Error -Message 'Administrator privileges are required to run this script.'
    Read-Host -Prompt 'Press any key to exit'
    exit 1
}
#endregion Check Administrator Privileges

#region Create Folders
if (-not (Test-Path "$Path\$ComputerName")) {
    $null = New-Item -Path "$Path\$ComputerName" -ItemType 'Directory'
}
#endregion Create Folders

#region Check Security Policy
if ($IsAdmin) {
	Export-SecurityPolicy
}
else {
    Write-Output "Administrator Rights not provided. Security and Group Policy settings cannot be exported." |
        Out-File -FilePath "$Path\$ComputerName\secpol-NotExported.txt" -Encoding 'ascii'
}
#endregion Check Security Policy

#region Check Users
Write-Output "Exporting User List - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$Obj = @()
$Now = Get-Date

$AllLocalAccounts = Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" -ErrorAction 'Stop'

$AllLocalAccounts | ForEach-Object {
    $User = ([adsi]"WinNT://$ComputerName/$($_.Name),user")
    $PwAge    = $User.PasswordAge.Value
    $MaxPwAge = $User.MaxPasswordAge.Value
    $PwLastSet = $now.AddSeconds(-$PwAge)

    New-Object -TypeName 'PSObject' -Property @{
        'Name'                 = $_.Name
        'Full Name'            = $_.FullName
        'Disabled'             = $_.Disabled
        'Description'          = $_.Description
        'Status'               = $_.Status
        'LockOut'              = $_.LockOut
        'Password Expires'     = $_.PasswordExpires
        'Password Last Set'    = $PwLastSet
        'Password Expiry Date' = $Now.AddSeconds($MaxPwAge - $PwAge)
        'Password Required'    = $_.PasswordRequired
        'Account Type'         = $_.AccountType
        'Domain'               = $_.Domain
        'Password Age'         = ($Now - $PwLastSet).Days
    }
} | Select-Object 'Name','Full Name','Disabled','Description','Status','LockOut','Password Expires','Password Last Set','Password Expiry Date',
    'Password Required','Account Type','Domain','Password Age' | ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-Users.csv" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-Users.csv" -PathType 'Leaf')){
    Write-Error -Message 'User List Export Failed. Output file not found.'
}
#endregion Check Users

#region Check Groups
Write-Output "Exporting Group List - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

$GroupList = Get-WmiObject -Class Win32_Group -Filter "Domain='$ComputerName'"
$GroupList | ForEach-Object {
    $CurrGroup = Get-WmiObject -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$ComputerName',Name='$($_.Name)'`""
    foreach ($Item in $CurrGroup) {
        $CurrentPart = $item.PartComponent
        if ($currentPart) {
            $UserName = $CurrentPart.split('=')[2] -replace '"', ''
            $Domain = $CurrentPart.split('=')[1].split(',')[0] -replace '"', ''
            $UserType = $CurrentPart.split(':')[1].split('.')[0].split('_')[1]
            $ComboName = "$Domain\$UserName"
        }
        else {
            $UserName = $null
            $Domain = $null
            $UserType = $null
            $ComboName = $null
        }
        New-Object -TypeName PSObject -Property @{
            'Name'          = $ComboName
            'ObjectClass'   = $UserType
            'Group'         = $_.Name
            'GroupSID'      = $_.SID
            'Computer'      = $ComputerName
        }
        $UserName = $null
        $Domain = $null
        $UserType = $null
    }
} | Select-Object 'Name','ObjectClass','Group','Computer' | ConvertTo-Csv -NoTypeInformation -Delimiter '|' |
    ForEach-Object { $_ -replace '"', '' } | Out-File -FilePath "$Path\$ComputerName\$ComputerName-Groups.csv" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-Groups.csv" -PathType 'Leaf')){
    Write-Error -Message 'Group List Failed. Output file not found.'
}
#endregion Check Groups

#region Check Services
Write-Output "Exporting Services - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-WmiObject -Class Win32_Service | Select-Object PSComputerName,Name, Caption, DisplayName, Description,
    ServiceType, StartMode,State, StartName, Status, AcceptPause, AcceptStop, PathName |
    Sort-Object State, DisplayName | ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-Services.csv" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-Services.csv" -PathType 'Leaf')){
    Write-Error -Message 'Services Export Failed. Output file not found.'
}
#endregion Check Services

#region Check Running Processes
Write-Output "Exporting Running Processes - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-WmiObject -Class Win32_Process | Select-Object Name,ProcessId,ExecutablePath,Description,CommandLine |
    ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-processes.csv" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-processes.csv" -PathType 'Leaf')){
    Write-Error -Message 'Running Processes Export Failed. Output file not found.'
}
#endregion Check Running Processes

#region Check for installed software at system level
Write-Output "Exporting Installed Software - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$SoftwareList = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
$SoftwareList += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
$SoftwareList | ForEach-Object { $_.PSParentPath = [string]$_.PSParentPath.Split(':')[2] }
$SoftwareList | Select-Object PSChildName,DisplayName,Publisher,DisplayVersion,UninstallString,PSParentPath |
    Sort-Object DisplayName | ConvertTo-Csv -NoTypeInformation -Delimiter '|' |
    ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-InstalledSoftware.csv" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-InstalledSoftware.csv" -PathType 'Leaf')){
    Write-Error -Message 'Installed Software Export Failed. Output file not found.'
}
#endregion Check for installed software at system level

#region Check Microsoft Update
Write-Output "Exporting Windows Updates - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-WindowsUpdate
#endregion Check Microsoft Update

#region Check Shares
Write-Output "Exporting Share Permissions - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-ShareReport
#endregion Check Shares

#region Check PowerShell Version
Write-Output "Exporting PowerShell Version Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-PSInfo.txt" -Append -Encoding 'ascii'
Write-Output "PowerShell Version Information" | Out-File -FilePath "$Path\$ComputerName\$ComputerName-PSInfo.txt" -Append -Encoding 'ascii'
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-PSInfo.txt" -Append -Encoding 'ascii'
$PSVersionTable | Out-File -FilePath "$Path\$ComputerName\$ComputerName-PSInfo.txt" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-PSInfo.txt" -PathType 'Leaf')){
    Write-Error -Message 'PowerShell Version Export Failed. Output file not found.'
}
#endregion Check PowerShell Version

#region Check System Information
Write-Output "Exporting System Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output "Computer System Information" | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Get-WmiObject -Class Win32_ComputerSystem | Select-Object Name, Model,
    Manufacturer, Description, DNSHostName, Domain, DomainRole, PartOfDomain,
    NumberOfProcessors, SystemType, TotalPhysicalMemory, UserName, Workgroup |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-sysinfo.txt" -PathType 'Leaf')){
    Write-Error -Message 'System Information Export Failed. Output file not found.'
}
#endregion Check System Information

#region Get OperatingSystem info
Write-Output "Exporting Operating System Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output "Operating System Information" | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Name, Version, FreePhysicalMemory,
    OSLanguage, OSProductSuite, OSType, OSArchitecture, BuildNumber, Caption, InstallDate,
    LastBootUpTime, LocalDateTime, SystemDrive, WindowsDirectory, SystemDirectory,
    ServicePackMajorVersion, ServicePackMinorVersion, RegisteredUser |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-sysinfo.txt" -PathType 'Leaf')){
    Write-Error -Message 'System Information Export Failed. Output file not found.'
}
#endregion Get OperatingSystem info

#region Get Network Login info
Write-Output "Exporting Network Login Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output "Network Login Information" | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Get-WmiObject -Class Win32_NetworkLoginProfile | Select-Object PSComputerName, Name, Caption,
    Description, FullName, HomeDirectory, HomeDirectoryDrive, LastLogon, LogonHours,
    LogonServer, PasswordExpires, PrimaryGroupID, UserType |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-sysinfo.txt" -PathType 'Leaf')){
    Write-Error -Message 'Network Login Export Failed. Output file not found.'
}
#endregion Get Network Login info

#region Get Network Connections info
Write-Output "Exporting Network Adapter Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output "Network Connections Information" | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
$NetworkAdapter = Get-WmiObject -Class Win32_NetworkAdapter | Select-Object PSComputerName,
    Availability, Name, AdapterType, Description, Installed, MACAddress, Manufacturer,
    NetConnectionID, @{Name='NetConnectionStatus';Expression={(ConvertFrom-NetStatus($_.NetConnectionStatus))}}, NetEnabled, PhysicalAdapter,
    ProductName, ServiceName, TimeOfLastRest
$NetworkConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
    Select-Object DHCPEnabled, DHCPLeaseObtained, DHCPLeaseExpires, DHCPServer, DNSDomain,
    DNSDomainSuffixSearchOrder, DNSEnabledForWINSResolution, DNSHostName, DNSServerSearchOrder,
    DomainDNSRegistrationEnabled, FullDNSRegistrationEnabled, IPAddress, IPEnabled,
    IPFilterSecurityEnabled, WINSEnableLMHostsLookup, WINSHostLookupFile, WINSPrimaryServer,
    WINSSecondaryServer, DefaultIPGateway, IPSubnet
$NA = $NetworkAdapter.getenumerator()
$NC = $NetworkConfig.getenumerator()

while($NA.MoveNext() -and $NC.MoveNext()){
    Write-Output $NA.current $NC.current | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
}

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-sysinfo.txt" -PathType 'Leaf')){
    Write-Error -Message 'Network Connections Export Failed. Output file not found.'
}

Write-Output "Exporting Open TCP/UDP Connections - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-Netstat | ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-Netstat.csv" -Append

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-Netstat.csv" -PathType 'Leaf')){
    Write-Error -Message 'Netstat Export Failed. Output file not found.'
}
#endregion Get Network Connections info

#region Get PhysicalMemory info
Write-Output "Exporting Memory Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output "Memory Information" | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Get-WmiObject -Class Win32_PhysicalMemory | Select-Object Name, Capacity, DeviceLocator, Tag |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-sysinfo.txt" -PathType 'Leaf')){
    Write-Error -Message 'Memory Information Export Failed. Output file not found.'
}
#endregion Get PhysicalMemory info

#region Get LogicalDisk info
Write-Output "Exporting Logical Disk Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output "Logical Disk Information" | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Get-WmiObject -Class Win32_LogicalDisk | Select-Object Name, ProviderName, Description, FreeSpace, Size |
    Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'

if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-sysinfo.txt" -PathType 'Leaf')){
    Write-Error -Message 'Logical Disk Information Export Failed. Output file not found.'
}
#endregion Get LogicalDisk info

#region Get Remote Desktop Status
Write-Output "Exporting RDP Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output "RDP Information" | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
Write-Output ("="*80) | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'

$RdpGPO = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDenyTSConnections' -ErrorAction 'SilentlyContinue')
if ($RdpGPO) {
    if ($RdpGPO.fDenyTSConnections -eq 1) {
        Write-Output 'Remote Desktop is disabled by Group Policy' | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
    }
    elseif ($RdpGPO.fDenyTSConnections -eq 0) {
        Write-Output 'Remote Desktop is enabled by Group Policy' | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
    }
}
else {
    Write-Output 'Remote Desktop is not configured by Group Policy' | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
    if (((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections').fDenyTSConnections) -eq 1) {
        Write-Output 'Remote Desktop is disabled in registry' | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
    }
    else {
        Write-Output 'Remote Desktop is enabled in registry' | Out-File -FilePath "$Path\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding 'ascii'
    }
}
if (-not (Test-Path -Path "$Path\$ComputerName\$ComputerName-sysinfo.txt" -PathType Leaf)){
    Write-Error -Message 'RDP Information Export Failed. Output file not found.'
}
#endregion

#region Get Firewall Settings
Write-Output "Exporting Firewall Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
if (-not (Test-Path "$Path\$ComputerName\Firewall" -PathType 'Container')) {
    $null = New-Item -Path "$Path\$ComputerName\Firewall" -ItemType 'Directory'
}

Get-FirewallRule -Local -GPO | ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallRules-Registry.csv" -Encoding 'ascii' -Append

if (-not (Test-Path -Path "$Path\$ComputerName\Firewall\$ComputerName-FirewallRules-Registry.csv" -PathType Leaf)){
    Write-Error -Message 'Firewall Registry Information Export Failed. Output file not found.'
}

if ([version]((Get-WmiObject -Class Win32_OperatingSystem -Property Version -ErrorAction SilentlyContinue) | Select-Object -ExpandProperty Version) -ge [version]'6.2.9200') {
    Get-NetFirewallRule -All -PolicyStore ActiveStore | Select-Object Name,DisplayName,InstanceID,Enabled,Profile,
        Direction,Action,EdgeTraversalPolicy,PolicyStoreSourceType,Description,DisplayGroup,Owner,
        @{Name='Platform';Expression={$_.Platform -join ', '}},
        @{Name='EnforcementStatus';Expression={$_.EnforcementStatus -join ', '}} |
        ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallRules.csv" -Encoding 'ascii' -Append

    Get-NetFirewallProfile -All -PolicyStore ActiveStore | ConvertTo-Csv -NoTypeInformation -Delimiter '|' |
        ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallProfiles.csv" -Encoding 'ascii' -Append

    Get-NetFirewallSetting -All -PolicyStore ActiveStore | ConvertTo-Csv -NoTypeInformation -Delimiter '|' |
        ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallSetting.csv" -Encoding 'ascii' -Append

    Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore | Select-Object InstanceID,Program,AppPath |
        ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallAppFilter.csv" -Encoding 'ascii' -Append

    Get-NetFirewallSecurityFilter -All -PolicyStore ActiveStore |
        Select-Object InstanceID,Authentication,Encryption,LocalUser,RemoteUser,RemoteMachine |
        ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallSecurityFilter.csv" -Encoding 'ascii' -Append

    Get-NetFirewallServiceFilter -All -PolicyStore ActiveStore | Select-Object InstanceID,Service,ServiceName |
        ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallServiceFilter.csv" -Encoding 'ascii' -Append

    if ($IsAdmin) {
        Get-NetFirewallPortFilter -All -PolicyStore ActiveStore |
            ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
            Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallPortFilters.csv" -Encoding 'ascii' -Append

        Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore |
            Select-Object InstanceID,LocalAddress,LocalIP,RemoteAddress,RemoteIP |
            ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
            Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallAddressFilters.csv" -Encoding 'ascii' -Append

        Get-NetFirewallInterfaceFilter -All -PolicyStore ActiveStore | Select-Object InstanceID,InterfaceAlias |
            ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
            Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallInterfaceFilters.csv" -Encoding 'ascii' -Append

        Get-NetFirewallInterfaceTypeFilter -All -PolicyStore ActiveStore | Select-Object InstanceID,InterfaceType |
            ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
            Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallInterfaceTypeFilters.csv" -Encoding 'ascii' -Append
    }
    else {
        Write-Output "Administrator Rights not provided. Firewall Port Filters cannot be exported." |
            Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallPortFilters-NotExported.txt"

        Write-Output "Administrator Rights not provided. Firewall Address Filters cannot be exported." |
            Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallAddressFilters-NotExported.txt"

        Write-Output "Administrator Rights not provided. Firewall Interface Filters cannot be exported." |
            Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallInterfaceFilters-NotExported.txt"

        Write-Output "Administrator Rights not provided. Firewall Interface Type Filters cannot be exported." |
            Out-File -FilePath "$Path\$ComputerName\Firewall\$ComputerName-FirewallInterfaceTypeFilters-NotExported.txt"
    }
}
#endregion

Write-Output "Information from $ComputerName exported successfully - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
