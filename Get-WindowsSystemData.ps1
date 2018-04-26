<#
.SYNOPSIS
This script is intended to gather information about Windows machines.
This can be run against workstations or servers and will gather
relevant information for auditing purposes.

.EXAMPLE
Single Machine Audit
PS C:\> Powershell.exe -ExecutionPolicy Bypass .\Get-WindowsSystemData.ps1
#>
Function Export-SecurityPolicy {
    $secpol = "$ScriptDir\$ComputerName\$ComputerName-secpol.inf"
    $gpo = "$ScriptDir\$ComputerName\$ComputerName-GPO.html"
    Write-Output "Exporting SecEdit Policy"
    Start-Process secedit -ArgumentList "/export /cfg `"$secpol`"" -WindowStyle Hidden -Wait
    Write-Output "Exporting Group Policy Resultant Set of Policy (RSOP)"
    Start-Process gpresult -ArgumentList "/H `"$gpo`"" -WindowStyle Hidden -Wait
    Start-Sleep -s 1
}

Function Get-SharePermission($ShareName) {
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
    #>
    $Share = Get-WmiObject Win32_LogicalShareSecuritySetting -Filter "name='$ShareName'"
    if ($Share) {
        $obj = @()
        $ACLS = $Share.GetSecurityDescriptor().Descriptor.DACL
        foreach($ACL in $ACLS) {
            $User = $ACL.Trustee.Name
            if(-not $User) {
                $User = $ACL.Trustee.SID
            }
            $Domain = $ACL.Trustee.Domain
            switch($ACL.AccessMask) {
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
            $obj = $obj + "$Domain\$user | $Perm<br>"
        }
    }
    else {
        $obj = " ERROR: cannot enumerate share permissions. "
    }
    Return $obj
} # End Get-SharePermissions Function

Function Get-NTFSOwner($Path){
	try {
		$ACL = Get-Acl -Path $Path
		$a = $ACL.Owner.ToString()
		Return $a
	}
	catch {
		$a = " NOTE: Do not have access to view permissions. "
		Return $a
	}
} # End Get-NTFSOwner Function

Function Get-NTFSPermission($Path){
	try {
		$ACL = Get-Acl -Path $Path
		$obj = @()
		foreach($a in $ACL.Access){
			$aA = $a.FileSystemRights
			$aB = $a.AccessControlType
			$aC = $a.IdentityReference
			$obj = $obj + "$aC | $aB | $aA <br>"
		}
		Return $obj
	}
	catch {
		$obj = " NOTE: Do not have access to view permissions. "
		Return $obj
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
    $z = $z + "<H4>Report Ran on:  $CheckDate</H4>"
    $z = $z + "<table><colgroup><col/><col/><col/><col/><col/><col/></colgroup>"
    $z = $z + "<tr><th>Share Name</th><th>Location</th><th>NTFS Permissions<br>User Identity | Access Control | Rights</th><th>NTFS Owner</th><th>Share Permissions<br>User Identity | Rights</th><th>Share Description</th></tr>"

    $MainShares = Get-WmiObject Win32_Share -Filter "type=0"
    Foreach($MainShare in $MainShares) {
        $MainShareName = $MainShare.Name
        $MainLocation = $MainShare.Path
        $MainNTFSPermissions = Get-NTFSPermission -Path $MainLocation
        $MainNTFSOwner = Get-NTFSOwner -Path $MainLocation
        $MainSharePermissions = Get-SharePermission -ShareName $MainShareName
        $MainShareDescription = $MainShare.Description

        $z = $z + "<tr><td>$MainShareName</td><td>$MainLocation</td><td>$MainNTFSPermissions</td><td>$MainNTFSOwner</td><td>$MainSharePermissions</td><td>$MainShareDescription</td></tr>"
    }
    $z = $z + "</table></body></html>"
    $OutFileName = $ComputerName + "-ShareReport.html"
    Out-File -FilePath "$ScriptDir\$ComputerName\$OutFileName" -InputObject $z -Encoding ASCII
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
    $wu = New-Object -ComObject "Microsoft.Update.Searcher"
    $totalupdates = $wu.GetTotalHistoryCount()
    $all = $wu.QueryHistory(0,$totalupdates)

    $all | ForEach-Object {
        $Title = $_.title
        $KB = [regex]::match($Title,'(KB\w+)').Groups[1].Value
        $Result = $null
        Switch ($_.ResultCode)
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
    Out-File -FilePath "$ScriptDir\$ComputerName\$ComputerName-Updates.csv" -Append
} # End Get-WindowsUpdate Function

function ConvertFrom-NetStatus {
    param (
        [Parameter(Mandatory=$True, Position=0, ValueFromPipeline=$true)]
        $Value
    )

    $statushash = @{
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

    if ($statushash.ContainsKey($Value)) {
        $newValue = $statusHash[$Value]
    }
    else {
        $newValue = 'Unknown Network Connection Status'
    }
    return $newValue
} # End ConvertFrom-NetStatus Function

Function Get-Netstat
{
    netstat -ano | select-object -skip 4 |
    ForEach-Object {
        $temp = ($_).Trim() -split "\s+"
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
    if (!($Local) -and !($Gpo)) {
        $Local = $true
    }

    $RegistryKeys = @()
    if ($Local) {$RegistryKeys += 'Registry::HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'}
    if ($GPO) {$RegistryKeys += 'Registry::HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules'}

    Foreach ($Key in $RegistryKeys) {
        if (Test-Path -Path $Key) {
            (Get-ItemProperty -Path $Key).PSObject.Members |
            Where-Object {(@('PSPath','PSParentPath','PSChildName') -notcontains $_.Name) -and ($_.MemberType -eq 'NoteProperty') -and ($_.TypeNameOfValue -eq 'System.String')} |
            ForEach-Object {
            
                # Prepare hashtable
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
                } else {
                    $HashProps.RuleType = 'GPO'
                }

                # Iterate through the value of the registry key and fill PSObject with the relevant data
                ForEach ($FireWallRule in ($_.Value -split '\|')) {
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
                        Default {}
                    }
                }
                # Create and output object using the properties defined in the hashtable
                New-Object -TypeName 'PSCustomObject' -Property $HashProps
            }
        }
    }
} # End Get-FirewallRule function

#region Check Administrator Privileges
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $isAdmin = $true
}
else {
    $message = "Administrator privileges not provided.";
    $caption = "Do you wish to proceed?";
    $chooseYes = new-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Yes, Proceed";
    $chooseNo = new-Object System.Management.Automation.Host.ChoiceDescription "&No","No, Do Not Proceed";
    $choices = [System.Management.Automation.Host.ChoiceDescription[]]($chooseNo,$chooseYes);
    $answer = $host.ui.PromptForChoice($caption,$message,$choices,0)

    switch ($answer){
        0 {
            Exit
        }
        1 {
            Write-Output "Proceeding with script."
        }
    }
}
#endregion Check Administrator Privileges

#region Create Folders
$ComputerName = $env:COMPUTERNAME
$ScriptDir = Split-Path -parent $MyInvocation.MyCommand.Path


if(-not (Test-Path "$ScriptDir\$ComputerName")) {
    New-Item -Path "$ScriptDir\$ComputerName" -ItemType Directory | out-null
}
#endregion Create Folders

#region Check Security Policy
if ($isAdmin) {
	Export-SecurityPolicy
}
else {
    Write-Output "Administrator Rights not provided. Security and Group Policy settings cannot be exported." |
        Out-File -FilePath "$ScriptDir\$ComputerName\secpol-NotExported.txt"
}
#endregion Check Security Policy

#region Check Users
Write-Output "Exporting User List - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$Obj = @()
$now = Get-Date

$AllLocalAccounts = Get-WmiObject -Class Win32_UserAccount -Namespace "root\cimv2" -Filter "LocalAccount='$True'" -ErrorAction Stop

$AllLocalAccounts | ForEach-Object {
    $user = ([adsi]"WinNT://$ComputerName/$($_.Name),user")
    $pwAge    = $user.PasswordAge.Value
    $maxPwAge = $user.MaxPasswordAge.Value
    $pwLastSet = $now.AddSeconds(-$pwAge)

    New-Object -TypeName PSObject -Property @{
        'Name'                 = $_.Name
        'Full Name'            = $_.FullName
        'Disabled'             = $_.Disabled
        'Description'          = $_.Description
        'Status'               = $_.Status
        'LockOut'              = $_.LockOut
        'Password Expires'     = $_.PasswordExpires
        'Password Last Set'    = $pwLastSet
        'Password Expiry Date' = $now.AddSeconds($maxPwAge - $pwAge)
        'Password Required'    = $_.PasswordRequired
        'Account Type'         = $_.AccountType
        'Domain'               = $_.Domain
        'Password Age'         = ($now - $pwLastSet).Days
    }
} | Select-Object 'Name','Full Name','Disabled','Description','Status','LockOut','Password Expires','Password Last Set','Password Expiry Date',
    'Password Required','Account Type','Domain','Password Age' | ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$ScriptDir\$ComputerName\$ComputerName-Users.csv" -Append
#endregion Check Users

#region Check Groups
Write-Output "Exporting Group List - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

$GroupList = Get-WmiObject -Class Win32_Group -Filter "Domain='$ComputerName'"
$GroupList | ForEach-Object {
    $CurrGroup = Get-WmiObject -Query "SELECT * FROM Win32_GroupUser WHERE GroupComponent=`"Win32_Group.Domain='$ComputerName',Name='$($_.Name)'`""
    ForEach ($item in $CurrGroup) {
        $UserName = $item.PartComponent.split('=')[2] -replace '"', ''
        $Domain = $item.PartComponent.split('=')[1].split(',')[0] -replace '"', ''
        $UserType = $item.PartComponent.split(':')[1].split('.')[0].split('_')[1]
        New-Object -TypeName PSObject -Property @{
            'Name'          = "$Domain\$UserName"
            'ObjectClass'  = $UserType
            'Group'         = $_.Name
            'Computer'      = $ComputerName
        }
    }
} | Select-Object 'Name','ObjectClass','Group','Computer' | ConvertTo-Csv -NoTypeInformation -Delimiter '|' |
    ForEach-Object { $_ -replace '"', ''} | Out-File -FilePath "$ScriptDir\$ComputerName\$ComputerName-Groups.csv" -Append
#endregion Check Groups

#region Check Services
Write-Output "Exporting Services - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-WmiObject -Class Win32_Service | Select-Object PSComputerName,Name, Caption, DisplayName, Description,
    ServiceType, StartMode,State, StartName, Status, AcceptPause, AcceptStop, PathName |
    Sort-Object State, DisplayName | ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$ScriptDir\$ComputerName\$ComputerName-Services.csv" -Append
#endregion Check Services

#region Check Running Processes
Write-Output "Exporting Running Processes - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-WmiObject -Class Win32_Process | Select-Object Name,ProcessId,ExecutablePath,Description,CommandLine |
    ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$ScriptDir\$ComputerName\$ComputerName-processes.csv" -Append
#endregion Check Running Processes

#region Check for installed software at system level
Write-Output "Exporting Installed Software - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$SoftwareList = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
$SoftwareList += Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
$SoftwareList | ForEach-Object { $_.PSParentPath = [string]$_.PSParentPath.Split(':')[2] }
$SoftwareList | Select-Object PSChildName,DisplayName,Publisher,DisplayVersion,UninstallString,PSParentPath |
    Sort-Object DisplayName | ConvertTo-Csv -NoTypeInformation -Delimiter '|' |
    ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$ScriptDir\$ComputerName\$ComputerName-InstalledSoftware.csv" -Append
#endregion Check for installed software at system level

#region Check Microsoft Update
Write-Output "Exporting Windows Updates - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-WindowsUpdate
#endregion Check Microsoft Update

#region Check Shares
Write-Output "Exporting Share Permissions - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-ShareReport
#endregion Check Shares

#region Check System Information
Write-Output "Exporting System Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output "Computer System Information" | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Get-WmiObject -Class Win32_ComputerSystem | Select-Object Name, Model,
    Manufacturer, Description, DNSHostName, Domain, DomainRole, PartOfDomain,
    NumberOfProcessors, SystemType, TotalPhysicalMemory, UserName, Workgroup |
    Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
#endregion Check System Information

#region Get OperatingSystem info
Write-Output "Exporting Operating System Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output "Operating System Information" | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Name, Version, FreePhysicalMemory,
    OSLanguage, OSProductSuite, OSType, OSArchitecture, BuildNumber, Caption, InstallDate,
    LastBootUpTime, LocalDateTime, SystemDrive, WindowsDirectory, SystemDirectory,
    ServicePackMajorVersion, ServicePackMinorVersion, RegisteredUser |
    Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -Encoding utf8
#endregion Get OperatingSystem info

#region Get Network Login info
Write-Output "Exporting Network Login Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output "Network Login Information" | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Get-WmiObject -Class Win32_NetworkLoginProfile | Select-Object PSComputerName, Name, Caption,
    Description, FullName, HomeDirectory, HomeDirectoryDrive, LastLogon, LogonHours,
    LogonServer, PasswordExpires, PrimaryGroupID, UserType |
    Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
#endregion Get Network Login info

#region Get Network Connections info
Write-Output "Exporting Network Adapter Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output "Network Connections Information" | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
$networkadapter = Get-WmiObject -Class Win32_NetworkAdapter | Select-Object PSComputerName,
    Availability, Name, AdapterType, Description, Installed, MACAddress, Manufacturer,
    NetConnectionID, @{Name='NetConnectionStatus';Expression={(ConvertFrom-NetStatus($_.NetConnectionStatus))}}, NetEnabled, PhysicalAdapter,
    ProductName, ServiceName, TimeOfLastRest
$networkconfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
    Select-Object DHCPEnabled, DHCPLeaseObtained, DHCPLeaseExpires, DHCPServer, DNSDomain,
    DNSDomainSuffixSearchOrder, DNSEnabledForWINSResolution, DNSHostName, DNSServerSearchOrder,
    DomainDNSRegistrationEnabled, FullDNSRegistrationEnabled, IPAddress, IPEnabled,
    IPFilterSecurityEnabled, WINSEnableLMHostsLookup, WINSHostLookupFile, WINSPrimaryServer,
    WINSSecondaryServer, DefaultIPGateway, IPSubnet
$na = $networkadapter.getenumerator()
$nc = $networkconfig.getenumerator()

while($na.MoveNext() -and $nc.MoveNext()){
    Write-Output $na.current $nc.current | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
}

Write-Output "Exporting Open TCP/UDP Connections - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Get-Netstat | ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$ScriptDir\$ComputerName\$ComputerName-Netstat.csv" -Append
#endregion Get Network Connections info

#region Get PhysicalMemory info
Write-Output "Exporting Memory Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output "Memory Information" | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Get-WmiObject -Class Win32_PhysicalMemory | Select-Object Name, Capacity, DeviceLocator, Tag |
    Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
#endregion Get PhysicalMemory info

#region Get LogicalDisk info
Write-Output "Exporting Logical Disk Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output "Logical Disk Information" | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Get-WmiObject -Class Win32_LogicalDisk | Select-Object Name, ProviderName, Description, FreeSpace, Size |
    Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
#endregion Get LogicalDisk info

#region Get Remote Desktop Status
Write-Output "Exporting RDP Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output "RDP Information" | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
Write-Output ("="*80) | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
if (((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections').fDenyTSConnections) -eq 1) {
    Write-Output 'Remote Desktop is disabled in registry' | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
}
else {
    Write-Output 'Remote Desktop is enabled in registry' | Out-File "$ScriptDir\$ComputerName\$ComputerName-sysinfo.txt" -Append -NoClobber -Encoding utf8
}
#endregion

#region Get Firewall Settings
Write-Output "Exporting Firewall Information - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
if (-not (Test-Path "$ScriptDir\$ComputerName\Firewall")) {
    New-Item -Path "$ScriptDir\$ComputerName\Firewall" -ItemType Directory | Out-Null
}

Get-FirewallRule -Local -GPO | ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
    Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallRules-Registry.csv" -Encoding utf8 -Append

if ([version](Get-CimInstance -ClassName Win32_OperatingSystem -Property Version).Version -ge [version]'6.2.9200') {
    Get-NetFirewallRule -All -PolicyStore ActiveStore | Select-Object Name,DisplayName,InstanceID,Enabled,Profile,
        Direction,Action,EdgeTraversalPolicy,PolicyStoreSourceType,Description,DisplayGroup,Owner,
        @{Name='Platform';Expression={$_.Platform -join ', '}},
        @{Name='EnforcementStatus';Expression={$_.EnforcementStatus -join ', '}} |
        ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallRules.csv" -Encoding utf8 -Append

    Get-NetFirewallProfile -All -PolicyStore ActiveStore | ConvertTo-Csv -NoTypeInformation -Delimiter '|' |
        ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallProfiles.csv" -Encoding utf8 -Append

    Get-NetFirewallSetting -All -PolicyStore ActiveStore | ConvertTo-Csv -NoTypeInformation -Delimiter '|' |
        ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallSetting.csv" -Encoding utf8 -Append

    Get-NetFirewallApplicationFilter -All -PolicyStore ActiveStore | Select-Object InstanceID,Program,AppPath |
        ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallAppFilter.csv" -Encoding utf8 -Append

    Get-NetFirewallSecurityFilter -All -PolicyStore ActiveStore | 
        Select-Object InstanceID,Authentication,Encryption,LocalUser,RemoteUser,RemoteMachine |
        ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallSecurityFilter.csv" -Encoding utf8 -Append

    Get-NetFirewallServiceFilter -All -PolicyStore ActiveStore | Select-Object InstanceID,Service,ServiceName |
        ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
        Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallServiceFilter.csv" -Encoding utf8 -Append

    if ($isAdmin) {
        Get-NetFirewallPortFilter -All -PolicyStore ActiveStore |
            ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
            Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallPortFilters.csv" -Encoding utf8 -Append

        Get-NetFirewallAddressFilter -All -PolicyStore ActiveStore |
            Select-Object InstanceID,LocalAddress,LocalIP,RemoteAddress,RemoteIP |
            ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
            Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallAddressFilters.csv" -Encoding utf8 -Append
        
        Get-NetFirewallInterfaceFilter -All -PolicyStore ActiveStore | Select-Object InstanceID,InterfaceAlias |
            ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
            Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallInterfaceFilters.csv" -Encoding utf8 -Append

        Get-NetFirewallInterfaceTypeFilter -All -PolicyStore ActiveStore | Select-Object InstanceID,InterfaceType |
            ConvertTo-Csv -NoTypeInformation -Delimiter '|' | ForEach-Object { $_ -replace '"', ''} |
            Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallInterfaceTypeFilters.csv" -Encoding utf8 -Append
    }
    else {
        Write-Output "Administrator Rights not provided. Firewall Port Filters cannot be exported." |
            Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallPortFilters-NotExported.txt"

        Write-Output "Administrator Rights not provided. Firewall Address Filters cannot be exported." |
            Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallAddressFilters-NotExported.txt"

        Write-Output "Administrator Rights not provided. Firewall Interface Filters cannot be exported." |
            Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallInterfaceFilters-NotExported.txt"

        Write-Output "Administrator Rights not provided. Firewall Interface Type Filters cannot be exported." |
            Out-File -FilePath "$ScriptDir\$ComputerName\Firewall\$ComputerName-FirewallInterfaceTypeFilters-NotExported.txt"
    }
}
#endregion

Write-Output "Information from $ComputerName exported successfully - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
