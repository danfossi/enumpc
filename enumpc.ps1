# description		: Script to enumerate local machine
# author(s)		: Dennis Anfossi
# date			: 07.07.2014
# version		: 0.1.4
# license		: GPLv2
# usage			: powershell -Noexit <path>\<to>\<script>.ps1
#			: powershell <path>\<to>\<script>.ps1 | out-file -filepath "C:\outfile.log"
#			: cmd.exe /c @powershell -Noexit <path>\<to>\<script>.ps1
###########################################################

Function Get-InstalledApplication
{ 
Param( 
[Parameter(Mandatory=$true)] 
[string[]]$Computername) 

#Registry Hives 

$Object =@() 

$excludeArray = ("Security Update for Windows", 
"Update for Windows", 
"Update for Microsoft .NET", 
"Update for Microsoft",
"Security Update for Microsoft", 
"Hotfix for Windows", 
"Hotfix for Microsoft .NET Framework",
"Definition Update",
"Hotfix for Microsoft Visual Studio 2007 Tools", 
"Hotfix") 

[long]$HIVE_HKROOT = 2147483648 
[long]$HIVE_HKCU = 2147483649 
[long]$HIVE_HKLM = 2147483650 
[long]$HIVE_HKU = 2147483651 
[long]$HIVE_HKCC = 2147483653 
[long]$HIVE_HKDD = 2147483654 

Foreach($EachServer in $Computername){ 
$Query = Get-WmiObject -ComputerName $Computername -query "Select AddressWidth, DataWidth,Architecture from Win32_Processor"  
foreach ($i in $Query) 
{ 
 If($i.AddressWidth -eq 64){             
 $OSArch='64-bit' 
 }             
Else{             
$OSArch='32-bit'             
} 
} 

Switch ($OSArch) 
{ 

 "64-bit"{ 
$RegProv = GWMI -Namespace "root\Default" -list -computername $EachServer| where{$_.Name -eq "StdRegProv"} 
$Hive = $HIVE_HKLM 
$RegKey_64BitApps_64BitOS = "Software\Microsoft\Windows\CurrentVersion\Uninstall" 
$RegKey_32BitApps_64BitOS = "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" 
$RegKey_32BitApps_32BitOS = "Software\Microsoft\Windows\CurrentVersion\Uninstall" 

############################################################################# 

# Get SubKey names 

$SubKeys = $RegProv.EnumKey($HIVE, $RegKey_64BitApps_64BitOS) 

# Make Sure No Error when Reading Registry 

if ($SubKeys.ReturnValue -eq 0) 
{  # Loop Trhough All Returned SubKEys 
ForEach ($Name in $SubKeys.sNames) 
 { 
$SubKey = "$RegKey_64BitApps_64BitOS\$Name" 
$ValueName = "DisplayName" 
$ValuesReturned = $RegProv.GetStringValue($Hive, $SubKey, $ValueName) 
$AppName = $ValuesReturned.sValue 
$Version = ($RegProv.GetStringValue($Hive, $SubKey, "DisplayVersion")).sValue  
$Publisher = ($RegProv.GetStringValue($Hive, $SubKey, "Publisher")).sValue  
$donotwrite = $false 

if($AppName.length -gt "0"){ 

 Foreach($exclude in $excludeArray)  
                        { 
                        if($AppName.StartsWith($exclude) -eq $TRUE) 
                            { 
                            $donotwrite = $true 
                            break 
                            } 
                        } 
            if ($donotwrite -eq $false)  
                        {                         
            $Object += New-Object PSObject -Property @{ 
            Appication = $AppName; 
            Architecture  = "64-BIT"; 
            ServerName = $EachServer; 
            Version = $Version; 
            Publisher= $Publisher; 
           } 
                        } 

} 

  }} 

############################################################################# 

$SubKeys = $RegProv.EnumKey($HIVE, $RegKey_32BitApps_64BitOS) 

# Make Sure No Error when Reading Registry 

if ($SubKeys.ReturnValue -eq 0) 

{ 

  # Loop Through All Returned SubKEys 

  ForEach ($Name in $SubKeys.sNames) 

  { 

    $SubKey = "$RegKey_32BitApps_64BitOS\$Name" 

$ValueName = "DisplayName" 
$ValuesReturned = $RegProv.GetStringValue($Hive, $SubKey, $ValueName) 
$AppName = $ValuesReturned.sValue 
$Version = ($RegProv.GetStringValue($Hive, $SubKey, "DisplayVersion")).sValue  
$Publisher = ($RegProv.GetStringValue($Hive, $SubKey, "Publisher")).sValue  
 $donotwrite = $false 

if($AppName.length -gt "0"){ 
 Foreach($exclude in $excludeArray)  
                        { 
                        if($AppName.StartsWith($exclude) -eq $TRUE) 
                            { 
                            $donotwrite = $true 
                            break 
                            } 
                        } 
            if ($donotwrite -eq $false)  
                        {                         
            $Object += New-Object PSObject -Property @{ 
            Appication = $AppName; 
            Architecture  = "32-BIT"; 
            ServerName = $EachServer; 
            Version = $Version; 
            Publisher= $Publisher; 
           } 
                        } 
           } 

    } 

} 

} #End of 64 Bit 

###################################################################################### 

########################################################################################### 

"32-bit"{ 

$RegProv = GWMI -Namespace "root\Default" -list -computername $EachServer| where{$_.Name -eq "StdRegProv"} 

$Hive = $HIVE_HKLM 

$RegKey_32BitApps_32BitOS = "Software\Microsoft\Windows\CurrentVersion\Uninstall" 

############################################################################# 

# Get SubKey names 

$SubKeys = $RegProv.EnumKey($HIVE, $RegKey_32BitApps_32BitOS) 

# Make Sure No Error when Reading Registry 

if ($SubKeys.ReturnValue -eq 0) 

{  # Loop Through All Returned SubKEys 

  ForEach ($Name in $SubKeys.sNames) 

  { 
$SubKey = "$RegKey_32BitApps_32BitOS\$Name" 
$ValueName = "DisplayName" 
$ValuesReturned = $RegProv.GetStringValue($Hive, $SubKey, $ValueName) 
$AppName = $ValuesReturned.sValue 
$Version = ($RegProv.GetStringValue($Hive, $SubKey, "DisplayVersion")).sValue  
$Publisher = ($RegProv.GetStringValue($Hive, $SubKey, "Publisher")).sValue  

if($AppName.length -gt "0"){ 

$Object += New-Object PSObject -Property @{ 
            Appication = $AppName; 
            Architecture  = "32-BIT"; 
            ServerName = $EachServer; 
            Version = $Version; 
            Publisher= $Publisher; 
           } 
           } 

  }} 

}#End of 32 bit 

} # End of Switch 

} 

#$AppsReport 

$column1 = @{expression="ServerName"; width=15; label="Name"; alignment="left"} 
$column2 = @{expression="Architecture"; width=10; label="32/64 Bit"; alignment="left"} 
$column3 = @{expression="Appication"; width=80; label="Appication"; alignment="left"} 
$column4 = @{expression="Version"; width=15; label="Version"; alignment="left"} 
$column5 = @{expression="Publisher"; width=30; label="Publisher"; alignment="left"} 

#"#"*80 
#"Installed Software Application Report" 
#"Numner of Installed Application count : $($object.count)" 
#"Generated $(get-date)" 
#"Generated from $(gc env:computername)" 
#"#"*80 

#$object |Format-Table $column1, $column2, $column3 ,$column4, $column5 

$object |Format-Table $column3

}

Clear-Host
Write-Host -ForegroundColor Green -NoNewline "Running script, please wait.."
$hostname = Invoke-Command -ScriptBlock {hostname}
$enum_os=([Environment]::OSVersion)
$os = ([string]$enum_os.Version.Major) + "." + $([string]$enum_os.Version.Minor)

if ($os -ge 6.1)
	{
	#"Win >= Win7 "
	$win_is_compatible = "True"
	}
else
	{
	#"Win < Win7"
	$win_is_compatible = "False"
	}
" "
" "
"= " + $hostname + " ="
"== System Info == "
"=== OS === "
"* OS Version   : " + (Get-WmiObject -class Win32_OperatingSystem).Caption
"* Installed on : " + ([WMI]'').ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).InstallDate) 
if ($win_is_compatible -match "True"){
"* Architecture : " + (Get-WmiObject Win32_OperatingSystem).OSArchitecture
}
$lastboot = Get-WmiObject win32_operatingsystem | select csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
"* Last boot    : " + $lastboot.lastbootuptime
if ($win_is_compatible -match "True"){
"* PowerShell   : " + (Get-ExecutionPolicy)
}
" "

if ($win_is_compatible -match "True"){
"=== Restore Point(s) ==="
 get-computerrestorepoint | format-table @{Label="Date"; Expression={$_.ConvertToDateTime($_.CreationTime)}}, Description
}

"=== CPU(s) === "
$cpus = Get-WmiObject -class win32_processor

foreach ($cpu in $cpus) {
"* CPU Type     : " + $($cpu.caption)
"* CPU Speed    : " + $($cpu.CurrentClockSpeed) + " MHz"
" "
}

"=== RAM === "
$ram = Get-WmiObject -Class Win32_ComputerSystem
"* RAM          : " + ([math]::Round($ram.TotalPhysicalMemory / 1gb,2)) + "Gb"
" "

"=== Disk(s) ==="
$disks = Get-WmiObject Win32_LogicalDisk
foreach ($disk in $disks) {
"* " + $disk.DeviceID + " (S/N: " + $($disk.VolumeSerialNumber) + ")"
"** FileSystem  : " + $($disk.FileSystem)
"** Disk Size   : " + $([math]::Round($disk.size / 1gb,2)) + "Gb"
"** Free space  : " + $([math]::Round($disk.freespace / 1gb,2)) + "Gb"
" "
}

"== Network Info == "
$strComputer ="."
$colItems = Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | where{$_.IPEnabled -eq "True"}
foreach($objItem in $colItems) {
"* Interface: " + $($objItem.Description)
"** IP Address  : " + $($objItem.IPAddress[0])
"** Netmask     : " + $($objItem.IPSubnet)
"** Gateway     : " + $($objItem.DefaultIPGateway)
"** DNS Server  : " + $($objItem.DNSServerSearchOrder)
"** Domain      : " + $($objItem.DNSDomain)
" "
"** Mac Address : " + $($objItem.MACAddress)
" "
"** DHCP Enabled: " + $($objItem.DHCPEnabled)
"** DHCP Server : " + $($objItem.DHCPServer)

" "		  
}

"== Account Info =="
[string[]]$ComputerName = $hostname
foreach ($Computer in $ComputerName) {
    $Results = @()
    ([adsi]"WinNT://$Computer").psbase.Children | ? {$_.SchemaClassName -eq 'Group'} | % {
        foreach ($Member in $($_.psbase.invoke('members'))) {
            $Results += New-Object -TypeName PSCustomObject -Property @{
                name = $Member.GetType().InvokeMember("Name", 'GetProperty', $null, $Member, $null) 
                class = $Member.GetType().InvokeMember("Class", 'GetProperty', $null, $Member, $null) 
                path = $Member.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $Member, $null)
                group = $_.psbase.name
            } | ? {($_.Class -eq 'User') -and ([regex]::Matches($_.Path,'/').Count -eq 4)}
        }
    }
    $Results | Group-Object Name | Select-Object Name,@{name='Group(s)';expression={$_.Group | % {$_.Group}}}
}
" "	
"=== Current Account ==="
$net = New-Object -comobject Wscript.Network
$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
$homeItems = (Get-ChildItem $($home) -recurse | Measure-Object -property length -sum)
$mailaccounts = Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\UnreadMail\
"* Username   : " + $($net.username)
"* Prof. Size : " + "{0:N2}" -f ($homeItems.sum / 1GB) + " Gb"
if ($WindowsPrincipal.IsInRole("Administrators"))
{
"* Group      : Administrators"
}
else
{
"* Group      : Users"
}
	if ($win_is_compatible -match "True"){
"* UAC        : " + (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA
}
" "

if ($mailaccounts) {
"==== Mail Address ===="
foreach ($mailaccount in $mailaccounts) {
"* Mail used : " + $mailaccount -replace "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\UnreadMail\\",""
}
""
}

$netItems = Get-WmiObject -Class Win32_MappedLogicalDisk | select Name, ProviderName
if ($netItems){
"== Mapped Drive =="

foreach($mapItem in $netItems) {
"* " +$($mapItem.Name) + "         : " + $($mapItem.ProviderName)
}
" "
}

"== Printers =="
$printItems = Get-WMIObject -class Win32_Printer | Select Name,DriverName,PortName
foreach($instPrinter in $printItems) {
"* " + $($instPrinter.Name)
"** " + $($instPrinter.PortName) + ": " + $($instPrinter.DriverName )
" "
}

"== Installed Software =="
Get-InstalledApplication -Computername localhost

" "
"****************************************************************************"
" "

Write-Host -ForegroundColor Green "done!"
