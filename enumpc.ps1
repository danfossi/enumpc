# description		: Extract PC info
# author(s)		: Dennis Anfossi
# date			: 29/04/2021
# version		: 0.2.0
# license		: GPLv2
# usage			: powershell -Noexit <path>\<to>\<script>.ps1
#			: powershell <path>\<to>\<script>.ps1 | out-file -filepath "C:\outfile.log"
#			: cmd.exe /c @powershell -Noexit <path>\<to>\<script>.ps1
###########################################################

#Clear-Host
#Write-Host -ForegroundColor Green -NoNewline "Running script, please wait.."
$ci = Get-ComputerInfo
$hostname = Invoke-Command -ScriptBlock {hostname}
$os = ($ci).WindowsCurrentVersion

if ($os -ge 6.1){
	#"Win >= Win7 "
	$win_is_compatible = "True"
	}
else{
	#"Win < Win7"
	$win_is_compatible = "False"
	}
" "
"******************************** [" + $hostname + "] ********************************"
" "

"== System Info == "
"=== Hardware === "
"* Brand   : " + ($ci).CsManufacturer
"* Modello : " + ($ci).CsModel
"* S/N     : " + ($ci).BiosSeralNumber
" "

"=== OS === "
"* OS Version   : " + (Get-WmiObject -class Win32_OperatingSystem).Caption + " (Build: " + ($ci).WindowsVersion + ")"
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
	$restore_points = get-computerrestorepoint 2>&1>$null
	if ($restore_points){
		"=== Restore Point(s) ==="
		foreach ($point in $restore_points) {
			$dateTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($point.CreationTime)
			"* " + $dateTime + " - " + $point.Description
		} 
		" "
	}	
}

"=== CPU(s) === "
$cpu = Get-WmiObject -class win32_processor
"* CPU Type     : " + ($ci).CsProcessors.name 
"* CPU Speed    : " + $($cpu.CurrentClockSpeed) + " MHz"
" "

"=== RAM === "
$ram = Get-WmiObject -Class Win32_ComputerSystem
"* RAM          : " + ([math]::Round($ram.TotalPhysicalMemory / 1gb,2)) + "Gb"
" "

"=== Disk(s) ==="
$disks = Get-WmiObject Win32_LogicalDisk | where {$_.DriveType -ne "5"}
foreach ($disk in $disks) {
	"* " + $disk.DeviceID + " (S/N: " + $($disk.VolumeSerialNumber) + ")"
	"** FileSystem  : " + $($disk.FileSystem)
	"** Disk Size   : " + $([math]::Round($disk.size / 1gb,2)) + "Gb"
	"** Free space  : " + $([math]::Round($disk.freespace / 1gb,2)) + "Gb"
	" "
}

"== Network Info == "
$adapters = Get-NetAdapter -physical | where status -eq "Up"
foreach ($adapter in $adapters){
	$ip = $adapter |  Get-NetIPAddress -AddressFamily IPv4 | select IPAddress
	$netmask = $adapter | Get-NetIPAddress -AddressFamily IPv4 | select PrefixLength
	$dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily Ipv4 | select ServerAddresses
	$advanced = Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | where{($_.Description -eq $adapter.ifDesc)}
	
	
	if ($env:userdnsdomain -eq $null){
		#$domain = Get-ComputerInfo -Property CsWorkgroup
		$domain = ($ci).CsWorkgroup
	}
	else{
		$domain = $env:userdnsdomain
	}
	"* Interface: " + $adapter.InterfaceDescription
	"** IP Address: " + $ip.IPAddress
	"** Netmask: " + $netmask.PrefixLength
	"** Gateway: " + ($adapter |Get-NetIPConfiguration).IPv4DefaultGateway.NextHop
	"** DNS: " + $dns.ServerAddresses
	"** Domain: " + $domain.CsWorkgroup
	"** MAC Address: " + $adapter.MacAddress -replace "-",":"
	"** Profile Type: " + ($adapter | Get-NetConnectionProfile).NetworkCategory
	"** WOL Enabled: " + ($adapter | Get-NetAdapterAdvancedProperty -RegistryKeyword "*WakeOnMagicPacket").RegistryValue 2>&1>$null
	"** DHCP: " + ($adapter | Get-NetIPInterface -AddressFamily IPv4).Dhcp
	if (($adapter | Get-NetIPInterface -AddressFamily IPv4).Dhcp -eq "Enabled"){
		"** DHCP Server: " + $advanced.DHCPServer
		" "
	}
	else{
		" "
	}
}

$netItems = Get-WmiObject -Class Win32_MappedLogicalDisk | select Name, ProviderName
if ($netItems){
	"== Mapped Drive =="
	foreach($mapItem in $netItems) {
		"* " +$($mapItem.Name) + "         : " + $($mapItem.ProviderName)
		}
		" "
	}

$printItems = Get-WMIObject -class Win32_Printer | where {($_.Name -notlike "*ax*") -and ($_.Name -notlike "*PDF*") -and ($_.Name -notlike "*XPS*") -and ($_.Name -notlike "*Note*")} | Select Name,DriverName,PortName
if ($printItems){
	"== Printers =="
	foreach($instPrinter in $printItems) {
		"* " + $($instPrinter.PortName)
		"** " + $($instPrinter.name) + ": " + $($instPrinter.DriverName )
		" "
	}
}

"== Installed Software =="
foreach($package in Get-Package | Where-Object {$_.name -notlike "*KB*"} | select Name, Version -Unique | Sort Name){
	"* " + $package.Name + " (Version: " + $package.version + ")"
}


" "
"******************************** [/" + $hostname + "] ********************************"
" "
