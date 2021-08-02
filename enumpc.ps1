# description		: Extract PC info
# author(s)		: Dennis Anfossi
# date			: 29/04/2021
# version		: 0.2.1
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
"* Model   : " + ($ci).CsModel
"* S/N     : " + ($ci).BiosSeralNumber
" "

"=== OS === "
"* OS Version   : " + ($ci).OsName + " (Build: " + ($ci).WindowsVersion + ")"
"* OS Language  : " + ($ci).OsLanguage
"* Installed on : " + ($ci).OsInstallDate
"* Architecture : " + ($ci).OsArchitecture
"* Last boot    : " + ($ci).OsLastBootUpTime
" "

if ($win_is_compatible -match "True"){
	"=== PowerShell ==="
	"* Execution    : " + (Get-ExecutionPolicy)
	Invoke-Command -ComputerName $hostname { 1 } 2>&1>$null
	if ($? -eq "True"){
		"* PSRemoting   : Enabled"
	}
	else{
		"* PSRemoting   : Disabled"
	}
}
" "

if ($win_is_compatible -match "True"){
	$restore_points = get-computerrestorepoint 2>$null
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
$totalram = Get-WmiObject -Class Win32_ComputerSystem
$rams = Get-WmiObject Win32_PhysicalMemory
"* Total Memory : " + ([math]::Round($totalram.TotalPhysicalMemory / 1gb)) + "Gb"
" "
if($rams){
	foreach ($ram in $rams){
		"==== " + $ram.DeviceLocator + " ===="
		"* P/N: " + $ram.PartNumber
		"* S/N: " + $ram.SerialNumber
		"* Capacity: " + ([math]::Round($ram.Capacity / 1gb,2))  + "Gb"
		"* Speed: " + $ram.Speed + "MHz"
		" "
	}
}

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
	"* Interface: " + $adapter.InterfaceDescription
	"** IP Address: " + $ip.IPAddress
	"** Netmask: " + $netmask.PrefixLength
	"** Gateway: " + ($adapter |Get-NetIPConfiguration).IPv4DefaultGateway.NextHop
	"** DNS: " + $dns.ServerAddresses
		if ($env:userdnsdomain -eq $null){
			"** Workgroup: " + ($ci).CsWorkgroup
		}
		else{
			"** Domain: " + $env:userdnsdomain
		}
	"** MAC Address: " + $adapter.MacAddress -replace "-",":"
	"** Profile Type: " + ($adapter | Get-NetConnectionProfile).NetworkCategory
	"** WOL Enabled: " + ($adapter | Get-NetAdapterAdvancedProperty -RegistryKeyword "*WakeOnMagicPacket").RegistryValue 2>$null
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

$printers = Get-Printer | where {($_.Name -notlike "*ax*") -and ($_.Name -notlike "*PDF*") -and ($_.Name -notlike "*XPS*") -and ($_.Name -notlike "*Note*")}
if ($printers){
	"== Printers =="
	foreach($printer in $printers){
		"* Printer: " + $printer.Name
		"** IP Address: " + $printer.PortName -replace "IP_",""
		"** Driver: " + $printer.DriverName
		"** Shared: " + $printer.Shared
		" "
	}
}

"== Installed Software =="
foreach($package in Get-Package | Where-Object {$_.name -notlike "*KB*"} | select Name, Version -Unique | Sort Name){
	"* " + $package.Name + " (Version: " + $package.version + ")"
}
" "

$autoruns = Get-CimInstance -ClassName Win32_StartupCommand | Select Caption, Location, Command
if ($autoruns){
	"== AutoRuns =="
	foreach($autorun in $autoruns){
		"* " + $autorun.caption
		"** Location: " + $autorun.location
		"** Command: " + $autorun.command
		" "
	}
}

" "
"******************************** [/" + $hostname + "] ********************************"
" "
