# description		: Extract PC info
# author(s)		: Dennis Anfossi
# date			: 29/04/2021
# version		: 0.2.3
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
"* Brand         : " + ($ci).CsManufacturer
"* Model         : " + ($ci).CsModel
"* S/N           : " + ($ci).BiosSeralNumber
" "

"== OS == "
"* OS Version    : " + ($ci).OsName + " (Build: " + ($ci).WindowsVersion + ")"
"* OS Language   : " + ($ci).OsLanguage
"* Installed on  : " + ($ci).OsInstallDate
"* Architecture  : " + ($ci).OsArchitecture
"* Last boot     : " + ($ci).OsLastBootUpTime
"* Hostname      : " + ($ci).csName
"* Description   : " + (Get-WmiObject -Class Win32_OperatingSystem).Description
" "

if ($win_is_compatible -match "True"){
	"== PowerShell =="
	"=== Policy ==="
	"* Execution     : " + (Get-ExecutionPolicy)
	" "
	"=== Remote Management ==="
	Invoke-Command -ComputerName $hostname { 1 } 2>&1>$null
	if ($? -eq "True"){
		"* PSRemoting    : Enabled"
	}
	else{
		"* PSRemoting    : Disabled"
	}
	" "
	$providers = Get-PackageProvider
	if ($providers){
		"=== Package Providers ==="
		foreach ($provider in $providers){
			"* " + $provider.name + " (Version: " + $provider.version + ")"
		}
	}
}
" "

if ($win_is_compatible -match "True"){
	$restore_points = get-computerrestorepoint 2>$null
	if ($restore_points){
		"== Restore Point(s) =="
		foreach ($point in $restore_points) {
			$dateTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($point.CreationTime)
			"* " + $dateTime + " - " + $point.Description
		} 
		" "
	}	
}

"== CPU(s) == "
$cpus = Get-WmiObject -class win32_processor
foreach ($cpu in $cpus){
	"* DeviceID       : " + ($cpu.DeviceID)
	"** CPU Type      : " + ($ci).CsProcessors.name 
	"** CPU Speed     : " + ($cpu.CurrentClockSpeed) + " MHz"
	"** Cores         : " + ($cpu.NumberOfCores)
	"** Architecture  : " + ($cpu.AddressWidth) + " bit"
	" "
}

"== RAM == "
$totalram = Get-WmiObject -Class Win32_ComputerSystem
$rams = Get-WmiObject Win32_PhysicalMemory
"* Total Memory  : " + ([math]::Round($totalram.TotalPhysicalMemory / 1gb)) + "Gb"
" "
if($rams){
	foreach ($ram in $rams){
		"=== " + $ram.DeviceLocator + " ==="
		"* P/N           : " + $ram.PartNumber
		"* S/N           : " + $ram.SerialNumber
		"* Capacity      : " + ([math]::Round($ram.Capacity / 1gb,2))  + "Gb"
		"* Speed         : " + $ram.Speed + "MHz"
		" "
	}
}

"== Disk(s) =="
Get-WmiObject Win32_DiskDrive | sort DeviceID | ForEach-Object {
	$disk = $_
	$partitions = "ASSOCIATORS OF " + "{Win32_DiskDrive.DeviceID='$($disk.DeviceID)'} " + "WHERE AssocClass = Win32_DiskDriveToDiskPartition"
	Get-WmiObject -Query $partitions | ForEach-Object {
		$partition = $_
		$drives = "ASSOCIATORS OF " + "{Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} " + "WHERE AssocClass = Win32_LogicalDiskToPartition"
		Get-WmiObject -Query $drives | ForEach-Object {
			"=== " + $_.VolumeName + " ==="
			"* Disk Number   : " + ($disk.DeviceID -replace '^[^PHYSICALDRIVE]*PHYSICALDRIVE', 'Disk ')
			"* Disk Model    : " + $disk.Model
			"* Disk Status   : " + $(Get-Disk -Number ($disk.DeviceID -replace '^[^PHYSICALDRIVE]*PHYSICALDRIVE', '')).HealthStatus
			"* Disk Size     : " + $([math]::Round($disk.Size / 1gb,2)) + "Gb"
			"* Partition     : " + $($partition.Name -replace '^[^,]*,', '' -replace " ","")
			"* Type          : " + $partition.type
			"* FileSystem    : " + $_.filesystem
			"* Drive Letter  : " + $_.DeviceID
			"* Volume Name   : " + $_.VolumeName
			"* Prtition Size : " + $([math]::Round($_.Size / 1gb,2)) + "Gb"
			"* Free Space    : " + $([math]::Round($_.FreeSpace / 1gb,2)) + "Gb"
			" "
			#$disk | format-list *
			#$partition | format-list * 
			#$_ | format-list *
	    }
  	}
}

"== Network Info == "
$adapters = Get-NetAdapter -physical | where status -eq "Up"
foreach ($adapter in $adapters){
	$ip = $adapter |  Get-NetIPAddress -AddressFamily IPv4 | select IPAddress
	$netmask = $adapter | Get-NetIPAddress -AddressFamily IPv4 | select PrefixLength
	$dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily Ipv4 | select ServerAddresses
	$advanced = Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | where{($_.Description -eq $adapter.ifDesc)}
	"* Interface     : " + $adapter.InterfaceDescription
	"** IP Address   : " + $ip.IPAddress
	"** Netmask      : " + $netmask.PrefixLength
	"** Gateway      : " + ($adapter |Get-NetIPConfiguration).IPv4DefaultGateway.NextHop
	"** DNS          : " + $dns.ServerAddresses
		if ($env:userdnsdomain -eq $null){
			"** Workgroup    : " + ($ci).CsWorkgroup
		}
		else{
			"** Domain       : " + $env:userdnsdomain
		}
	"** MAC Address  : " + $adapter.MacAddress -replace "-",":"
	"** Profile Type : " + ($adapter | Get-NetConnectionProfile).NetworkCategory
	"** WOL Enabled  : " + ($adapter | Get-NetAdapterAdvancedProperty -RegistryKeyword "*WakeOnMagicPacket").RegistryValue 2>$null
	"** DHCP         : " + ($adapter | Get-NetIPInterface -AddressFamily IPv4).Dhcp
	if (($adapter | Get-NetIPInterface -AddressFamily IPv4).Dhcp -eq "Enabled"){
		"** DHCP Server  : " + $advanced.DHCPServer
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
		"* " +$($mapItem.Name) + "          : " + $($mapItem.ProviderName)
	}
	" "
}

$shares = Get-SmbShare | where {$_.Name -notmatch "IPC\$" -and $_.Name -notmatch "ADMIN\$" -and $_.Name -notmatch "[A-Z]\$"}
if($shares){
	"== Shared Folder(s) =="
	foreach ($share in $shares){
		$permissions = Get-SmbShareAccess -Name $share.name
		"* " + $share.name
		if ($share.description -ne ""){
		"** Description  : " + $share.description
		}
		foreach ($permission in $permissions){
			"** User         : " + $permission.AccountName
			"** Access       : " + $permission.AccessRight
			" "
		}
	}
}

if (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\"){
	if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\" -Name UseWuServer).UseWuServer -eq 1){
		"== Windows Update Settings =="
		"* WSUS Enabled  : Yes"
		"* Server        : " + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\" -Name WuServer).WuServer
		"* Status Server  : " + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\" -Name WuStatusServer).WuStatusServer
		if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\" -Name TargetGroupEnabled).TargetGroupEnabled -eq 1){
			"* Use Target    : Yes"
			"* Target Name   : " + (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\" -Name TargetGroup).TargetGroup
		}
		" "
	}
}

$printers = Get-Printer | where {($_.Name -notlike "*ax*") -and ($_.Name -notlike "*PDF*") -and ($_.Name -notlike "*XPS*") -and ($_.Name -notlike "*Note*")}
if ($printers){
	"== Printers =="
	foreach($printer in $printers){
		"* Printer       : " + $printer.Name
		"** IP Address   : " + $printer.PortName -replace "IP_",""
		"** Driver       : " + $printer.DriverName
		"** Shared       : " + $printer.Shared
		" "
	}
}

"== Installed Software =="
foreach($package in Get-Package | Where-Object {$_.name -notlike "*KB*"} | select Name, Version -Unique | Sort Name){
	if ($package.version -eq $null){
		"* " + $package.Name
	}
	else{
		"* " + $package.Name + " (Version: " + $package.version + ")"
	}
}
" "

$autoruns = Get-CimInstance -ClassName Win32_StartupCommand | Select Caption, Location, Command
if ($autoruns){
	"== AutoRuns =="
	"=== Applications ==="
	foreach($autorun in $autoruns){
		"* " + $autorun.caption
		"** Location     : " + $autorun.location
		"** Command      : " + $autorun.command
		" "
	}
}

$NonDefaultServices = Get-WmiObject win32_service | where { $_.Caption -notmatch "Windows" -and $_.PathName -notmatch "Windows"  `
-and $_.PathName -notmatch "policyhost.exe" -and $_.Name -ne "LSM" -and $_.PathName -notmatch "OSE.EXE" -and $_.PathName -notmatch  `
"OSPPSVC.EXE" -and $_.PathName -notmatch "Microsoft Security Client" -and $_.Name -notlike "*edge*"  -and $_.Name -notlike "ClickToRunSvc" `
-and $_.Name -notlike "*Mozilla*" -and $_.PathName -notmatch "armsvc.exe"}

if($NonDefaultServices){
	"=== Services ==="
	foreach ($service in $NonDefaultServices){
		if ($service.StartMode -eq "Auto"){
			"* " + $service.DisplayName
			"** Command      : " + $service.PathName
			"** StartUp      : " + $service.StartMode
			"** Account      : " + $service.StartName
			#"** State        : " + $service.State
			#"** Status       : " + $service.Status
			#"** Started      : " + $service.Started
			#"** Description  : " + $service.Description
			if ($service.PathName -notmatch '"'){
			"** Vulnerable   : Yes"
			}
		" "
		}
	}	
}


" "
"******************************** [/" + $hostname + "] ********************************"
" "
