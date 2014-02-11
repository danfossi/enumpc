# description		: Script to enumerate local machine
# author(s)		: Dennis Anfossi
# date			: 11.02.2014
# version		: 0.1.2
# license		: GPLv2
# usage			: powershell -Noexit <path>\<to>\<script>.ps1
#			: powershell <path>\<to>\<script>.ps1 | out-file -filepath "C:\outfile.log"
#			: cmd.exe /c @powershell -Noexit <path>\<to>\<script>.ps1
###########################################################

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
"******************************** " + $hostname + " ********************************"
" "

"== System Info == "
"=== OS === "
"* OS Version  : " + (Get-WmiObject -class Win32_OperatingSystem).Caption
"* Installed on: " + ([WMI]'').ConvertToDateTime((Get-WmiObject Win32_OperatingSystem).InstallDate) 
if ($win_is_compatible -match "True"){
"* Architecture: " + (Get-WmiObject Win32_OperatingSystem).OSArchitecture
}
		$lastboot = Get-WmiObject win32_operatingsystem | select csname, @{LABEL='LastBootUpTime';EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}}
"* Last boot   : " + $lastboot.lastbootuptime
if ($win_is_compatible -match "True"){
"* PowerShell  : " + (Get-ExecutionPolicy)
}
" "

if ($win_is_compatible -match "True"){
"=== Restore Point ==="
 get-computerrestorepoint | format-table @{Label="Date"; Expression={$_.ConvertToDateTime($_.CreationTime)}}, Description
}

"=== CPU(s) === "
$cpu = Get-WmiObject -class win32_processor
"* CPU Type    : " + $($cpu.caption)
"* CPU Speed   : " + $($cpu.CurrentClockSpeed) + " MHz"
" "

"=== RAM === "
$ram = Get-WmiObject -Class Win32_ComputerSystem
"* RAM         : " + ([math]::Round($ram.TotalPhysicalMemory / 1gb,2)) + "Gb"
" "

$disks = Get-WmiObject Win32_LogicalDisk
"=== Disk(s) ==="
foreach ($disk in $disks) {
"* " + $disk.DeviceID + " (S/N: " + $($disk.VolumeSerialNumber) + ")"
"** FileSystem  : " + $($disk.FileSystem)
"** Disk Size   : " + $([math]::Round($disk.size / 1gb,2)) + "Gb"
"** Free space  : " + $([math]::Round($disk.freespace / 1gb,2)) + "Gb"
" "
}


"== Network Info == "
$strComputer ="."
$colItems = Get-WmiObject Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" | where{$_.IPEnabled -eq “True”}
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
"* Username   : "  + $($net.username)
if ($WindowsPrincipal.IsInRole("Administrators"))
{
"* Group      : Administators"
}
else
{
"* Group      : Users"
}
	if ($win_is_compatible -match "True"){
"* UAC        : " + (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA
}
" "


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
"* " + $($instPrinter.PortName)
"** " + $($instPrinter.name) + ": " + $($instPrinter.DriverName )
" "
}

"== Installed Software =="
$listsoft = Get-WmiObject -Class Win32_Product | Select-Object -Property Name | Sort-Object -Property Name
foreach ($instsoft in $listsoft) {
"* " + $($instsoft.name)
}

" "
"****************************************************************************"
" "
Write-Host -ForegroundColor Green "done!"
