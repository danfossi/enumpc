# enumpc
Enumerate local machine using powershell 1.0

## Prerequisites
- You need to have powershell installed
- Your ExecutionPolicy must be different from Restricted or AllSigned (see: http://technet.microsoft.com/en-us/library/ee176961.aspx)
- Must have Administrators rights

## Usage
* `powershell -Noexit path\to\enumpc.ps1`
 
* `powershell  path\to\enumpc.ps1 | out-file -filepath "C:\outfile.log"`
 
* `cmd.exe /c @powershell -Noexit  path\to\enumpc.ps1`

## Features
* Get OS info (installation date, architecture, last boot, os version)
* Get Restore Point infos
* Get machine info (RAM, CPU, HDD)
* Get network info (network interface, IPv4 info, MAC address)
* Enumerate Local Group/Account and associate it
* Get more info on user that run script (UAC, Group)
* Enumerate printer (driver, port)
* Get installed software (microsoft update are excluded)
* Get firewall profiles rules
