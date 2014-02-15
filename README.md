# enumpc
Enumerate local machine using powershell 1.0

## Prerequisites
- You must have PowerShell installed
- Your ExecutionPolicy must be different from Restricted or AllSigned (see: http://technet.microsoft.com/en-us/library/ee176961.aspx)
- Must have Administrators rights

## Usage
* `powershell -Noexit path\to\enumpc.ps1`
 
* `powershell  path\to\enumpc.ps1 | out-file -filepath "C:\outfile.log"`
 
* `cmd.exe /c @powershell -Noexit  path\to\enumpc.ps1`

## Features
* Get OS info (installation date, architecture, last boot, os version)
* Get PowerShell ExecutionPolicy
* Get Restore Point infos (Windows 7 or above)
* Get Machine Info (RAM, CPU, HDD)
* Get Network Info (network interface, IPv4 info, MAC address)
* Enumerate Local Group/Account and associate it
* Get more info on user that run script (UAC, Group)
* Enumerate Printer (name, driver and port)
* Get a list of installed software (microsoft update are excluded)
* Get firewall profiles rules
