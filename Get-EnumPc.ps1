$hostname = Invoke-Command -ScriptBlock {hostname}
$storageDir = $pwd
$webclient = New-Object System.Net.WebClient
$url = "https://raw.github.com/danfossi/enumpc/master/enumpc.ps1"
$file = "$storageDir\enumpc.ps1"
$webclient.DownloadFile($url,$file)
powershell.exe -ExecutionPolicy unrestricted $storageDir\enumpc.ps1 | Out-File $pwd\$hostname.txt
