Set fso = WScript.CreateObject("Scripting.Filesystemobject")
set wscr = WScript.CreateObject("WScript.Shell")
strDesktop = wscr.SpecialFolders("Desktop")
ImageFile = "enumpc.ps1"
DestFolder = strDesktop
URL = "https://raw.github.com/danfossi/enumpc/master/enumpc.ps1"

Set xml = CreateObject("Microsoft.XMLHTTP")
xml.Open "GET", URL, False
xml.Send

set oStream = createobject("Adodb.Stream")
Const adTypeBinary = 1
Const adSaveCreateOverWrite = 2
Const adSaveCreateNotExist = 1

oStream.type = adTypeBinary
oStream.open
oStream.write xml.responseBody

oStream.savetofile DestFolder & "\" & ImageFile, adSaveCreateOverWrite

oStream.Close

wscr.Popup "Download Completed!",4

set oStream = nothing
Set xml = Nothing

wscr.Popup "Running Script..",4

enumpc = "powershell.exe -noexit -ExecutionPolicy unrestricted " & Chr(34) & DestFolder & "\" & "enumpc.ps1" & Chr(34)

wscr.Run enumpc
