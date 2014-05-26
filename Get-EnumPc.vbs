Set fso = WScript.CreateObject("Scripting.Filesystemobject")
set wscr = WScript.CreateObject("WScript.Shell")
strDesktop = wscr.SpecialFolders("Desktop")
ImageFile = "enumpc.ps1"
DestFolder = strDesktop
URL = "https://raw.github.com/danfossi/enumpc/master/enumpc.ps1"

wscr.Popup "Download Script..",4
wget = "bitsadmin /transfer " & Chr(34) & "Download_Enumpc" & Chr(34) & " " & Chr(34) & URL & Chr(34) & " " & Chr(34) & DestFolder & "\" & "enumpc.ps1" & Chr(34)
wscr.Run wget,0

Set svc=getobject("winmgmts:root\cimv2")
sQuery="select * from win32_process where name='bitsadmin.exe'"
Set cproc=svc.execquery(sQuery)
iniproc=cproc.count
Do While iniproc = 1
    wscript.sleep 5000
    set svc=getobject("winmgmts:root\cimv2")
    sQuery="select * from win32_process where name='bitsadmin.exe'"
    set cproc=svc.execquery(sQuery)
    iniproc=cproc.count
Loop
Set cproc=nothing
Set svc=Nothing

wscr.Popup "Download completed! Runnig script..",4

enumpc = "powershell.exe -noexit -ExecutionPolicy unrestricted " & Chr(34) & DestFolder & "\" & "enumpc.ps1" & Chr(34)

wscr.Run enumpc
