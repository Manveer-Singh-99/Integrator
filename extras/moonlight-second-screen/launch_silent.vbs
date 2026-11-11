Set ws = CreateObject("WScript.Shell")
ws.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File ""C:\VirtualDisplayDriver\Stream-Mac-Second-Screen.ps1""", 0, False
