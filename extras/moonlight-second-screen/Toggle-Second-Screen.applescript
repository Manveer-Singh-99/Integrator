set isRunning to false
try
	do shell script "pgrep -f 'vd165'"
	set isRunning to true
end try

set linkInfo to do shell script "/usr/local/bin/detect-pc-link.sh"
set AppleScript's text item delimiters to "|"
set connMode to text item 1 of linkInfo
set pcIp to text item 2 of linkInfo
set macIp to text item 3 of linkInfo
set AppleScript's text item delimiters to ""

if isRunning then
	do shell script "pkill -f 'vd165'; killall Sunshine 2>/dev/null || true; nohup ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \"Manveer Singh@" & pcIp & "\" 'taskkill /F /IM Moonlight.exe 2>$null; exit 0' >/dev/null 2>&1 &"
	display notification "Virtual display stopped (" & connMode & "). Windows snapped back to MacBook." with title "Second Screen Disabled" sound name "Blow"
else
	do shell script "nohup /Users/manveersingh/.local/bin/vd165 1920 1200 165 > /Users/manveersingh/Library/Logs/vd165.log 2>&1 </dev/null &"
	delay 0.4
	do shell script "/Users/manveersingh/.local/bin/set_sunshine_display"
	do shell script "open -a '/Applications/Sunshine.app'; nohup /bin/sh -c \"sleep 0.5 && ssh -o BatchMode=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null 'Manveer Singh@" & pcIp & "' 'schtasks.exe /Run /TN LaunchMoonlightWin'\" >/dev/null 2>&1 &"
	display notification "1920×1200 @ 165Hz active via " & connMode & " (" & macIp & " -> " & pcIp & ")." with title "Second Screen Enabled" sound name "Glass"
end if
