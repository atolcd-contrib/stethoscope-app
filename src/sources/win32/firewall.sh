#!/usr/bin/env kmd
exec powershell.exe /c Get-NetFirewallProfile
trim
split \r\n\r\n
  save _line
  extract Name[^]*?: (Domain|Private|Public)
  save type

  load _line
  extract Enabled[^]*?: +(True|False)
  save status

  remove _line
noEmpty
save firewalls
