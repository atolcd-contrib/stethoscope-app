#!/usr/bin/env kmd
exec powershell.exe /c Get-MpComputerStatus
save line
extract AntivirusEnabled[^]*?: (True|False)
save defender
remove line
