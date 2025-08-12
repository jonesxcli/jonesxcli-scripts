<#
.SYNOPSIS Backup Windows Eventlogs via DEM
.NOTES  Author:  JonEsxcli twitter @jonesxcli
.NOTES  Site:    www.vjonathan.com
.VERSION v1
.DATE  8-12-2025
#>

Function Backup-DEMEventLog {
$SecLog = Get-WmiObject win32_nteventlogfile | where {$_.LogFileName -eq “Security”} 
$SysLog = Get-WmiObject win32_nteventlogfile | where {$_.LogFileName -eq “System”} 
$AppLog = Get-WmiObject win32_nteventlogfile | where {$_.LogFileName -eq “Application”} 
$YearDate = Get-Date -Format yyyy
$FolderDate = Get-Date -Format MM_dd_yyyy 
$EventDate = Get-Date -Format hhmmss_MM_dd_yyyy
#Location for Event logs.
$BackupPath = “\\esx.lab\uem\UEMEventLog” 



#Test Backup Location
IF (Test-Path -Path “$BackupPath$YearDate”){Write-Host “Year Folder Exists $YearDate” -ForegroundColor Green} Else {Write-Host “Year Folder doesn’t exist…Creating new folder $YearDate” -ForegroundColor Yellow 
New-Item -ItemType Directory -Path “$BackupPath$YearDate”}
IF (Test-Path -Path (Join-Path -Path “$BackupPath$YearDate -ChildPath $FolderDate") -PathType Container){Write-Host “Day Folder Exists $YearDate$FolderDate” -ForegroundColor Green} Else {Write-Host “Day Folder doesn’t exist…Creating new folder $YearDate$FolderDate” -ForegroundColor Yellow 
New-Item -ItemType Directory -Path (Join-Path -Path “$BackupPath$YearDate” -ChildPath "$FolderDate")}


#Backups Eventlogs 
$Seclog.BackupEventLog("$BackupPath$YearDate\$FolderDate\$env:COMPUTERNAME$env:USERNAME-Security-$Eventdate.evt") | Out-Null 
$Applog.BackupEventLog("$BackupPath$YearDate\$FolderDate\$env:COMPUTERNAME$env:USERNAME-Application-$Eventdate.evt") | Out-Null 
$Syslog.BackupEventLog("$BackupPath$YearDate\$FolderDate\$env:COMPUTERNAME$env:USERNAME-System-$Eventdate.evt") | Out-Null

#Test Backup Logs
IF (Test-Path -Path (Join-Path -Path "$BackupPath$YearDate" -ChildPath “$FolderDate\$env:COMPUTERNAME$env:USERNAME-Security-$Eventdate.evt”)){Write-Host “SUCCESS: Security Event log $env:COMPUTERNAME$env:USERNAME-Security-$Eventdate.evt exists”-ForegroundColor Green} Else {Write-Host " FAILED: Security Log $env:COMPUTERNAME$env:USERNAME-Security-$Eventdate.evt does’t exist" -ForegroundColor Red} 
IF (Test-Path -Path (Join-Path -Path "$BackupPath$YearDate" -ChildPath "$FolderDate\$env:COMPUTERNAME$env:USERNAME-System-$Eventdate.evt”)){Write-Host “SUCCESS: System Event log $env:COMPUTERNAME$env:USERNAME-System-$Eventdate.evt exists”-ForegroundColor Green} Else {Write-Host " FAILED: System Log $env:COMPUTERNAME$env:USERNAME-System-$Eventdate.evt does’t exist" -ForegroundColor Red} 
IF (Test-Path -Path (Join-Path -Path "$BackupPath$YearDate" -ChildPath “$FolderDate\$env:COMPUTERNAME$env:USERNAME-Application-$Eventdate.evt”)){Write-Host “SUCCESS: Application Event log $env:COMPUTERNAME$env:USERNAME-Application-$Eventdate.evt exists”-ForegroundColor Green} Else {Write-Host " FAILED: Application Log $env:COMPUTERNAME$env:USERNAME-Application-$Eventdate.evt does’t exist" -ForegroundColor Red} 
}

Backup-DEMEventLog
