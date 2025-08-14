<#
.SYNOPSIS Omnissa Golden Image Shutdown Script.
.NOTES  Author:  JonEsxcli twitter @jonesxcli
.NOTES  Site:    www.vjonathan.com
.VERSION v1.0
.DATE 8-11-2025
#>


<#############################################################
# Function to .Net Opimization 
# See for more info https://techzone.omnissa.com/creating-optimized-windows-image-vmware-horizon-virtual-desktop
#############################################################>
Function Start-NetOptimization 
{
Write-Host "⏳ Running Function... Start .Net Opimization." -ForegroundColor DarkYellow
Write-Host "🔧 Running .NET Optimization...This might take a couple of minutes..." -ForegroundColor Green
$NGENPath = Join-Path -Path $env:SystemRoot -ChildPath "Microsoft.Net" 
$CurrentNGEN = Get-ChildItem -Path $ngenpath -Recurse | where {$_.Name -eq "ngen.exe"} | foreach {& "$($_.FullName)" "executequeueditems"}
$CurrentNGEN
}


<#############################################################
# Function to Disable Windows Update Service
#############################################################>
Function Disable-WindowsUpdate
{
 Write-Host "⏳ Running Function... Disable Windows Update Service" -ForegroundColor DarkYellow
 $WU = "Windows Update"
 $SoftwareDistribution = 'C:\Windows\SoftwareDistribution'

     If (Get-Service -DisplayName $WU | where {$_.starttype -eq "Disabled"}) { Write-Host "$WU service is already disabled" -ForegroundColor Green
  }
  Else
     {
     Write-Host "🔧 Checking if $WU service is running..." -ForegroundColor Yellow
     if (Get-Service -DisplayName $WU | where {$_.status -eq "Running"}) {Write-Host "🛠️ $WU service is still running... Stopping service..." -ForegroundColor Yellow 
     Stop-Service -DisplayName $WU -Force} else { Write-Host "🛠️ $WU Service is not running" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WU | where {$_.starttype -cnotmatch "Disabled"}) {Write-Host "🛠️ $WU service is currently not disabled!" -ForegroundColor Yellow
     Get-Service -DisplayName $WU | Set-Service -StartupType Disabled } else {Write-Host "🛠️ $WU service is currently disabled!" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WU | where {$_.Starttype -eq "Disabled"}) {Write-Host "🛠️ $WU service is now disabled!" -ForegroundColor Green}
     if (Test-Path $SoftwareDistribution | where {$_.Exists -eq 'True'}) {Write-Host "🗑️ Deleting Software Distribution folder" -ForegroundColor Red 
     Remove-Item -Path $SoftwareDistribution -Recurse -Force} else {Write-Host "🚫 Software Distribution folder no longer exists" -ForegroundColor Green}
    }
}

<#############################################################
# Function to Disable Windows Update Medic Service
#############################################################>
Function Disable-WindowsMedicUpdate
{
Write-Host "⏳ Running Function... Disable Windows Update Medic Service" -ForegroundColor DarkYellow
$WUMedic = "Windows Update Medic Service"

 If (Get-Service -$WUMedic -ErrorAction SilentlyContinue){

     If (Get-Service -DisplayName $WUMedic | where {$_.starttype -eq "Disabled"}) { Write-Host "🚫 $WUMedic is already disabled" -ForegroundColor Green
    }
  Else
     {
     Write-Host "🔧 Checking if $WUMedic is still running..." -ForegroundColor Yellow
     if (Get-Service -DisplayName $WUMedic | where {$_.status -eq "Running"}) {Write-Host "🛠️ $WUMedic is still running... Stopping Service..." -ForegroundColor Yellow 
     Stop-Service -DisplayName $WUMedic -Force} else { Write-Host "🚫 $WUMedic is not running" -ForegroundColor Yellow}
     if (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc\ -Name Start | where {$_.start -eq "4"}){Write-Host "🛠️ $WUMedic is currently set to disabled!" -ForegroundColor Yellow}
     else {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc\ -Name Start -Value 4 -Force {Write-Host "🛠️ Setting $WUMedic startup type disabled!" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WUMedic | where {$_.starttype -eq "Disabled"}) {Write-Host "🛠️ $WUMedic is now disabled!" -ForegroundColor Green}
     }
     Else {Write-Host "🚫 $WUMedic not found..." -ForegroundColor Yellow}
     }
    }
}

<#############################################################
# Function to Disable Windows Module Installer 
# https://docs.omnissa.com/bundle/AppVolumesAdminGuideV2312/page/ReduceAppVolumesLoginTimeonWindows10.html for more detail.
#############################################################>

Function Disable-WindowsModuleInstaller
{
Write-Host "⏳ Running Function... Disable Windows Module Installer" -ForegroundColor DarkYellow
 $TrustedInstaller = "Windows Modules Installer"
  
     If (Get-Service -DisplayName $TrustedInstaller | where {$_.starttype -eq "Disabled"}) { Write-Host "🛠️ $TrustedInstaller service is already disabled" -ForegroundColor Green
    }
  Else
     {
     Write-Host "🔧 Checking if $TrustedInstaller service is still running..." -ForegroundColor Yellow
     if (Get-Service -DisplayName $TrustedInstaller | where {$_.status -eq "Running"}) {Write-Host "🛠️ $TrustedInstaller service is still running... Stopping service..." -ForegroundColor Yellow 
     Stop-Service -DisplayName $TrustedInstaller -Force} else { Write-Host "🛠️ $TrustedInstaller service is not running" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $TrustedInstaller | where {$_.starttype -cnotmatch "Disabled"}) {Write-Host "🛠️ $TrustedInstaller service is currently not disabled!" -ForegroundColor Yellow
     Get-Service -DisplayName $TrustedInstaller | Set-Service -StartupType Disabled} else {Write-Host "🚫 $TrustedInstaller service is currently disabled!" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $TrustedInstaller | where {$_.starttype -eq "Disabled"}) {Write-Host "🚫 $TrustedInstaller service is now disabled!" -ForegroundColor Green} else {Write-Host "$TrustedInstaller is not disabled" -ForegroundColor Red}
    }
}


<#############################################################
# Function to Disable Windows Update Task Scheduler(SIH)
# See https://twitter.com/edbaker1965/status/976138729541816320 for more details.
#############################################################>

Function Disable-WUTasks
{
Write-Host "⏳ Running Function... Disable Windows Update SIH Task" -ForegroundColor DarkYellow
$Trigger= New-ScheduledTaskTrigger -AtStartup 
$User= "NT AUTHORITY\SYSTEM" 
$Action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "Get-ScheduledTask -TaskPath \Microsoft\Windows\WindowsUpdate\ | Disable-ScheduledTask" 
Write-Host "🔧 Creating new task "SIH"..." -ForegroundColor Green
Register-ScheduledTask -TaskName "SIH" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest -Force | Out-Null
}

<#############################################################
# Function to Enable Logon Monitor
# See https://docs.omnissa.com/bundle/Horizon-AdministrationV2406/page/UsingtheLogonMonitor.html for more details.
#############################################################>
Function Enable-LogonMonitor 
{
 Write-Host "⏳ Running Function... Enable Logon Monitor" -ForegroundColor DarkYellow
 $LogonMonitor = "Omnissa Horizon Logon Monitor"
 if (Get-Service -DisplayName $LogonMonitor | where {$_.starttype -eq "Automatic"})
 {Write-Host "🛠️ $LogonMonitor service is already set to automatic" -ForegroundColor Green}
 else {
 Write-Host "❎ $LogonMonitor service startup type is not automatic" -ForegroundColor Yellow
 Write-Host "🛠️ Setting $LogonMonitor service to automatic" -ForegroundColor Yellow
 (Get-Service -DisplayName $LogonMonitor | Set-Service -DisplayName $LogonMonitor -StartupType Automatic)
 }
 if (Get-Service -DisplayName $LogonMonitor | where {$_.Status -eq "Running"} -ErrorAction SilentlyContinue)
 {Write-Host "✅ $LogonMonitor service already running" -ForegroundColor Green}
 else {
 Write-Host "🛠️ Starting $LogonMonitor service..." -ForegroundColor Yellow
 Start-Service -DisplayName $LogonMonitor}
 }


<#############################################################
# Function to cleanup Logon Monitor
# See https://docs.omnissa.com/bundle/Horizon-AdministrationV2406/page/UsingtheLogonMonitor.html for more details.
#############################################################>
Function Cleanup-OmnissaLogonMonitorLogs
{
Write-Host "⏳ Running Function... Omnissa Cleanup Logon Monitor Logs" -ForegroundColor DarkYellow
$LogonMonitorPath = "C:\ProgramData\Omnissa\Logon Monitor\Logs"
$LogsPath = "C:\ProgramData\Omnissa\Logs"
if (Test-Path -Path $LogonMonitorPath){
Write-Host "🛠️ Cleaning up $LogonMonitorPath directory" -ForegroundColor Green
Get-ChildItem -Path $LogonMonitorPath -Recurse | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue}
else {
Write-Host "🚫 $LogonMonitorPath doesn't exist" -ForegroundColor Red}
if (Test-Path -Path $LogsPath){
Write-Host "🛠️ Cleaning up $LogsPath directory" -ForegroundColor Green
Get-ChildItem -Path $LogsPath -Recurse | Remove-Item -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue}
else {
Write-Host "🚫 $LogsPath doesn't exist" -ForegroundColor Red}
}


<#############################################################
# Function to Disable Logon Monitor
# See https://docs.omnissa.com/bundle/Horizon-AdministrationV2406/page/UsingtheLogonMonitor.html for more details.
#############################################################>
Function Disable-LogonMonitor 
{
 Write-Host "⏳ Running Function... Disable Omnissa Logon Monitor" -ForegroundColor DarkYellow
 $LogonMonitor = "Omnissa Horizon Logon Monitor"
 if (Get-Service -DisplayName $LogonMonitor | where {$_.Status -eq "Stopped"} -ErrorAction SilentlyContinue)
 {Write-Host "❎ $LogonMonitor service already running" -ForegroundColor Red}
 else {
 Write-Host "🛠️ Stopping $LogonMonitor service..." -ForegroundColor Yellow
 Stop-Service -DisplayName $LogonMonitor}
 if (Get-Service -DisplayName $LogonMonitor | where {$_.starttype -eq "Disable"})
 {Write-Host "✅ $LogonMonitor startup type already set to disabled" -ForegroundColor Green}
 else {
 Write-Host "🛠️ Setting $LogonMonitor service startup type is disabled" -ForegroundColor Yellow
 (Get-Service -DisplayName $LogonMonitor | Set-Service -DisplayName $LogonMonitor -StartupType Disabled)
 }
 }


<#############################################################
# Function to Disable Speculative
# See https://support.microsoft.com/en-us/topic/kb4073119-windows-client-guidance-for-it-pros-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-35820a8a-ae13-1299-88cc-357f104f5b11 for details.
#############################################################>

Function Disable-Speculative 
{
 Write-Host "⏳ Running Function... Disable Speculative Migiations" -ForegroundColor DarkYellow
 $MMUPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
 $MitigationName = 'FeatureSettingsOverride'

  If (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue | where {$_.FeatureSettingsOverride -eq '3'}) { Write-Host "👻 Mitigations for CVE-2017-5715 (Spectre Variant 2) is already disabled" -ForegroundColor Green
}
  Else
     {
     Write-Host "👻 Disabling Mitigations for CVE-2017-5715 (Spectre Variant 2)" -ForegroundColor Yellow
     If (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue) {Write-Host "👻 FeatureSettingsOverride exists! Setting Value to '3'" -ForegroundColor Green
     Set-ItemProperty -Path $MMUPath -Name $MitigationName -Value 3 -Force -ErrorAction SilentlyContinue
     } 
     Else { Write-host "👻 Creating FeatureSettingsOverride" -ForegroundColor Yellow
     New-ItemProperty -Path $MMUPath -Name $MitigationName -PropertyType DWORD -Value 3 -Force
     IF (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue | where {$_.FeatureSettingsOverride -eq '3'}) {Write-Host "👻 Mitigations for CVE-2017-5715 (Spectre Variant 2) is now disabled!" -ForegroundColor Green}
     }
     }
}
 
<#############################################################
# Function to Disable Meltdown
# See https://support.microsoft.com/en-us/topic/kb4073119-windows-client-guidance-for-it-pros-to-protect-against-silicon-based-microarchitectural-and-speculative-execution-side-channel-vulnerabilities-35820a8a-ae13-1299-88cc-357f104f5b11 for details.
#############################################################>

Function Disable-Meltdown
{
Write-Host "⏳ Running Function... Disable Meltdown Migiations " -ForegroundColor DarkYellow
 $MMUPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
 $MitigationName = 'FeatureSettingsOverrideMask'

  If (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue | where {$_.FeatureSettingsOverrideMask -eq '3'}) { Write-Host "🛡️ Mitigations for CVE-2017-5754 (Meltdown) is already disabled" -ForegroundColor Green
}
  Else
     {
     Write-Host "🛡️ Disabling Mitigations for CVE-2017-5715 (Spectre Variant 2)" -ForegroundColor Yellow
     If (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue) {Write-Host "🛡️ FeatureSettingsOverrideMask exists! Setting Value to '3'" -ForegroundColor Green
     Set-ItemProperty -Path $MMUPath -Name $MitigationName -Value 3 -Force -ErrorAction SilentlyContinue
     } 
     Else { Write-host "🛡️ Creating FeatureSettingsOverride" -ForegroundColor Yellow
     New-ItemProperty -Path $MMUPath -Name $MitigationName -PropertyType DWORD -Value 3 -Force
     IF (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue | where {$_.FeatureSettingsOverrideMask -eq '3'}) {Write-Host "🛡️ Mitigations for CVE-2017-5754 (Meltdown) is now disabled!" -ForegroundColor Green}
     }
     }
}



<#############################################################
# Function to Import OEM Default App Assoications
#############################################################>

Function Import-OEMDefaultAppAssociations #Modify $OEMDefaultAssociations for your to your enviroment needs
{
 Write-Host "⏳ Running Function... Import OEM Default App Associations" -ForegroundColor DarkYellow
 $OEMDefaultAssociationsDefaultPath = "$env:SystemRoot\System32\OEMDefaultAssociations.xml"
 $DISM = "dism.exe"
 $OEMDefaultAssociations = @"
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
  <Association Identifier=".3g2" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".3gp" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".3gp2" ProgId="WMP11.AssocFile.3G2" ApplicationName="Windows Media Player" />
  <Association Identifier=".3gpp" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".aac" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".adt" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".adts" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".amr" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".avi" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".bmp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".dib" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".flac" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".gif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".htm" ProgId="AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" ApplicationName="Microsoft Edge" />
  <Association Identifier=".html" ProgId="AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" ApplicationName="Microsoft Edge" />
  <Association Identifier=".jfif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpe" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jpeg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".JPG" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".jxr" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".m2t" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".m2ts" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".m3u" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".m4a" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".m4r" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".m4v" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".mkv" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".MOD" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".mov" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".MP2" ProgId="WMP11.AssocFile.MP3" ApplicationName="Windows Media Player" />
  <Association Identifier=".mp3" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".mp4" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".mp4v" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".mpa" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".mpeg" ProgId="WMP11.AssocFile.mpeg" ApplicationName="Windows Media Player" />
  <Association Identifier=".MPV2" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".mts" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".oxps" ProgId="Windows.XPSReachViewer" ApplicationName="XPS Viewer" />
  <Association Identifier=".pdf" ProgId="Acrobat.Document.2015" ApplicationName="Adobe Acrobat DC" />
  <Association Identifier=".png" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".tif" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" />
  <Association Identifier=".tiff" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" />
  <Association Identifier=".TS" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".TTS" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".txt" ProgId="txtfile" ApplicationName="Notepad" />
  <Association Identifier=".url" ProgId="IE.AssocFile.URL" ApplicationName="Internet Browser" />
  <Association Identifier=".wav" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".wdp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" />
  <Association Identifier=".website" ProgId="IE.AssocFile.WEBSITE" ApplicationName="Internet Explorer" />
  <Association Identifier=".wm" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".wma" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".wmv" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".wpl" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier=".xps" ProgId="Windows.XPSReachViewer" ApplicationName="XPS Viewer" />
  <Association Identifier=".xvid" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" />
  <Association Identifier=".zpl" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Groove Music" />
  <Association Identifier="http" ProgId="AppXq0fevzme2pys62n3e0fbqa7peapykr8v" ApplicationName="Microsoft Edge" />
  <Association Identifier="https" ProgId="AppX90nv6nhay5n6a98fnetv7tpk64pp35es" ApplicationName="Microsoft Edge" />
  <Association Identifier="mailto" ProgId="Outlook.URL.mailto.15" ApplicationName="Outlook" />
  <Association Identifier="microsoft-edge" ProgId="AppX7rm9drdg8sk7vqndwj3sdjw11x96jc0y" ApplicationName="Microsoft Edge" />
  <Association Identifier="mswindowsvideo" ProgId="AppX6w6n4f8xch1s3vzwf3af6bfe88qhxbza" ApplicationName="Movies &amp; TV" />
</DefaultAssociations>
"@

if (Get-ChildItem -Path $OEMDefaultAssociationsCustomPath | where {$_.Exists -eq "true"}) {Remove-Item -Path $OEMDefaultAssociationsDefaultPath -Force}
New-Item -Path $PSScriptRoot -Name TEMPDEFAULTASSOCIATIONS.XML -ItemType File -Value $OEMDefaultAssociations -Force | Out-Null
DISM /online /import-defaultappassociations:"$PSScriptRoot\TEMPDEFAULTASSOCIATIONS.XML" | Out-Null
if (Get-ChildItem -Path $PSScriptRoot\TEMPDEFAULTASSOCIATIONS.XML | where {$_.Exists -eq "true"}) {Remove-Item -Path $PSScriptRoot\TEMPDEFAULTASSOCIATIONS.XML -Force | Out-Null}
}


<#############################################################
# Function to Import Custom Startlayout for Windows 10... not supported with Windows 11
# Modify $TempStartLayout for your to your enviroment needs
# Example with Office 2016
#############################################################>

Function Import-CustomStartLayout 
{
Write-Host "⏳ Running Function...Import Custom Start Layout " -ForegroundColor DarkYellow
$computerinfo = Get-ComputerInfo
$osversion = $computerinfo.OsName
$LayoutPath = "$PSScriptRoot\TempStartLayout.xml"
$TempStartLayout = @"
<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
  <LayoutOptions StartTileGroupCellWidth="6" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth="6">
        <start:Group Name="Common Utilities">
          <start:DesktopApplicationTile Size="2x2" Column="4" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\computer.lnk" />
          <start:Tile Size="2x2" Column="0" Row="2" AppUserModelID="Microsoft.WindowsCalculator_8wekyb3d8bbwe!App" />
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" />
          <start:Tile Size="2x2" Column="4" Row="2" AppUserModelID="windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" />
          <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\Control Panel.lnk" />
          <start:Tile Size="2x2" Column="2" Row="2" AppUserModelID="Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe!App" />
        </start:Group><start:Group Name="Office Applications" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout">
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Word 2016.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="2" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Excel 2016.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="4" Row="0" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Outlook 2016.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="0" Row="2" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Powerpoint 2016.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="2" Row="2" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Skype for Business 2016.lnk" />
          <start:DesktopApplicationTile Size="2x2" Column="4" Row="2" DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\OneNote 2016.lnk" />
        </start:Group>
      </defaultlayout:StartLayout>
    </StartLayoutCollection>
  </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@
#Removed IE11
#$SourceFile = "$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe"
#$ShortCutFile = "$env:SystemDrive\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk"
#$WScript = New-Object -ComObject WScript.Shell
#$ShortCut = $WScript.CreateShortcut($ShortCutFile)
#$ShortCut.TargetPath = $SourceFile
#$shortcut.Save()

 Write-Host "🛠️ Checking OS version...for Custom Start Layout" -ForegroundColor Green
 if ($computerinfo | where {$_.OsName -eq "Windows 10"}){Write-Host "🛠️ Running supported version of $OSVersion...running import start layout task." -ForegroundColor Green
 New-Item -Path $PSScriptRoot -Name TempStartLayout.XML -ItemType File -Value $TempStartLayout -Force  | Out-Null
 if (Get-ChildItem -Path $LayoutPath -ErrorAction SilentlyContinue | where {$_.Exists -eq "true"}) {Import-StartLayout -LayoutPath $LayoutPath -MountPath $env:SystemDrive\} 
 Write-Host "🚫 Skipping Startlayout... custom startayout.xml doesn't exist." -ForegroundColor Red}
 if (Get-ChildItem -Path $LayoutPath -ErrorAction SilentlyContinue | where {$_.Exists -eq "true"}){Remove-Item -Path $LayoutPath -Force}
 else {
 Write-Host "🚫 $osversion not supported with Import-StartLayout cmdlet." -ForegroundColor Red
 }
 }
 


 <#############################################################
# Function to Disable Shadowcopies
# See for more info https://techzone.omnissa.com/creating-optimized-windows-image-vmware-horizon-virtual-desktop
#############################################################>

Function Disable-Shadowcopies
{
Write-Host "⏳ Running Function... Disable Volume Shadow Copy Serivce" -ForegroundColor DarkYellow
 $VSS = "VSS"
 $VSSadmin = "vssadmin.exe"
 If (Get-Service -Name $VSS | where {$_.status -eq "Disabled"}) { Write-Host "✅ Volume Shadow Copy service is already disabled" -ForegroundColor Green
}
  Else
     {
  Write-Host "🚫 Volume Shadow Copy service is still enabled" -ForegroundColor Yellow
  Write-Host "🗑️ Clearing Shadow Copies..." -ForegroundColor Yellow
  Start-Process $VSSadmin -ArgumentList "Delete shadows /all /quiet" -wait -WindowStyle Hidden 
  if (Get-Service -Name $VSS | where {$_.Status -eq "Running"}) {Write-Host "🚫 Volume Shadow Copy service is currently running." -ForegroundColor Yellow} else {Write-Host "🛠️ Stopping $VSS service..." -ForegroundColor Yellow 
  Get-Service -Name $VSS  | Stop-Service -Force}
  if (Get-Service -Name $VSS | where {$_.starttype -eq "Disabled"}) {Write-Host "✅ Volume Shadow Copy service is now disabled!" -ForegroundColor yellow} else {Write-Host "🛠️ Disabling $VSS service" -ForegroundColor Yellow
  Get-Service -Name $VSS | Set-Service -StartupType Disabled}
  }
}

 <#############################################################
# Function to run clean up manager
# NOTE: DOESN'T CLEANUP WINDOWS EVENT LOGS
#############################################################>

Function Start-Cleanup
{
Write-Host "⏳ Running Function... Start Cleanup Manager " -ForegroundColor DarkYellow
 $Cleanmgr = "C:\windows\System32\cleanmgr.exe"
 $arguements = "/autoclean"
 Write-Host "🗑️ Running Cleanup Manager..." -ForegroundColor Yellow
 Start-Process $Cleanmgr -ArgumentList $arguements -Wait -WindowStyle Hidden
 Write-Host "✅ Cleanup Manager Completed" -ForegroundColor Green
}

 <#############################################################
# Function to start shutdown process
#############################################################>

Function Start-Shutdown
{
Write-Host "⏳ Running Function... Start Shutdown Process" -ForegroundColor DarkYellow
$Interface = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | where {$_.Ipenabled -eq "True" -and $_.DhcpEnabled -eq "True"}
$cscript = "C:\Windows\System32\cscript.exe"
 Write-Host "🗑️ Removing Domain Profiles..." -ForegroundColor Red
 #Update this line to add exclude any accounts
 Get-CimInstance -ClassName Win32_UserProfile | where {$_.LocalPath -notlike "C:\Users\DoD_Admin" -and $_.LocalPath -notlike "C:\windows\system32\config\systemprofile" -and $_.LocalPath -notlike "C:\windows\ServiceProfiles\NetworkService" -and $_.LocalPath -notlike  "C:\windows\ServiceProfiles\LocalService"  } | Remove-CimInstance -ErrorAction SilentlyContinue
 Write-Host "🗑️ Flushing DNS..." -ForegroundColor Yellow
 Clear-DnsClientCache
 Write-Host "🗑️ Clearing name of KMS Computer and disabling KMS host caching..." -ForegroundColor Yellow
 Start-Process $cscript -ArgumentList "//B C:\windows\System32\slgmr.vbs /ckms" -Wait -WindowStyle Hidden
 Start-Process $cscript -ArgumentList "//B C:\windows\System32\slgmr.vbs /ckhc" -Wait -WindowStyle Hidden
 Write-Host "✅ Confirming Shutdown...Shutting down in 10 seconds" -ForegroundColor Red
 foreach ($int in $Interface){
 Write-Host "Releasing IP..." -ForegroundColor Yellow
 $int.ReleaseDHCPLease() | Out-Null
 } 
 Start-Sleep -Seconds 10
 Stop-Computer -Confirm:$false 
 }


 <#############################################################
# Function to Enable Windows Update Service
#############################################################>

Function Enable-WindowsUpdate
{
Write-Host "⏳ Running Function... Enable Windows Update Service " -ForegroundColor DarkYellow
 $WU = "Windows Update"
 $SoftwareDistribution = 'C:\Windows\SoftwareDistribution'

     If (Get-Service -DisplayName $WU | where {$_.starttype -eq "Automatic" -and $_.Status -EQ "Running"}) { Write-Host "✅ $WU service is running and set to automatic start Type" -ForegroundColor Green
}
  Else
     {
     if (Test-Path $SoftwareDistribution | where {$_.Exists -eq 'True'}) {Write-Host "🗑️ Deleting Software Distribution folder" -ForegroundColor Red 
     Stop-Service -Displayname $WU | Remove-Item -Path $SoftwareDistribution -Recurse -Force} else {Write-Host "✅ Software Distribution folder no longer exists" -ForegroundColor Green}
     if (Get-Service -DisplayName $WU | where {$_.StartType -cnotmatch "Automatic"}) {Write-Host "❎ $WU service is currently not set to automatic!" -ForegroundColor Yellow
     get-service -displayname $WU | Set-Service -StartupType Automatic } else {Write-Host "❎ $WU service is currently set to automatic" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WU | where {$_.StartType -cnotmatch "running"}) {Write-Host "❎ $WU service is not running..." -ForegroundColor Yellow 
     Start-Service -DisplayName $WU} else { Write-Host "✅ $WU service is already running" -ForegroundColor Green}
     }
     }


<#############################################################
# Function to Enable Windows Update Service
#############################################################>

Function Enable-WindowsMedicUpdate
{
Write-Host "⏳ Running Function... Enable Windows Update Medic Service " -ForegroundColor DarkYellow
 $WUMedic = "Windows Update Medic Service"

 If (Get-Service -$WUMedic -ErrorAction SilentlyContinue){

     If ((Get-Service -DisplayName $WUMedic | where {$_.status -eq "running" -and  $_.StartType -eq "Automatic"})) { Write-Host "✅ $WUMedic service is already running and set to Automatic" -ForegroundColor Green
}
  Else
     {
     if (Get-Service -DisplayName $WUMedic | where {$_.StartType -cnotmatch "Automatic"}) {Write-Host "❎ $WUMedic is currently not to Automatic!" -ForegroundColor Yellow
     Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc\ -Name Start -Value 3 -Force
     {Write-Host "❎ $WUMedic is currently set to Automatic!" -ForegroundColor Yellow} 
     else {Write-Host "✅ Setting $WUMedic service startup type Automatic!" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WUMedic | where {$_.StartType -cnotmatch "Running"}) {Write-Host "🛠️ $WUMedic Service is running..." -ForegroundColor Yellow 
     Start-Service -DisplayName $WUMedic} else { Write-Host "✅ $WUMedic Service is running" -ForegroundColor Yellow}
     }
     }

    Else {Write-Host "🚫 $WUMedic not found..." -ForegroundColor Yellow
}
     }
     }
     
<#############################################################
# Function to Enable Windows Module Installer
#############################################################>
   

Function Enable-WindowsModuleInstaller
{
 Write-Host "⏳ Running Function... Enable Windows Module Installer " -ForegroundColor DarkYellow
 $TrustedInstaller = "Windows Modules Installer"
  
     If (Get-Service -DisplayName $TrustedInstaller | where {$_.StartType -eq "Manual"}) { Write-Host "✅ $TrustedInstaller service is already set to manual" -ForegroundColor Green
}
  Else
     {
     if (Get-Service -DisplayName $TrustedInstaller | where {$_.StartType -cnotmatch "Manual"}) {Write-Host "❎ $TrustedInstaller service is currently not set to manual!" -ForegroundColor Yellow
     get-service -DisplayName $TrustedInstaller | Set-Service -StartupType Manual | Write-Host "🛠️ $TrustedInstaller service started..."} else {Write-Host "✅ $TrustedInstaller service is currently set to manual!" -ForegroundColor Yellow}
     }
     }

<#############################################################
# Function to Enable Flash Player for Windows Server 2016
# See for more info https://techzone.vmware.com/creating-optimized-windows-image-vmware-horizon-virtual-desktop#944285
#############################################################>

Function Enable-FlashPlayerServer2016 
{
Write-Host "⏳ Running Function... Enable Flash Player for Windows Server 2016" -ForegroundColor DarkYellow
$computerinfo = Get-ComputerInfo
$osversion = $computerinfo.OsName
Write-Host "🛠️ Checking OS version..." -ForegroundColor Green
if ($computerinfo | where {$_.OsName -eq "Windows Server 2016"}){Write-Host "Running Windows Server 2016...Enabling Flash Player" -ForegroundColor Green
dism /online /add-package /packagepath:"C:\Windows\servicing\Packages\Adobe-Flash-For-Windows-Package~31bf3856ad364e35~amd64~~10.0.14393.0.mum"
}else{ 
Write-Host "🚫 $osversion not supported...Skipping Enabling Flash Player" -ForegroundColor Red
}
}


<#############################################################
# Function to start component cleanup
# See for more info https://techzone.vmware.com/creating-optimized-windows-image-vmware-horizon-virtual-desktop#944285
#############################################################>

Function Start-ComponentCleanup
{
Write-Host "⏳ Running Function... Component Cleanup" -ForegroundColor DarkYellow
Write-Host "🛠️ Windows Module Installer service needed for CBS..." -ForegroundColor Yellow
Enable-WindowsModuleInstaller
Write-Host "🗑️ Starting Component Cleanup" -ForegroundColor Green
dism /online /cleanup-image /startcomponentcleanup /resetbase
Write-Host "🛠️ Starting CompactOS NOTE: This may take awhile..." -ForegroundColor Green
compact /compactos:always 
Write-Host "✅ Windows Modules Installer service no longer needed..." -ForegroundColor Yellow
Disable-WindowsModuleInstaller
}

<#############################################################
# Function to test run as admin
# Credit http://www.danielclasson.com/check-if-powershell-script-is-running-as-administrator/
#############################################################>

Function Test-RunAsAdmin 
{
    #Checks if the user is in the administrator group. Warns and stops if the user is not.
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "🚫 You are not running this as an administrator. Run it again in an elevated prompt." ; break
    }
    }


<############################################################
# Function to display menu for user options
############################################################>
function Show-Menu {
    Clear-Host
    Write-Host "================================================== 🚀vJonathan Golden Image Shutdown Script🚀 ==========================================="
    Write-Host "  📝 Created by vJonathan" -ForegroundColor Green
    Write-Host "  Disclaimer : Before executing this script, the Horizon environment needs to be at Version 2503 or later."  -ForegroundColor Yellow
    Write-Host "                                                                                                                                          "
    Write-Host "  																      "
    Write-Host "                                                                                                                                          " 
    Write-Host "  Please update the Import-CustomStartLayout function for your environment needs" -ForegroundColor Yellow
    Write-Host "  Please update the Import-OEMDefaultAppAssociations function for your environment needs" -ForegroundColor Yellow
    Write-Host "                                                                                                                                          " 
    Write-Host "  Omnissa Logon Monitor will be enabled when running shutdown script." -ForegroundColor Yellow
    Write-Host "  Please remove 'Enable-LogonMonitor' function if not needed" -ForegroundColor Yellow
    Write-Host "  Cleanup Manager will run during this shutdown script but will not cleanup any Windows Event logs"  -ForegroundColor Yellow
    Write-Host "                                                                                                                                          "
    Write-Host "  🐦 Follow @JonEsxCli on Twitter" -ForegroundColor Green
    Write-Host "  🖥️ Please visit vjonathan.com " -ForegroundColor Green         
    Write-Host "==========================================================================================================================================" 
    Write-Host "                                                                                                                                          " 
    Write-Host " Press '1' 🛠️ Run Shutdown script"
    Write-Host " Press '2' 🖌️ Run Shutdown script without Preferences"
    Write-Host " Press '3' 🔨 Run Shutdown Script with 🛡️Meltdown and 👻Speculative Disabled"
    Write-Host " Press '4' 💊 Re-Enable Windows Update Services"
    Write-Host " Press '5' 🌊 Disable Omnissa Logon Monitor"
    Write-Host " Press '6' 🗑️ Cleanup Omnissa Logon Logs"
    Write-Host " Press '7' 🔧 Enable Windows Module Installer"
    Write-Host " Press '8' 🧹 Run Cleanup Manager"
    Write-Host " Press '9' 🛑 To quit"
}


Show-Menu 
$selection = Read-Host "Please select the option (Default Selection: 'Run Shutdown Script')"
if (-not $selection) {
$selection = "1"}
Write-Host "You Selected: $selection"
switch ($selection) {
    "1" {
    Write-Host "Shutdown Script Selected" -ForegroundColor Green
    Test-RunAsAdmin
    Write-Host "---------Running Optimization---------" -ForegroundColor DarkYellow
    Enable-FlashPlayerServer2016
    Start-ComponentCleanup
    Start-NetOptimization
    Write-Host "---------Configuring Services---------" -ForegroundColor DarkYellow
    Disable-WindowsUpdate
    Disable-WindowsMedicUpdate
    Disable-WUTasks
    Disable-Shadowcopies
    Enable-LogonMonitor
    Cleanup-OmnissaLogonMonitorLogs
    Disable-WindowsModuleInstaller
    Write-Host "---------Running Preferences---------" -ForegroundColor DarkYellow
    Import-CustomStartLayout
    Import-OEMDefaultAppAssociations
    Write-Host "---------Running Cleanup and Preparing shutdown" -ForegroundColor DarkYellow
    Start-Cleanup
    Start-Shutdown
    return
    } 

    "2" {
    Write-Host "Shutdown Script without Preferences Selected" -ForegroundColor Green
    Test-RunAsAdmin
    Write-Host "---------Running Optimization---------" -ForegroundColor DarkYellow
    Enable-FlashPlayerServer2016
    Start-ComponentCleanup
    Start-NetOptimization
    Write-Host "---------Configuring Services---------" -ForegroundColor DarkYellow
    Disable-WindowsUpdate
    Disable-WindowsMedicUpdate
    Disable-WUTasks
    Disable-Shadowcopies
    Enable-LogonMonitor
    Cleanup-OmnissaLogonMonitorLogs
    Disable-WindowsModuleInstaller
    Write-Host "---------Running Cleanup and Preparing shutdown" -ForegroundColor DarkYellow
    Start-Cleanup
    Start-Shutdown
    return
    }
     "3" {
    Write-Host "Shutdown Script with Meltdown and Speculative Disabled" -ForegroundColor Green
    Test-RunAsAdmin
    Write-Host "---------Running Optimization---------" -ForegroundColor DarkYellow
    Enable-FlashPlayerServer2016
    Start-ComponentCleanup
    Start-NetOptimization
    Write-Host "---------Disabling Meltdown and Speculative---------" -ForegroundColor DarkYellow
    Disable-Meltdown
    Disable-Speculative
    Write-Host "---------Configuring Services---------" -ForegroundColor DarkYellow
    Disable-WindowsUpdate
    Disable-WindowsMedicUpdate
    Disable-WUTasks
    Disable-Shadowcopies
    Enable-LogonMonitor
    Cleanup-OmnissaLogonMonitorLogs
    Disable-WindowsModuleInstaller
    Write-Host "---------Running Preferences---------" -ForegroundColor DarkYellow
    Import-CustomStartLayout
    Import-OEMDefaultAppAssociations
    Write-Host "---------Running Cleanup and Preparing shutdown" -ForegroundColor DarkYellow
    Start-Cleanup
    Start-Shutdown
    return
    } 

    "4"{
    Write-Host "Re-Enable Windows Update Service Selected" -ForegroundColor Green
    Test-RunAsAdmin
    Write-Host "---------Re-enable Windows Update Services---------" -ForegroundColor DarkYellow
    Enable-WindowsUpdate
    Enable-WindowsMedicUpdate
    Enable-WindowsModuleInstaller
    return
    }

    "5" {
    Write-Host "Disable Omnissa Logon Monitor Selected" -ForegroundColor Green
    Test-RunAsAdmin
    Write-Host "---------Disable Omnissa Logon Monitor---------" -ForegroundColor DarkYellow
    Disable-LogonMonitor
    Cleanup-OmnissaLogonMonitorLogs
    return
    }

    "6" { 
    Write-Host "Cleanup Omnissa Logs Selected" -ForegroundColor Green
    Test-RunAsAdmin
    Write-Host "---------Cleanup Omnissa Logs---------" -ForegroundColor DarkYellow
    Cleanup-OmnissaLogonMonitorLogs
    return      
    }

    "7" { 
    Write-Host "Enable Windows Module Installer Selected" -ForegroundColor Green
    Test-RunAsAdmin
    Write-Host "---------Enable Windows Module Installer---------" -ForegroundColor DarkYellow
    Enable-WindowsModuleInstaller
    return
    }

    "8"{
    Write-Host "Run Cleanup Manager Selected" -ForegroundColor Green
    Test-RunAsAdmin
    Write-Host "---------Running Cleanup Manager---------" -ForegroundColor DarkYellow
    Start-Cleanup
    return
    }

    "9" {
    Write-Host "🛑 Exiting Script"  -ForegroundColor Green
    return
    }
    }
    Write-Host "⛔ Invalid Input...Please Re-Run Script" -ForegroundColor Yellow



    

