﻿<#
.SYNOPSIS VDI  Master Image Shutdown Script
.NOTES  Author:  JonEsxcli twitter @jonesxcli
.NOTES  Site:    www.vjonathan.com
.VERSION BETA
.DATE 7-5-2019
#>


Function Start-NetOptimization #See https://techzone.vmware.com/creating-optimized-windows-image-vmware-horizon-virtual-desktop
{

$NGENPath = Join-Path -Path $env:SystemRoot -ChildPath "Microsoft.Net" 
$CurrentNGEN = Get-ChildItem -Path $ngenpath -Recurse | where {$_.Name -eq "ngen.exe"} | foreach {& "$($_.FullName)" "executequeueditems"}
$CurrentNGEN
}

Function Disable-WindowsUpdate
{
 $WU = "Windows Update"
 $SoftwareDistribution = 'C:\Windows\SoftwareDistribution'

     If (Get-Service -DisplayName $WU | where {$_.status -eq "Disabled"}) { Write-Host "$WU Service is already disabled" -ForegroundColor Green
}
  Else
     {
     if (Get-Service -DisplayName $WU | where {$_.status -eq "Running"}) {Write-Host "$WU is still running... Stopping serivce...." -ForegroundColor Yellow 
     Stop-Service -DisplayName $WU -Force} else { Write-Host "$WU Service is not running" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WU | where {$_.StartType -cnotmatch "Disabled"}) {Write-Host "$WU is currenlty not disabled!" -ForegroundColor Yellow
     Set-Service -DisplayName $WU -StartupType Disabled } else {Write-Host "$WU is currenlty disabled!" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WU | where {$_.Status -eq "Disabled"}) {Write-Host "$WU Serivce is now disabled!" -ForegroundColor Green}
     if (Test-Path $SoftwareDistribution | where {$_.Exists -eq 'True'}) {Write-Host "Deleting Software Distribution folder" -ForegroundColor Red 
     Remove-Item -Path $SoftwareDistribution -Recurse -Force} else {Write-Host "Software Distribution folder no longer exists" -ForegroundColor Green}
     }
     }

Function Disable-WindowsMedicUpdate
{
 $WUMedic = "Windows Update Medic Service"

 If (Get-Service -$WUMedic -ErrorAction SilentlyContinue){

     If (Get-Service -DisplayName $WUMedic | where {$_.status -eq "Disabled"}) { Write-Host "$WUMedic is already disabled" -ForegroundColor Green
}
  Else
     {
     if (Get-Service -DisplayName $WUMedic | where {$_.status -eq "Running"}) {Write-Host "$WUMedic is still running... Stopping serivce...." -ForegroundColor Yellow 
     Stop-Service -DisplayName $WUMedic -Force} else { Write-Host "$WUMedic is not running" -ForegroundColor Yellow}
     if (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc\ -Name Start | where {$_.start -eq "4"}){Write-Host "$WUMedic is currenlty set to disabled!" -ForegroundColor Yellow}
     else {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc\ -Name Start -Value 4 -Force {Write-Host "Setting $WUMedic service startup type disabled!" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WUMedic | where {$_.Status -eq "Disabled"}) {Write-Host "$WUMedic is now disabled!" -ForegroundColor Green}
     }

Else {Write-Host "$WUMedic not found..." -ForegroundColor Yellow
}
     }
     }
     }

Function Disable-WindowsModuleInstaller #See https://docs.vmware.com/en/VMware-App-Volumes/2.15/com.vmware.appvolumes.admin.doc/GUID-813F8AD2-4534-42FB-806D-BF327669FA54.html for more detail.
{
 $TrustedInsatller = "Windows Modules Installer"
  
     If (Get-Service -DisplayName $TrustedInsatller | where {$_.status -eq "Disabled"}) { Write-Host "$TrustedInsatller service is already disabled" -ForegroundColor Green
}
  Else
     {
      if (Get-Service -DisplayName $TrustedInsatller | where {$_.status -eq "Running"}) {Write-Host "$TrustedInsatller service is still running... Stopping serivce...." -ForegroundColor Yellow 
    Stop-Service -DisplayName $TrustedInsatller -Force} else { Write-Host "$TrustedInsatller Service is not running" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $TrustedInsatller | where {$_.StartType -cnotmatch "Disabled"}) {Write-Host "$TrustedInsatller Installer service is currenlty not disabled!" -ForegroundColor Yellow
     Set-Service -DisplayName $TrustedInsatller -StartupType Disabled} else {Write-Host "$TrustedInsatller service is currently disabled!" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $TrustedInsatller | where {$_.Status -eq "Disabled"}) {Write-Host "$TrustedInsatller service is now disabled!" -ForegroundColor Green}
     }
     }


Function Disable-WUTasks #See https://twitter.com/edbaker1965/status/976138729541816320 
{$Trigger= New-ScheduledTaskTrigger -AtStartup 
$User= "NT AUTHORITY\SYSTEM" 
$Action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "Get-ScheduledTask -TaskPath \Microsoft\Windows\WindowsUpdate\ | Disable-ScheduledTask" 
Register-ScheduledTask -TaskName "SIH" -Trigger $Trigger -User $User -Action $Action -RunLevel Highest -Force -Verbose}

Function Disable-WindowsModuleInstaller #See https://docs.vmware.com/en/VMware-App-Volumes/2.15/com.vmware.appvolumes.admin.doc/GUID-813F8AD2-4534-42FB-806D-BF327669FA54.html for more detail.
{
 $TrustedInsatller = "Windows Modules Installer"
  
     If (Get-Service -DisplayName $TrustedInsatller | where {$_.status -eq "Disabled"}) { Write-Host "Windows Module Installer service is already disabled" -ForegroundColor Green
}
  Else
     {
      if (Get-Service -DisplayName $TrustedInsatller | where {$_.status -eq "Running"}) {Write-Host "Windows Module Installer service is still running... Stopping serivce...." -ForegroundColor Yellow 
    Stop-Service -DisplayName $TrustedInsatller -Force} else { Write-Host "Windows Module Installer Service is not running" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $TrustedInsatller | where {$_.StartType -cnotmatch "Disabled"}) {Write-Host "Windows Module Installer service is currenlty not disabled!" -ForegroundColor Yellow
     Set-Service -DisplayName $TrustedInsatller -StartupType Disabled} else {Write-Host "Windows Module Installer service is currently disabled!" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $TrustedInsatller | where {$_.Status -eq "Disabled"}) {Write-Host "Windows Module Installer is now disabled!" -ForegroundColor Green}
     if (Test-Path $SoftwareDistribution | where {$_.Exists -eq 'True'}) {Write-Host "Deleting Software Distribution folder" -ForegroundColor Red}
     }
     }

Function Enable-LogonMonitor #See https://docs.vmware.com/en/VMware-Horizon-7/7.9/horizon-administration/GUID-618B1899-AF59-4991-83F3-FFFDFF917F22.html
{
 $LogonMonitor = "VMware Horizon View Logon Monitor"
 $LogonMonitorPath = "C:\ProgramData\VMware\VMware Logon Monitor\Logs"
  
     If (Get-Service -DisplayName $LogonMonitor | where {$_.StartType -eq "Automatic"}) { Write-Host "$LogonMonitor is already set to Automatic" -ForegroundColor Green
}
  Else
     {
    if (Get-Service -DisplayName $LogonMonitor | where {$_.status -eq "Running"}) {Write-Host "$LogonMonitor is currenlty running"  -ForegroundColor Yellow } 
    else {Write-Host "$LogonMonitor is not running...starting service..." -ForegroundColor Yellow 
    Start-Service -DisplayName $LogonMonitor}
    if (Get-Service -DisplayName $LogonMonitor | where {$_.StartType -cnotmatch "Automatic"}) {Write-Host "$LogonMonitor service is not configured for automatic .. configuring startup type to automatic" -ForegroundColor Red
    Set-Service -DisplayName $LogonMonitor -StartupType Automatic } else {Write-Host "$LogonMonitor service is currently set to automatic" -ForegroundColor Yellow}
    if (Test-Path $LogonMonitorPath | where {$_.Exists -eq 'True'}) {Write-Host "Cleaning up VMware Logon Monitor Logs" -ForegroundColor Red} {Get-ChildItem -Path $LogonMonitor -Recurse | Remove-Item -Recurse -Force -Confirm:$false}
    else {Write-Host "$LogonMonitor doesn't exist" -ForegroundColor Red}
    }
    }

Function Disable-Speculative #See https://communities.vmware.com/thread/590287 
{
 $MMUPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
 $MitigationName = 'FeatureSettingsOverride'

  If (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue | where {$_.FeatureSettingsOverride -eq '3'}) { Write-Host "Mitigations for CVE-2017-5715 (Spectre Variant 2) is already disabled" -ForegroundColor Green
}
  Else
     {
     Write-Host "Disabling Mitigations for CVE-2017-5715 (Spectre Variant 2)" -ForegroundColor Yellow
     If (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue) {Write-Host "FeatureSettingsOverride Exists! Setting Value to '3'" -ForegroundColor Green
     Set-ItemProperty -Path $MMUPath -Name $MitigationName -Value 3 -Force -ErrorAction SilentlyContinue
     } 
     Else { Write-host "Creating FeatureSettingsOverride" -ForegroundColor Yellow
     New-ItemProperty -Path $MMUPath -Name $MitigationName -PropertyType DWORD -Value 3 -Force
     IF (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue | where {$_.FeatureSettingsOverride -eq '3'}) {Write-Host "Mitigations for CVE-2017-5715 (Spectre Variant 2) is now disabled!" -ForegroundColor Green}
     }
     }
     }
 
Function Disable-Meltdown #See https://communities.vmware.com/thread/590287
{
 $MMUPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
 $MitigationName = 'FeatureSettingsOverrideMask'

  If (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue | where {$_.FeatureSettingsOverrideMask -eq '3'}) { Write-Host "Mitigations for CVE-2017-5754 (Meltdown) is already disabled" -ForegroundColor Green
}
  Else
     {
     Write-Host "Disabling Mitigations for CVE-2017-5715 (Spectre Variant 2)" -ForegroundColor Yellow
     If (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue) {Write-Host "FeatureSettingsOverrideMask Exists! Setting Value to '3'" -ForegroundColor Green
     Set-ItemProperty -Path $MMUPath -Name $MitigationName -Value 3 -Force -ErrorAction SilentlyContinue
     } 
     Else { Write-host "Creating FeatureSettingsOverride" -ForegroundColor Yellow
     New-ItemProperty -Path $MMUPath -Name $MitigationName -PropertyType DWORD -Value 3 -Force
     IF (Get-ItemProperty -Path $MMUPath -Name $MitigationName -ErrorAction SilentlyContinue | where {$_.FeatureSettingsOverrideMask -eq '3'}) {Write-Host "Mitigations for CVE-2017-5754 (Meltdown) is now disabled!" -ForegroundColor Green}
     }
     }
     }

Function Disable-ShadowCopies
{
 $VSS = "VSS"
 $vssadmin = 'C:\Windows\System32\vssadmin.exe'
 $arguements = "Delete Shadows /all /quiet"

     If (Get-Service -Name $VSS | where {$_.status -eq "Disabled"}) { Write-Host "Volume Shadow Copy service is already disabled" -ForegroundColor Green
}
  Else
     {
     Write-Host "Volume Shadow Copy is still enabled" -ForegroundColor Yellow
     Start-Process $vssadmin $arguements -Wait
     Write-Host "Clearing Shadow Copies..." -ForegroundColor Yellow
     Set-Service -Name $vss -StartupType Disabled
    if (Get-Service -Name $VSS | where {$_.Status -eq "Running"}) {Write-Host "Volume Shadow Copy service is currently running." -ForegroundColor Yellow} else {Stop-Service -Name $VSS -Force}
    if (Get-Service -Name $VSS | where {$_.Status -eq "Disabled"}) {Write-Host "Volume Shadow Copy Serivce is now disabled!" -ForegroundColor Green}
      }
      }

Function Import-OEMDefaultAppAssociations #Modify $OEMDefaultAssociations for your to your enviroment needs
{
 $OEMDefaultAssociationsDefaultPath = "$env:SystemRoot\System32\OEMDefaultAssociations.xml"
 $DISM = "dism.exe"
 $OEMDefaultAssociations = @"
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
  <Association Identifier=".3g2" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.3G2" />
  <Association Identifier=".3gp" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.3GP" />
  <Association Identifier=".3gp2" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgI
dIs="WMP11.AssocFile.3G2" />
  <Association Identifier=".3gpp" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgI
dIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.3GP" />
  <Association Identifier=".3mf" ProgId="AppXr0rz9yckydawgnrx5df1t9s57ne60yhn" ApplicationName="Print 3D" ApplyOnUpgrade="true" OverwriteIfProgIdIs="App
Xvhc4p7vz4b485xfp46hhk3fq3grkdgjg;AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp;AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k"  />
  <Association Identifier=".aac" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".ac3" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".adt" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".adts" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".amr" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".arw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".avi" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.AVI" />
  <Association Identifier=".bmp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;Paint.Picture" />
  <Association Identifier=".cr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".crw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".dib" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;Paint.Picture" />
  <Association Identifier=".ec3" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".epub" ProgId="AppXvepbp3z66accmsd0x877zbbxjctkpr6t" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" />
  <Association Identifier=".erf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".fbx" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="Mixed Reality Viewer" ApplyOnUpgrade="true" />
  <Association Identifier=".flac" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".gif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;giffile" />
  <Association Identifier=".glb" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="Mixed Reality Viewer" ApplyOnUpgrade="true" />
  <Association Identifier=".gltf" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="Mixed Reality Viewer" ApplyOnUpgrade="true" />
  <Association Identifier=".htm" ProgId="AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgIdI
s="AppX6k1pws1pa7jjhchyzw9jce3e6hg6vn8d" />
  <Association Identifier=".html" ProgId="htmlfile" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgId
Is="AppX6k1pws1pa7jjhchyzw9jce3e6hg6vn8d" />
  <Association Identifier=".jfif" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX
9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;pjpegfile" />
  <Association Identifier=".jpe" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;jpegfile" />
  <Association Identifier=".jpeg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX
9vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;jpegfile" />
  <Association Identifier=".jpg" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;jpegfile" />
  <Association Identifier=".jxr" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;wdpfile" />
  <Association Identifier=".kdc" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".m2t" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="WMP11.AssocFile.M2TS" />
  <Association Identifier=".m2ts" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgI
dIs="WMP11.AssocFile.M2TS" />
  <Association Identifier=".m3u" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".m4a" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".m4r" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".m4v" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.MP4"/>
  <Association Identifier=".mka" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".mkv" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true"  OverwriteIfProgI
dIs="WMP11.AssocFile.MKV"/>
  <Association Identifier=".mod" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="WMP11.AssocFile.MPEG" />
  <Association Identifier=".mov" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.MOV" />
  <Association Identifier=".mrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".MP2" ProgId="WMP11.AssocFile.MP3" ApplicationName="Windows Media Player" />
  <Association Identifier=".mp3" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".mp4" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.MP4" />
  <Association Identifier=".mp4v" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgI
dIs="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.MP4" />
  <Association Identifier=".mpa" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".MPE" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="WMP11.AssocFile.MPEG" />
  <Association Identifier=".mpeg" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgI
dIs="WMP11.AssocFile.MPEG" />
  <Association Identifier=".mpg" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="WMP11.AssocFile.MPEG" />
  <Association Identifier=".mpv2" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgI
dIs="WMP11.AssocFile.MPEG" />
  <Association Identifier=".mts" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="WMP11.AssocFile.M2TS" />
  <Association Identifier=".nef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".nrw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".obj" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="Mixed Reality Viewer" ApplyOnUpgrade="true" />
  <Association Identifier=".oga" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".ogg" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".ogm" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />
  <Association Identifier=".ogv" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />
  <Association Identifier=".ogx" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />
  <Association Identifier=".opus" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".orf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".oxps" ProgId="Windows.XPSReachViewer" ApplicationName="XPS Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX86746z2101
ayy2ygv3g96e4eqdf8r99j" />
  <Association Identifier=".pdf" ProgId="AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgIdI
s="AppXk660crfh0gw7gd9swc1nws708mn7qjr1;AppX86746z2101ayy2ygv3g96e4eqdf8r99j" />
  <Association Identifier=".pef" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".ply" ProgId="AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k" ApplicationName="Mixed Reality Viewer" ApplyOnUpgrade="true" />
  <Association Identifier=".png" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype;pngfile" />
  <Association Identifier=".raf" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".raw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".rw2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".rwl" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".tif" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="A
ppX86746z2101ayy2ygv3g96e4eqdf8r99j;AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;TIFImage.Document" />
  <Association Identifier=".tiff" ProgId="PhotoViewer.FileAssoc.Tiff" ApplicationName="Windows Photo Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="
AppX86746z2101ayy2ygv3g96e4eqdf8r99j;AppX9vdwcvrwnbettpahnt26jswq0n8hgyah;TIFImage.Document" />
  <Association Identifier=".tod" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />
  <Association Identifier=".sr2" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".srw" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".stl" ProgId="AppXr0rz9yckydawgnrx5df1t9s57ne60yhn" ApplicationName="Print 3D" ApplyOnUpgrade="true" OverwriteIfProgIdIs="App
Xvhc4p7vz4b485xfp46hhk3fq3grkdgjg;AppX4r6v2fg5b2qwg1jprp713smfp4wb02yp;AppXmgw6pxxs62rbgfp9petmdyb4fx7rnd4k"  />
  <Association Identifier=".TS" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdI
s="WMP11.AssocFile.TTS" />
  <Association Identifier=".TTS" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="WMP11.AssocFile.TTS" />
  <Association Identifier=".txt" ProgId="txtfile" ApplicationName="Notepad" />
  <Association Identifier=".url" ProgId="IE.AssocFile.URL" ApplicationName="Internet Explorer" />
  <Association Identifier=".wav" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".wdp" ProgId="AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" ApplicationName="Photos" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX9
vdwcvrwnbettpahnt26jswq0n8hgyah;Paint.Paint;Microsoft.PhotoManager.imagetype" />
  <Association Identifier=".webm" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />
  <Association Identifier=".website" ProgId="IE.AssocFile.WEBSITE" ApplicationName="Internet Explorer" />
  <Association Identifier=".wm" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgIdI
s="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.ASF" />
  <Association Identifier=".wma" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".wmv" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" OverwriteIfProgId
Is="AppXhjhjmgrfm2d7rd026az898dy2p1pcsyt;WMP11.AssocFile.WMV" />
  <Association Identifier=".WPL" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier=".wsb" ProgId="Windows.Sandbox" ApplicationName="Windows Sandbox" />
  <Association Identifier=".xps" ProgId="Windows.XPSReachViewer" ApplicationName="XPS Viewer" ApplyOnUpgrade="true" OverwriteIfProgIdIs="AppX86746z2101a
yy2ygv3g96e4eqdf8r99j" />
  <Association Identifier=".xvid" ProgId="AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />
  <Association Identifier=".zpl" ProgId="AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier="bingmaps" ProgId="AppXp9gkwccvk6fa6yyfq3tmsk8ws2nprk1p" ApplicationName="Maps" ApplyOnUpgrade="true" OverwriteIfProgIdIs="App
Xde453qzh223ys1wt2jpyxz3z4cn10ngt;AppXsmrmb683pb8qxt0pktr3q27hkbyjm8sb" />
  <Association Identifier="http" ProgId="AppXq0fevzme2pys62n3e0fbqa7peapykr8v" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgIdI
s="AppXehk712w0hx4w5b8k25kg808a9h84jamg" />
  <Association Identifier="https" ProgId="AppX90nv6nhay5n6a98fnetv7tpk64pp35es" ApplicationName="Microsoft Edge" ApplyOnUpgrade="true" OverwriteIfProgId
Is="AppXz8ws88f5y0y5nyrw1b3pj7xtm779tj2t" />
  <Association Identifier="mailto" ProgId="AppXydk58wgm44se4b399557yyyj1w7mbmvd" ApplicationName="Mail" ApplyOnUpgrade="true" />
  <Association Identifier="mswindowsmusic" ProgId="AppXtggqqtcfspt6ks3fjzyfppwc05yxwtwy" ApplicationName="Music" ApplyOnUpgrade="true" />
  <Association Identifier="mswindowsvideo" ProgId="AppX6w6n4f8xch1s3vzwf3af6bfe88qhxbza" ApplicationName="Movies &amp; TV" ApplyOnUpgrade="true" />
</DefaultAssociations>
"@

if (Get-ChildItem -Path $OEMDefaultAssociationsCustomPath | where {$_.Exists -eq "true"}) {Remove-Item -Path $OEMDefaultAssociationsDefaultPath -Force -WhatIf}
New-Item -Path $PSScriptRoot -Name TEMPDEFAULTASSOCIATIONS.XML -ItemType File -Value $OEMDefaultAssociations -Force
DISM /online /import-defaultappassociations:"$PSScriptRoot\TEMPDEFAULTASSOCIATIONS.XML"
if (Get-ChildItem -Path $PSScriptRoot\TEMPDEFAULTASSOCIATIONS.XML | where {$_.Exists -eq "true"}) {Remove-Item -Path C:\temp\TEMPDEFAULTASSOCIATIONS.XML -Force -Verbose}
}

Function Import-CustomStartLayout #Modify $TempStartLayout for your to your enviroment needs
{
$LayoutPath = "$PSScriptRoot\TempStartLayout.xml"
$TempStartLayout = @"
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate
    xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification"
    xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
    xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout"
    xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout"
    Version="1">
  <LayoutOptions StartTileGroupCellWidth="6" StartTileGroupsColumnCount="1" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth="6" xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout">
        <start:Group Name="Life at a glance" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout">
          <start:Tile Size="2x2" Column="0" Row="0" AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />
          <start:Tile Size="2x2" Column="4" Row="0" AppUserModelID="Microsoft.Windows.Cortana_cw5n1h2txyewy!CortanaUI" />
          <start:Tile Size="2x2" Column="2" Row="0" AppUserModelID="Microsoft.BingWeather_8wekyb3d8bbwe!App" />
        </start:Group>        
      </defaultlayout:StartLayout>
    </StartLayoutCollection>
  </DefaultLayoutOverride>
    <CustomTaskbarLayoutCollection>
      <defaultlayout:TaskbarLayout>
        <taskbar:TaskbarPinList>
          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />
	  <taskbar:DesktopApp DesktopApplicationLinkPath="%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk" />
        </taskbar:TaskbarPinList>
      </defaultlayout:TaskbarLayout>
    </CustomTaskbarLayoutCollection>
</LayoutModificationTemplate>
"@
$SourceFile = "$env:SystemDrive\Program Files\Internet Explorer\iexplore.exe"
$ShortCutFile = "$env:SystemDrive\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Internet Explorer.lnk"
$WScript = New-Object -ComObject WScript.Shell
$ShortCut = $WScript.CreateShortcut($ShortCutFile)
$ShortCut.TargetPath = $SourceFile
$shortcut.Save()

 New-Item -Path $PSScriptRoot -Name TempStartLayout.XML -ItemType File -Value $TempStartLayout -Force
 if (Get-ChildItem -Path $LayoutPath | where {$_.Exists -eq "true"}) {Import-StartLayout -LayoutPath $LayoutPath -MountPath $env:SystemDrive\} else {Write-Host "Skipping Startlayout... custom startayout.xml doesn't exist." -ForegroundColor Red}
 if (Get-ChildItem -Path $LayoutPath| where {$_.Exists -eq "true"}) {Remove-Item -Path $LayoutPath -Force}
 }

Function Start-Cleanup
{

 $Cleanmgr = "C:\windows\System32\cleanmgr.exe"
 $arguements = "/autoclean"
 $Process = "Start-Process $Cleanmgr $arguements -wait"

 $Process
 (Get-WmiObject win32_shadowcopy).delete()
 }

Function Start-Shutdown
{
 Write-Host "Releasing IP and Flushing DNS" -ForegroundColor Yellow
 Start-Process ipconfig -ArgumentList /release -wait
 Start-Process ipconfig -ArgumentList /flusdns -wait
 Write-Host "Comfirming Shutdown..." -ForegroundColor Red
 Stop-Computer -Confirm
 }


Function Enable-WindowsUpdate
{
 $WU = "Windows Update"
 $SoftwareDistribution = 'C:\Windows\SoftwareDistribution'

     If (Get-Service -DisplayName $WU | where {$_.status -eq "Automatic" -and "Running"}) { Write-Host "$WU is running and set to automatic start Type" -ForegroundColor Green
}
  Else
     {
     if (Test-Path $SoftwareDistribution | where {$_.Exists -eq 'True'}) {Write-Host "Deleting Software Distribution folder" -ForegroundColor Red 
     Remove-Item -Path $SoftwareDistribution -Recurse -Force} else {Write-Host "Software Distribution folder no longer exists" -ForegroundColor Green}
     if (Get-Service -DisplayName $WU | where {$_.StartType -cnotmatch "Automatic"}) {Write-Host "$WU is currenlty not disabled!" -ForegroundColor Yellow
     Set-Service -DisplayName $WU -StartupType Disabled } else {Write-Host "$WU is currenlty disabled!" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WU | where {$_.status -cnotmatch "running"}) {Write-Host "$WU is not running......." -ForegroundColor Yellow 
     Start-Service -DisplayName $WU -StartupType Automatic -Force} else { Write-Host "$WU Service start type is set to Automatic" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WU | where {$_.StartType -cnotmatch "Disabled"}) {Write-Host "$WU is currenlty not disabled!" -ForegroundColor Yellow}
     }
     }

Function Enable-WindowsMedicUpdate
{
 $WUMedic = "Windows Update Medic Service"

 If (Get-Service -$WUMedic -ErrorAction SilentlyContinue){

     If (Get-Service -DisplayName $WUMedic | where {$_.status -eq "running" -and "Automatic"}) { Write-Host "$WUMedic service is already running and set to Automatic" -ForegroundColor Green
}
  Else
     {
     if (Get-Service -DisplayName $WU | where {$_.StartType -cnotmatch "Automatic"}) {Write-Host "$WUMedic is currenlty not to Automatic!" -ForegroundColor Yellow
     if (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc\ -Name Start | where {$_.start -eq "3"}){Write-Host "$WUMedic is currenlty set to Automatic!" -ForegroundColor Yellow}
     else {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc\ -Name Start -Value 3 -Force {Write-Host "Setting $WUMedic service startup type Automatic!" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WUMedic | where {$_.status -cnotmatch "Running"}) {Write-Host "$WUMedic Service is running...." -ForegroundColor Yellow 
     Start-Service -DisplayName $WUMedic -Force} else { Write-Host "$WUMedic Service is running" -ForegroundColor Yellow}
     if (Get-Service -DisplayName $WUMedic | where {$_.Status -eq "Automatic"}) {Write-Host "$WUMedic Serivce is now running!" -ForegroundColor Green}
     }
     }

Else {Write-Host "$WUMedic not found..." -ForegroundColor Yellow
}
     }
     }
     }
   

Function Enable-WindowsModuleInstaller # See https://docs.vmware.com/en/VMware-App-Volumes/2.15/com.vmware.appvolumes.admin.doc/GUID-813F8AD2-4534-42FB-806D-BF327669FA54.html for more detail.
{
 $TrustedInsatller = "Windows Modules Installer"
  
     If (Get-Service -DisplayName $TrustedInsatller | where {$_.status -eq "Manual"}) { Write-Host "$TrustedInsatller service is already set to Manual" -ForegroundColor Green
}
  Else
     {
     if (Get-Service -DisplayName $TrustedInsatller | where {$_.StartType -cnotmatch "Manual"}) {Write-Host "$TrustedInsatller service is currenlty not set to manual!" -ForegroundColor Yellow
     Set-Service -DisplayName $TrustedInsatller -StartupType Manual} else {Write-Host "$TrustedInsatller service is currently set to manual!" -ForegroundColor Yellow}
     }
     }

Function Remove-CustomTask  #See https://twitter.com/edbaker1965/status/976138729541816320 
{Get-ScheduledTask -TaskName SIH | Unregister-ScheduledTask -Confirm:$false
}

Function Enable-FlashPlayerServer2016 #See https://techzone.vmware.com/creating-optimized-windows-image-vmware-horizon-virtual-desktop#944285
{
$releaseid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name Releaseid).ReleaseId
$osversion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName

if ($osversion | where {$_.ProductName -eq "Windows Server 2016"}){Write-Host "Running Windows Server 2016...Enabling Flash Player" -ForegroundColor Green
dism /online /add-package /packagepath:"C:\Windows\servicing\Packages\Adobe-Flash-For-Windows-Package~31bf3856ad364e35~amd64~~10.0.14393.0.mum"
}else{Write-Host "Not Windows Server 2016..." -ForegroundColor Yellow}
}


Function Start-ComponentCleanup #See https://techzone.vmware.com/creating-optimized-windows-image-vmware-horizon-virtual-desktop#944285
{
$releaseid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name Releaseid).ReleaseId
$osversion = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName


if ($osversion | where {$_.ProductName -clike "Windows 10" -or "Windows Server 2016"}){Write-Host "Running Windows Server 2016 Or Windows 10...... Starting component cleanup and compactOS" -ForegroundColor Green
dism /online /cleanup-image /startcomponentcleanup /resetbase
compact /compactos:always
}else{
Write-Host "Not Windows 10 or Windows Server 2016.." -ForegroundColor Red}
}



$Title = "@JonEsxcli VDI Cleanup Script"
$Info = "Welcome to @JonEsxcli VDI Cleanup Script"
 $options = [System.Management.Automation.Host.ChoiceDescription[]] @("Shutdown Script", "Shutdown Script(Disable Spectre/Meltdown) Troubleshooting Only!", "Clone Master Image", "App Volume Provisoning Machine(COMING SOON)", "UEM Profiler Machine(COMING SOON)")
[int]$defaultchoice = 0
$opt = $host.UI.PromptForChoice($Title , $Info , $Options, $defaultchoice)
switch($opt)
{
0 { Write-Host "Shutdown Script Selected" -ForegroundColor Green
Enable-FlashPlayerServer2016
Start-ComponentCleanup
Start-NetOptimization
Disable-WindowsUpdate
Disable-WindowsMedicUpdate
Disable-WUTasks
Disable-WindowsModuleInstaller
Enable-LogonMonitor
Disable-ShadowCopies
Import-OEMDefaultAppAssociations
Import-CustomStartLayout
Start-Cleanup
Start-Shutdown
}
1 { Write-Host "Shutdown Script(Disable Spectre/Meltdown) Troubleshooting Only! Seleted!" -ForegroundColor Green
Enable-FlashPlayerServer2016
Start-ComponentCleanup
Start-NetOptimization
Disable-WindowsUpdate
Disable-WindowsMedicUpdate
Disable-WUTasks
Disable-WindowsModuleInstaller
Enable-LogonMonitor
Disable-Meltdown
Disable-Speculative
Disable-ShadowCopies
Import-OEMDefaultAppAssociations
Import-CustomStartLayout
Start-Cleanup
Start-Shutdown
}
2 {Write-Host "Clone Master Image Selected" -ForegroundColor Green
Start-ComponentCleanup
Start-NetOptimization
Enable-WindowsUpdate
Enable-WindowsMedicUpdate
Remove-CustomTask
Enable-WindowsModuleInstaller
Import-OEMDefaultAppAssociations
Import-CustomStartLayout
Start-Cleanup
Start-Shutdown
}

3 {Write-Host "App Volume Provisoning Machine(COMING SOON) Selected" -ForegroundColor Green
Write-Host "Work in progress...." -ForegroundColor Yellow
}
4 {Write-Host "UEM Profiler Machine(COMING SOON) Selected" -ForegroundColor Green 
Write-Host "Work in progres...." -ForegroundColor Yellow
}


}
