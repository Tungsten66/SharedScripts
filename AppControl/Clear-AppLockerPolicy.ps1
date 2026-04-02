<##############################################################################
LEGAL DISCLAIMER
This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys' fees, that arise or result
from the use or distribution of the Sample Code.
 
This posting is provided "AS IS" with no warranties, and confers no rights. Use
of included script samples are subject to the terms specified
at https://www.microsoft.com/en-us/legal/copyright.

##############################################################################>

#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Clears all local AppLocker policies and disables AppLocker services.

.DESCRIPTION
    Use this script to fully remove AppLocker from a device when it is no longer
    needed. It clears all local AppLocker policies by applying an empty policy,
    stops the AppLocker services, sets them to demand start, and removes any
    leftover AppLocker rule files.
    Note: This script only clears locally-applied AppLocker policies. GPO-enforced
    policies must be removed through Group Policy.
    Reference:
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/delete-an-applocker-rule

.INPUTS
    None

.OUTPUTS
    None

.NOTES
    Name: Clear-AppLockerPolicy.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 4-1-2026
    Revisions: 1.0 - Initial script development
#>

[CmdletBinding()]
param()

Import-Module AppLocker -ErrorAction Stop

# Step 1: Clear all local AppLocker policies using an empty policy XML
Write-Host "Clearing all local AppLocker policies..." -ForegroundColor Cyan

$clearXmlPath = Join-Path $env:TEMP 'ClearAppLockerPolicy.xml'
try {
    Set-Content -Path $clearXmlPath -Value '<AppLockerPolicy Version="1" />' -Force
    Set-AppLockerPolicy -XmlPolicy $clearXmlPath
    Write-Host "AppLocker policies cleared successfully." -ForegroundColor Green
}
finally {
    Remove-Item -Path $clearXmlPath -Force -ErrorAction SilentlyContinue
}

# Step 2: Stop AppLocker services and set them to demand start
Write-Host "`nStopping AppLocker services..." -ForegroundColor Cyan

& appidtel.exe stop -mionly 2>$null

$services = @(
    @{ Name = 'applockerfltr'; DisplayName = 'AppLocker Filter' }
    @{ Name = 'appidsvc';      DisplayName = 'Application Identity Service' }
    @{ Name = 'appid';         DisplayName = 'Application Identity Driver' }
)

foreach ($svc in $services) {
    & sc.exe config $svc.Name start=demand 2>$null | Out-Null
    & sc.exe stop $svc.Name 2>$null | Out-Null
    Write-Host "  $($svc.DisplayName) ($($svc.Name)) - stopped and set to demand start" -ForegroundColor Gray
}

# Step 3: Clean up leftover AppLocker rule files
$appLockerDir = "$env:SystemRoot\System32\AppLocker"
if (Test-Path $appLockerDir) {
    $ruleFiles = Get-ChildItem -Path $appLockerDir -File -ErrorAction SilentlyContinue
    if ($ruleFiles) {
        Write-Host "`nRemoving leftover AppLocker rule files from $appLockerDir..." -ForegroundColor Cyan
        $ruleFiles | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed $($ruleFiles.Count) file(s)." -ForegroundColor Gray
    }
}

Write-Host "`nComplete. All local AppLocker policies have been cleared." -ForegroundColor Green
