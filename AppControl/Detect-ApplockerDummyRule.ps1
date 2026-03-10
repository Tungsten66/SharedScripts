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
    Detects an AppLocker "Dummy Rule" and clears AppLocker policies if found.

.DESCRIPTION
    Checks all AppLocker rule collections for a rule named "Dummy Rule".
    If detected, clears all local AppLocker policies and stops AppLocker services
    per Microsoft guidance:
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/delete-an-applocker-rule

.INPUTS
    None

.OUTPUTS
    None

.NOTES
    Name: Detect-ApplockerDummyRule.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 3-10-2026
    Revisions:1.0 - Initial script development
#>

[CmdletBinding()]
param()

Import-Module AppLocker -ErrorAction Stop

# Step 1: Detect "Dummy Rule" in AppLocker policy
Write-Host "Checking for AppLocker 'Dummy Rule'..." -ForegroundColor Cyan

$appLockerPolicy = Get-AppLockerPolicy -Effective
$dummyRules = $appLockerPolicy.RuleCollections |
    ForEach-Object { $_ } |
    Where-Object { $_.Name -eq 'Dummy Rule' }

if (-not $dummyRules) {
    Write-Host "No 'Dummy Rule' found in AppLocker policy. No action needed." -ForegroundColor Green
    return
}

Write-Host "Found 'Dummy Rule' in AppLocker policy:" -ForegroundColor Yellow
foreach ($rule in $dummyRules) {
    Write-Host "  Collection: $($rule.GetType().Name), Action: $($rule.Action), UserOrGroupSid: $($rule.UserOrGroupSid)" -ForegroundColor Yellow
}

# Step 2: Clear all local AppLocker policies using an empty policy XML
Write-Host "`nClearing all local AppLocker policies..." -ForegroundColor Cyan

$clearXmlPath = Join-Path $env:TEMP 'ClearAppLockerPolicy.xml'
try {
    Set-Content -Path $clearXmlPath -Value '<AppLockerPolicy Version="1" />' -Force
    Set-AppLockerPolicy -XmlPolicy $clearXmlPath
    Write-Host "AppLocker policies cleared successfully." -ForegroundColor Green
}
finally {
    Remove-Item -Path $clearXmlPath -Force -ErrorAction SilentlyContinue
}

# Step 3: Stop AppLocker services and set them to demand start
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

# Step 4: Clean up leftover AppLocker rule files
$appLockerDir = "$env:SystemRoot\System32\AppLocker"
if (Test-Path $appLockerDir) {
    $ruleFiles = Get-ChildItem -Path $appLockerDir -File -ErrorAction SilentlyContinue
    if ($ruleFiles) {
        Write-Host "`nRemoving leftover AppLocker rule files from $appLockerDir..." -ForegroundColor Cyan
        $ruleFiles | Remove-Item -Force -ErrorAction SilentlyContinue
        Write-Host "  Removed $($ruleFiles.Count) file(s)." -ForegroundColor Gray
    }
}

Write-Host "`nRemediation complete. 'Dummy Rule' AppLocker policy has been cleared." -ForegroundColor Green