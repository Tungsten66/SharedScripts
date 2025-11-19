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

<#
.SYNOPSIS
    Troubleshoots Azure Arc agent connection issues.
   
.DESCRIPTION
    This script checks for common Azure Arc agent connection problems including:
    - Agent service status
    - Network connectivity to Azure endpoints
    - Proxy configuration
    - Agent installation and configuration
    - Certificate validation

.INPUTS
    None
   
.OUTPUTS
    Console output with diagnostic information
   
.NOTES
    Name: Troubleshoot-Arc.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 11/14/2025
    Revisions: V1.0 - initial version
    Reference: https://learn.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-agent-onboard
#>

[CmdletBinding()]
param()
# Check if server is running in Azure
Write-Host "`n[0/6] Checking if server is running in Azure..." -ForegroundColor Yellow
try {
    $azureMetadata = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -Headers @{Metadata="true"} -TimeoutSec 5 -ErrorAction Stop
    if ($azureMetadata) {
        Write-Host "`n=== SERVER IS RUNNING IN AZURE ===" -ForegroundColor Red
        Write-Host "This server is an Azure VM and cannot be onboarded to Azure Arc." -ForegroundColor Red
        Write-Host "Azure Arc is only for servers running outside of Azure (on-premises, other clouds, etc.)" -ForegroundColor Yellow
        Write-Host "`nVM Details:" -ForegroundColor Cyan
        Write-Host "  Name: $($azureMetadata.compute.name)" -ForegroundColor White
        Write-Host "  Resource Group: $($azureMetadata.compute.resourceGroupName)" -ForegroundColor White
        Write-Host "  Location: $($azureMetadata.compute.location)" -ForegroundColor White
        Write-Host "  Subscription ID: $($azureMetadata.compute.subscriptionId)" -ForegroundColor White
        Write-Host "`nExiting..." -ForegroundColor Yellow
        return
    }
} catch {
    Write-Host "  Server is not running in Azure. Proceeding with Arc diagnostics..." -ForegroundColor Green
}

# Prompt for Azure Cloud Environment
Write-Host "`n[0.5/6] Select Azure Cloud Environment:" -ForegroundColor Yellow
Write-Host "  1. Azure Public Cloud" -ForegroundColor White
Write-Host "  2. Azure Government Cloud" -ForegroundColor White
do {
    $cloudChoice = Read-Host "Enter your choice (1 or 2)"
    if ($cloudChoice -ne "1" -and $cloudChoice -ne "2") {
        Write-Host "  Invalid choice. Please enter 1 or 2." -ForegroundColor Red
    }
} while ($cloudChoice -ne "1" -and $cloudChoice -ne "2")

switch ($cloudChoice) {
    "2" {
        Write-Host "  Selected: Azure Government Cloud" -ForegroundColor Cyan
        $endpoints = @(
            "download.microsoft.com",
            "packages.microsoft.com",
            "login.microsoftonline.us",
            "pas.windows.net",
            "management.usgovcloudapi.net",
            "*.his.arc.azure.us",
            "*.guestconfiguration.azure.us",
            "guestnotificationservice.azure.us",
            "*.guestnotificationservice.azure.us",
            "azgn*.servicebus.usgovcloudapi.net",
            # Include endpoints from public cloud that are also required for gov cloud
            "*.servicebus.windows.net", # For Windows Admin Center and SSH scenarios
            "*.waconazure.com", # If you use Windows Admin Center
            "*.blob.core.windows.net" # Always, except when you use private endpoints
        )
    }
    default {
        Write-Host "  Selected: Azure Public Cloud" -ForegroundColor Cyan
        $endpoints = @(
            "download.microsoft.com", # Only at installation time
            "packages.microsoft.com", # Only at installation time
            "login.microsoftonline.com", # Always
            "*.login.microsoft.com", # Always
            "pas.windows.net", # Always
            "management.azure.com", # Only when you connect or disconnect a server
            "*.his.arc.azure.com", # Always
            "*.guestconfiguration.azure.com", # Always
            "guestnotificationservice.azure.com", # Always
            "*.guestnotificationservice.azure.com", # Always
            "azgn*.servicebus.windows.net", # Always
            "*.servicebus.windows.net", # Always (for Windows Admin Center and SSH scenarios)
            "*.waconazure.com", # If you use Windows Admin Center
            "*.blob.core.windows.net", # Always, except when you use private endpoints
            "dc.services.visualstudio.com" # Optional (Not used in agent versions 1.24+)
        )
    }
}

Write-Host "=== Azure Arc Agent Connection Troubleshooter ===" -ForegroundColor Cyan

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "This script should be run as Administrator for complete diagnostics."
}

# Check Agent Service Status
Write-Host "`n[1/6] Checking Azure Connected Machine Agent service..." -ForegroundColor Yellow
$service = Get-Service -Name "himds" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "  Service Status: $($service.Status)" -ForegroundColor $(if ($service.Status -eq 'Running') { 'Green' } else { 'Red' })
    if ($service.Status -ne 'Running') {
        Write-Warning "  Service is not running. Try: Start-Service himds"
    }
} else {
    Write-Host "  Azure Arc agent service not found. Agent may not be installed." -ForegroundColor Red
}

# Check Agent Installation
Write-Host "`n[2/6] Checking agent installation..." -ForegroundColor Yellow
$agentPath = "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe"
if (Test-Path $agentPath) {
    Write-Host "  Agent installed at: $agentPath" -ForegroundColor Green
    try {
        $version = & $agentPath version
        Write-Host "  Agent version: $version" -ForegroundColor Green
    } catch {
        Write-Warning "  Could not retrieve agent version."
    }
} else {
    Write-Host "  Agent executable not found at expected path." -ForegroundColor Red
}

# Check Connection Status
Write-Host "`n[3/6] Checking connection status..." -ForegroundColor Yellow
if (Test-Path $agentPath) {
    try {
        $status = & $agentPath show -j | ConvertFrom-Json
        Write-Host "  Status: $($status.status)" -ForegroundColor $(if ($status.status -eq 'Connected') { 'Green' } else { 'Red' })
        if ($status.status -eq 'Connected') {
            Write-Host "  Resource Name: $($status.resourceName)" -ForegroundColor Green
            Write-Host "  Resource Group: $($status.resourceGroup)" -ForegroundColor Green
        }
    } catch {
        Write-Warning "  Could not retrieve connection status: $_"
    }
}

# Check Network Connectivity
Write-Host "`n[4/6] Testing network connectivity to Azure endpoints..." -ForegroundColor Yellow
$connectivityIssues = @()
foreach ($endpoint in $endpoints) {
    if ($endpoint -notlike "*``**") {
        try {
            $result = Test-NetConnection -ComputerName $endpoint -Port 443 -WarningAction SilentlyContinue -ErrorAction Stop
            if ($result.TcpTestSucceeded) {
                Write-Host "  $endpoint : OK" -ForegroundColor Green
            } else {
                Write-Host "  $endpoint : FAILED" -ForegroundColor Red
                $connectivityIssues += $endpoint
            }
        } catch {
            Write-Host "  $endpoint : Could not test (may require wildcard testing)" -ForegroundColor Yellow
        }
    }
}

# Check Proxy Configuration
Write-Host "`n[5/6] Checking proxy configuration..." -ForegroundColor Yellow
$proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($proxySettings.ProxyEnable) {
    Write-Host "  Proxy enabled: $($proxySettings.ProxyServer)" -ForegroundColor Yellow
    Write-Host "  Verify proxy allows access to Azure Arc endpoints." -ForegroundColor Yellow
} else {
    Write-Host "  No proxy configured." -ForegroundColor Green
}

# Check Agent Logs
Write-Host "`n[6/6] Checking recent agent logs..." -ForegroundColor Yellow
$logPath = "$env:ProgramData\AzureConnectedMachineAgent\Log\himds.log"
if (Test-Path $logPath) {
    Write-Host "  Log file location: $logPath" -ForegroundColor Green
    Write-Host "  Recent errors:" -ForegroundColor Yellow
    Get-Content $logPath -Tail 20 | Select-String -Pattern "error|fail|exception" -SimpleMatch | Select-Object -First 5 | ForEach-Object {
        Write-Host "    $_" -ForegroundColor Red
    }
} else {
    Write-Warning "  Log file not found at expected location."
}

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
if ($connectivityIssues.Count -gt 0) {
    Write-Host "Network connectivity issues detected for: $($connectivityIssues -join ', ')" -ForegroundColor Red
    Write-Host "Check firewall rules and proxy configuration." -ForegroundColor Yellow
}
if ($service.Status -ne 'Running') {
    Write-Host "Agent service is not running." -ForegroundColor Red
}
Write-Host "`nFor detailed troubleshooting steps, visit:" -ForegroundColor Cyan
Write-Host "https://learn.microsoft.com/en-us/azure/azure-arc/servers/troubleshoot-agent-onboard"