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
against any claims or lawsuits, including attorneys’ fees, that arise or result
from the use or distribution of the Sample Code.
 
This posting is provided "AS IS" with no warranties, and confers no rights. Use
of included script samples are subject to the terms specified
at https://www.microsoft.com/en-us/legal/copyright.

##############################################################################>

<#
.SYNOPSIS
   Checks Windows Defender prerequisites on a server.
.DESCRIPTION
   This script checks if Windows Defender is installed, if the "DisableAntiSpyware" policy is present,
   and if the server is running as an Azure VM.
.INPUTS
    Server name (or 'localhost' for local execution)
.OUTPUTS
    A PSCustomObject containing the results of the checks
.NOTES
    Name: Check-DefenderPrereqs.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 9/29/2025
    Revisions: 1.0 - Initial version
#>

# Function to detect if the server is running in Azure (used for local check only)
function Test-IsAzureVM {
    try {
        $metadataUrl = 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
        $headers = @{Metadata = 'true'}
        $null = Invoke-RestMethod -Method GET -Uri $metadataUrl -Headers $headers -TimeoutSec 2 -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# Prompt for server name
$ServerName = Read-Host "Enter server name (use 'localhost' for local)"

# Determine if local or remote
$isLocal = $ServerName -eq "localhost" -or $ServerName -eq "." -or $ServerName -eq $env:COMPUTERNAME

# Define script block for remote execution
$scriptBlock = {
    $result = @{}
    $result.DefenderInstalled = (Get-WindowsFeature -Name Windows-Defender).Installed

    $regPath = "HKLM:\Software\Policies\Microsoft\Windows Defender"
    if (Test-Path $regPath) {
        $regValue = Get-ItemProperty -Path $regPath -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
        $result.DisableAntiSpywarePresent = $regValue.DisableAntiSpyware -ne $null
    } else {
        $result.DisableAntiSpywarePresent = $false
    }

    # Inline Azure detection logic
    try {
        $metadataUrl = 'http://169.254.169.254/metadata/instance?api-version=2021-02-01'
        $headers = @{Metadata = 'true'}
        $null = Invoke-RestMethod -Method GET -Uri $metadataUrl -Headers $headers -TimeoutSec 2 -ErrorAction Stop
        $result.IsAzureVM = $true
    } catch {
        $result.IsAzureVM = $false
    }

    return $result
}

# Execute locally or remotely
if ($isLocal) {
    Write-Host "Running local check..." -ForegroundColor Cyan
    $result = @{
        DefenderInstalled = (Get-WindowsFeature -Name Windows-Defender).Installed
        DisableAntiSpywarePresent = $null -ne (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue).DisableAntiSpyware
        IsAzureVM = Test-IsAzureVM
    }
} else {
    Write-Host "Running remote check on $ServerName..." -ForegroundColor Cyan
    $result = Invoke-Command -ComputerName $ServerName -ScriptBlock $scriptBlock
}

# Output results
Write-Host "`n╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        Microsoft Defender for Server Prerequisites Check             ║" -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

if ($result.DefenderInstalled) {
    Write-Host "✓ Windows Defender is installed" -ForegroundColor Green
} else {
    Write-Host "✗ Windows Defender is NOT installed" -ForegroundColor Red
}

if ($result.DisableAntiSpywarePresent) {
    Write-Host "✗ DisableAntiSpyware registry setting is PRESENT" -ForegroundColor Red
    Write-Host "This will block Defender onboarding. Please remove or set GPO to 'Not Configured'" -ForegroundColor Yellow
} else {
    Write-Host "✓ DisableAntiSpyware registry setting is NOT present" -ForegroundColor Green
}

# Azure Arc onboarding pre-checks
if (-not $result.IsAzureVM) {
    Write-Host "`n╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║        Azure Arc Onboarding Endpoint Pre-Check (Non-Azure VM)        ║" -ForegroundColor White -BackgroundColor DarkBlue
    Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

    # Prompt for cloud environment
    Write-Host "`n[+] Select the Azure cloud environment for Arc onboarding endpoint test:" -ForegroundColor Cyan
    Write-Host "    [1] AzureCloud (Commercial) - gbl.his.arc.azure.com"
    Write-Host "    [2] AzureUSGovernment - gbl.his.arc.azure.us"
    $cloudChoice = Read-Host "Enter '1' for AzureCloud or '2' for AzureUSGovernment"
    switch ($cloudChoice) {
        '1' { $targetHost = "gbl.his.arc.azure.com" }
        '2' { $targetHost = "gbl.his.arc.azure.us" }
        default {
            Write-Host "✗ Invalid selection. Please enter '1' or '2'." -ForegroundColor Red
            return
        }
    }

    # Prompt for endpoint type
    $endpointChoice = Read-Host "Select endpoint type: Enter '1' for Public or '2' for Private"
    switch ($endpointChoice) {
        '1' { $endpointType = "Public" }
        '2' { $endpointType = "Private" }
        default {
            Write-Host "✗ Invalid selection. Please enter '1' or '2'." -ForegroundColor Red
            return
        }
    }

    # DNS resolution
    Write-Host "`n[+] Resolving DNS for $targetHost..." -ForegroundColor Cyan
    try {
        $resolvedIP = (Resolve-DnsName -Name $targetHost -ErrorAction Stop).IPAddress
        Write-Host "✓ Resolved IP: $resolvedIP" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to resolve DNS for $targetHost" -ForegroundColor Red
        return
    }

    # Heuristic check for public IP
    $publicIpPatterns = @(
        '^20\.141\.\d{1,3}\.\d{1,3}$',   # AzureUSGovernment
        '^20\.140\.\d{1,3}\.\d{1,3}$',   # AzureUSGovernment
        '^52\.127\.\d{1,3}\.\d{1,3}$',   # AzureUSGovernment
        '^52\.243\.\d{1,3}\.\d{1,3}$',   # AzureUSGovernment
        '^52\.245\.\d{1,3}\.\d{1,3}$',   # AzureUSGovernment
        '^20\.158\.\d{1,3}\.\d{1,3}$',   # AzureUSGovernment
        '^4\.\d{1,3}\.\d{1,3}\.\d{1,3}$', # AzureCloud
        '^13\.\d{1,3}\.\d{1,3}\.\d{1,3}$', # AzureCloud
        '^20\.\d{1,3}\.\d{1,3}\.\d{1,3}$', # AzureCloud
        '^40\.\d{1,3}\.\d{1,3}\.\d{1,3}$', # AzureCloud
        '^51\.\d{1,3}\.\d{1,3}\.\d{1,3}$', # AzureCloud
        '^52\.\d{1,3}\.\d{1,3}\.\d{1,3}$', # AzureCloud
        '^102\.\d{1,3}\.\d{1,3}\.\d{1,3}$', # AzureCloud
        '^104\.\d{1,3}\.\d{1,3}\.\d{1,3}$', # AzureCloud
        '^172\.\d{1,3}\.\d{1,3}\.\d{1,3}$', # AzureCloud
        '^191\.\d{1,3}\.\d{1,3}\.\d{1,3}$'  # AzureCloud
    )

    $isPublic = $false
    foreach ($pattern in $publicIpPatterns) {
        if ($resolvedIP -match $pattern) {
            $isPublic = $true
            break
        }
    }

    # Final endpoint type validation
    if ($endpointType -eq "Private" -and $isPublic) {
        Write-Host "✗ DNS resolves to a PUBLIC endpoint, but Private was selected." -ForegroundColor Red
        return
    } elseif ($endpointType -eq "Public" -and -not $isPublic) {
        Write-Host "✗ DNS does NOT resolve to a Public endpoint. Check your configuration." -ForegroundColor Red
        return
    } else {
        Write-Host "✓ DNS resolution matches expected endpoint type." -ForegroundColor Green
    }

    # Port 443 connectivity test
    Write-Host "`n[+] Testing TCP connectivity to $targetHost on port 443..." -ForegroundColor Cyan
    try {
        $tcpTest = Test-NetConnection -ComputerName $targetHost -Port 443 -WarningAction SilentlyContinue
        if (-not $tcpTest.TcpTestSucceeded) {
            Write-Host "✗ Port 443 is NOT open. Arc onboarding will fail." -ForegroundColor Red
            return
        } else {
            Write-Host "✓ Port 443 is open on $targetHost. Endpoint is reachable." -ForegroundColor Green
        }
    } catch {
        Write-Host "✗ Error testing port 443 connectivity." -ForegroundColor Red
        return
    }
} else {
    Write-Host "`n✓ Server is detected as an Azure VM. Skipping Azure Arc onboarding checks because this step is only required for non-Azure servers." -ForegroundColor Green
}