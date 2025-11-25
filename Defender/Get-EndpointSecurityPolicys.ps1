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
    Reports on Intune Endpoint Security policy deployment status for MDE-managed devices.

.DESCRIPTION
    This script generates a comprehensive report of Endpoint Security policies from Microsoft Intune
    that are delivered through Microsoft Defender for Endpoint (MDE) Security Settings Management.
    
    This is specifically designed for reporting on policies created under Endpoint Security in Intune
    that support MDE Security Settings Management, including:
    - Antivirus policies (Microsoft Defender Antivirus, Exclusions, Update Controls)
    - Firewall policies and Firewall Rules
    - Endpoint Detection & Response (EDR) policies
    - Attack Surface Reduction (ASR) policies
    - Configuration Policies with Defender settings (Settings Catalog)
    
    Results can be filtered by Microsoft Defender for Endpoint (MDE) device groups to show only
    devices that belong to a specific group (useful for targeting servers or workstations).
    
    The report includes:
    - Policy name and type
    - Device name and compliance status
    - Assignment status (Success, Error, Conflict, Not Applicable)
    - Last sync time and OS version
    - Device group membership (when filtered)
    
    Reference: https://learn.microsoft.com/en-us/intune/protect/mde-security-integration
    
    REQUIRED PERMISSIONS:
    - DeviceManagementConfiguration.Read.All
    - DeviceManagementManagedDevices.Read.All
    - ThreatHunting.Read.All (for MDE device group access via Advanced Hunting)
    - DeviceManagementApps.Read.All (for reporting APIs)
    
    Supports both interactive delegated authentication and app-only authentication using
    certificate-based authentication with an Azure AD App Registration.

.PARAMETER
    PolicyName - Optional. Filter results to a specific policy name (supports wildcards).
    
    DeviceGroupName - Optional. Filter results to show only devices in the specified MDE device group.
    
    ClientId - Optional. The Application (Client) ID of your Azure AD App Registration.
               Required when using app-based authentication with certificate.
    
    TenantId - Optional. The Directory (Tenant) ID of your Azure AD tenant.
               Required when using app-based authentication with certificate.
    
    CertificateThumbprint - Optional. The thumbprint of the certificate uploaded to your App Registration.
                            Required when using app-based authentication with certificate.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    Displays results in Out-GridView and optionally exports to CSV and/or HTML files.

.EXAMPLE
    .\Get-EndpointSecurityPolicys.ps1
    
    Generates a report for all Endpoint Security policies across all devices.

.EXAMPLE
    .\Get-EndpointSecurityPolicys.ps1 -PolicyName "Antivirus*"
    
    Reports on policies with names starting with "Antivirus".

.EXAMPLE
    .\Get-EndpointSecurityPolicys.ps1 -DeviceGroupName "Production Devices"
    
    Reports on all policies but only for devices in the "Production Devices" MDE group.

.EXAMPLE
    .\Get-EndpointSecurityPolicys.ps1 -PolicyName "Firewall*" -DeviceGroupName "Production Devices"
    
    Reports on Firewall policies for devices in the Production Devices group.

.EXAMPLE
    .\Get-EndpointSecurityPolicys.ps1 -ClientId "12345678-1234-1234-1234-123456789012" -TenantId "87654321-4321-4321-4321-210987654321" -CertificateThumbprint "ABC123DEF456..."
    
    Uses app registration with certificate authentication to connect to Microsoft Graph.

.NOTES
    Name: Get-EndpointSecurityPolicys.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: November 20, 2025
    Revisions: 
        1.0 - Initial version with policy status reporting and MDE device group filtering
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$PolicyName,
    
    [Parameter(Mandatory = $false)]
    [string]$DeviceGroupName,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientId,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint
)

#Requires -Modules Microsoft.Graph.Authentication

# Prompt user to select environment
Write-Host "`nSelect Microsoft Graph Environment:" -ForegroundColor Yellow
Write-Host "  [1] Global (Commercial Cloud)" -ForegroundColor White
Write-Host "  [2] USGov (Azure Government)" -ForegroundColor White
Write-Host "  [3] USGovDoD (Azure Government DoD)" -ForegroundColor White

do {
    $envSelection = Read-Host "`nSelect environment (1-3)"
    $envSelectionValid = $envSelection -match '^[1-3]$'
    if (-not $envSelectionValid) {
        Write-Host "Invalid selection. Please enter 1, 2, or 3." -ForegroundColor Red
    }
} while (-not $envSelectionValid)

# Map selection to environment
$environment = switch ($envSelection) {
    '1' { 'Global'; break }
    '2' { 'USGov'; break }
    '3' { 'USGovDoD'; break }
}

Write-Host "Selected environment: $environment" -ForegroundColor Green

# Connect to Microsoft Graph with required permissions
Write-Host "`nConnecting to Microsoft Graph ($environment)..." -ForegroundColor Cyan

# Check if using app registration authentication
$useAppAuth = $ClientId -and $TenantId -and $CertificateThumbprint

try {
    if ($useAppAuth) {
        Write-Host "Using App Registration authentication" -ForegroundColor Yellow
        Write-Host "Client ID: $ClientId" -ForegroundColor Gray
        Write-Host "Tenant ID: $TenantId" -ForegroundColor Gray
        Write-Host "Certificate Thumbprint: $CertificateThumbprint" -ForegroundColor Gray
        
        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificateThumbprint $CertificateThumbprint -Environment $environment -NoWelcome -ErrorAction Stop
    }
    else {
        Write-Host "Using interactive delegated authentication" -ForegroundColor Yellow
        Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All", "DeviceManagementManagedDevices.Read.All", "ThreatHunting.Read.All", "DeviceManagementApps.Read.All" -Environment $environment -NoWelcome -ErrorAction Stop
    }
    
    Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# Get MDE device group members if filtering is requested
$deviceGroupMembers = @()
if ($DeviceGroupName) {
    Write-Host "`nRetrieving MDE device group: '$DeviceGroupName'..." -ForegroundColor Cyan
    try {
        # Query MDE device groups via Advanced Hunting
        # DeviceInfo table contains the latest device information
        $uri = "https://graph.microsoft.com/v1.0/security/microsoft.graph.security.runHuntingQuery"
        $body = @{
            Query = @"
DeviceInfo
| where isnotempty(MachineGroup) 
| where MachineGroup =~ '$DeviceGroupName'
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceId, DeviceName, MachineGroup
"@
        } | ConvertTo-Json
        
        $deviceGroupResponse = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ErrorAction Stop
        
        if ($deviceGroupResponse.Results) {
            $deviceGroupMembers = $deviceGroupResponse.Results | ForEach-Object { 
                [PSCustomObject]@{
                    DeviceId = $_.DeviceId
                    DeviceName = $_.DeviceName
                    MachineGroup = $_.MachineGroup
                }
            }
            Write-Host "Found $($deviceGroupMembers.Count) device(s) in group '$DeviceGroupName'" -ForegroundColor Green
        }
        else {
            Write-Warning "No devices found in MDE device group '$DeviceGroupName'"
            Write-Host "`nNote: MDE device groups are stored in the 'MachineGroup' field." -ForegroundColor Yellow
            Write-Host "Ensure the group name matches exactly (case-insensitive)." -ForegroundColor Yellow
            Disconnect-MgGraph | Out-Null
            exit 0
        }
    }
    catch {
        Write-Warning "Could not retrieve MDE device group. Ensure the group name is correct and you have ThreatHunting.Read.All permission."
        Write-Warning "Error: $_"
        Write-Host "`nTip: You can grant ThreatHunting.Read.All permission by running:" -ForegroundColor Yellow
        Write-Host "Connect-MgGraph -Scopes 'ThreatHunting.Read.All' -Environment $environment" -ForegroundColor Cyan
        Disconnect-MgGraph | Out-Null
        exit 1
    }
}

# Get all Endpoint Security policies
# These are policies created under Endpoint Security node that can be delivered via MDE
Write-Host "`nRetrieving Endpoint Security policies..." -ForegroundColor Cyan
Write-Host "Note: This script focuses on Endpoint Security Intents and Configuration Policies" -ForegroundColor Gray
Write-Host "      that support MDE Security Settings Management (devices managed via Defender)" -ForegroundColor Gray

try {
    $allPolicies = @()
    
    # Get Endpoint Security Intents - Primary policy type for MDE security settings management
    # These include: Antivirus, Firewall, Endpoint Detection & Response, Attack Surface Reduction
    Write-Host "`nChecking Endpoint Security Intents (Antivirus, Firewall, EDR, ASR)..." -ForegroundColor Cyan
    $uri = "https://graph.microsoft.com/beta/deviceManagement/intents"
    $intuneIntents = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    
    $configPolicies = $intuneIntents.value
    
    # Get additional pages if needed
    while ($intuneIntents.'@odata.nextLink') {
        $uri = $intuneIntents.'@odata.nextLink'
        $intuneIntents = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $configPolicies += $intuneIntents.value
    }
    
    Write-Host "  Found $($configPolicies.Count) Endpoint Security Intent(s)" -ForegroundColor Gray
    
    # Also get Configuration Policies (Settings Catalog) as they can contain Defender settings
    Write-Host "`nChecking Configuration Policies (Settings Catalog)..." -ForegroundColor Cyan
    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
    $configPolicyResponse = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
    
    if ($configPolicyResponse.value) {
        $settingsCatalogPolicies = $configPolicyResponse.value
        
        # Get additional pages if needed
        while ($configPolicyResponse.'@odata.nextLink') {
            $uri = $configPolicyResponse.'@odata.nextLink'
            $configPolicyResponse = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $settingsCatalogPolicies += $configPolicyResponse.value
        }
        
        Write-Host "  Found $($settingsCatalogPolicies.Count) Configuration Policy/Policies" -ForegroundColor Gray
        $configPolicies += $settingsCatalogPolicies
    }
    
    Write-Host "Total policies retrieved: $($configPolicies.Count)" -ForegroundColor Gray
    
    if ($PolicyName) {
        Write-Host "Filtering by policy name: '$PolicyName'" -ForegroundColor Gray
        $configPolicies = $configPolicies | Where-Object { $_.displayName -like $PolicyName -or $_.name -like $PolicyName }
        Write-Host "Policies after filtering: $($configPolicies.Count)" -ForegroundColor Gray
        
        if ($configPolicies.Count -eq 0) {
            Write-Host "`nNo policies matched the filter '$PolicyName'. Showing available policies:" -ForegroundColor Yellow
            
            # Show sample of available policies
            $allAvailablePolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/intents" -ErrorAction SilentlyContinue
            $allConfigPolicies = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies" -ErrorAction SilentlyContinue
            $allDeviceConfigs = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -ErrorAction SilentlyContinue
            
            $samplePolicies = @()
            if ($allAvailablePolicies.value) { $samplePolicies += $allAvailablePolicies.value }
            if ($allConfigPolicies.value) { $samplePolicies += $allConfigPolicies.value }
            if ($allDeviceConfigs.value) { $samplePolicies += $allDeviceConfigs.value }
            
            if ($samplePolicies.Count -gt 0) {
                Write-Host "`nAvailable policies (showing first 20):" -ForegroundColor Cyan
                $samplePolicies | Select-Object -First 20 | ForEach-Object {
                    $policyName = if ($_.displayName) { $_.displayName } else { $_.name }
                    Write-Host "  - $policyName" -ForegroundColor White
                }
                if ($samplePolicies.Count -gt 20) {
                    Write-Host "  ... and $($samplePolicies.Count - 20) more" -ForegroundColor Gray
                }
            }
        }
    }
    
    $allPolicies += $configPolicies
    
    Write-Host "Found $($allPolicies.Count) matching policy/policies" -ForegroundColor Green
}
catch {
    Write-Error "Failed to retrieve Endpoint Security policies: $_"
    Disconnect-MgGraph | Out-Null
    exit 1
}

if ($allPolicies.Count -eq 0) {
    Write-Warning "No Endpoint Security policies found matching the criteria."
    Disconnect-MgGraph | Out-Null
    exit 0
}

# Build detailed policy status report
Write-Host "`nGathering policy deployment status..." -ForegroundColor Cyan
$results = @()
$counter = 0
$totalPolicies = $allPolicies.Count

foreach ($policy in $allPolicies) {
    $counter++
    $policyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }
    Write-Progress -Activity "Processing Endpoint Security Policies" -Status "Policy $counter of $totalPolicies - $policyName" -PercentComplete (($counter / $totalPolicies) * 100)
    
    try {
        $deviceStatuses = @()
        
        # Determine policy type and retrieve device states accordingly
        # Type 1: Intent-based policies (Endpoint Security) - Main type for MDE Security Settings Management
        if ($policy.'@odata.type' -eq '#microsoft.graph.deviceManagementIntent' -or $policy.templateId) {
            Write-Host "  Processing Endpoint Security Intent: $policyName" -ForegroundColor Gray
            
            # Get device states for this intent
            $uri = "https://graph.microsoft.com/beta/deviceManagement/intents/$($policy.id)/deviceStates"
            $deviceStatusResponse = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
            
            if ($deviceStatusResponse.value) {
                $deviceStatuses = $deviceStatusResponse.value
                
                # Get additional pages if needed
                while ($deviceStatusResponse.'@odata.nextLink') {
                    $uri = $deviceStatusResponse.'@odata.nextLink'
                    $deviceStatusResponse = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction SilentlyContinue
                    if ($deviceStatusResponse.value) {
                        $deviceStatuses += $deviceStatusResponse.value
                    }
                }
            }
        }
        # Type 2: Configuration Policies (Settings Catalog) - Can also contain Defender settings
        elseif ($policy.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationPolicy' -or $policy.technologies) {
            Write-Host "  Processing Configuration Policy: $policyName" -ForegroundColor Gray
            
            # Use the export API to get device assignment status for configuration policies
            try {
                Write-Host "    Creating export job..." -ForegroundColor DarkGray
                
                # Step 1: Create export job
                $exportUri = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs"
                $exportBody = @{
                    reportName = "DeviceAssignmentStatusByConfigurationPolicyV3"
                    filter = "(PolicyId eq '$($policy.id)')"
                    select = @("PolicyId", "PolicyName", "DeviceName", "UPN", "AssignmentStatus", "IntuneDeviceId", "AadDeviceId")
                } | ConvertTo-Json
                
                $exportJob = Invoke-MgGraphRequest -Method POST -Uri $exportUri -Body $exportBody -ContentType "application/json" -ErrorAction Stop
                $exportJobId = $exportJob.id
                Write-Host "    Export job ID: $exportJobId" -ForegroundColor DarkGray
                
                # Step 2: Poll for completion (max 60 seconds)
                $maxWaitSeconds = 60
                $waitedSeconds = 0
                $jobComplete = $false
                
                while ($waitedSeconds -lt $maxWaitSeconds -and -not $jobComplete) {
                    Start-Sleep -Seconds 2
                    $waitedSeconds += 2
                    
                    $statusUri = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$exportJobId')"
                    $jobStatus = Invoke-MgGraphRequest -Method GET -Uri $statusUri -ErrorAction Stop
                    
                    if ($jobStatus.status -eq "completed") {
                        $jobComplete = $true
                        Write-Host "    Export completed in $waitedSeconds seconds" -ForegroundColor DarkGray
                        
                        # Step 3: Download and parse the report
                        if ($jobStatus.url) {
                            $reportData = Invoke-WebRequest -Uri $jobStatus.url -UseBasicParsing
                            
                            # The export is a ZIP file - extract it
                            $tempZip = Join-Path $env:TEMP "intuneExport_$([guid]::NewGuid().ToString()).zip"
                            $tempExtract = Join-Path $env:TEMP "intuneExport_$([guid]::NewGuid().ToString())"
                            
                            try {
                                [System.IO.File]::WriteAllBytes($tempZip, $reportData.Content)
                                Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force
                                
                                # Find the CSV file in the extracted contents
                                $csvFile = Get-ChildItem -Path $tempExtract -Filter "*.csv" | Select-Object -First 1
                                
                                if ($csvFile) {
                                    $csvData = Import-Csv -Path $csvFile.FullName
                                    
                                    # Debug: Show CSV structure
                                    if ($csvData.Count -gt 0) {
                                        $columns = $csvData[0].PSObject.Properties.Name
                                        Write-Host "      CSV has $($csvData.Count) rows, $($columns.Count) columns" -ForegroundColor DarkGray
                                        Write-Host "      Columns: $($columns -join ', ')" -ForegroundColor DarkGray
                                    }
                                } else {
                                    Write-Host "      No CSV file found in export" -ForegroundColor Yellow
                                    $csvData = @()
                                }
                            }
                            finally {
                                # Cleanup temp files
                                if (Test-Path $tempZip) { Remove-Item $tempZip -Force -ErrorAction SilentlyContinue }
                                if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue }
                            }
                            
                            foreach ($row in $csvData) {
                                $deviceStatuses += [PSCustomObject]@{
                                    deviceId = $row.IntuneDeviceId
                                    azureADDeviceId = $row.AadDeviceId
                                    deviceDisplayName = $row.DeviceName
                                    userPrincipalName = $row.UPN
                                    state = $row.AssignmentStatus
                                    lastReportedDateTime = $row.PspdpuLastModifiedTimeUtc
                                }
                            }
                        } else {
                            Write-Host "    Export completed but no download URL" -ForegroundColor Yellow
                        }
                    } elseif ($jobStatus.status -eq "failed") {
                        Write-Host "    Export job failed" -ForegroundColor Yellow
                        break
                    }
                }
                
                if (-not $jobComplete) {
                    Write-Host "    Export timed out after $maxWaitSeconds seconds" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "    Unable to retrieve status via export API: $_" -ForegroundColor DarkGray
            }
        }
        
        Write-Host "    Found $($deviceStatuses.Count) device status record(s)" -ForegroundColor DarkGray
        
        # Debug: Show sample device names if filtering by group
        if ($DeviceGroupName -and $deviceStatuses.Count -gt 0) {
            Write-Host "    MDE Group devices: $($deviceGroupMembers.DeviceName -join ', ')" -ForegroundColor DarkGray
            Write-Host "    Policy status sample devices: $($deviceStatuses[0..2].deviceDisplayName -join ', ')" -ForegroundColor DarkGray
        }
        
        # Process device statuses
        if ($deviceStatuses.Count -gt 0) {
            foreach ($deviceStatus in $deviceStatuses) {
                try {
                    # Filter by device group if specified
                    if ($DeviceGroupName) {
                        # Match by device name - handle both exact match and hostname-only match (without domain)
                        $statusDeviceName = $deviceStatus.deviceDisplayName
                        $statusHostname = if ($statusDeviceName -match '\.') { $statusDeviceName.Split('.')[0] } else { $statusDeviceName }
                        
                        $deviceInGroup = $deviceGroupMembers | Where-Object { 
                            # Exact match (case-insensitive)
                            ($_.DeviceName -ieq $statusDeviceName) -or
                            # Hostname-only match (without domain suffix)
                            ($_.DeviceName -ieq $statusHostname) -or
                            ($_.DeviceName.Split('.')[0] -ieq $statusHostname)
                        }
                        if (-not $deviceInGroup) {
                            continue
                        }
                    }
                    
                    # Try to get additional device details
                    $device = $null
                    if ($deviceStatus.deviceId) {
                        try {
                            # Try by managed device ID first
                            $deviceUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($deviceStatus.deviceId)"
                            $device = Invoke-MgGraphRequest -Method GET -Uri $deviceUri -ErrorAction SilentlyContinue
                        }
                        catch {
                            # If that fails, try searching by Azure AD device ID
                            $deviceUri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=azureADDeviceId eq '$($deviceStatus.deviceId)'"
                            $deviceSearch = Invoke-MgGraphRequest -Method GET -Uri $deviceUri -ErrorAction SilentlyContinue
                            if ($deviceSearch.value) {
                                $device = $deviceSearch.value[0]
                            }
                        }
                    }
                    
                    # Determine status - handle both Intent policies (state) and Configuration policies (AssignmentStatus)
                    $rawStatus = if ($deviceStatus.state) { $deviceStatus.state } else { $deviceStatus.AssignmentStatus }
                    
                    $status = switch ($rawStatus) {
                        "compliant" { "Success" }
                        "succeeded" { "Success" }
                        "success" { "Success" }
                        "notCompliant" { "Error" }
                        "failed" { "Error" }
                        "conflict" { "Conflict" }
                        "error" { "Error" }
                        "notApplicable" { "Not Applicable" }
                        "notAssigned" { "Not Assigned" }
                        "pending" { "Pending" }
                        default { if ($rawStatus) { $rawStatus } else { "Unknown" } }
                    }
                    
                    $results += [PSCustomObject]@{
                        PolicyName = $policyName
                        PolicyType = if ($policy.templateId) { $policy.templateId.Split('_')[0] } elseif ($policy.technologies) { $policy.technologies -join ", " } else { "Configuration" }
                        DeviceName = if ($device) { $device.deviceName } else { $deviceStatus.deviceDisplayName }
                        UserPrincipalName = if ($device) { $device.userPrincipalName } elseif ($deviceStatus.userPrincipalName) { $deviceStatus.userPrincipalName } else { "N/A" }
                        Status = $status
                        LastSync = if ($device) { $device.lastSyncDateTime } else { $deviceStatus.lastReportedDateTime }
                        OSVersion = if ($device) { $device.osVersion } else { "N/A" }
                        ComplianceState = if ($device) { $device.complianceState } else { $status }
                        DeviceId = if ($deviceStatus.deviceId) { $deviceStatus.deviceId } else { $deviceStatus.azureADDeviceId }
                        ErrorDescription = if ($status -eq "Error") { "Check device logs for details" } else { "" }
                    }
                }
                catch {
                    Write-Warning "Failed to retrieve device details for device ID $($deviceStatus.deviceId): $_"
                }
            }
        }
        else {
            # Policy with no device assignments
            $results += [PSCustomObject]@{
                PolicyName = $policy.displayName
                PolicyType = if ($policy.templateId) { $policy.templateId.Split('_')[0] } else { "Unknown" }
                DeviceName = "No devices assigned"
                UserPrincipalName = ""
                Status = "Not Assigned"
                LastSync = $null
                OSVersion = ""
                ComplianceState = ""
                DeviceId = ""
                ErrorDescription = ""
            }
        }
    }
    catch {
        Write-Warning "Failed to retrieve status for policy '$($policy.displayName)': $_"
    }
}

Write-Progress -Activity "Processing Endpoint Security Policies" -Completed

if ($results.Count -eq 0) {
    Write-Warning "No device status information found for the specified criteria."
    Disconnect-MgGraph | Out-Null
    exit 0
}

# Calculate summary statistics
$totalDevices = $results | Where-Object { $_.DeviceName -ne "No devices assigned" } | Select-Object -ExpandProperty DeviceId -Unique | Measure-Object | Select-Object -ExpandProperty Count
$successCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
$errorCount = ($results | Where-Object { $_.Status -eq "Error" }).Count
$conflictCount = ($results | Where-Object { $_.Status -eq "Conflict" }).Count

# Display results in Out-GridView
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Endpoint Security Policy Status Report" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Policies: $($allPolicies.Count)" -ForegroundColor Green
Write-Host "Total Devices: $totalDevices" -ForegroundColor Green
Write-Host "Success: $successCount | Errors: $errorCount | Conflicts: $conflictCount" -ForegroundColor Green
Write-Host "Opening results in GridView...`n" -ForegroundColor Cyan

$results | Sort-Object PolicyName, DeviceName | Out-GridView -Title "Endpoint Security Policy Status Report"

# Optionally export results
$export = Read-Host "`nWould you like to export these results? (Y/N)"
if ($export -eq 'Y' -or $export -eq 'y') {
    $format = Read-Host "Select export format: [1] CSV  [2] HTML  [3] Both"
    
    # Export to CSV
    if ($format -eq '1' -or $format -eq '3') {
        $defaultPath = Join-Path $PSScriptRoot "EndpointSecurity_PolicyStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $csvPath = Read-Host "Enter the path for the CSV file (press Enter for default: $defaultPath)"
        
        if ([string]::IsNullOrWhiteSpace($csvPath)) {
            $csvPath = $defaultPath
        }
        
        try {
            $results | Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction Stop
            Write-Host "Results exported to: $csvPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export CSV: $_"
        }
    }
    
    # Export to HTML
    if ($format -eq '2' -or $format -eq '3') {
        $defaultHtmlPath = Join-Path $PSScriptRoot "EndpointSecurity_PolicyStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlPath = Read-Host "Enter the path for the HTML file (press Enter for default: $defaultHtmlPath)"
        
        if ([string]::IsNullOrWhiteSpace($htmlPath)) {
            $htmlPath = $defaultHtmlPath
        }
        
        try {
            $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Endpoint Security Policy Status Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background-color: #0078d4;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
        }
        .header .info {
            margin-top: 10px;
            font-size: 14px;
        }
        .summary {
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-item {
            display: inline-block;
            margin-right: 30px;
            font-size: 16px;
        }
        .summary-label {
            font-weight: bold;
            color: #555;
        }
        .summary-value {
            color: #0078d4;
            font-weight: bold;
        }
        .success { color: #107c10; font-weight: bold; }
        .error { color: #d13438; font-weight: bold; }
        .conflict { color: #ff8c00; font-weight: bold; }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 5px;
            overflow: hidden;
        }
        th {
            background-color: #0078d4;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            position: sticky;
            top: 0;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
            font-size: 14px;
        }
        tr:hover {
            background-color: #f0f0f0;
        }
        tr:last-child td {
            border-bottom: none;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Endpoint Security Policy Status Report</h1>
        <div class="info">
            <strong>Generated:</strong> $(Get-Date -Format "MMMM dd, yyyy HH:mm:ss")<br>
"@
            
            if ($DeviceGroupName) {
                $htmlContent += "            <strong>Filtered by MDE Device Group:</strong> $DeviceGroupName<br>`n"
            }
            if ($PolicyName) {
                $htmlContent += "            <strong>Filtered by Policy:</strong> $PolicyName<br>`n"
            }
            
            $htmlContent += @"
        </div>
    </div>
    
    <div class="summary">
        <div class="summary-item">
            <span class="summary-label">Total Policies:</span> 
            <span class="summary-value">$($allPolicies.Count)</span>
        </div>
        <div class="summary-item">
            <span class="summary-label">Total Devices:</span> 
            <span class="summary-value">$totalDevices</span>
        </div>
        <div class="summary-item">
            <span class="summary-label">Success:</span> 
            <span class="success">$successCount</span>
        </div>
        <div class="summary-item">
            <span class="summary-label">Errors:</span> 
            <span class="error">$errorCount</span>
        </div>
        <div class="summary-item">
            <span class="summary-label">Conflicts:</span> 
            <span class="conflict">$conflictCount</span>
        </div>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Policy Name</th>
                <th>Policy Type</th>
                <th>Device Name</th>
                <th>User</th>
                <th>Status</th>
                <th>Last Sync</th>
                <th>OS Version</th>
            </tr>
        </thead>
        <tbody>
"@
        
            foreach ($item in ($results | Sort-Object PolicyName, DeviceName)) {
                $statusClass = switch ($item.Status) {
                    "Success" { "success" }
                    "Error" { "error" }
                    "Conflict" { "conflict" }
                    default { "" }
                }
                
                $lastSyncFormatted = if ($item.LastSync) { $item.LastSync.ToString("yyyy-MM-dd HH:mm") } else { "" }
                
                $htmlContent += @"
            <tr>
                <td>$($item.PolicyName)</td>
                <td>$($item.PolicyType)</td>
                <td>$($item.DeviceName)</td>
                <td>$($item.UserPrincipalName)</td>
                <td class="$statusClass">$($item.Status)</td>
                <td>$lastSyncFormatted</td>
                <td>$($item.OSVersion)</td>
            </tr>
"@
            }
        
            $htmlContent += @"
        </tbody>
    </table>
    
    <div class="footer">
        Report generated by Get-EndpointSecurityPolicys.ps1
    </div>
</body>
</html>
"@
        
            $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8 -ErrorAction Stop
            Write-Host "HTML report exported to: $htmlPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export HTML report: $_"
        }
    }
}

# Disconnect from Microsoft Graph
Disconnect-MgGraph | Out-Null
Write-Host "`nDisconnected from Microsoft Graph" -ForegroundColor Cyan
