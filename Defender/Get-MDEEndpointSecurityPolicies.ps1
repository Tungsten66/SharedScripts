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
    Reports on Intune Endpoint Security policy assignments and group targeting.

.DESCRIPTION
    This script generates a report of Endpoint Security policies from Microsoft Intune
    including policy assignments and group targeting information.
    
    This is specifically designed for reporting on policies created under Endpoint Security in Intune
    that target Microsoft Defender for Endpoint (MDE) and MDM-managed devices, including:
    - Antivirus policies (Microsoft Defender Antivirus, Windows Security Experience)
    - Firewall policies and Firewall Rules
    - Endpoint Detection & Response (EDR) policies
    - Attack Surface Reduction (ASR) policies
    
    The report displays policies with the following information:
    - Policy name
    - Policy type (as shown in Intune GUI)
    - Target (technologies: mdm, microsoftSense)
    - Platform (Windows, macOS, etc.)
    - Assigned groups (Include Groups)
    
    Note: This script filters for policies targeting microsoftSense technology.
    Policies may also include mdm, but microsoftSense is required.
    Configuration Policies without microsoftSense are excluded from the report.
    
    Reference: https://learn.microsoft.com/en-us/mem/intune/protect/mde-security-integration
    
    REQUIRED PERMISSIONS:
    - DeviceManagementConfiguration.Read.All (to read Intune policies)
    - Group.Read.All (to resolve group names from IDs)
    
    PREREQUISITES:
    - Azure CLI installed and authenticated (az login)
    - Microsoft.Graph.Authentication PowerShell module
    - Appropriate Graph API permissions (listed above)
    
    Uses Azure CLI for authentication with support for:
    - Commercial Cloud (AzureCloud)
    - Government Cloud (AzureUSGovernment)

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    Displays results on screen or exports to CSV.

.EXAMPLE
    .\Get-MDEEndpointSecurityPolicies.ps1
    
    Prompts for policy filter (supports wildcards like "CORP-*") and generates a report 
    for matching MDE/Defender Endpoint Security policies. Displays policies targeting 
    microsoftSense technology only (may also include mdm).

.NOTES
    Name: Get-MDEEndpointSecurityPolicies.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: January 15, 2026
    Revisions: 
        1.0 - Initial version of Endpoint Security policy reporting script
        1.1 - Added filtering for microsoftSense target (MDE policies only)
        1.2 - Enhanced policy type detection using templateDisplayName from GUI
        1.3 - Added security improvements and file path validation
#>

[CmdletBinding()]
param()

#Requires -Modules Microsoft.Graph.Authentication

# Verify Azure CLI is installed and user is logged in
Write-Host "`nVerifying Azure CLI session..." -ForegroundColor Cyan
try {
    $azAccount = az account show 2>$null | ConvertFrom-Json
    if ($null -eq $azAccount) {
        Write-Error "No active Azure CLI session found. Please run 'az login' first."
        Write-Host "`nSetup Instructions:" -ForegroundColor Yellow
        Write-Host "  1. For Commercial Cloud: az cloud set --name AzureCloud" -ForegroundColor White
        Write-Host "  2. For GCC High: az cloud set --name AzureUSGovernment" -ForegroundColor White
        Write-Host "  3. Login: az login" -ForegroundColor White
        Write-Host "  4. Run this script again" -ForegroundColor White
        exit 1
    }
    
    $cloudName = az cloud show --query name -o tsv
    Write-Host "Active Azure Cloud: $cloudName" -ForegroundColor Green
    Write-Host "Logged in as: $($azAccount.user.name)" -ForegroundColor Green
    
    # Map Azure CLI cloud to Microsoft Graph environment
    $graphEnvironment = switch ($cloudName) {
        'AzureCloud' { 'Global'; break }
        'AzureUSGovernment' { 'USGov'; break }
        default { 'Global' }
    }
    Write-Host "Microsoft Graph Environment: $graphEnvironment" -ForegroundColor Gray
    
    # Set Graph endpoint based on environment
    $script:graphEndpoint = switch ($graphEnvironment) {
        'USGov' { 'https://graph.microsoft.us'; break }
        'USGovDoD' { 'https://dod-graph.microsoft.us'; break }
        default { 'https://graph.microsoft.com' }
    }
    Write-Host "Graph API Endpoint: $script:graphEndpoint" -ForegroundColor Gray
}
catch {
    Write-Error "Azure CLI not found or not configured. Please install Azure CLI and run 'az login'."
    exit 1
}

# Connect to Microsoft Graph using Azure CLI token
Write-Host "`nConnecting to Microsoft Graph using Azure CLI token..." -ForegroundColor Cyan

# Check if already connected
$existingContext = Get-MgContext -ErrorAction SilentlyContinue
if ($existingContext) {
    Write-Host "Already connected to Microsoft Graph" -ForegroundColor Green
    Write-Host "Account: $($existingContext.Account)" -ForegroundColor Gray
}
else {
    try {
        # Get access token from Azure CLI for the correct cloud
        $token = az account get-access-token --resource-type ms-graph --query accessToken -o tsv
        
        if ([string]::IsNullOrWhiteSpace($token)) {
            throw "Failed to retrieve access token from Azure CLI"
        }
        
        # Convert token to SecureString
        $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
        
        # Clear token from memory
        Clear-Variable -Name token -ErrorAction SilentlyContinue
        
        # Connect to Microsoft Graph with the token and correct environment
        Connect-MgGraph -AccessToken $secureToken -Environment $graphEnvironment -NoWelcome -ErrorAction Stop
        
        # Clear SecureString token from memory after successful connection
        Clear-Variable -Name secureToken -ErrorAction SilentlyContinue
        
        Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
        Write-Host "  - Ensure you have the required permissions (DeviceManagementConfiguration.Read.All, Group.Read.All)" -ForegroundColor White
        Write-Host "  - Verify your Azure CLI session is active: az account show" -ForegroundColor White
        Write-Host "  - Try logging in again: az login" -ForegroundColor White
        Write-Host "`nIf you continue to see login prompts, the app may need admin consent for the required permissions." -ForegroundColor Yellow
        exit 1
    }
}

# Prompt for policy filter
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Policy Selection" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Enter a policy name filter (supports wildcards)" -ForegroundColor White
Write-Host "Examples: CORP-*, *Firewall*, *Antivirus*" -ForegroundColor Gray
Write-Host "Press Enter to view all policies" -ForegroundColor Gray
$policyFilter = Read-Host "`nPolicy filter"

if ([string]::IsNullOrWhiteSpace($policyFilter)) {
    $policyFilter = "*"
    Write-Host "Retrieving all policies..." -ForegroundColor Cyan
}
else {
    Write-Host "Retrieving policies matching: $policyFilter" -ForegroundColor Cyan
}

# Get all Endpoint Security policies
# These are policies created under Endpoint Security node
Write-Host "`nRetrieving Endpoint Security policies..." -ForegroundColor Cyan

try {
    $allPolicies = @()
    
    # Get Endpoint Security Intents - Primary policy type
    # These include: Antivirus, Firewall, Endpoint Detection & Response, Attack Surface Reduction
    Write-Host "Checking Endpoint Security Intents (Antivirus, Firewall, EDR, ASR)..." -ForegroundColor Cyan
    $uri = "$script:graphEndpoint/beta/deviceManagement/intents"
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
    Write-Host "Checking Configuration Policies (Settings Catalog)..." -ForegroundColor Cyan
    $uri = "$script:graphEndpoint/beta/deviceManagement/configurationPolicies"
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
    
    # Filter by policy name
    Write-Host "Filtering by policy name: '$policyFilter'" -ForegroundColor Gray
    $configPolicies = $configPolicies | Where-Object { 
        ($_.displayName -like $policyFilter) -or ($_.name -like $policyFilter) 
    }
    Write-Host "Policies after filtering: $($configPolicies.Count)" -ForegroundColor Gray
    
    if ($configPolicies.Count -eq 0) {
        Write-Host "`nNo policies matched the filter '$policyFilter'." -ForegroundColor Yellow
        Disconnect-MgGraph | Out-Null
        exit 0
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
    exit 0
}

# Function to get raw policy type value
function Get-FriendlyPolicyType {
    param($policy)
    
    # Return templateId if available (Endpoint Security Intents)
    if ($policy.templateId) {
        return $policy.templateId
    }
    
    # Return technologies if available (Settings Catalog / Configuration Policies)
    if ($policy.technologies) {
        return $policy.technologies -join ", "
    }
    
    # Return odata.type as fallback
    if ($policy.'@odata.type') {
        return $policy.'@odata.type'
    }
    
    # Default
    return "Unknown"
}

# Build policy assignment report
Write-Host "`nGathering policy assignments...`n" -ForegroundColor Cyan
$results = @()
$counter = 0
$totalPolicies = $allPolicies.Count

foreach ($policy in $allPolicies) {
    $counter++
    $policyName = if ($policy.displayName) { $policy.displayName } else { $policy.name }
    Write-Progress -Activity "Processing Endpoint Security Policies" -Status "Policy $counter of $totalPolicies - $policyName" -PercentComplete (($counter / $totalPolicies) * 100)
    
    # Verbose: Show all policy properties
    Write-Verbose "========================================"
    Write-Verbose "Policy: $policyName"
    Write-Verbose "All Properties:"
    $policy.PSObject.Properties | ForEach-Object {
        $value = $_.Value
        # If the value is a hashtable or object, try to show more detail
        if ($value -is [hashtable]) {
            Write-Verbose "  $($_.Name) = [Hashtable]:"
            $value.GetEnumerator() | ForEach-Object {
                # Check if nested value is also a hashtable
                if ($_.Value -is [hashtable]) {
                    Write-Verbose "    $($_.Key) = [Nested Hashtable]:"
                    $_.Value.GetEnumerator() | ForEach-Object {
                        Write-Verbose "      $($_.Key) = $($_.Value)"
                    }
                }
                else {
                    Write-Verbose "    $($_.Key) = $($_.Value)"
                }
            }
        }
        elseif ($value -is [array]) {
            Write-Verbose "  $($_.Name) = [Array]: $($value -join ', ')"
        }
        else {
            Write-Verbose "  $($_.Name) = $($_.Value)"
        }
    }
    Write-Verbose "========================================"
    
    try {
        # SECURITY: Verbose output may contain policy IDs and group IDs - use only in secure environments
        # Get policy type with friendly name
        $policyType = Get-FriendlyPolicyType -policy $policy
        
        # Determine policy type classification - use templateDisplayName if available (GUI name)
        $policyTypeClassification = if ($policy.templateReference -and $policy.templateReference.templateDisplayName) {
            $policy.templateReference.templateDisplayName
        }
        elseif ($policy.templateDisplayName) {
            $policy.templateDisplayName
        }
        elseif ($policy.'@odata.type' -eq '#microsoft.graph.deviceManagementIntent' -or $policy.templateId) {
            "Endpoint Security Intent"
        }
        elseif ($policy.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationPolicy' -or $policy.technologies) {
            "Configuration Policy"
        }
        else {
            "Unknown"
        }
        
        # Determine platform from policy or assignments
        $platform = if ($policy.platforms) {
            $policy.platforms -join ", "
        }
        elseif ($policy.platformType) {
            $policy.platformType
        }
        else {
            "Not specified"
        }
        
        # Normalize platform name: windows10 -> windows
        $platform = $platform -replace '^windows10$', 'windows'
        
        # Get policy assignments
        $includeGroups = @()
        $assignments = @()
        
        # Determine assignment endpoint based on policy type
        $assignUri = $null
        
        # Check @odata.type for policy categorization
        Write-Verbose "Policy '$policyName' type: $($policy.'@odata.type')"
        
        if ($policy.'@odata.type' -eq '#microsoft.graph.deviceManagementIntent' -or $policy.templateId) {
            # Endpoint Security Intent assignments
            $assignUri = "$script:graphEndpoint/beta/deviceManagement/intents/$($policy.id)/assignments"
            Write-Verbose "Using Intent assignment URI"
        }
        elseif ($policy.'@odata.type' -eq '#microsoft.graph.deviceManagementConfigurationPolicy' -or $policy.technologies) {
            # Configuration Policy assignments (Settings Catalog)
            $assignUri = "$script:graphEndpoint/beta/deviceManagement/configurationPolicies/$($policy.id)/assignments"
            Write-Verbose "Using Configuration Policy assignment URI"
        }
        else {
            # Fallback: try configuration policy endpoint for unrecognized types
            Write-Verbose "Unknown policy type, trying Configuration Policy endpoint as fallback"
            $assignUri = "$script:graphEndpoint/beta/deviceManagement/configurationPolicies/$($policy.id)/assignments"
        }
        
        if ($assignUri) {
            try {
                $assignmentResponse = Invoke-MgGraphRequest -Method GET -Uri $assignUri -ErrorAction Stop
                $assignments = $assignmentResponse.value
                
                Write-Verbose "Policy '$policyName' has $($assignments.Count) assignment(s)"
                
                # Process assignments to get Include groups
                foreach ($assignment in $assignments) {
                    Write-Verbose "  Processing assignment with target type: $($assignment.target.'@odata.type')"
                    
                    # For Configuration Policies, there's no intent field - all group assignments are includes by default
                    # For Intent policies, check the intent property
                    $isInclude = $true
                    
                    # Check if this is an exclusion target type
                    if ($assignment.target.'@odata.type' -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                        $isInclude = $false
                        Write-Verbose "    -> Exclusion group, skipping"
                    }
                    # Check intent field if it exists (Intent-based policies)
                    elseif ($assignment.PSObject.Properties['intent'] -and $assignment.intent) {
                        $isInclude = $assignment.intent -eq 'apply'
                        Write-Verbose "    -> Intent field: $($assignment.intent), IsInclude: $isInclude"
                    }
                    
                    # Only process include assignments
                    if ($isInclude) {
                        if ($assignment.target.'@odata.type' -eq '#microsoft.graph.groupAssignmentTarget') {
                            # This is a group assignment (Include)
                            $groupId = $assignment.target.groupId
                            Write-Verbose "    -> Group assignment, GroupId: $groupId"
                            
                            # Get group name
                            try {
                                $groupUri = "$script:graphEndpoint/v1.0/groups/$groupId"
                                $group = Invoke-MgGraphRequest -Method GET -Uri $groupUri -ErrorAction SilentlyContinue
                                if ($group.displayName) {
                                    $includeGroups += $group.displayName
                                    Write-Verbose "    -> Added group: $($group.displayName)"
                                }
                                else {
                                    $includeGroups += $groupId
                                    Write-Verbose "    -> Added group ID: $groupId"
                                }
                            }
                            catch {
                                $includeGroups += $groupId
                                Write-Verbose "    -> Failed to get group name, added ID: $groupId"
                            }
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allLicensedUsersAssignmentTarget') {
                            $includeGroups += "All Users"
                            Write-Verbose "    -> All Users assignment"
                        }
                        elseif ($assignment.target.'@odata.type' -eq '#microsoft.graph.allDevicesAssignmentTarget') {
                            $includeGroups += "All Devices"
                            Write-Verbose "    -> All Devices assignment"
                        }
                    }
                }
                
                Write-Verbose "Policy '$policyName' final include groups count: $($includeGroups.Count)"
            }
            catch {
                Write-Host "  Could not retrieve assignments for policy: $policyName - $_" -ForegroundColor Yellow
            }
        }
        else {
            Write-Verbose "No assignment URI for policy: $policyName"
        }
        
        # Format include groups
        $includeGroupsText = if ($includeGroups.Count -gt 0) {
            $includeGroups -join "; "
        }
        else {
            ""
        }
        
        # Only add to results if Target contains MicrosoftSense (may also contain mdm)
        $targetValues = $policyType -split ',' | ForEach-Object { $_.Trim() }
        $containsMicrosoftSense = $targetValues | Where-Object { $_ -match '^microsoftsense$' }
        
        if ($containsMicrosoftSense -and $policyTypeClassification -ne "Configuration Policy") {
            # Add to results
            $results += [PSCustomObject]@{
                PolicyName = $policyName
                PolicyType = $policyTypeClassification
                Target = $policyType
                Platform = $platform
                IncludeGroups = $includeGroupsText
            }
        }
        else {
            Write-Verbose "Skipping policy '$policyName' - Target '$policyType' does not contain MicrosoftSense or PolicyType is 'Configuration Policy'"
        }
    }
    catch {
        Write-Warning "Failed to process policy '$policyName': $_"
    }
}

Write-Progress -Activity "Processing Endpoint Security Policies" -Completed

if ($results.Count -eq 0) {
    Write-Warning "No policy information found."
    exit 0
}

# Display results summary
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Endpoint Security Policy Assignment Report" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total Policies: $($results.Count)" -ForegroundColor Green

# Prompt for output option
Write-Host "`nOutput Options:" -ForegroundColor Yellow
Write-Host "  [1] Display on screen" -ForegroundColor White
Write-Host "  [2] Export to CSV" -ForegroundColor White
Write-Host "  [3] Both" -ForegroundColor White

do {
    $outputChoice = Read-Host "`nSelect option (1-3)"
    $outputChoiceValid = $outputChoice -match '^[1-3]$'
    if (-not $outputChoiceValid) {
        Write-Host "Invalid selection. Please enter 1, 2, or 3." -ForegroundColor Red
    }
} while (-not $outputChoiceValid)

# Display on screen
if ($outputChoice -eq '1' -or $outputChoice -eq '3') {
    Write-Host "`nPolicy Assignment Report:" -ForegroundColor Cyan
    $results | Sort-Object PolicyName | Format-Table -AutoSize
}

# Export to CSV
if ($outputChoice -eq '2' -or $outputChoice -eq '3') {
    $defaultPath = Join-Path $PSScriptRoot "MDE_EndpointSecurity_Policies_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $csvPath = Read-Host "`nEnter the path for the CSV file (press Enter for default: $defaultPath)"
    
    if ([string]::IsNullOrWhiteSpace($csvPath)) {
        $csvPath = $defaultPath
    }
    
    # Validate and sanitize file path
    try {
        $csvPath = $csvPath.Trim()
        # Ensure .csv extension
        if ($csvPath -notmatch '\.csv$') {
            $csvPath += '.csv'
        }
        
        # Validate path doesn't contain invalid characters or path traversal attempts
        $invalidChars = [System.IO.Path]::GetInvalidPathChars() + @('<', '>', '|', '"')
        $fileName = [System.IO.Path]::GetFileName($csvPath)
        foreach ($char in $invalidChars) {
            if ($fileName.Contains($char)) {
                throw "Invalid character in file path: $char"
            }
        }
        
        # Resolve to absolute path to prevent path traversal
        $csvPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($csvPath)
        
        $results | Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction Stop
        Write-Host "Results exported to: $csvPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}
# Disconnect from Microsoft Graph
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Write-Host "`nScript completed successfully" -ForegroundColor Cyan
