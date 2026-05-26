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
    
    The primary report displays each policy with:
    - Policy name
    - Policy type (as shown in Intune GUI)
    - Target (technologies: mdm, microsoftSense)
    - Platform (Windows, macOS, etc.)
    - Include groups
    - Exclude groups

    Optional reports (opt-in via switches; both are slow):
    - -IncludeDeviceStatus: per-device assignment status (mirrors the Intune
      GUI 'Device assignment status' panel: Success / Pending / Error /
      Conflict / Not applicable per device).
    - -IncludeDevicePolicySettings: per-setting status for each device
      (mirrors the Intune GUI 'Policy Settings' view that lists every
      individual setting and its Succeeded / Error / Conflict / Pending
      result per device). Implies -IncludeDeviceStatus.
    
    Note: This script filters for policies targeting microsoftSense technology.
    Policies may also include mdm, but microsoftSense is required.
    Configuration Policies without microsoftSense are excluded from the report.
    
    Reference: https://learn.microsoft.com/en-us/mem/intune/protect/mde-security-integration
    
    REQUIRED PERMISSIONS:
    - DeviceManagementConfiguration.Read.All (Intune configuration policies)
    - DeviceManagementEndpointSecurity.Read.All (Endpoint Security intents)
    - Group.Read.All (resolve group names and transitive device members)
    
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
    Displays results on screen or exports to CSV. When exporting to CSV and
    the optional reports are requested, two companion files are written
    alongside the main file:
      <basename>_DeviceStatus.csv    (when -IncludeDeviceStatus is set)
      <basename>_SettingStatus.csv   (when -IncludeDevicePolicySettings is set)

.EXAMPLE
    # Fully interactive run. Prompts for -PolicyFilter (supports wildcards
    # like "CORP-*"), then prompts [y/N] for -IncludeDeviceStatus and
    # -IncludeDevicePolicySettings. Defaults skip the slow per-device reports
    # and produce only the policy-level assignment summary.
    .\Get-MDEEndpointSecurityPolicies.ps1

    # Non-interactive policy selection. Generates the policy-level assignment
    # summary for every MDE/Defender Endpoint Security policy whose name
    # matches '*Firewall*'. Per-device reports are skipped (switches not set).
    .\Get-MDEEndpointSecurityPolicies.ps1 -PolicyFilter '*Firewall*'

    # Adds the per-device assignment status report (mirrors the Intune GUI
    # 'Device assignment status' panel) for policies matching 'CORP-*'.
    # Skips all interactive prompts.
    .\Get-MDEEndpointSecurityPolicies.ps1 -PolicyFilter 'CORP-*' -IncludeDeviceStatus

    # Adds both the per-device assignment status report AND the per-setting
    # status report (mirrors the Intune GUI 'Policy Settings' view that lists
    # every individual setting and its Succeeded / Error / Conflict result
    # per device). -IncludeDevicePolicySettings implies -IncludeDeviceStatus.
    # This is the slowest combination and produces the largest result set.
    .\Get-MDEEndpointSecurityPolicies.ps1 -PolicyFilter '*STIG Microsoft Defender*' -IncludeDevicePolicySettings

.NOTES
    Name: Get-MDEEndpointSecurityPolicies.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: January 15, 2026
    Revisions: 
        1.0 - Initial version of Endpoint Security policy reporting script
        1.1 - Added filtering for microsoftSense target (MDE policies only)
        1.2 - Enhanced policy type detection using templateDisplayName from GUI
        1.3 - Added security improvements and file path validation
        1.4 - Added per-device assignment status report (cached-report API
              with assignments-derived fallback) and Exclude group output
        1.5 - Added per-setting status report mirroring the Intune GUI
              'Policy Settings' view; added per-device rollup that fills in
              AssignmentStatus when the cached-report path is unavailable
        1.6 - Replaced -SkipDeviceStatus with opt-in -IncludeDeviceStatus and
              renamed -IncludeSettingStatus to -IncludeDevicePolicySettings
        1.7 - Batched cached-report pipeline; per-setting queue filter for
              Pending/Not applicable; parallel per-setting fetch (ForEach-
              Object -Parallel, throttle 8) with Invoke-RestMethod + 429/503
              backoff; per-phase Stopwatch timing
        1.8 - List<object> for hot-path result collections (avoids O(n^2)
              array reallocation); microsoftSense funnel log line after
              main loop; try/finally cleanup zeros the bearer token and
              disconnects MgGraph on any exit (including Ctrl+C)
#>

[CmdletBinding()]
param(
    # Policy name filter (supports wildcards, e.g. 'CORP-*', '*Firewall*').
    # When supplied, the interactive policy-filter prompt is skipped. Use '*'
    # or omit to retrieve all policies non-interactively.
    [string]$PolicyFilter,

    # Include the per-device assignment status report (mirrors the Intune GUI
    # 'Device assignment status' panel). Off by default - this can be slow on
    # large estates. When supplied, the related interactive prompt is skipped.
    [switch]$IncludeDeviceStatus,

    # Include per-setting status for each device (mirrors the Intune GUI
    # 'Policy Settings' view that lists every individual setting and its
    # Succeeded / Error / Conflict state per device). Off by default - this
    # is the most expensive report and produces a large result set. Implies
    # -IncludeDeviceStatus. When supplied, the related interactive prompt is
    # skipped.
    [switch]$IncludeDevicePolicySettings
)

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

        # Connect to Microsoft Graph with the token and correct environment
        Connect-MgGraph -AccessToken $secureToken -Environment $graphEnvironment -NoWelcome -ErrorAction Stop

        # Clear SecureString token from memory after successful connection
        Clear-Variable -Name secureToken -ErrorAction SilentlyContinue

        Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to connect to Microsoft Graph: $_"
        Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
        Write-Host "  - Ensure you have the required permissions (DeviceManagementConfiguration.Read.All, DeviceManagementEndpointSecurity.Read.All, Group.Read.All)" -ForegroundColor White
        Write-Host "  - Verify your Azure CLI session is active: az account show" -ForegroundColor White
        Write-Host "  - Try logging in again: az login" -ForegroundColor White
        Write-Host "`nIf you continue to see login prompts, the app may need admin consent for the required permissions." -ForegroundColor Yellow
        exit 1
    }
}

# Acquire a raw Graph bearer token for parallel runspaces. ForEach-Object
# -Parallel runs each script block in its own runspace and does NOT share
# the MgGraph connection / $script: variables, so workers need to call Graph
# directly via Invoke-RestMethod with an Authorization header.
$script:graphBearerToken = $null
try {
    $script:graphBearerToken = az account get-access-token --resource-type ms-graph --query accessToken -o tsv 2>$null
} catch { }

if ([string]::IsNullOrWhiteSpace($script:graphBearerToken)) {
    Write-Host "No usable Graph bearer token; parallel per-setting fetch will fall back to serial mode." -ForegroundColor Yellow
}

# Prompt for policy filter (skip when -PolicyFilter was supplied)
if ($PSBoundParameters.ContainsKey('PolicyFilter')) {
    $policyFilter = $PolicyFilter
    if ([string]::IsNullOrWhiteSpace($policyFilter)) { $policyFilter = '*' }
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Policy Selection" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Using -PolicyFilter: $policyFilter" -ForegroundColor Cyan
}
else {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Policy Selection" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Enter a policy name filter (supports wildcards)" -ForegroundColor White
    Write-Host "Examples: CORP-*, *Firewall*, *Antivirus*" -ForegroundColor Gray
    Write-Host "Press Enter to view all policies" -ForegroundColor Gray
    $policyFilter = Read-Host "`nPolicy filter"
}

if ([string]::IsNullOrWhiteSpace($policyFilter)) {
    $policyFilter = "*"
    Write-Host "Retrieving all policies..." -ForegroundColor Cyan
}
else {
    Write-Host "Retrieving policies matching: $policyFilter" -ForegroundColor Cyan
}

# Prompt for per-device assignment status / per-setting status. Skip the
# prompts entirely when either switch was passed on the command line.
# -IncludeDevicePolicySettings implies -IncludeDeviceStatus.
$deviceStatusExplicit  = $PSBoundParameters.ContainsKey('IncludeDeviceStatus')
$settingStatusExplicit = $PSBoundParameters.ContainsKey('IncludeDevicePolicySettings')
$skipPrompts = $deviceStatusExplicit -or $settingStatusExplicit

if ($IncludeDevicePolicySettings) { $IncludeDeviceStatus = $true }

if (-not $skipPrompts) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Report Options" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Include per-device assignment status?" -ForegroundColor White
    Write-Host "  This mirrors the Intune GUI 'Device assignment status' panel but" -ForegroundColor Gray
    Write-Host "  significantly increases runtime (especially for many policies/devices)." -ForegroundColor Gray
    $deviceStatusChoice = Read-Host "Include device status? [y/N]"
    if ($deviceStatusChoice -notmatch '^(y|yes)$') {
        $IncludeDeviceStatus = $false
        Write-Host "Skipping per-device assignment status." -ForegroundColor Yellow
    }
    else {
        $IncludeDeviceStatus = $true
        Write-Host "Including per-device assignment status (this may take a while)." -ForegroundColor Cyan
    }

    # Per-setting status (Intune 'Policy Settings' view: each setting's
    # Succeeded / Error / Conflict result per device)
    if ($IncludeDeviceStatus) {
        Write-Host "`nInclude per-setting status for each device?" -ForegroundColor White
        Write-Host "  This mirrors the Intune GUI 'Policy Settings' view that lists every" -ForegroundColor Gray
        Write-Host "  individual setting (e.g. Allow Cloud Protection, PUA Protection) and" -ForegroundColor Gray
        Write-Host "  its result on each targeted device. Produces a much larger report and" -ForegroundColor Gray
        Write-Host "  takes the longest to run." -ForegroundColor Gray
        $settingStatusChoice = Read-Host "Include per-setting status? [y/N]"
        if ($settingStatusChoice -match '^(y|yes)$') {
            $IncludeDevicePolicySettings = $true
            Write-Host "Including per-setting status for each device (this will take longer)." -ForegroundColor Cyan
        }
        else {
            Write-Host "Skipping per-setting status." -ForegroundColor Yellow
        }
    }
}
else {
    if ($IncludeDevicePolicySettings) {
        Write-Host "`n-IncludeDevicePolicySettings set: including per-device assignment status and per-setting status." -ForegroundColor Cyan
    }
    elseif ($IncludeDeviceStatus) {
        Write-Host "`n-IncludeDeviceStatus set: including per-device assignment status." -ForegroundColor Cyan
    }
    else {
        Write-Host "`nNeither -IncludeDeviceStatus nor -IncludeDevicePolicySettings supplied: per-device reports will be skipped." -ForegroundColor Yellow
    }
}

# Get all Endpoint Security policies
# These are policies created under Endpoint Security node
# Wrap the remainder of the script in try/finally so the bearer token is
# zeroed from memory and the MgGraph session is closed even on Ctrl+C or
# an unhandled error mid-run.
try {
Write-Host "`nRetrieving Endpoint Security policies..." -ForegroundColor Cyan

try {
    $allPolicies = @()
    
    # Get Endpoint Security Intents - Legacy template-based policy type
    # These include: Antivirus, Firewall, Endpoint Detection & Response, Attack Surface Reduction
    # NOTE: The /intents endpoint is legacy. Newer Endpoint Security policies are exposed
    # via /configurationPolicies with a templateReference. A 403 here typically means the
    # calling app (e.g. Azure CLI) lacks DeviceManagementConfiguration.Read.All consent.
    # See: https://learn.microsoft.com/troubleshoot/mem/intune/general/403-error-graph-explorer-query
    Write-Host "Checking Endpoint Security Intents (legacy: Antivirus, Firewall, EDR, ASR)..." -ForegroundColor Cyan
    $configPolicies = @()
    $uri = "$script:graphEndpoint/beta/deviceManagement/intents"
    try {
        $intuneIntents = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
        $configPolicies = $intuneIntents.value

        # Get additional pages if needed
        while ($intuneIntents.'@odata.nextLink') {
            $uri = $intuneIntents.'@odata.nextLink'
            $intuneIntents = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $configPolicies += $intuneIntents.value
        }

        Write-Host "  Found $($configPolicies.Count) Endpoint Security Intent(s)" -ForegroundColor Gray
    }
    catch {
        $statusCode = $null
        if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
        if ($statusCode -eq 403 -or $_.ErrorDetails.Message -match 'Forbidden|not authorized') {
            Write-Warning "Skipping legacy /deviceManagement/intents endpoint - 403 Forbidden."
            Write-Host "  The calling app lacks DeviceManagementConfiguration.Read.All consent for this endpoint." -ForegroundColor Yellow
            Write-Host "  This is the legacy template-based API; newer Endpoint Security policies will still be retrieved" -ForegroundColor Yellow
            Write-Host "  from /configurationPolicies below." -ForegroundColor Yellow
            Write-Host "  To resolve, see: https://learn.microsoft.com/troubleshoot/mem/intune/general/403-error-graph-explorer-query" -ForegroundColor Yellow
            Write-Host "  Or reconnect with: Connect-MgGraph -Scopes 'DeviceManagementConfiguration.Read.All','Group.Read.All'" -ForegroundColor Yellow
        }
        else {
            throw
        }
    }
    
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

# Caches keyed by ID to avoid re-querying Graph for the same group / device list
$script:groupDeviceCache  = @{}
$script:allManagedDevices = $null

# Maps the integer SettingStatus returned by getConfigurationSettingsReport to
# the labels used by the Intune portal's 'Policy Settings' view. Values are
# based on the Intune configurationPolicyDeviceStatus enum: 0=None,
# 1=NotApplicable, 2=Compliant/Succeeded, 3=Remediated, 4=NonCompliant/Error,
# 5=Error, 6=Conflict (legacy ordering observed in some reports may differ;
# unknown values are returned as 'Unknown (<int>)').
function ConvertTo-SettingStatusLabel {
    param($Value)
    # Note: must compare with string on the LHS - PowerShell coerces the RHS to
    # the LHS type, so `0 -eq ''` returns $true (RHS becomes int 0). Putting
    # the empty string first keeps the comparison as a real string test.
    if ($null -eq $Value -or '' -eq [string]$Value) { return '(no status)' }
    $intVal = 0
    if (-not [int]::TryParse([string]$Value, [ref]$intVal)) { return [string]$Value }
    switch ($intVal) {
        # 0 = 'None' in the raw enum; the Intune portal treats this as "device
        # has not reported back yet" and hides the row. We surface it as
        # 'Pending' to match the per-device rollup vocabulary.
        0 { 'Pending' }
        1 { 'Not applicable' }
        2 { 'Succeeded' }
        3 { 'Remediated' }
        4 { 'Conflict' }
        5 { 'Error' }
        6 { 'Pending' }
        default { "Unknown ($intVal)" }
    }
}

# Returns all directory device objects (Entra ID) that are transitive members of
# the given group. Each returned object has at minimum: id, displayName, deviceId.
# 'deviceId' is the Entra device GUID (== managedDevice.azureADDeviceId).
function Get-GroupDeviceMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $GroupId,
        [Parameter(Mandatory)] [string] $GraphEndpoint
    )
    if ($script:groupDeviceCache.ContainsKey($GroupId)) {
        return $script:groupDeviceCache[$GroupId]
    }
    $devices = @()
    try {
        $uri = "$GraphEndpoint/v1.0/groups/$GroupId/transitiveMembers/microsoft.graph.device" +
               '?$select=id,displayName,deviceId,accountEnabled,operatingSystem'
        do {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $devices += $resp.value
            $uri = $resp.'@odata.nextLink'
        } while ($uri)
    }
    catch {
        Write-Verbose "Get-GroupDeviceMembers: failed for group $GroupId : $_"
    }
    $script:groupDeviceCache[$GroupId] = $devices
    return $devices
}

# Returns all Intune managed devices (cached for the lifetime of the script).
# Used to enrich Entra device members with deviceName and lastSyncDateTime.
function Get-AllManagedDevices {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $GraphEndpoint
    )
    if ($null -ne $script:allManagedDevices) { return $script:allManagedDevices }
    $devices = @()
    $uri = "$GraphEndpoint/v1.0/deviceManagement/managedDevices" +
           '?$select=id,deviceName,azureADDeviceId,userId,lastSyncDateTime,operatingSystem,complianceState'
    try {
        do {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            $devices += $resp.value
            $uri = $resp.'@odata.nextLink'
        } while ($uri)
    }
    catch {
        Write-Warning "Failed to retrieve managed devices: $_"
    }
    $script:allManagedDevices = $devices
    return $devices
}

# ---------------------------------------------------------------------------
# Intune cached-report helpers (mirrors the portal's network calls for the
# "Device assignment status" panel: cachedReportConfigurations + getCachedReport).
# Modeled after the working pattern in Get-STIGcompliance.ps1.
# ---------------------------------------------------------------------------

function New-CachedReportConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $ReportId,
        [Parameter(Mandatory)] [string]   $Filter,
        [Parameter(Mandatory)] [string[]] $Select
    )
    $uri = "$script:graphEndpoint/beta/deviceManagement/reports/cachedReportConfigurations"
    $body = @{
        id      = $ReportId
        filter  = $Filter
        orderBy = @()
        select  = $Select
    } | ConvertTo-Json -Depth 5

    # Up to 2 attempts: if the POST fails with 5xx (stale/corrupt config), DELETE
    # the existing entry and retry once. 'already exists' is treated as success.
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
            Write-Verbose "Created cached report configuration: $ReportId"
            return
        }
        catch {
            $msg = $_.Exception.Message
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
            if ($msg -like '*already exists*') {
                Write-Verbose "Cached report configuration '$ReportId' already exists; continuing."
                return
            }
            $statusCode = $null
            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
            if ($attempt -eq 1 -and ($statusCode -ge 500 -or $msg -match 'InternalServerError|Bad Gateway|Service Unavailable')) {
                try {
                    $delUri = "$script:graphEndpoint/beta/deviceManagement/reports/cachedReportConfigurations('$ReportId')"
                    Invoke-MgGraphRequest -Method DELETE -Uri $delUri -ErrorAction SilentlyContinue | Out-Null
                } catch { }
                Start-Sleep -Seconds 2
                continue
            }
            throw
        }
    }
}

function Get-CachedReportStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ReportId)
    $uri = "$script:graphEndpoint/beta/deviceManagement/reports/cachedReportConfigurations('$ReportId')"
    # Retry on transient 5xx (Intune reports backend is flaky on cached configs).
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try { return Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop }
        catch {
            $code = $null
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($attempt -lt 3 -and ($code -ge 500 -or $_.Exception.Message -match 'InternalServerError|Bad Gateway|Service Unavailable')) {
                Start-Sleep -Seconds (2 * $attempt)
                continue
            }
            throw
        }
    }
}

function Wait-ForReportCompletion {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ReportId,
        [int] $MaxRetries        = 10,
        [int] $RetryDelaySeconds = 1
    )
    for ($i = 0; $i -lt $MaxRetries; $i++) {
        $status = Get-CachedReportStatus -ReportId $ReportId
        switch ($status.status) {
            'completed' { Write-Verbose "Report '$ReportId' completed."; return $true }
            'failed'    { Write-Verbose "Report '$ReportId' failed.";    return $false }
            default     { Write-Verbose "Report '$ReportId' status: $($status.status) (attempt $($i+1)/$MaxRetries)" }
        }
        Start-Sleep -Seconds $RetryDelaySeconds
    }
    Write-Verbose "Report '$ReportId' did not complete within timeout."
    return $false
}

function Get-CachedReportResults {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $ReportId,
        [Parameter(Mandatory)] [string]   $Filter,
        [Parameter(Mandatory)] [string[]] $Select,
        [int] $PageSize = 50
    )
    $uri = "$script:graphEndpoint/beta/deviceManagement/reports/getCachedReport"
    $all = @()
    $skip = 0
    while ($true) {
        $body = @{
            id      = $ReportId
            filter  = $Filter
            orderBy = @()
            select  = $Select
            search  = ''
            skip    = $skip
            top     = $PageSize
        } | ConvertTo-Json -Depth 5
        $resp = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                $resp = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json' -ErrorAction Stop
                break
            }
            catch {
                $code = $null
                if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
                if ($attempt -lt 3 -and ($code -ge 500 -or $_.Exception.Message -match 'InternalServerError|Bad Gateway|Service Unavailable')) {
                    Start-Sleep -Seconds (2 * $attempt)
                    continue
                }
                throw
            }
        }
        if (-not $resp.Values -or $resp.Values.Count -eq 0) { break }
        $schema = $resp.Schema
        foreach ($row in $resp.Values) {
            $obj = [ordered]@{}
            for ($j = 0; $j -lt $schema.Count; $j++) {
                $obj[$schema[$j].Column] = $row[$j]
            }
            $all += [PSCustomObject]$obj
        }
        if ($resp.Values.Count -lt $PageSize) { break }
        $skip += $PageSize
    }
    return ,$all
}

# Starts a cached report (POST only - does NOT poll). Returns $true if the
# request was accepted (or the configuration already existed), $false on hard
# failure. Used by the batched device-status pipeline so creation, polling,
# and reading can be overlapped across many policies instead of running
# serially per policy (the big runtime win for large policy counts).
function Start-CachedReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $ReportId,
        [Parameter(Mandatory)] [string]   $Filter,
        [Parameter(Mandatory)] [string[]] $Select
    )
    $uri  = "$script:graphEndpoint/beta/deviceManagement/reports/cachedReportConfigurations"
    $body = @{ id = $ReportId; filter = $Filter; orderBy = @(); select = $Select } | ConvertTo-Json -Depth 5
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        try {
            Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json' -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            $msg = $_.Exception.Message
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
            if ($msg -like '*already exists*') { return $true }
            $statusCode = $null
            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
            if ($attempt -eq 1 -and ($statusCode -ge 500 -or $msg -match 'InternalServerError|Bad Gateway|Service Unavailable')) {
                try {
                    $delUri = "$script:graphEndpoint/beta/deviceManagement/reports/cachedReportConfigurations('$ReportId')"
                    Invoke-MgGraphRequest -Method DELETE -Uri $delUri -ErrorAction SilentlyContinue | Out-Null
                } catch { }
                Start-Sleep -Seconds 2
                continue
            }
            Write-Verbose "Start-CachedReport failed for ${ReportId}: $msg"
            return $false
        }
    }
    return $false
}

# Orchestrator: returns the per-device assignment status rows for a Settings-
# Catalog / modern Endpoint Security policy, mirroring the Intune portal's
# "Device assignment status" panel. Returns $null on any failure so callers can
# fall back to the assignments-derived path. Kept for ad-hoc / single-policy
# use; the main script uses the batched pipeline (Start-CachedReport +
# post-loop sweep) instead for performance on large policy counts.
function Get-ConfigurationPolicyDeviceAssignmentStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $PolicyId)

    $reportId = "DeviceAssignmentStatusByConfigurationPolicy_$PolicyId"
    $filter   = "(PolicyId eq '$PolicyId') and (PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy' or PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration' or PolicyBaseTypeName eq 'DeviceConfigurationAdmxPolicy' or PolicyBaseTypeName eq 'DeviceManagementAuditPolicy')"
    $select   = @(
        'DeviceName','UPN','ReportStatus','PspdpuLastModifiedTimeUtc',
        'IntuneDeviceId','AadDeviceId','DeviceId','Model','UnifiedPolicyPlatformType',
        'UserId','PolicyBaseTypeName','AssignmentStatus'
    )

    try {
        New-CachedReportConfiguration -ReportId $reportId -Filter $filter -Select $select
        if (-not (Wait-ForReportCompletion -ReportId $reportId)) {
            Write-Verbose "Cached report '$reportId' did not complete in time; falling back"
            return $null
        }
        $rows = Get-CachedReportResults -ReportId $reportId -Filter $filter -Select $select -PageSize 50
        Write-Verbose "Cached report PolicyId=$PolicyId returned $(@($rows).Count) device row(s)"
        return $rows
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $parsed = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($parsed.error.message) { $msg = $parsed.error.message }
            } catch { }
        }
        Write-Verbose "Cached report FAILED for PolicyId=${PolicyId}: $msg"
        return $null
    }
}

# Orchestrator: returns per-setting status rows for a single (policy, device)
# pair, mirroring the Intune portal's "Policy Settings" view that lists each
# individual setting (Allow Cloud Protection, PUA Protection, etc.) and its
# Succeeded / Error / Conflict result. Returns $null on any failure.
#
# Returns per-setting status rows (SettingName, SettingStatus, ErrorCode, etc.)
# for a Settings Catalog / modern Endpoint Security configurationPolicy on a
# specific managed device. Uses the synchronous portal endpoint
# /beta/deviceManagement/reports/getConfigurationSettingsReport, which keys
# on the Intune managed device id and the Entra (AAD) user object id.
# Returns $null on failure so callers can degrade gracefully.
function Get-ConfigurationPolicySettingStatusForDevice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $PolicyId,
        [Parameter(Mandatory)] [string] $IntuneDeviceId,
        [string] $AadDeviceId,
        [string] $ReportDeviceId,
        [string] $UserId
    )

    $uri    = "$script:graphEndpoint/beta/deviceManagement/reports/getConfigurationSettingsReport"
    $select = @('SettingName','SettingStatus','ErrorCode','SettingId','SettingInstanceId')
    $requestId = [guid]::NewGuid().ToString()
    $headers = @{
        'client-request-id'      = $requestId
        'x-ms-client-request-id' = $requestId
        'x-ms-command-name'      = 'getReport_/deviceManagement/reports/getConfigurationSettingsReport'
    }

    # Filter requires PolicyId + DeviceId (Intune managed device id) + UserId
    # (Entra user object id). UserId is required for Settings Catalog scope.
    # For devices with no primary user (system account / shared / kiosk), the
    # Intune portal sends the all-zero GUID; mirror that behavior here.
    if ([string]::IsNullOrWhiteSpace($UserId)) {
        $UserId = '00000000-0000-0000-0000-000000000000'
    }
    $filterParts = @("(PolicyId eq '$PolicyId')")
    if ($IntuneDeviceId) { $filterParts += "(DeviceId eq '$IntuneDeviceId')" }
    $filterParts += "(UserId eq '$UserId')"
    $filter = $filterParts -join ' and '

    $all  = @()
    $skip = 0
    $pageSize = 50
    try {
        while ($true) {
            $body = @{
                top    = $pageSize
                skip   = $skip
                select = $select
                orderBy = @()
                search = ''
                filter = $filter
            } | ConvertTo-Json -Depth 5

            $resp = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType 'application/json' -Headers $headers -ErrorAction Stop

            # Invoke-MgGraphRequest sometimes returns the raw JSON string for
            # this report endpoint instead of a deserialized hashtable. Detect
            # and parse so $resp.Schema / $resp.Values are usable downstream.
            if ($resp -is [string]) {
                try { $resp = $resp | ConvertFrom-Json -ErrorAction Stop -AsHashtable } catch {
                    try { $resp = $resp | ConvertFrom-Json -ErrorAction Stop } catch {
                        Write-Verbose "Failed to parse getConfigurationSettingsReport response JSON: $($_.Exception.Message)"
                    }
                }
            }

            if (-not $resp.Values -or $resp.Values.Count -eq 0) { break }
            $schema = $resp.Schema
            foreach ($row in $resp.Values) {
                $obj = [ordered]@{}
                for ($j = 0; $j -lt $schema.Count; $j++) {
                    $obj[$schema[$j].Column] = $row[$j]
                }
                $all += [PSCustomObject]$obj
            }
            if ($resp.Values.Count -lt $pageSize) { break }
            $skip += $pageSize
        }
    }
    catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            try {
                $parsed = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($parsed.error.message) { $msg = $parsed.error.message }
            } catch { }
        }
        Write-Verbose "getConfigurationSettingsReport failed for policy $PolicyId device $IntuneDeviceId : $msg"
        return $null
    }

    if ($all.Count -eq 0) { return $null }
    return ,$all
}

function Get-ConfigurationPolicySettingStatusWithCandidateIds {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $PolicyId,
        [string] $PolicyName,
        [string] $DeviceName,
        [string] $IntuneDeviceId,
        [string] $AadDeviceId,
        [string] $ReportDeviceId,
        [string] $UserId
    )

    $candidateIds = New-Object System.Collections.Generic.List[string]
    foreach ($id in @($ReportDeviceId, $IntuneDeviceId, $AadDeviceId)) {
        if (-not [string]::IsNullOrWhiteSpace($id) -and -not $candidateIds.Contains($id)) {
            $candidateIds.Add($id) | Out-Null
        }
    }

    if ($candidateIds.Count -eq 0) {
        Write-Verbose "Per-setting: $PolicyName / $DeviceName : no DeviceId candidates"
        return $null
    }

    $candidateUserIds = New-Object System.Collections.Generic.List[string]
    foreach ($id in @($UserId, '00000000-0000-0000-0000-000000000000')) {
        if (-not [string]::IsNullOrWhiteSpace($id) -and -not $candidateUserIds.Contains($id)) {
            $candidateUserIds.Add($id) | Out-Null
        }
    }

    foreach ($candidateId in $candidateIds) {
        foreach ($candidateUserId in $candidateUserIds) {
            $rows = Get-ConfigurationPolicySettingStatusForDevice -PolicyId $PolicyId -IntuneDeviceId $candidateId -AadDeviceId $AadDeviceId -ReportDeviceId $ReportDeviceId -UserId $candidateUserId
            if ($rows -and $rows.Count -gt 0) {
                Write-Verbose "Per-setting: $PolicyName / $DeviceName : $($rows.Count) row(s) (DeviceId=$candidateId UserId=$candidateUserId)"
                return ,$rows
            }
        }
    }

    Write-Verbose "Per-setting: $PolicyName / $DeviceName : no rows for any DeviceId/UserId candidate"
    return $null
}

# Build policy assignment report
Write-Host "`nGathering policy assignments...`n" -ForegroundColor Cyan
# Use List<object> instead of @() + '+=': arrays in PowerShell are immutable,
# so '+=' re-allocates and copies on every append - O(n^2) for large estates.
# List<object>.Add() is amortized O(1).
$results              = [System.Collections.Generic.List[object]]::new()
$deviceStatusResults  = [System.Collections.Generic.List[object]]::new()
$settingStatusResults = [System.Collections.Generic.List[object]]::new()
$settingFetchQueue    = [System.Collections.Generic.List[object]]::new()
# Settings-Catalog / modern Endpoint Security policies are processed in a
# batched pipeline AFTER the main loop so all cached reports can cook in
# parallel server-side. Each queue entry captures everything the post-loop
# phase needs (policy id + name + resolved include/exclude groups for the
# fallback path), so we don't have to re-resolve assignments later.
$cachedReportQueue    = [System.Collections.Generic.List[object]]::new()
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
        $excludeGroups = @()
        $includeGroupIds = @()
        $excludeGroupIds = @()
        $includeAllDevices = $false
        $excludeAllDevices = $false

        # Local helper to resolve a group ID to its display name (cached across all policies)
        if (-not $script:groupNameCache) { $script:groupNameCache = @{} }
        $resolveGroupName = {
            param($gid)
            if ($script:groupNameCache.ContainsKey($gid)) { return $script:groupNameCache[$gid] }
            $resolved = $gid
            try {
                $g = Invoke-MgGraphRequest -Method GET -Uri "$script:graphEndpoint/v1.0/groups/$gid`?`$select=displayName" -ErrorAction SilentlyContinue
                if ($g.displayName) { $resolved = $g.displayName }
            }
            catch { }
            $script:groupNameCache[$gid] = $resolved
            return $resolved
        }
        
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

                # Process assignments to get Include and Exclude groups
                foreach ($assignment in $assignments) {
                    $targetType = $assignment.target.'@odata.type'
                    Write-Verbose "  Processing assignment with target type: $targetType"

                    # Determine include vs exclude
                    # - exclusionGroupAssignmentTarget => exclude
                    # - Intent-based policies use an 'intent' field ('apply' = include, 'remove' = exclude)
                    # - Configuration Policies: groupAssignmentTarget = include
                    $isExclude = $false
                    if ($targetType -eq '#microsoft.graph.exclusionGroupAssignmentTarget') {
                        $isExclude = $true
                    }
                    elseif ($assignment.PSObject.Properties['intent'] -and $assignment.intent) {
                        $isExclude = ($assignment.intent -ne 'apply')
                        Write-Verbose "    -> Intent field: $($assignment.intent), IsExclude: $isExclude"
                    }

                    switch ($targetType) {
                        '#microsoft.graph.groupAssignmentTarget' {
                            $gid = $assignment.target.groupId
                            $name = & $resolveGroupName $gid
                            if ($isExclude) {
                                $excludeGroups += $name
                                $excludeGroupIds += $gid
                            } else {
                                $includeGroups += $name
                                $includeGroupIds += $gid
                            }
                            Write-Verbose "    -> Group ($([string]::Join('', @('Exclude','Include')[[int](-not $isExclude)]))): $name"
                        }
                        '#microsoft.graph.exclusionGroupAssignmentTarget' {
                            $gid = $assignment.target.groupId
                            $excludeGroups += (& $resolveGroupName $gid)
                            $excludeGroupIds += $gid
                        }
                        '#microsoft.graph.allLicensedUsersAssignmentTarget' {
                            if ($isExclude) { $excludeGroups += "All Users" } else { $includeGroups += "All Users" }
                        }
                        '#microsoft.graph.allDevicesAssignmentTarget' {
                            if ($isExclude) {
                                $excludeGroups += "All Devices"
                                $excludeAllDevices = $true
                            } else {
                                $includeGroups += "All Devices"
                                $includeAllDevices = $true
                            }
                        }
                        default {
                            Write-Verbose "    -> Unknown target type: $targetType"
                        }
                    }
                }

                Write-Verbose "Policy '$policyName' final include count: $($includeGroups.Count), exclude count: $($excludeGroups.Count)"
            }
            catch {
                Write-Host "  Could not retrieve assignments for policy: $policyName - $_" -ForegroundColor Yellow
            }
        }
        else {
            Write-Verbose "No assignment URI for policy: $policyName"
        }
        
        # Format include / exclude groups (deduplicated)
        $includeGroupsText = if ($includeGroups.Count -gt 0) {
            ($includeGroups | Select-Object -Unique) -join ";"
        }
        else {
            ""
        }
        $excludeGroupsText = if ($excludeGroups.Count -gt 0) {
            ($excludeGroups | Select-Object -Unique) -join ";"
        }
        else {
            ""
        }

        # Only add to results if Target contains MicrosoftSense (may also contain mdm)
        $targetValues = $policyType -split ',' | ForEach-Object { $_.Trim() }
        $containsMicrosoftSense = $targetValues | Where-Object { $_ -match '^microsoftsense$' }

        if ($containsMicrosoftSense -and $policyTypeClassification -ne "Configuration Policy") {
            # Add to results
            $results.Add([PSCustomObject]@{
                PolicyName    = $policyName
                PolicyType    = $policyTypeClassification
                Target        = $policyType
                Platform      = $platform
                IncludeGroups = $includeGroupsText
                ExcludeGroups = $excludeGroupsText
            }) | Out-Null

            # Retrieve per-device assignment status (mirrors Intune GUI "Device assignment status")
            # This is the slowest part of the script - only run when -IncludeDeviceStatus is set.
            if (-not $IncludeDeviceStatus) {
                Write-Verbose "Skipping device assignment status for policy '$policyName' (-IncludeDeviceStatus not set)"
                continue
            }
            try {
                if ($policy.'@odata.type' -eq '#microsoft.graph.deviceManagementIntent' -or $policy.templateId) {
                    # Legacy Endpoint Security Intent: /intents/{id}/deviceStates
                    $statusUri = "$script:graphEndpoint/beta/deviceManagement/intents/$($policy.id)/deviceStates"
                    $statusResp = Invoke-MgGraphRequest -Method GET -Uri $statusUri -ErrorAction Stop
                    $deviceStates = $statusResp.value
                    while ($statusResp.'@odata.nextLink') {
                        $statusResp = Invoke-MgGraphRequest -Method GET -Uri $statusResp.'@odata.nextLink' -ErrorAction Stop
                        $deviceStates += $statusResp.value
                    }

                    foreach ($ds in $deviceStates) {
                        $deviceStatusResults.Add([PSCustomObject]@{
                            PolicyName                 = $policyName
                            DeviceName                 = $ds.deviceDisplayName
                            AssignmentStatus           = $ds.state
                            LastReportModificationTime = $ds.lastReportedDateTime
                        }) | Out-Null
                    }
                    Write-Verbose "Policy '$policyName': retrieved $($deviceStates.Count) device state(s) via /intents endpoint"
                }
                else {
                    # Modern Endpoint Security / Settings Catalog policies.
                    # Queue for the batched post-loop pipeline so all cached
                    # reports cook concurrently server-side instead of one at
                    # a time per policy. Capture the resolved include/exclude
                    # group info now so the fallback path (assignments-derived
                    # device list) doesn't have to re-query assignments later.
                    $cachedReportQueue.Add([PSCustomObject]@{
                        PolicyId          = $policy.id
                        PolicyName        = $policyName
                        IncludeGroupIds   = @($includeGroupIds)
                        ExcludeGroupIds   = @($excludeGroupIds)
                        IncludeAllDevices = $includeAllDevices
                        ExcludeAllDevices = $excludeAllDevices
                    }) | Out-Null
                }
            }
            catch {
                # Try to extract the JSON error message from the response body for diagnostics
                $errMsg = $_.Exception.Message
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                    try {
                        $parsed = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                        if ($parsed.error.message) { $errMsg = $parsed.error.message }
                    } catch { }
                }
                Write-Warning "Could not retrieve device status for policy '$policyName': $errMsg"
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

# Funnel summary: clarify how many of the retrieved policies actually target MDE.
Write-Host ("Policies that target microsoftSense (MDE Endpoint Security): {0} of {1}" -f $results.Count, $allPolicies.Count) -ForegroundColor Gray
if ($results.Count -lt $allPolicies.Count) {
    Write-Host ("  ({0} policy/policies skipped: not a recognized Endpoint Security template or technologies does not include microsoftSense)" -f ($allPolicies.Count - $results.Count)) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Batched device-status pipeline.
# Three phases for the queued Settings-Catalog / modern Endpoint Security
# policies, overlapping the wall-clock cost of the cached-report API:
#   1. POST cachedReportConfigurations for every queued policy (fire-and-
#      forget). The reports then cook in parallel on the Intune backend.
#   2. Single-sweep poll loop: each sweep checks every still-pending report
#      once, then sleeps. Collapses N x (poll-wait) -> ~1 x (poll-wait).
#   3. Fetch results for completed reports; for failed/empty ones, run the
#      assignments-derived fallback using the captured group info.
# ---------------------------------------------------------------------------
if ($IncludeDeviceStatus -and $cachedReportQueue.Count -gt 0) {
    Write-Host ("`nGathering per-device assignment status for {0} policy/policies (batched)..." -f $cachedReportQueue.Count) -ForegroundColor Cyan
    $swDeviceStatus = [System.Diagnostics.Stopwatch]::StartNew()

    $reportSelect   = @(
        'DeviceName','UPN','ReportStatus','PspdpuLastModifiedTimeUtc',
        'IntuneDeviceId','AadDeviceId','DeviceId','Model','UnifiedPolicyPlatformType',
        'UserId','PolicyBaseTypeName','AssignmentStatus'
    )
    $baseTypeFilter = "(PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy' or PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration' or PolicyBaseTypeName eq 'DeviceConfigurationAdmxPolicy' or PolicyBaseTypeName eq 'DeviceManagementAuditPolicy')"

    # --- Phase 1: POST every cached-report config (no waiting) ---
    $pending = New-Object System.Collections.Generic.List[object]
    foreach ($q in $cachedReportQueue) {
        $reportId = "DeviceAssignmentStatusByConfigurationPolicy_$($q.PolicyId)"
        $filter   = "(PolicyId eq '$($q.PolicyId)') and $baseTypeFilter"
        $started  = Start-CachedReport -ReportId $reportId -Filter $filter -Select $reportSelect
        $pending.Add([PSCustomObject]@{
            Queue    = $q
            ReportId = $reportId
            Filter   = $filter
            Status   = if ($started) { 'pending' } else { 'failed' }
        }) | Out-Null
    }
    Write-Host ("  Submitted {0} cached report request(s); polling for completion..." -f $pending.Count) -ForegroundColor Gray

    # --- Phase 2: sweep-poll until all done or timeout (~60s total) ---
    $maxSweeps  = 30
    $sleepSec   = 2
    for ($sweep = 0; $sweep -lt $maxSweeps; $sweep++) {
        $stillPending = @($pending | Where-Object { $_.Status -eq 'pending' })
        if ($stillPending.Count -eq 0) { break }
        foreach ($p in $stillPending) {
            try {
                $st = Get-CachedReportStatus -ReportId $p.ReportId
                switch ($st.status) {
                    'completed' { $p.Status = 'completed' }
                    'failed'    { $p.Status = 'failed' }
                }
            }
            catch {
                # transient - leave pending, retry on next sweep
            }
        }
        $stillPending = @($pending | Where-Object { $_.Status -eq 'pending' })
        if ($stillPending.Count -eq 0) { break }
        Write-Host ("  Waiting on {0}/{1} cached report(s)..." -f $stillPending.Count, $pending.Count) -ForegroundColor Gray
        Start-Sleep -Seconds $sleepSec
    }

    $completed = @($pending | Where-Object { $_.Status -eq 'completed' }).Count
    $failed    = @($pending | Where-Object { $_.Status -ne 'completed' }).Count
    Write-Host ("  Reports completed: {0}; failed/timeout: {1}" -f $completed, $failed) -ForegroundColor Gray

    # --- Phase 3: fetch results / fallback to assignments-derived ---
    foreach ($p in $pending) {
        $q          = $p.Queue
        $policyName = $q.PolicyName
        $reportRows = $null
        if ($p.Status -eq 'completed') {
            try {
                $reportRows = Get-CachedReportResults -ReportId $p.ReportId -Filter $p.Filter -Select $reportSelect -PageSize 1000
            }
            catch {
                Write-Verbose "Get-CachedReportResults failed for $($p.ReportId): $($_.Exception.Message)"
            }
        }

        if ($reportRows -and $reportRows.Count -gt 0) {
            foreach ($r in $reportRows) {
                $ts = $r.PspdpuLastModifiedTimeUtc
                if ([string]::IsNullOrEmpty($ts)) { $ts = $null }
                $deviceStatusResults.Add([PSCustomObject]@{
                    PolicyName                 = $policyName
                    DeviceName                 = $r.DeviceName
                    AssignmentStatus           = $r.ReportStatus
                    LastReportModificationTime = $ts
                }) | Out-Null
                if ($IncludeDevicePolicySettings -and $r.IntuneDeviceId) {
                    $settingFetchQueue.Add([PSCustomObject]@{
                        PolicyId         = $q.PolicyId
                        PolicyName       = $policyName
                        DeviceName       = $r.DeviceName
                        IntuneDeviceId   = $r.IntuneDeviceId
                        AadDeviceId      = $r.AadDeviceId
                        ReportDeviceId   = $r.DeviceId
                        UserId           = $r.UserId
                        AssignmentStatus = $r.ReportStatus
                    }) | Out-Null
                }
            }
            Write-Verbose "Policy '$policyName': retrieved $($reportRows.Count) row(s) via batched cached-report API"
            continue
        }

        # Fallback: assignments-derived device list.
        Write-Verbose "Policy '$policyName': cached-report empty/failed; falling back to assignments-derived list"
        $managedDevices = Get-AllManagedDevices -GraphEndpoint $script:graphEndpoint
        $mdByEntraId = @{}
        foreach ($md in $managedDevices) {
            if ($md.azureADDeviceId) { $mdByEntraId[$md.azureADDeviceId] = $md }
        }

        $inScopeIds = New-Object System.Collections.Generic.HashSet[string]
        if ($q.IncludeAllDevices) {
            foreach ($md in $managedDevices) {
                if ($md.azureADDeviceId) { [void]$inScopeIds.Add($md.azureADDeviceId) }
            }
        }
        foreach ($gid in $q.IncludeGroupIds) {
            foreach ($d in (Get-GroupDeviceMembers -GroupId $gid -GraphEndpoint $script:graphEndpoint)) {
                if ($d.deviceId) { [void]$inScopeIds.Add($d.deviceId) }
            }
        }
        if ($q.ExcludeAllDevices) { $inScopeIds.Clear() }
        foreach ($gid in $q.ExcludeGroupIds) {
            foreach ($d in (Get-GroupDeviceMembers -GroupId $gid -GraphEndpoint $script:graphEndpoint)) {
                if ($d.deviceId) { [void]$inScopeIds.Remove($d.deviceId) }
            }
        }

        foreach ($entraId in $inScopeIds) {
            $md = $mdByEntraId[$entraId]
            if ($md) {
                $deviceStatusResults.Add([PSCustomObject]@{
                    PolicyName                 = $policyName
                    DeviceName                 = $md.deviceName
                    AssignmentStatus           = 'Assigned'
                    LastReportModificationTime = $md.lastSyncDateTime
                }) | Out-Null
                if ($IncludeDevicePolicySettings -and $md.id) {
                    $settingFetchQueue.Add([PSCustomObject]@{
                        PolicyId         = $q.PolicyId
                        PolicyName       = $policyName
                        DeviceName       = $md.deviceName
                        IntuneDeviceId   = $md.id
                        AadDeviceId      = $md.azureADDeviceId
                        ReportDeviceId   = $null
                        UserId           = $md.userId
                        AssignmentStatus = 'Assigned'
                    }) | Out-Null
                }
            }
            else {
                $deviceStatusResults.Add([PSCustomObject]@{
                    PolicyName                 = $policyName
                    DeviceName                 = "(Entra device $entraId — not enrolled in Intune)"
                    AssignmentStatus           = 'Assigned (not enrolled)'
                    LastReportModificationTime = $null
                }) | Out-Null
            }
        }
        Write-Verbose "Policy '$policyName': resolved $($inScopeIds.Count) in-scope device(s) from assignments"
    }
    $swDeviceStatus.Stop()
    Write-Host ("  Device-status phase: {0:N1}s" -f $swDeviceStatus.Elapsed.TotalSeconds) -ForegroundColor DarkGray
}

# Fetch per-setting status (Intune "Policy Settings" view) for each
# (policy, device) pair queued during the assignment-status pass.
if ($IncludeDevicePolicySettings -and $settingFetchQueue.Count -gt 0) {
    # Skip per-setting fetches for devices whose AssignmentStatus indicates
    # the device has not reported back or has no data to report. The
    # getConfigurationSettingsReport endpoint returns empty for these and
    # we'd otherwise pay a full round-trip per device to confirm an empty
    # result. Items added via the assignments-fallback path carry
    # AssignmentStatus='Assigned' (no real check-in state) - those are kept
    # because we don't know whether they have data until we ask.
    $skipStatuses = @('Pending','Not applicable','NotApplicable','notApplicable')
    $originalQueueCount = $settingFetchQueue.Count
    $filteredQueue = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $settingFetchQueue) {
        if ($skipStatuses -notcontains $item.AssignmentStatus) {
            $filteredQueue.Add($item) | Out-Null
        }
    }
    $settingFetchQueue = $filteredQueue
    $skippedCount = $originalQueueCount - $settingFetchQueue.Count
    if ($skippedCount -gt 0) {
        Write-Host ("  Skipping {0} device(s) with status Pending/Not applicable (no per-setting data expected)." -f $skippedCount) -ForegroundColor Gray
    }
}
if ($IncludeDevicePolicySettings -and $settingFetchQueue.Count -gt 0) {
    Write-Host "`nGathering per-setting status for $($settingFetchQueue.Count) policy/device pair(s)..." -ForegroundColor Cyan
    $swSettings = [System.Diagnostics.Stopwatch]::StartNew()
    $sOkCount    = 0
    $sEmptyCount = 0
    # Per-(policy,device) raw status list, used to compute a per-device
    # rollup status (mirrors the Intune portal's Pending/Success/Error/
    # Conflict roll-up shown on the policy overview).
    $deviceSettingRollup = @{}
    $prevProgress      = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        $useParallel = -not [string]::IsNullOrWhiteSpace($script:graphBearerToken)
        $rawResults  = $null

        if ($useParallel) {
            # Parallel fetch. Each runspace re-implements the candidate-ID /
            # candidate-UserId loop inline (it can't call script-scope helpers
            # or use Invoke-MgGraphRequest, since the MgGraph connection is
            # not shared). Workers call /reports/getConfigurationSettingsReport
            # via Invoke-RestMethod with a Bearer header and honor 429/503
            # backoff. Throttle 8 is conservative against Intune reports
            # throttling; raise if you don't see 429s, lower if you do.
            $bearer  = $script:graphBearerToken
            $graphEp = $script:graphEndpoint
            Write-Host ("  Using parallel fetch (ThrottleLimit=8)...") -ForegroundColor DarkGray
            $rawResults = $settingFetchQueue | ForEach-Object -ThrottleLimit 8 -Parallel {
                $t      = $_
                $token  = $using:bearer
                $ep     = $using:graphEp
                $uri    = "$ep/beta/deviceManagement/reports/getConfigurationSettingsReport"
                $select = @('SettingName','SettingStatus','ErrorCode','SettingId','SettingInstanceId')

                $candidateIds = @()
                foreach ($id in @($t.ReportDeviceId, $t.IntuneDeviceId, $t.AadDeviceId)) {
                    if (-not [string]::IsNullOrWhiteSpace($id) -and ($candidateIds -notcontains $id)) {
                        $candidateIds += $id
                    }
                }
                if ($candidateIds.Count -eq 0) {
                    return [PSCustomObject]@{ Item = $t; Rows = $null }
                }

                $userId = if ([string]::IsNullOrWhiteSpace($t.UserId)) { '00000000-0000-0000-0000-000000000000' } else { $t.UserId }
                $candidateUsers = @($userId)
                if ($userId -ne '00000000-0000-0000-0000-000000000000') {
                    $candidateUsers += '00000000-0000-0000-0000-000000000000'
                }

                $allRows = $null
                foreach ($cid in $candidateIds) {
                    foreach ($uid in $candidateUsers) {
                        $filter = "(PolicyId eq '$($t.PolicyId)') and (DeviceId eq '$cid') and (UserId eq '$uid')"
                        $reqId  = [guid]::NewGuid().ToString()
                        $headers = @{
                            Authorization            = "Bearer $token"
                            'client-request-id'      = $reqId
                            'x-ms-client-request-id' = $reqId
                            'x-ms-command-name'      = 'getReport_/deviceManagement/reports/getConfigurationSettingsReport'
                        }
                        $skip = 0
                        $pageSize = 50
                        $collected = @()
                        $hardFail  = $false
                        while (-not $hardFail) {
                            $body = @{
                                top     = $pageSize
                                skip    = $skip
                                select  = $select
                                orderBy = @()
                                search  = ''
                                filter  = $filter
                            } | ConvertTo-Json -Depth 5 -Compress
                            $resp = $null
                            $retry = 0
                            while ($true) {
                                try {
                                    $resp = Invoke-RestMethod -Method POST -Uri $uri -Headers $headers -ContentType 'application/json' -Body $body -ErrorAction Stop
                                    break
                                } catch {
                                    $code = $null
                                    try { if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode } } catch {}
                                    if (($code -eq 429 -or $code -eq 503 -or $code -ge 500) -and $retry -lt 4) {
                                        $ra = 0
                                        try {
                                            $h = $_.Exception.Response.Headers
                                            if ($h -and $h['Retry-After']) { $ra = [int]$h['Retry-After'] }
                                        } catch {}
                                        if ($ra -le 0) { $ra = [Math]::Min(30, [Math]::Pow(2, $retry + 1)) }
                                        Start-Sleep -Seconds $ra
                                        $retry++
                                        continue
                                    }
                                    $hardFail = $true
                                    break
                                }
                            }
                            if ($hardFail -or -not $resp) { break }
                            if ($resp -is [string]) {
                                try { $resp = $resp | ConvertFrom-Json -ErrorAction Stop } catch { break }
                            }
                            if (-not $resp.Values -or $resp.Values.Count -eq 0) { break }
                            $schema = $resp.Schema
                            foreach ($r in $resp.Values) {
                                $obj = [ordered]@{}
                                for ($j = 0; $j -lt $schema.Count; $j++) { $obj[$schema[$j].Column] = $r[$j] }
                                $collected += [PSCustomObject]$obj
                            }
                            if ($resp.Values.Count -lt $pageSize) { break }
                            $skip += $pageSize
                        }
                        if ($collected.Count -gt 0) { $allRows = $collected; break }
                    }
                    if ($allRows) { break }
                }

                [PSCustomObject]@{ Item = $t; Rows = $allRows }
            }
        }
        else {
            # Serial fallback (no bearer token available).
            Write-Host ("  Using serial fetch (no bearer token for parallel)...") -ForegroundColor DarkGray
            $rawResults = foreach ($t in $settingFetchQueue) {
                $rows = Get-ConfigurationPolicySettingStatusWithCandidateIds -PolicyId $t.PolicyId -PolicyName $t.PolicyName -DeviceName $t.DeviceName -IntuneDeviceId $t.IntuneDeviceId -AadDeviceId $t.AadDeviceId -ReportDeviceId $t.ReportDeviceId -UserId $t.UserId
                [PSCustomObject]@{ Item = $t; Rows = $rows }
            }
        }

        # Drain results (serial, main thread) into the result collections.
        foreach ($res in $rawResults) {
            $t    = $res.Item
            $rows = $res.Rows
            if ($rows -and $rows.Count -gt 0) {
                $sOkCount++
                $rollupKey = "$($t.PolicyName)|$($t.DeviceName)"
                if (-not $deviceSettingRollup.ContainsKey($rollupKey)) {
                    $deviceSettingRollup[$rollupKey] = New-Object System.Collections.Generic.List[int]
                }
                foreach ($r in $rows) {
                    $rawStatus = $r.SettingStatus
                    $settingStatusResults.Add([PSCustomObject]@{
                        PolicyName    = $t.PolicyName
                        DeviceName    = $t.DeviceName
                        SettingName   = $r.SettingName
                        SettingStatus = (ConvertTo-SettingStatusLabel $rawStatus)
                        ErrorCode     = $r.ErrorCode
                    }) | Out-Null
                    $intVal = -1
                    if ([int]::TryParse([string]$rawStatus, [ref]$intVal)) {
                        $deviceSettingRollup[$rollupKey].Add($intVal) | Out-Null
                    }
                }
            }
            else {
                $sEmptyCount++
            }
        }
    }
    finally {
        $ProgressPreference = $prevProgress
    }
    $swSettings.Stop()
    Write-Host ("`nPer-setting summary: {0} device(s) with data, {1} empty ({2:N1}s)" -f $sOkCount, $sEmptyCount, $swSettings.Elapsed.TotalSeconds) -ForegroundColor Cyan
    if ($settingStatusResults.Count -eq 0) {
        Write-Warning "Per-setting status report returned no rows. See summary above for whether the API errored or returned empty results."
    }

    # Roll up per-setting statuses to a single per-device AssignmentStatus
    # whenever the cached-report path failed (which leaves the placeholder
    # 'Assigned' / 'Assigned (not enrolled)' in $deviceStatusResults). This
    # mirrors the portal's overview status: any Error/Conflict wins; else any
    # None(0) -> Pending; else Success.
    if ($deviceSettingRollup.Count -gt 0) {
        # Rebuild $deviceStatusResults so we don't depend on in-place index
        # assignment against a possibly fixed-size Object[].
        $updated = New-Object System.Collections.Generic.List[object]
        foreach ($row in $deviceStatusResults) {
            $key = "$($row.PolicyName)|$($row.DeviceName)"
            $isPlaceholder = ($row.AssignmentStatus -eq 'Assigned' -or $row.AssignmentStatus -eq 'Assigned (not enrolled)')
            if ($isPlaceholder -and $deviceSettingRollup.ContainsKey($key)) {
                $statuses = $deviceSettingRollup[$key]
                if ($statuses.Count -gt 0) {
                    $rollup =
                        if     ($statuses -contains 5) { 'Error' }
                        elseif ($statuses -contains 4) { 'Conflict' }
                        elseif ($statuses -contains 0) { 'Pending' }
                        elseif ($statuses -contains 3) { 'Remediated' }
                        elseif ($statuses -contains 2) { 'Success' }
                        else                           { 'Not applicable' }
                    $updated.Add([PSCustomObject]@{
                        PolicyName                 = $row.PolicyName
                        DeviceName                 = $row.DeviceName
                        AssignmentStatus           = $rollup
                        LastReportModificationTime = $row.LastReportModificationTime
                    }) | Out-Null
                    continue
                }
            }
            $updated.Add($row) | Out-Null
        }
        $deviceStatusResults = $updated
    }
}
elseif ($IncludeDevicePolicySettings) {
    Write-Host "`nNo policy/device pairs available for per-setting status (none had an IntuneDeviceId)." -ForegroundColor Yellow
}

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

    if ($deviceStatusResults.Count -gt 0) {
        Write-Host "`nDevice Assignment Status Report:" -ForegroundColor Cyan
        $deviceStatusResults | Sort-Object PolicyName, DeviceName | Format-Table -AutoSize
    }
    else {
        Write-Host "`nNo device assignment status data was returned." -ForegroundColor Yellow
    }

    if ($IncludeDevicePolicySettings) {
        if ($settingStatusResults.Count -gt 0) {
            Write-Host "`nPer-Setting Status Report:" -ForegroundColor Cyan
            $settingStatusResults | Sort-Object PolicyName, DeviceName, SettingName | Format-Table -AutoSize
        }
        else {
            Write-Host "`nNo per-setting status data was returned." -ForegroundColor Yellow
        }
    }
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

        # Also export device status report alongside the policy report
        if ($deviceStatusResults.Count -gt 0) {
            $deviceCsvPath = [System.IO.Path]::ChangeExtension($csvPath, $null).TrimEnd('.') + '_DeviceStatus.csv'
            $deviceStatusResults | Sort-Object PolicyName, DeviceName |
                Export-Csv -Path $deviceCsvPath -NoTypeInformation -ErrorAction Stop
            Write-Host "Device assignment status exported to: $deviceCsvPath" -ForegroundColor Green
        }

        # Also export per-setting status report when requested
        if ($IncludeDevicePolicySettings -and $settingStatusResults.Count -gt 0) {
            $settingCsvPath = [System.IO.Path]::ChangeExtension($csvPath, $null).TrimEnd('.') + '_SettingStatus.csv'
            $settingStatusResults | Sort-Object PolicyName, DeviceName, SettingName |
                Export-Csv -Path $settingCsvPath -NoTypeInformation -ErrorAction Stop
            Write-Host "Per-setting status exported to: $settingCsvPath" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}
}
finally {
    # Always zero the bearer token and disconnect, even on Ctrl+C / unhandled error.
    if ($script:graphBearerToken) {
        Clear-Variable -Name graphBearerToken -Scope Script -ErrorAction SilentlyContinue
    }
    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "`nScript completed successfully" -ForegroundColor Cyan
