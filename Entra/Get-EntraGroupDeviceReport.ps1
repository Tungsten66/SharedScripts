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
    Generates reports on Entra ID security groups and their device members from Administrative Units or all Entra ID.

.DESCRIPTION
    This script connects to Microsoft Graph using Azure CLI token authentication,
    allows you to select an Administrative Unit, and displays all groups within that AU
    including their Name, Object ID, and Device Count.
    Results can be filtered by group name and exported to CSV format.
    
    PREREQUISITES:
    - Azure CLI installed and configured for your environment
      * Download MSI installer: https://aka.ms/installazurecliwindows
      * Or install via winget: winget install -e --id Microsoft.AzureCLI
      * Restart PowerShell after installation
    - User logged in via 'az login'
    - For USGovernment: az cloud set --name AzureUSGovernment
    - PowerShell Modules (install if missing):
      * Microsoft.Graph.Authentication
      * Microsoft.Graph.Identity.DirectoryManagement
      * Microsoft.Graph.Groups
      
      Install with: Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups -Scope CurrentUser
    
    REQUIRED ENTRA ID ROLE PERMISSIONS:
    Users running this script need ONE of these roles assigned:
    - Global Reader (recommended - read-only access)
    - Groups Administrator
    - Privileged Role Administrator
    - Global Administrator
    
    SETUP INSTRUCTIONS:
    1. Install Azure CLI if not already installed
    2. Configure Azure CLI for your cloud environment:
       - Commercial: az cloud set --name AzureCloud
       - USGovernment: az cloud set --name AzureUSGovernment
    3. Login once at the start of your session: az login or az login --use-device-code
    4. Run this script as many times as needed - no additional authentication required
    
    The script uses the existing Azure CLI session, eliminating repeated authentication prompts
    while maintaining security through Azure CLI's credential management

.PARAMETER
    AdministrativeUnit - Optional. Name of the Administrative Unit to query.
                         If not specified, searches all security groups in Entra ID.
    
    SearchGroupName - Optional filter to search for groups by name (supports wildcards).
    
    ReportType - Type of report to generate:
                 'GroupSummary' (default) - Shows groups with device counts
                 'DeviceMembers' - Shows all device members with SecurityGroupName, DeviceName, OS
    
    ExportCSV - Optional. Path to export results to CSV file.
                Specify a path, or leave empty to use default filename.
                When this parameter is used, script runs non-interactively.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    Displays results in console and optionally exports to CSV files.

.EXAMPLE
    .\Get-EntraGroupDeviceReport.ps1
    
    Lists all security groups in Entra ID using existing Azure CLI session.
    Prompts interactively for Administrative Unit, group filter, report type, and output options.

.NOTES
    Name: Get-EntraGroupDeviceReport.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: November 18, 2025
    Revisions: 
        1.0 - Initial version with interactive authentication
        1.1 - Added app registration support with certificate authentication
        2.0 - Simplified to use Azure CLI token authentication only
              Removed environment selection and certificate authentication
              Optimized for teams running multiple reports daily
        2.1 - Fixed filename references, optimized group filtering with OData,
              added verbose logging support
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AdministrativeUnit,
    
    [Parameter(Mandatory = $false)]
    [string]$SearchGroupName,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('GroupSummary', 'DeviceMembers')]
    [string]$ReportType = 'GroupSummary',
    
    [Parameter(Mandatory = $false)]
    [string]$ExportCSV
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups

# Verify Azure CLI is installed and user is logged in
Write-Host "`nVerifying Azure CLI session..." -ForegroundColor Cyan
Write-Verbose "Checking for active Azure CLI session"

try {
    $azAccount = az account show 2>$null | ConvertFrom-Json
    if ($null -eq $azAccount) {
        Write-Verbose "No active Azure CLI session detected"
        Write-Error "No active Azure CLI session found. Please run 'az login' first."
        Write-Host "`nSetup Instructions:" -ForegroundColor Yellow
        Write-Host "  1. For Commercial Cloud: az cloud set --name AzureCloud" -ForegroundColor White
        Write-Host "  2. For GCC High: az cloud set --name AzureUSGovernment" -ForegroundColor White
        Write-Host "  3. Login: az login" -ForegroundColor White
        Write-Host "  4. Run this script again" -ForegroundColor White
        exit 1
    }
    
    $cloudName = az cloud show --query name -o tsv
    Write-Verbose "Detected Azure Cloud: $cloudName"
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
        'China' { 'https://microsoftgraph.chinacloudapi.cn'; break }
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
Write-Verbose "Requesting access token for Microsoft Graph from Azure CLI"

try {
    # Get access token from Azure CLI for the correct cloud
    $token = az account get-access-token --resource-type ms-graph --query accessToken -o tsv
    Write-Verbose "Successfully retrieved access token"
    
    if ([string]::IsNullOrWhiteSpace($token)) {
        throw "Failed to retrieve access token from Azure CLI"
    }
    
    # Convert token to SecureString
    $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
    
    # Clear token from memory
    Clear-Variable -Name token -ErrorAction SilentlyContinue
    
    # Connect to Microsoft Graph with the token and correct environment
    Write-Verbose "Connecting to Microsoft Graph with environment: $graphEnvironment"
    Connect-MgGraph -AccessToken $secureToken -Environment $graphEnvironment -NoWelcome -ErrorAction Stop
    Write-Verbose "Microsoft Graph connection established successfully"
    Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    Write-Host "`nTroubleshooting:" -ForegroundColor Yellow
    Write-Host "  - Ensure you have the required Entra ID role (Global Reader recommended)" -ForegroundColor White
    Write-Host "  - Verify your Azure CLI session is active: az account show" -ForegroundColor White
    Write-Host "  - Try logging in again: az login" -ForegroundColor White
    exit 1
}

# If no parameters provided, prompt for input
if (-not $PSBoundParameters.ContainsKey('AdministrativeUnit') -and 
    -not $PSBoundParameters.ContainsKey('SearchGroupName') -and 
    -not $PSBoundParameters.ContainsKey('ReportType') -and
    -not $PSBoundParameters.ContainsKey('ExportCSV')) {
    
    Write-Host "`nInteractive Mode" -ForegroundColor Yellow
    Write-Host "================" -ForegroundColor Yellow
    
    # Prompt for Administrative Unit
    $auInput = Read-Host "`nEnter Administrative Unit name (leave blank to search all Entra ID)"
    if (-not [string]::IsNullOrWhiteSpace($auInput)) {
        $AdministrativeUnit = $auInput.Trim().Trim('"').Trim("'")
    }
    
    # Prompt for group name filter
    $groupInput = Read-Host "Filter by group name (leave blank for all groups, supports wildcards)"
    if (-not [string]::IsNullOrWhiteSpace($groupInput)) {
        $SearchGroupName = $groupInput.Trim().Trim('"').Trim("'")
    }
    
    # Prompt for report type
    Write-Host "`nSelect Report Type:" -ForegroundColor Yellow
    Write-Host "  [1] Group Summary (default) - Shows groups with device counts" -ForegroundColor White
    Write-Host "  [2] Device Members - Shows devices with SecurityGroupName, DeviceName, OS" -ForegroundColor White
    $reportInput = Read-Host "Select report type (1-2, or press Enter for default)"
    
    if ($reportInput -eq '2') {
        $ReportType = 'DeviceMembers'
    }
    else {
        $ReportType = 'GroupSummary'
    }
    
    Write-Host ""
}

# Get groups based on whether AU is specified
if ($AdministrativeUnit) {
    # Trim whitespace and remove surrounding quotes if present
    $auName = $AdministrativeUnit.Trim().Trim('"').Trim("'")
    
    # Sanitize input to prevent OData filter injection
    $auNameSanitized = $auName.Replace("'", "''")
    
    # Get the Administrative Unit by name
    Write-Host "`nSearching for Administrative Unit: '$auName'..." -ForegroundColor Cyan    Write-Verbose "Using OData filter: displayName eq '$auNameSanitized'"    try {
        $selectedAdminUnit = Get-MgDirectoryAdministrativeUnit -Filter "displayName eq '$auNameSanitized'" -ErrorAction Stop
        
        if ($null -eq $selectedAdminUnit) {
            Write-Error "Administrative Unit '$auName' not found."
            Disconnect-MgGraph | Out-Null
            exit 1
        }
        
        Write-Host "Found Administrative Unit: $($selectedAdminUnit.DisplayName)" -ForegroundColor Green
        Write-Host "Object ID: $($selectedAdminUnit.Id)" -ForegroundColor Gray
    }
    catch {
        Write-Error "Failed to retrieve Administrative Unit: $_"
        Disconnect-MgGraph | Out-Null
        exit 1
    }
    
    # Get all groups in the selected Administrative Unit
    Write-Host "`nRetrieving groups from Administrative Unit..." -ForegroundColor Cyan    Write-Verbose "Querying AU members for ID: $($selectedAdminUnit.Id)"    try {
        $auGroups = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $selectedAdminUnit.Id -All -ErrorAction Stop | 
            Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group' }
        
        if ($auGroups.Count -eq 0) {
            Write-Warning "No groups found in this Administrative Unit."
            Disconnect-MgGraph | Out-Null
            exit 0
        }
        
        Write-Host "Found $($auGroups.Count) group(s)" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to retrieve groups from Administrative Unit: $_"
        Disconnect-MgGraph | Out-Null
        exit 1
    }
    
    $scopeDescription = "Administrative Unit: $($selectedAdminUnit.DisplayName)"
}
else {
    # Get all security groups in Entra ID
    
    # Build optimized OData filter with group name if provided
    $filter = "securityEnabled eq true"
    $filterApplied = $false
    
    if ($SearchGroupName) {
        # Convert wildcard to OData filter (only supports startswith for simple patterns)
        if ($SearchGroupName -match '^([^*?]+)\*$') {
            # Pattern like "Desktop*" - use startswith
            $prefix = $matches[1].Replace("'", "''")
            $filter += " and startswith(displayName, '$prefix')"
            $filterApplied = $true
            Write-Host "`nRetrieving security groups matching '$SearchGroupName' from Entra ID..." -ForegroundColor Cyan
            Write-Verbose "Using optimized OData filter: $filter"
        }
        elseif ($SearchGroupName -notmatch '[*?]') {
            # Exact match - no wildcards
            $exact = $SearchGroupName.Replace("'", "''")
            $filter += " and displayName eq '$exact'"
            $filterApplied = $true
            Write-Host "`nRetrieving security group '$SearchGroupName' from Entra ID..." -ForegroundColor Cyan
            Write-Verbose "Using optimized OData filter: $filter"
        }
        else {
            # Complex wildcard pattern - will filter client-side
            Write-Host "`nRetrieving all security groups from Entra ID..." -ForegroundColor Cyan
            Write-Verbose "Complex wildcard pattern detected - will filter client-side after retrieval"
        }
    }
    else {
        Write-Host "`nRetrieving all security groups from Entra ID..." -ForegroundColor Cyan
    }
    
    try {
        Write-Verbose "Executing query with filter: $filter"
        $allGroups = Get-MgGroup -Filter $filter -All -ErrorAction Stop
        
        if ($allGroups.Count -eq 0) {
            Write-Warning "No security groups found in Entra ID."
            Disconnect-MgGraph | Out-Null
            exit 0
        }
        
        # Convert to same format as AU groups for consistency
        $auGroups = $allGroups | ForEach-Object { [PSCustomObject]@{ Id = $_.Id } }
        
        Write-Host "Found $($auGroups.Count) security group(s)" -ForegroundColor Green
        Write-Verbose "Retrieved $($auGroups.Count) groups from Entra ID"
    }
    catch {
        Write-Error "Failed to retrieve groups from Entra ID: $_"
        Disconnect-MgGraph | Out-Null
        exit 1
    }
    
    $scopeDescription = "All Entra ID Security Groups"
    $selectedAdminUnit = [PSCustomObject]@{ DisplayName = "All Entra ID" }
}

# Apply group name filter client-side only if needed (AU queries or complex wildcards not already filtered)
if ($SearchGroupName -and ($AdministrativeUnit -or (-not $filterApplied -and $SearchGroupName -match '[*?]'))) {
    Write-Host "`nFiltering groups by name: '$SearchGroupName'..." -ForegroundColor Cyan
    Write-Verbose "Performing client-side filtering for pattern: $SearchGroupName"
    
    $beforeCount = $auGroups.Count
    $auGroups = $auGroups | Where-Object { 
        # Get the group display name to filter
        $groupObj = Get-MgGroup -GroupId $_.Id -ErrorAction SilentlyContinue
        $groupObj.DisplayName -like $SearchGroupName
    }
    
    Write-Verbose "Filtered from $beforeCount to $($auGroups.Count) groups"
    
    if ($auGroups.Count -eq 0) {
        Write-Warning "No groups found matching the search criteria."
        Disconnect-MgGraph | Out-Null
        exit 0
    }
    
    Write-Host "Found $($auGroups.Count) matching group(s)" -ForegroundColor Green
}

# Build report based on selected type
if ($ReportType -eq 'DeviceMembers') {
    Write-Host "`nGathering device members from all security groups..." -ForegroundColor Cyan
    Write-Verbose "Starting DeviceMembers report generation for $($auGroups.Count) groups"
    $results = [System.Collections.ArrayList]::new()
    $counter = 0
    
    foreach ($auGroup in $auGroups) {
        $counter++
        Write-Progress -Activity "Processing Groups" -Status "Group $counter of $($auGroups.Count)" -PercentComplete (($counter / $auGroups.Count) * 100)
        
        try {
            # Get full group details
            $group = Get-MgGroup -GroupId $auGroup.Id -ErrorAction Stop
            
            # Get all members
            $members = Get-MgGroupMember -GroupId $auGroup.Id -All -ErrorAction SilentlyContinue
            
            # Filter device members
            $deviceMembers = $members | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.device' }
            
            foreach ($deviceMember in $deviceMembers) {
                try {
                    # Get full device details using the correct cmdlet for the environment
                    $device = Get-MgDevice -DeviceId $deviceMember.Id -ErrorAction Stop
                    
                    [void]$results.Add([PSCustomObject]@{
                        SecurityGroupName = $group.DisplayName
                        DeviceName        = $device.DisplayName
                        OS                = $device.OperatingSystem
                    })
                }
                catch {
                    Write-Warning "Failed to retrieve device details for $($deviceMember.Id): $_"
                }
            }
        }
        catch {
            Write-Warning "Failed to retrieve details for group $($auGroup.Id): $_"
        }
    }
    
    Write-Progress -Activity "Processing Groups" -Completed
}
else {
    # GroupSummary report
    Write-Host "`nGathering group details and device counts..." -ForegroundColor Cyan
    Write-Verbose "Starting GroupSummary report generation for $($auGroups.Count) groups"
    $results = [System.Collections.ArrayList]::new()
    $counter = 0
    
    foreach ($auGroup in $auGroups) {
        $counter++
        Write-Progress -Activity "Processing Groups" -Status "Group $counter of $($auGroups.Count)" -PercentComplete (($counter / $auGroups.Count) * 100)
        
        try {
            # Get full group details
            $group = Get-MgGroup -GroupId $auGroup.Id -ErrorAction Stop
            
            # Get device count (members that are devices)
            $members = Get-MgGroupMember -GroupId $auGroup.Id -All -ErrorAction SilentlyContinue
            $deviceCount = ($members | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.device' }).Count
            
            [void]$results.Add([PSCustomObject]@{
                Name        = $group.DisplayName
                ObjectId    = $group.Id
                DeviceCount = $deviceCount
            })
        }
        catch {
            Write-Warning "Failed to retrieve details for group $($auGroup.Id): $_"
        }
    }
    
    Write-Progress -Activity "Processing Groups" -Completed
}

# Display results summary
Write-Host "`n========================================" -ForegroundColor Cyan
if ($ReportType -eq 'DeviceMembers') {
    Write-Host "Device Members - $scopeDescription" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total device entries: $($results.Count)" -ForegroundColor Green
}
else {
    Write-Host "Groups - $scopeDescription" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total groups: $($results.Count)" -ForegroundColor Green
}

# Handle viewing and exporting based on parameters or interactively
if ($PSBoundParameters.ContainsKey('ExportCSV')) {
    # Non-interactive export mode
    if ([string]::IsNullOrWhiteSpace($ExportCSV)) {
        $ExportCSV = Join-Path $PSScriptRoot "AdminUnit_Groups_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    }
    
    try {
        # Validate file path for security
        $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExportCSV)
        
        # Ensure .csv extension
        if ([System.IO.Path]::GetExtension($resolvedPath) -ne '.csv') {
            $resolvedPath = [System.IO.Path]::ChangeExtension($resolvedPath, '.csv')
            Write-Host "File extension changed to .csv: $resolvedPath" -ForegroundColor Yellow
        }
        
        # Verify parent directory exists or can be created
        $parentDir = Split-Path -Path $resolvedPath -Parent
        if (-not (Test-Path -Path $parentDir)) {
            New-Item -Path $parentDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        
        Write-Verbose "Exporting $($results.Count) records to CSV: $resolvedPath"
        $results | Export-Csv -Path $resolvedPath -NoTypeInformation -ErrorAction Stop
        Write-Host "Results exported to CSV: $resolvedPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to export CSV: $_"
    }
}
else {
    # Interactive mode - prompt for viewing/exporting
    Write-Host "`nView Results:" -ForegroundColor Yellow
    Write-Host "  [1] Display on screen" -ForegroundColor White
    Write-Host "  [2] Export to CSV" -ForegroundColor White
    Write-Host "  [3] Both" -ForegroundColor White
    Write-Host "  [4] Skip" -ForegroundColor White

    do {
        $viewChoice = Read-Host "`nSelect option (1-4)"
        $viewChoiceValid = $viewChoice -match '^[1-4]$'
        if (-not $viewChoiceValid) {
            Write-Host "Invalid selection. Please enter 1, 2, 3, or 4." -ForegroundColor Red
        }
    } while (-not $viewChoiceValid)

    # Display on screen
    if ($viewChoice -eq '1' -or $viewChoice -eq '3') {
        Write-Host "`nDisplaying results..." -ForegroundColor Cyan
        if ($ReportType -eq 'DeviceMembers') {
            $results | Sort-Object SecurityGroupName, DeviceName | Format-Table -AutoSize
        }
        else {
            $results | Sort-Object Name | Format-Table -AutoSize
        }
    }

    # Export to CSV
    if ($viewChoice -eq '2' -or $viewChoice -eq '3') {
        $defaultPath = Join-Path $PSScriptRoot "AdminUnit_Groups_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $csvPath = Read-Host "`nEnter the path for the CSV file (press Enter for default: $defaultPath)"
        
        if ([string]::IsNullOrWhiteSpace($csvPath)) {
            $csvPath = $defaultPath
        }
        
        # Validate file path for security
        try {
            # Resolve to absolute path and validate extension
            $resolvedPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($csvPath)
            
            # Ensure .csv extension
            if ([System.IO.Path]::GetExtension($resolvedPath) -ne '.csv') {
                $resolvedPath = [System.IO.Path]::ChangeExtension($resolvedPath, '.csv')
                Write-Host "File extension changed to .csv: $resolvedPath" -ForegroundColor Yellow
            }
            
            # Verify parent directory exists or can be created
            $parentDir = Split-Path -Path $resolvedPath -Parent
            if (-not (Test-Path -Path $parentDir)) {
                New-Item -Path $parentDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
                Write-Host "Created directory: $parentDir" -ForegroundColor Yellow
            }
            
            Write-Verbose "Exporting $($results.Count) records to CSV: $resolvedPath"
            $results | Export-Csv -Path $resolvedPath -NoTypeInformation -ErrorAction Stop
            Write-Host "Results exported to: $resolvedPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export CSV: $_"
        }
    }
}

# Disconnect from Microsoft Graph
Disconnect-MgGraph | Out-Null
Write-Host "`nDisconnected from Microsoft Graph" -ForegroundColor Cyan
