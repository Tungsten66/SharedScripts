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
    Lists all groups in a selected Administrative Unit with device counts.

.DESCRIPTION
    This script connects to Microsoft Graph, allows you to select an Administrative Unit,
    and displays all groups within that AU including their Name, Object ID, and Device Count.
    Results can be filtered by group name and exported to CSV or HTML format.
    
    Supports both interactive delegated authentication and app-only authentication using
    certificate-based authentication with an Azure AD App Registration.
    
    REQUIRED PERMISSIONS:
    - AdministrativeUnit.Read.All
    - Group.Read.All
    - GroupMember.Read.All
    
    PERMISSION SETUP (RECOMMENDED - LEAST PRIVILEGE APPROACH):
    Grant permissions to specific users or groups only:
    
    1. Navigate to Azure Portal > Microsoft Entra ID > Enterprise Applications
    2. Search for 'Microsoft Graph Command Line Tools' or 'Microsoft Graph PowerShell'
    3. Click on the application
    4. In the left menu, select 'Users and groups'
    5. Click '+ Add user/group'
    6. Select the specific users or groups who need access
    7. Click 'Assign'
    8. Go to 'Permissions' in the left menu
    9. Verify the required permissions are listed
    10. Click 'Grant admin consent for [Your Organization]' to approve these permissions
    11. Confirm the consent
    
    ALTERNATIVE SETUP (MOST SECURE - APP-ONLY AUTHENTICATION):
    Use app registration with certificate-based authentication:
    
    1. Create an App Registration in Entra ID
    2. Assign API permissions (Application type):
       - AdministrativeUnit.Read.All
       - Group.Read.All
       - GroupMember.Read.All
    3. Grant admin consent for the app
    4. Generate and upload a certificate for authentication
    5. Note the Application (Client) ID, Directory (Tenant) ID, and Certificate Thumbprint
    6. Run the script with app authentication parameters

.PARAMETER
    SearchName - Optional filter to search for groups by name (supports wildcards).
    
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
    .\Get-AdminUnitGroups.ps1
    
    Lists all groups in the selected Administrative Unit using interactive authentication.

.EXAMPLE
    .\Get-AdminUnitGroups.ps1 -SearchName "Desktop*"
    
    Lists groups whose names start with "Desktop" in the selected Administrative Unit.

.EXAMPLE
    .\Get-AdminUnitGroups.ps1 -ClientId "12345678-1234-1234-1234-123456789012" -TenantId "87654321-4321-4321-4321-210987654321" -CertificateThumbprint "ABC123DEF456..."
    
    Uses app registration with certificate authentication to connect to Microsoft Graph.

.NOTES
    Name: Get-AdminUnitGroups.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: November 18, 2025
    Revisions: 
        1.0 - Initial version with interactive authentication
        1.1 - Added app registration support with certificate authentication
              Added environment selection (Global, USGov, USGovDoD)
              Added HTML export functionality
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SearchName,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientId,
    
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$CertificateThumbprint
)

#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups

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
        Connect-MgGraph -Scopes "AdministrativeUnit.Read.All", "Group.Read.All", "Device.Read.All" -Environment $environment -NoWelcome -ErrorAction Stop
    }
    
    Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# Prompt user to enter Administrative Unit name
$auName = Read-Host "`nEnter the Administrative Unit name"

if ([string]::IsNullOrWhiteSpace($auName)) {
    Write-Error "Administrative Unit name cannot be empty."
    Disconnect-MgGraph | Out-Null
    exit 1
}

# Get the Administrative Unit by name
Write-Host "`nSearching for Administrative Unit: '$auName'..." -ForegroundColor Cyan
try {
    $selectedAdminUnit = Get-MgDirectoryAdministrativeUnit -Filter "displayName eq '$auName'" -ErrorAction Stop
    
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
Write-Host "`nRetrieving groups from Administrative Unit..." -ForegroundColor Cyan
try {
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

# Build detailed group information with device counts
Write-Host "`nGathering group details and device counts..." -ForegroundColor Cyan
$results = @()
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
        
        $results += [PSCustomObject]@{
            Name        = $group.DisplayName
            ObjectId    = $group.Id
            DeviceCount = $deviceCount
        }
    }
    catch {
        Write-Warning "Failed to retrieve details for group $($auGroup.Id): $_"
    }
}

Write-Progress -Activity "Processing Groups" -Completed

# Apply search filter if provided
if ($SearchName) {
    Write-Host "`nFiltering results by name: '$SearchName'" -ForegroundColor Cyan
    $results = $results | Where-Object { $_.Name -like $SearchName }
    
    if ($results.Count -eq 0) {
        Write-Warning "No groups found matching the search criteria."
        Disconnect-MgGraph | Out-Null
        exit 0
    }
}

# Display results in Out-GridView
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Groups in Administrative Unit: $($selectedAdminUnit.DisplayName)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Total groups: $($results.Count)" -ForegroundColor Green
Write-Host "Opening results in GridView...`n" -ForegroundColor Cyan

$results | Sort-Object Name | Out-GridView -Title "Groups in Administrative Unit: $($selectedAdminUnit.DisplayName)"

# Optionally export results
$export = Read-Host "`nWould you like to export these results? (Y/N)"
if ($export -eq 'Y' -or $export -eq 'y') {
    $format = Read-Host "Select export format: [1] CSV  [2] HTML  [3] Both"
    
    # Export to CSV
    if ($format -eq '1' -or $format -eq '3') {
        $defaultPath = Join-Path $PSScriptRoot "AdminUnit_Groups_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
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
        $defaultHtmlPath = Join-Path $PSScriptRoot "AdminUnit_Groups_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
        $htmlPath = Read-Host "Enter the path for the HTML file (press Enter for default: $defaultHtmlPath)"
        
        if ([string]::IsNullOrWhiteSpace($htmlPath)) {
            $htmlPath = $defaultHtmlPath
        }
        
        try {
            $totalDevices = ($results | Measure-Object -Property DeviceCount -Sum).Sum
        
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Administrative Unit Groups Report</title>
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
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
        }
        tr:hover {
            background-color: #f0f0f0;
        }
        tr:last-child td {
            border-bottom: none;
        }
        .device-count {
            text-align: center;
            font-weight: bold;
        }
        .footer {
            margin-top: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
        }
        .object-id {
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Administrative Unit Groups Report</h1>
        <div class="info">
            <strong>Administrative Unit:</strong> $($selectedAdminUnit.DisplayName)<br>
            <strong>Object ID:</strong> $($selectedAdminUnit.Id)<br>
            <strong>Generated:</strong> $(Get-Date -Format "MMMM dd, yyyy HH:mm:ss")
        </div>
    </div>
    
    <div class="summary">
        <div class="summary-item">
            <span class="summary-label">Total Groups:</span> 
            <span class="summary-value">$($results.Count)</span>
        </div>
        <div class="summary-item">
            <span class="summary-label">Total Devices:</span> 
            <span class="summary-value">$totalDevices</span>
        </div>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Group Name</th>
                <th>Object ID</th>
                <th style="text-align: center;">Device Count</th>
            </tr>
        </thead>
        <tbody>
"@
        
        foreach ($item in ($results | Sort-Object Name)) {
            $htmlContent += @"
            <tr>
                <td>$($item.Name)</td>
                <td class="object-id">$($item.ObjectId)</td>
                <td class="device-count">$($item.DeviceCount)</td>
            </tr>
"@
        }
        
        $htmlContent += @"
        </tbody>
    </table>
    
    <div class="footer">
        Report generated by Get-AdminUnitGroups.ps1
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
