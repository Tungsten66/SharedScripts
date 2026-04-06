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
    Deploys MDATP weekly scan cron policy definitions and assignments.
.DESCRIPTION
    Creates two Azure Policy definitions (Arc Linux and Azure VM Linux) at management group
    scope, assigns them with system-assigned managed identities, grants the required
    role assignments, and can optionally create remediation tasks for existing machines
    — all in a single run.

    Run from Azure Cloud Shell (PowerShell) or a local PowerShell session with Az module.
.PARAMETER ManagementGroupId
    Management group where policy definitions will be created. Definitions are always
    created at this level regardless of assignment scope.
.PARAMETER Location
    Azure region for the policy assignment managed identities.
    Use 'eastus' for Azure Commercial, 'usgovvirginia' for Azure Government.
.PARAMETER AssignmentScope
    Scope at which both policies will be assigned. Defaults to the management group.
    Examples:
      /providers/Microsoft.Management/managementGroups/<mg-id>   (default)
      /subscriptions/<subscription-id>
      /subscriptions/<subscription-id>/resourceGroups/<rg-name>
.PARAMETER Environment
    Azure cloud environment. 'AzureCloud' (default) or 'AzureUSGovernment'.
.PARAMETER CreateRemediationTasks
    Creates remediation tasks for both assignments using ReEvaluateCompliance so existing
    matching machines are discovered and remediated in addition to future new or updated
    machines.
.EXAMPLE
    # Assign at management group scope (covers all subscriptions under the MG)
    .\Deploy-MdatpScanPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus'
.EXAMPLE
    # Assign at a single subscription
    .\Deploy-MdatpScanPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
        -AssignmentScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy'
.EXAMPLE
    # Assign at a resource group
    .\Deploy-MdatpScanPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
        -AssignmentScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy/resourceGroups/<resource-group-name>'
.EXAMPLE
    # Azure Government
    .\Deploy-MdatpScanPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'usgovvirginia' `
        -Environment 'AzureUSGovernment'
.EXAMPLE
    # Assign and immediately create remediation tasks for existing machines
    .\Deploy-MdatpScanPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
        -CreateRemediationTasks
.NOTES
    Name:           Deploy-MdatpScanPolicy.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 4-3-2026
    Revisions: v1 Initial script development
               v2 Optional remediation task creation for existing machines
#>
#Requires -Modules Az.Accounts, Az.Resources, Az.PolicyInsights

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$ManagementGroupId,

    [Parameter(Mandatory)]
    [string]$Location,

    [string]$AssignmentScope,

    [ValidateSet('AzureCloud', 'AzureUSGovernment')]
    [string]$Environment = 'AzureCloud',

    [switch]$CreateRemediationTasks
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Get principal ID via REST — avoids Az module version differences in property names
function Get-AssignmentPrincipalId ([string]$AssignmentId) {
    $resp = Invoke-AzRestMethod -Method GET -Path "${AssignmentId}?api-version=2024-04-01"
    return ($resp.Content | ConvertFrom-Json).identity.principalId
}

function Start-RemediationIfMissing {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [string]$PolicyAssignmentId,

        [Parameter(Mandatory)]
        [string]$Scope,

        [Parameter(Mandatory)]
        [string]$Label
    )

    $existingRemediation = Get-AzPolicyRemediation -Name $Name -Scope $Scope -ErrorAction SilentlyContinue
    if ($existingRemediation) {
        Write-Host "  $Label remediation already exists, skipping"
        return
    }

    Start-AzPolicyRemediation `
        -Name $Name `
        -PolicyAssignmentId $PolicyAssignmentId `
        -Scope $Scope `
        -ResourceDiscoveryMode ReEvaluateCompliance | Out-Null
    Write-Host "  $Label remediation started with ReEvaluateCompliance"
}

# --- Authenticate ---
$ctx = Get-AzContext
if (-not $ctx -or $ctx.Environment.Name -ne $Environment) {
    Write-Host "Connecting to $Environment..." -ForegroundColor Yellow
    Connect-AzAccount -Environment $Environment
}

# --- Defaults ---
if (-not $AssignmentScope) {
    $AssignmentScope = "/providers/Microsoft.Management/managementGroups/$ManagementGroupId"
}

$ScriptDir = $PSScriptRoot

# --- Names ---
$arcPolicyName     = 'deploy-mdatp-scan-arc-linux'
$vmPolicyName      = 'deploy-mdatp-scan-vm-linux'
$arcAssignmentName = 'deploy-mdatp-cron-arc'
$vmAssignmentName  = 'deploy-mdatp-cron-vm'
$arcRemediationName = 'remediate-arc'
$vmRemediationName  = 'remediate-vm'

# Connected Machine Resource Administrator / Virtual Machine Contributor
$arcRoleId = 'cd570a14-e51a-42ad-bac8-bafd67325302'
$vmRoleId  = '9980e02c-c2be-4d73-94e8-173b1dc7cf3c'

# ============================================================
# Step 1 — Policy definitions (management group scope)
# ============================================================
Write-Host "`n[1/3] Creating policy definitions at management group: $ManagementGroupId" -ForegroundColor Cyan

$arcRule = Get-Content (Join-Path $ScriptDir 'mdatp-scan-arc-policy-rule.json') -Raw
$vmRule  = Get-Content (Join-Path $ScriptDir 'mdatp-scan-vm-policy-rule.json')  -Raw

$arcDef = New-AzPolicyDefinition `
    -Name        $arcPolicyName `
    -DisplayName 'Deploy: MDATP Weekly Scan Cron — Arc Linux' `
    -Description 'Deploys the MDATP weekly quick scan cron entry to Arc-connected Linux machines via Run Command. Requires the MDE.Linux extension to be provisioned.' `
    -Policy      $arcRule `
    -Mode        'Indexed' `
    -ManagementGroupName $ManagementGroupId

Write-Host "  Arc definition: $($arcDef.Id)"

$vmDef = New-AzPolicyDefinition `
    -Name        $vmPolicyName `
    -DisplayName 'Deploy: MDATP Weekly Scan Cron — Azure VM Linux' `
    -Description 'Deploys the MDATP weekly quick scan cron entry to Azure Linux VMs via Run Command. Requires the MDE.Linux extension to be provisioned.' `
    -Policy      $vmRule `
    -Mode        'Indexed' `
    -ManagementGroupName $ManagementGroupId

Write-Host "  VM definition:  $($vmDef.Id)"

# ============================================================
# Step 2 — Policy assignments
# ============================================================
Write-Host "`n[2/3] Creating policy assignments at scope: $AssignmentScope" -ForegroundColor Cyan

$arcAssignment = Get-AzPolicyAssignment -Name $arcAssignmentName -Scope $AssignmentScope -ErrorAction SilentlyContinue
$newAssignmentsCreated = $false
if (-not $arcAssignment) {
    New-AzPolicyAssignment `
        -Name             $arcAssignmentName `
        -DisplayName      'Deploy: MDATP Weekly Scan Cron — Arc Linux' `
        -PolicyDefinition $arcDef `
        -Scope            $AssignmentScope `
        -Location         $Location `
        -IdentityType     'SystemAssigned' | Out-Null
    $arcAssignment = Get-AzPolicyAssignment -Name $arcAssignmentName -Scope $AssignmentScope
    $newAssignmentsCreated = $true
    Write-Host "  Arc assignment created."
} else {
    Write-Host "  Arc assignment already exists."
}
$arcPrincipalId = Get-AssignmentPrincipalId $arcAssignment.Id
Write-Host "  Arc assignment principal: $arcPrincipalId"

$vmAssignment = Get-AzPolicyAssignment -Name $vmAssignmentName -Scope $AssignmentScope -ErrorAction SilentlyContinue
if (-not $vmAssignment) {
    New-AzPolicyAssignment `
        -Name             $vmAssignmentName `
        -DisplayName      'Deploy: MDATP Weekly Scan Cron — Azure VM Linux' `
        -PolicyDefinition $vmDef `
        -Scope            $AssignmentScope `
        -Location         $Location `
        -IdentityType     'SystemAssigned' | Out-Null
    $vmAssignment = Get-AzPolicyAssignment -Name $vmAssignmentName -Scope $AssignmentScope
    $newAssignmentsCreated = $true
    Write-Host "  VM assignment created."
} else {
    Write-Host "  VM assignment already exists."
}
$vmPrincipalId = Get-AssignmentPrincipalId $vmAssignment.Id
Write-Host "  VM assignment principal:  $vmPrincipalId"

# Allow time for new managed identity service principals to propagate in Entra ID
if ($newAssignmentsCreated) {
    Write-Host "  Waiting 30 seconds for managed identity propagation..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
}

# ============================================================
# Step 3 — Role assignments
# ============================================================
Write-Host "`n[3/3] Creating role assignments at scope: $AssignmentScope" -ForegroundColor Cyan

try {
    New-AzRoleAssignment `
        -ObjectId         $arcPrincipalId `
        -RoleDefinitionId $arcRoleId `
        -Scope            $AssignmentScope | Out-Null
    Write-Host "  Arc: Connected Machine Resource Administrator assigned"
} catch {
    if ($_.Exception.Message -match 'already exists|Conflict') {
        Write-Host "  Arc: Role assignment already exists, skipping"
    } else { throw }
}

$retries = 3
foreach ($attempt in 1..$retries) {
    try {
        New-AzRoleAssignment `
            -ObjectId         $vmPrincipalId `
            -RoleDefinitionId $vmRoleId `
            -Scope            $AssignmentScope | Out-Null
        Write-Host "  VM:  Virtual Machine Contributor assigned"
        break
    } catch {
        if ($_.Exception.Message -match 'already exists|Conflict') {
            Write-Host "  VM:  Role assignment already exists, skipping"
            break
        } elseif ($attempt -lt $retries) {
            Write-Host "  VM:  Role assignment attempt $attempt failed, retrying in 15 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 15
        } else { throw }
    }
}

# ============================================================
# Step 4 — Remediation tasks (optional)
# ============================================================
if ($CreateRemediationTasks) {
    Write-Host "`n[4/4] Creating remediation tasks at scope: $AssignmentScope" -ForegroundColor Cyan

    Start-RemediationIfMissing -Name $arcRemediationName -PolicyAssignmentId $arcAssignment.Id -Scope $AssignmentScope -Label 'Arc'
    Start-RemediationIfMissing -Name $vmRemediationName -PolicyAssignmentId $vmAssignment.Id -Scope $AssignmentScope -Label 'VM'
}

# ============================================================
# Done
# ============================================================
Write-Host "`nDeployment complete." -ForegroundColor Green
Write-Host ""
if ($CreateRemediationTasks) {
    Write-Host "Remediation tasks were started for existing machines using ReEvaluateCompliance." -ForegroundColor Green
} else {
    Write-Host "Existing machines require remediation or a qualifying resource update before DeployIfNotExists will apply." -ForegroundColor Yellow
    Write-Host "To remediate existing machines without waiting for future create/update events:" 
    Write-Host "  Start-AzPolicyRemediation -Name '$arcRemediationName' -PolicyAssignmentId '$($arcAssignment.Id)' -Scope '$AssignmentScope' -ResourceDiscoveryMode ReEvaluateCompliance"
    Write-Host "  Start-AzPolicyRemediation -Name '$vmRemediationName'  -PolicyAssignmentId '$($vmAssignment.Id)'  -Scope '$AssignmentScope' -ResourceDiscoveryMode ReEvaluateCompliance"
}
