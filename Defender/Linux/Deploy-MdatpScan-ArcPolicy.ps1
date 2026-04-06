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
    Deploys the Arc MDATP weekly scan cron policy definition and assignment.
.DESCRIPTION
    Creates the Azure Policy definition for Arc-connected Linux machines at management group
    scope, assigns it with a system-assigned managed identity, grants the required
    role assignment, and can optionally create a remediation task for existing machines
    — all in a single run.

    Run from Azure Cloud Shell (PowerShell) or a local PowerShell session with Az module.
.PARAMETER ManagementGroupId
    Management group where policy definitions will be created. Definitions are always
    created at this level regardless of assignment scope.
.PARAMETER Location
    Azure region for the policy assignment managed identities.
    Use 'eastus' for Azure Commercial, 'usgovvirginia' for Azure Government.
.PARAMETER AssignmentScope
    Scope at which the policy will be assigned. Defaults to the management group.
    Examples:
      /providers/Microsoft.Management/managementGroups/<mg-id>   (default)
      /subscriptions/<subscription-id>
      /subscriptions/<subscription-id>/resourceGroups/<rg-name>
.PARAMETER Environment
    Azure cloud environment. 'AzureCloud' (default) or 'AzureUSGovernment'.
.PARAMETER CreateRemediationTasks
    Creates remediation tasks for the assignment so existing matching machines are
    discovered and remediated in addition to future new or updated machines.
.PARAMETER RemediationScope
    Optional remediation scope or scopes. When omitted and the assignment scope is a
    management group, the script automatically creates one remediation task per child
    subscription under that management group. When omitted and the assignment scope is a
    subscription or resource group, the assignment scope is used.
.EXAMPLE
    # Assign at management group scope (covers all subscriptions under the MG)
    .\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus'
.EXAMPLE
    # Assign at a single subscription
    .\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
        -AssignmentScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy'
.EXAMPLE
    # Assign at a resource group
    .\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
        -AssignmentScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy/resourceGroups/<resource-group-name>'
.EXAMPLE
    # Azure Government
    .\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'usgovvirginia' `
        -Environment 'AzureUSGovernment'
.EXAMPLE
    # Assign and immediately create remediation tasks for existing machines across child subscriptions
    .\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
        -CreateRemediationTasks
.EXAMPLE
    # Assign at management group scope and remediate only a specific subscription
    .\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
        -CreateRemediationTasks `
        -RemediationScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy'
.NOTES
    Name:           Deploy-MdatpScan-ArcPolicy.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 4-3-2026
    Revisions: v1 Initial script development
               v2 Optional remediation task creation for existing machines
               v3 Arc-only deployment
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

    [string[]]$RemediationScope,

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
        return $false
    }

    $isManagementGroupScope = $Scope.StartsWith('/providers/Microsoft.Management/managementGroups/', [System.StringComparison]::OrdinalIgnoreCase)
    if ($isManagementGroupScope) {
        throw "Remediation scope '$Scope' is a management group. Use subscription or resource group scope for remediation."
    } else {
        Start-AzPolicyRemediation `
            -Name $Name `
            -PolicyAssignmentId $PolicyAssignmentId `
            -Scope $Scope `
            -ResourceDiscoveryMode ReEvaluateCompliance | Out-Null
        Write-Host "  $Label remediation started with ReEvaluateCompliance"
    }
    return $true
}

function Get-EffectiveRemediationScopes {
    param(
        [Parameter(Mandatory)]
        [string]$AssignmentScope,

        [Parameter(Mandatory)]
        [string]$ManagementGroupId,

        [string[]]$RequestedScopes
    )

    if ($RequestedScopes -and $RequestedScopes.Count -gt 0) {
        return $RequestedScopes | Select-Object -Unique
    }

    $isManagementGroupScope = $AssignmentScope.StartsWith('/providers/Microsoft.Management/managementGroups/', [System.StringComparison]::OrdinalIgnoreCase)
    if (-not $isManagementGroupScope) {
        return @($AssignmentScope)
    }

    $subscriptions = Get-AzManagementGroupSubscription -GroupName $ManagementGroupId
    if (-not $subscriptions) {
        throw "No subscriptions were found under management group '$ManagementGroupId'. Specify -RemediationScope explicitly."
    }

    return $subscriptions | ForEach-Object { "/subscriptions/$($_.Name)" } | Select-Object -Unique
}

function Get-RemediationTaskName {
    param(
        [Parameter(Mandatory)]
        [string]$BaseName,

        [Parameter(Mandatory)]
        [string]$Scope,

        [Parameter(Mandatory)]
        [int]$TotalScopeCount
    )

    if ($TotalScopeCount -le 1) {
        return $BaseName
    }

    if ($Scope -match '^/subscriptions/([^/]+)$') {
        return "$BaseName-$($Matches[1])"
    }

    if ($Scope -match '^/subscriptions/([^/]+)/resourceGroups/([^/]+)$') {
        return "$BaseName-$($Matches[1])-$($Matches[2])"
    }

    $sanitizedScope = ($Scope -replace '[^A-Za-z0-9-]', '-') -replace '-{2,}', '-'
    return "$BaseName-$sanitizedScope"
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
$arcPolicyName      = 'deploy-mdatp-scan-arc-linux'
$arcAssignmentName  = 'deploy-mdatp-cron-arc'
$arcRemediationName = 'remediate-arc'

# Connected Machine Resource Administrator
$arcRoleId = 'cd570a14-e51a-42ad-bac8-bafd67325302'

# ============================================================
# Step 1 — Policy definitions (management group scope)
# ============================================================
Write-Host "`n[1/3] Creating policy definitions at management group: $ManagementGroupId" -ForegroundColor Cyan

$arcRule = Get-Content (Join-Path $ScriptDir 'mdatp-scan-arc-policy-rule.json') -Raw

$arcDef = New-AzPolicyDefinition `
    -Name        $arcPolicyName `
    -DisplayName 'Deploy: MDATP Weekly Scan Cron — Arc Linux' `
    -Description 'Deploys the MDATP weekly quick scan cron entry to Arc-connected Linux machines via Run Command. The script validates that mdatp exists on the machine before installing the cron entry.' `
    -Policy      $arcRule `
    -Mode        'Indexed' `
    -ManagementGroupName $ManagementGroupId

Write-Host "  Arc definition: $($arcDef.Id)"

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

# ============================================================
# Step 4 — Remediation tasks (optional)
# ============================================================
if ($CreateRemediationTasks) {
    $effectiveRemediationScopes = @(Get-EffectiveRemediationScopes -AssignmentScope $AssignmentScope -ManagementGroupId $ManagementGroupId -RequestedScopes $RemediationScope)
    Write-Host "`n[4/4] Creating remediation tasks at scope(s): $($effectiveRemediationScopes -join ', ')" -ForegroundColor Cyan

    $startedRemediations = New-Object System.Collections.Generic.List[string]
    $skippedRemediations = New-Object System.Collections.Generic.List[string]

    foreach ($scope in $effectiveRemediationScopes) {
        $taskName = Get-RemediationTaskName -BaseName $arcRemediationName -Scope $scope -TotalScopeCount $effectiveRemediationScopes.Count
        $label = "Arc [$scope]"
        $started = Start-RemediationIfMissing -Name $taskName -PolicyAssignmentId $arcAssignment.Id -Scope $scope -Label $label
        if ($started) {
            $startedRemediations.Add("$taskName @ $scope") | Out-Null
        } else {
            $skippedRemediations.Add("$taskName @ $scope") | Out-Null
        }
    }
}

# ============================================================
# Done
# ============================================================
Write-Host "`nDeployment complete." -ForegroundColor Green
Write-Host ""
if ($CreateRemediationTasks) {
    if ($startedRemediations.Count -gt 0) {
        Write-Host "Started remediation tasks using ReEvaluateCompliance at subscription or resource group scope:" -ForegroundColor Green
        foreach ($entry in $startedRemediations) {
            Write-Host "  $entry" -ForegroundColor Green
        }
    }
    if ($skippedRemediations.Count -gt 0) {
        Write-Host "Skipped existing remediation tasks:" -ForegroundColor Yellow
        foreach ($entry in $skippedRemediations) {
            Write-Host "  $entry" -ForegroundColor Yellow
        }
        Write-Host "Delete the existing remediation task or use a different remediation scope if you need to rerun remediation immediately." -ForegroundColor Yellow
    }
} else {
    Write-Host "Existing machines require remediation or a qualifying resource update before DeployIfNotExists will apply." -ForegroundColor Yellow
    Write-Host "To remediate existing machines without waiting for future create/update events:" 
    Write-Host "  Start-AzPolicyRemediation -Name '$arcRemediationName' -PolicyAssignmentId '$($arcAssignment.Id)' -Scope '/subscriptions/<subscription-id>' -ResourceDiscoveryMode ReEvaluateCompliance"
}
