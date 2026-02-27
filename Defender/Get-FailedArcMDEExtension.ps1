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
    Reports Azure Arc Windows machines with failed MDE.Windows extension and
    optionally uninstalls the extension.

.DESCRIPTION
    Queries all subscriptions (or a specified subscription) for Azure Arc 
    connected Windows machines that have the MDE.Windows extension in a failed
    provisioning state. Displays a report and prompts the user to optionally
    uninstall the failed extension from those machines.
    
    Designed to run in Azure Cloud Shell (PowerShell) where Az modules and
    authentication are available by default.

.PARAMETER SubscriptionId
    Optional. Limit the scan to a single subscription by ID.

.PARAMETER Force
    Skip the interactive confirmation prompt and immediately uninstall failed
    extensions. Useful for automation scenarios.

.PARAMETER ExportCsv
    Optional. File path to export the report of failed extensions as CSV.

.INPUTS
    None. Interactive script.

.OUTPUTS
    Console report of affected machines. Optional extension removal.

.NOTES
    Name: Arc-MDEWindowsExtension.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 02/25/2025
    Revisions:
    Requires: Az.Accounts (pre-installed in Cloud Shell)
#>

#Requires -Modules Az.Accounts

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [switch]$Force,

    [Parameter(Mandatory = $false)]
    [string]$ExportCsv
)

# Ensure Azure context
$context = Get-AzContext -ErrorAction SilentlyContinue
if (-not $context) {
    Write-Error "No Azure context found. Please run Connect-AzAccount or open Azure Cloud Shell."
    return
}
Write-Host "Authenticated as: $($context.Account.Id)" -ForegroundColor Cyan
Write-Host ""

# Build subscription list
if ($SubscriptionId) {
    $subscriptions = @(Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop)
}
else {
    $subscriptions = @(Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
}

Write-Host "Scanning $($subscriptions.Count) subscription(s) for Arc machines with failed MDE.Windows extension..." -ForegroundColor Cyan
Write-Host ""

# Collect results across subscriptions
$failedMachines = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($sub in $subscriptions) {
    # Set subscription context
    $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop

    # Query connected Windows Arc machines via Resource Graph REST API
    $query = @"
resources
| where type =~ 'microsoft.hybridcompute/machines'
| where properties.osType =~ 'Windows'
| where properties.status =~ 'Connected'
| project id, name, resourceGroup, subscriptionId, 
          osName = properties.osName, 
          status = properties.status,
          location
"@

    $body = @{
        subscriptions = @($sub.Id)
        query         = $query
    } | ConvertTo-Json -Depth 5

    try {
        $response = Invoke-AzRestMethod -Path "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01" `
            -Method POST -Payload $body -ErrorAction Stop

        if ($response.StatusCode -ne 200) {
            Write-Warning "Resource Graph query failed for subscription '$($sub.Name)' ($($sub.Id)): HTTP $($response.StatusCode)"
            continue
        }

        $resultData = ($response.Content | ConvertFrom-Json).data
    }
    catch {
        Write-Warning "Failed to query subscription '$($sub.Name)' ($($sub.Id)): $_"
        continue
    }

    if (-not $resultData -or $resultData.Count -eq 0) {
        continue
    }

    Write-Host "  Subscription: $($sub.Name) — found $($resultData.Count) connected Windows Arc machine(s), checking extensions..." -ForegroundColor DarkGray

    $machineIndex = 0
    foreach ($machine in $resultData) {
        $machineIndex++
        Write-Progress -Activity "Checking extensions" `
            -Status "[$($sub.Name)] $($machine.name) ($machineIndex of $($resultData.Count))" `
            -PercentComplete (($machineIndex / $resultData.Count) * 100)

        $machineId = $machine.id
        $extensionsPath = "$machineId/extensions?api-version=2022-12-27"

        try {
            $extResponse = Invoke-AzRestMethod -Path $extensionsPath -Method GET -ErrorAction Stop

            if ($extResponse.StatusCode -ne 200) {
                Write-Warning "    Could not retrieve extensions for $($machine.name): HTTP $($extResponse.StatusCode)"
                continue
            }

            $extensions = ($extResponse.Content | ConvertFrom-Json).value
        }
        catch {
            Write-Warning "    Could not retrieve extensions for $($machine.name): $_"
            continue
        }

        # Find MDE.Windows extension with failed status (take first match)
        $mdeExt = $extensions | Where-Object {
            ($_.properties.type -eq 'MDE.Windows') -and
            ($_.properties.provisioningState -ne 'Succeeded')
        } | Select-Object -First 1

        if ($mdeExt) {
            $failedMachines.Add([PSCustomObject]@{
                Subscription      = $sub.Name
                SubscriptionId    = $sub.Id
                ResourceGroup     = $machine.resourceGroup
                MachineName       = $machine.name
                Location          = $machine.location
                ArcStatus         = $machine.status
                ExtensionName     = $mdeExt.name
                ProvisioningState = $mdeExt.properties.provisioningState
                StatusMessage     = (($mdeExt.properties.instanceView.status.message -join ' ') -replace '\s+', ' ')
                ExtensionId       = $mdeExt.id
            })
        }
    }
}

Write-Progress -Activity "Checking extensions" -Completed

# Display report
Write-Host ""
if ($failedMachines.Count -eq 0) {
    Write-Host "No connected Windows Arc machines found with a failed MDE.Windows extension." -ForegroundColor Green
    return
}

Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host " FAILED MDE.Windows EXTENSIONS ON CONNECTED ARC MACHINES" -ForegroundColor Yellow
Write-Host " Total: $($failedMachines.Count) machine(s)" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

$failedMachines | Format-Table -AutoSize -Property MachineName, ResourceGroup, Subscription, ProvisioningState, Location

# Detailed view
foreach ($m in $failedMachines) {
    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Machine:       $($m.MachineName)" -ForegroundColor White
    Write-Host "  Resource Group: $($m.ResourceGroup)"
    Write-Host "  Subscription:  $($m.Subscription)"
    Write-Host "  Location:      $($m.Location)"
    Write-Host "  Arc Status:    $($m.ArcStatus)" -ForegroundColor Green
    Write-Host "  Ext State:     $($m.ProvisioningState)" -ForegroundColor Red
    if ($m.StatusMessage) {
        Write-Host "  Status Msg:    $($m.StatusMessage)" -ForegroundColor DarkYellow
    }
}
Write-Host ""

# Export to CSV if requested
if ($ExportCsv) {
    $failedMachines | Export-Csv -Path $ExportCsv -NoTypeInformation -Force
    Write-Host "Report exported to: $ExportCsv" -ForegroundColor Green
    Write-Host ""
}

# Prompt to uninstall
if (-not $Force) {
    $answer = Read-Host "Do you want to uninstall the failed MDE.Windows extension from these $($failedMachines.Count) machine(s)? (y/N)"

    if ($answer -notmatch '^[Yy]') {
        Write-Host "No changes made. Exiting." -ForegroundColor Cyan
        return
    }
}

Write-Host ""
Write-Host "Uninstalling MDE.Windows extension from $($failedMachines.Count) machine(s)..." -ForegroundColor Yellow
Write-Host ""

$successCount = 0
$failCount = 0

foreach ($m in $failedMachines) {
    if (-not $PSCmdlet.ShouldProcess($m.MachineName, "Remove failed MDE.Windows extension")) {
        continue
    }

    Write-Host "  [$($m.MachineName)] Removing extension..." -ForegroundColor White -NoNewline

    try {
        # Set correct subscription context
        $null = Set-AzContext -SubscriptionId $m.SubscriptionId -ErrorAction Stop

        $deletePath = "$($m.ExtensionId)?api-version=2022-12-27"
        $deleteResponse = Invoke-AzRestMethod -Path $deletePath -Method DELETE -ErrorAction Stop

        if ($deleteResponse.StatusCode -in 200, 202, 204) {
            Write-Host " Accepted (async removal initiated)" -ForegroundColor Green
            $successCount++
        }
        else {
            $errorBody = $deleteResponse.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
            $errorMsg = if ($errorBody.error.message) { $errorBody.error.message } else { "HTTP $($deleteResponse.StatusCode)" }
            Write-Host " Failed — $errorMsg" -ForegroundColor Red
            $failCount++
        }
    }
    catch {
        Write-Host " Failed — $_" -ForegroundColor Red
        $failCount++
    }
}

Write-Host ""
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Uninstall Summary: $successCount succeeded, $failCount failed" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: Extension removal is asynchronous. Re-run this script in a few minutes to verify." -ForegroundColor DarkGray