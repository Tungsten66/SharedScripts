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
     Create or update tags for AWS Arc-enabled machines in Azure Arc.
.DESCRIPTION
    By default, AWS Arc-enabled machines in Azure Arc are named using their AWS instance ID, which may not be intuitive for users.
    Refer to: https://learn.microsoft.com/en-us/azure/azure-arc/servers/azcmagent-connect
    This script improves identification by tagging each AWS Arc-enabled machine with its computer name.
    It scans for AWS Arc-enabled machines, checks if the "ComputerName" tag matches the OSProfile.ComputerName property, and applies the tag if needed.
    Machines already tagged with the correct value are skipped.
    Requires the Az.ConnectedMachine and Az.Resources PowerShell modules.
    Minimum permissions required: Microsoft.HybridCompute/machines/read, Microsoft.Resources/tags/write.
.INPUTS
    -CloudEnvironment
.OUTPUTS
    Tags applied to AWS Arc-enabled machines.
.NOTES
    ScriptName: Set-AwsArcComputerNameTag.ps1
    Authors/Contributors: Tungsten66
    DateCreated: 7/29/2025
    Revisions:
#>

param(
    [string] [ValidateSet("AzureCloud", "AzureUSGovernment")]
    $CloudEnvironment = "AzureCloud"
)

# Check if already logged in
$context = Get-AzContext
if ($null -eq $context) {
    # Login to Azure
    Connect-AzAccount -Environment $CloudEnvironment
}
else {
    $currentAccount = $context.Account
    $continue = Read-Host "You are already logged in as $($currentAccount.Id). Do you want to continue using this account? (Y/N)"
    if ($continue -ne 'Y') {
        # Login to Azure
        Connect-AzAccount -Environment $CloudEnvironment | Out-Null
    }
}
# Ensure you have the necessary permissions to tag resources in Azure Arc
# Requires Az.ConnectedMachine and Az.Resources modules

# Get all subscriptions
$subscriptions = Get-AzSubscription -TenantId $context.Tenant.Id
foreach ($subscription in $subscriptions) {
    Write-Host "Processing subscription: $($subscription.Name)"
    # Ensure context is set with correct tenant
    Set-AzContext -SubscriptionId $subscription.Id -TenantId $subscription.TenantId
    # If context is not authenticated, prompt login for this tenant
    if (-not (Get-AzContext).Account) {
        Connect-AzAccount -Environment $CloudEnvironment -TenantId $subscription.TenantId -SubscriptionId $subscription.Id
    }
    # Get all Arc-enabled machines in the current subscription
    $arcMachines = Get-AzConnectedMachine
    foreach ($machine in $arcMachines) {
        # Check if detectedProperties.cloudprovider is AWS
        $cloudProvider = $machine.DetectedProperty["cloudprovider"]
        if ($cloudProvider -eq "AWS") {
            # Get the computer name from properties.osProfile.ComputerName
            $ComputerName = $machine.OSProfile.ComputerName

            if ($null -ne $ComputerName) {
                # Check if the tag already exists
                $existingTags = $machine.Tags
                if ($existingTags.ContainsKey("ComputerName") -and $existingTags["ComputerName"] -eq $ComputerName) {
                    Write-Host "Tag already exists for $($machine.Name), skipping."
                    continue
                }

                # Prepare the tag
                $tags = @{"ComputerName" = $ComputerName}

                # Tag the Arc machine
                Update-AzTag -ResourceId $machine.Id -Tag $tags -Operation Merge
                Write-Host "Tagged $($machine.Name) with ComputerName=$ComputerName"
            }
        }
    }
}
