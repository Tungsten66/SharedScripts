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
    Get Azure VM extensions and if enabled for automatic upgrade
.DESCRIPTION
    Reports all VM extensions and if they are enabled for automatic upgrade.
    If the -EnableAutomaticUpgrade switch is used, the script will enable automatic upgrade for all extensions.
    Example: .\Get-VmExtUpdateStatus.ps1 -CloudEnvironment AzureUSGovernment -EnableAutomaticUpgrade -OutputReport 

    https://learn.microsoft.com/en-us/azure/virtual-machines/automatic-extension-upgrade?tabs=powershell1%2CRestAPI2
.INPUTS
    -CloudEnvironment
    -EnableAutomaticUpgrade
    -OutputReport
.OUTPUTS
    output to screen and optional CSV file
.NOTES
    Name: Get-VmExtUpdateStatus.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 10/2/2024
    Revisions:
#>

param(
    [string] [ValidateSet("AzureCloud", "AzureUSGovernment")]
    $CloudEnvironment = "AzureCloud",
    [switch] $EnableAutomaticUpgrade,
    [switch] $OutputReport
)

# Check if already logged in
$context = Get-AzContext
if ($null -eq $context) {
    # Login to Azure
    Connect-AzAccount
}
else {
    $currentAccount = $context.Account
    $continue = Read-Host "You are already logged in as $($currentAccount.Id). Do you want to continue using this account? (Y/N)"
    if ($continue -ne 'Y') {
        # Login to Azure
        Connect-AzAccount -environment $CloudEnvironment > $null
    }
}

# Get all subscriptions
$subscriptions = Get-AzSubscription

# Initialize an array to store the results
$results = @()

foreach ($subscription in $subscriptions) {
    # Set the current subscription context and suppress output
    Set-AzContext -SubscriptionId $subscription.Id > $null

    # Get all VMs in the current subscription
    $vms = Get-AzVM -Status

    foreach ($vm in $vms) {
        
        # Get all extensions for the current VM
        $extensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name
        if ($vm.PowerState -eq "VM deallocated") {
            Write-Host "VM '$($vm.Name)' is deallocated. Skipping." -ForegroundColor Yellow
        }

        foreach ($extension in $extensions) {

            # Add the result to the array
            $results += [PSCustomObject]@{
                SubscriptionName       = $subscription.Name
                ResourceGroupName      = $vm.ResourceGroupName
                VMName                 = $vm.Name
                PowerState             = $vm.PowerState
                ExtensionName          = $extension.Name
                EnableAutomaticUpgrade = if ($EnableAutomaticUpgrade) { $true } elseif ($null -ne $extension.EnableAutomaticUpgrade) { $extension.EnableAutomaticUpgrade } else { $false }
            }

            if ($EnableAutomaticUpgrade) {
                Set-AzVMExtension -Publisher $extension.Publisher -ExtensionType $extension.ExtensionType -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -Name $extension.Name -EnableAutomaticUpgrade $true > $null
                Write-Host "Automatic upgrade enabled for VM '$($vm.Name)' and extension '$($extension.Name)' in resource group '$($vm.ResourceGroupName)'." -ForegroundColor Green
            }
        }
    }
}

# Output the results to the screen
$results | Format-Table -AutoSize
# Export the results to a CSV file
if ($OutputReport) {
    $results | Export-Csv -Path "vmExtensionUpgradeStatus.csv" -NoTypeInformation
    Write-Output "Report generated: vmExtensionUpgradeStatus.csv"
}

