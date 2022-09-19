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
   List Windows VMs that are not configured for Azure Hybrid License Benefit and Update to Hybrid Benefit
.DESCRIPTION
    https://learn.microsoft.com/en-us/azure/virtual-machines/windows/hybrid-use-benefit-licensing
.INPUTS
   -NotHybridBenefit
   -EnableHybridBenefit
.OUTPUTS
   Version output to screen
.NOTES
    Name: VMLicenseType.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 9/17/2022
    Revisions:
#>

[CmdletBinding()]

param
(
    [Parameter(Mandatory = $false)]
    [switch]$NotHybridBenefit,
    [Parameter(Mandatory = $false)]
    [switch]$EnableHybridBenefit
)
 
#List Current Subscription Selected
$CurrentSub = (Get-AzContext).Subscription.Name
Write-Host "Current Subscription Selected: $CurrentSub" -ForegroundColor Yellow

if ($NotHybridBenefit) {
    #list Windows VMs not utilizing the licensing benefit
    Get-AzVM | Where-Object { ($_.StorageProfile.OsDisk.OsType -eq "Windows") -and ($null -eq $_.LicenseType) } | Select-Object ResourceGroupName, Name, LicenseType
}
else {

    #How to verify your VM is utilizing the licensing benefit
    Get-AzVM | Where-Object { ($_.StorageProfile.OsDisk.OsType -eq "Windows") } | Select-Object ResourceGroupName, Name, LicenseType
}
#Convert existing Windows Server VMs to Azure Hybrid Benefit for Windows Server
    
if ($EnableHybridBenefit) {

    $VMs = Get-AzVM | Where-Object { ($_.StorageProfile.OsDisk.OsType -eq "Windows") -and ($null -eq $_.LicenseType) } 
    Foreach ($VM in $VMs) {
	
        $VM.LicenseType = "Windows_Server"
        Write-Host "Updating $($VM.Name) Licensing for Hybrid Benefit" -ForegroundColor Green
        Update-AzVM -ResourceGroupName $VM.ResourceGroupName -VM $VM
        
    }
}