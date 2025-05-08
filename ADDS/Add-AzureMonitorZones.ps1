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
   Example of how to configure Active Directory-integrated DNS in a hybrid environment to resolve Azure Monitor private DNS zones
.DESCRIPTION
    This script adds conditional forwarders to forward Azure Monitor private zone lookup to an Azure DNS Private Resolver
    Public DNS zone forwarders- https://learn.microsoft.com/en-us/azure/private-link/private-endpoint-dns#management-and-governance
    Private link resource type Azure Monitor (Microsoft.Insights/privateLinkScopes)
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Add-AzureMonitorZones.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 5/8/2025
    Revisions:
#>



#Variables
$domain = Get-ADDomain
$PDCe = $domain.PDCEmulator
$DNSprivateResolver = Read-Host -Prompt "Enter the IP address of the Azure DNS private resolver"
$ZoneNames = @(
    "monitor.azure.com", 
    "oms.opinsights.azure.com", 
    "ods.opinsights.azure.com", 
    "agentsvc.azure-automation.net", 
    "blob.core.windows.net", 
    "services.visualstudio.com",
    "applicationinsights.azure.com"
)

# Add the Azure DNS private resolver as a conditional forwarder to the PDC emulator
foreach ($ZoneName in $ZoneNames) {
    # Check if the zone already exists
    $zoneExists = Get-DnsServerZone -Name $zoneName -ComputerName $PDCe -ErrorAction SilentlyContinue

    if ($zoneExists) {
        Write-Host "Zone $zoneName already exists. Skipping creation."
    } else {
        # Create the conditional forwarder zone
        Write-Host "Creating conditional forwarder zone for $zoneName..."
        Add-DnsServerConditionalForwarderZone -Name $zoneName -ReplicationScope Forest -MasterServers $DNSprivateResolver -ComputerName $PDCe
    }
}