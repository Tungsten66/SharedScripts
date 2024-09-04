
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
   Export data from a Log Analytics Workspace table in csv format and upload to an Azure storage account
.DESCRIPTION
    This was created as proof of concept to export data from a Log Analytics Workspace table in csv format and upload to an Azure storage account.  
    Then you have the option to use LightIngest to ingest the data into ADX
.INPUTS
   KQL query of what data you want to export to storage for retention or archival
   Update variables for your environment
   This example loops through each hour (in seconds) between August 1 and August 10 for the SecurityEvent table
.OUTPUTS
   Data will be uploaded to a storage account
   A log file will be created with the status of the export of a working directory of c:\temp
.NOTES
    Name: ExportLAWdata2Storage.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 8/28/2024
    Revisions:
#>

# Define variables
$resourceGroup = "<resourceGroup>"
$storageAccountName = "<storageAccountName>"
$containerName = "<containerName>"
$workspaceId = "<workspaceId>"
$tenantId = "<tenantId>"
$tableName = "SecurityEvent"

#Reporting
$outfile = "c:\temp\$(Get-Date -format 'ddMMMyy')_DataExport.log"
if (!(Test-Path $outfile)) {
    "$TableName`tstartDate`tendDate`tStatus" | out-file $outfile -Append
}

# Authenticate to Azure
Connect-AzAccount -Environment AzureUSGovernment -Tenant $tenantId

# Loop through each hour (in seconds) between August 1 and August 10
$startDate = Get-Date "2024-08-27T00:00:00Z"
$endDate = Get-Date "2024-08-28T23:59:59Z"

while ($startDate -le $endDate) {
    $endDateTime = $startDate.AddSeconds(3600)

    # Query Log Analytics
    $query = "$tableName
    | where TimeGenerated between (datetime($($startDate.ToString("yyyy-MM-ddTHH:mm:ssZ"))) .. datetime($($endDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))))"

    $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $query

    # Export results to Blob Storage
    $file = "c:\temp\logs_$(Get-Date -format 'yyyyMMddTHHmmss').csv"
    $result.results | export-csv $file -Delimiter "," -NoTypeInformation -Append

    # Get the storage account context
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroup -Name $storageAccountName
    $ctx = $storageAccount.Context

    # Upload the file
    Set-AzStorageBlobContent -File $file -Container $containerName -Context $ctx

    Write-Host "File uploaded successfully!"
    "$TableName`t$startDate`t$endDate`tUploaded" | out-file $outfile -Append
    remove-item $file

    # Move to the next second
    $startDate = $endDateTime
}
