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
   Build an XML file from a CSV file containing USB device InstancePathId values.
.DESCRIPTION
   This script reads a CSV file containing USB device InstancePathId values and builds an XML file with these values.
   The script replaces the last digit in each InstancePathId with a wildcard (*) to account for variable USB slot numbers.
   It also escapes the '&' character in the InstancePathId values to ensure valid XML formatting.
.INPUTS
    The script takes a CSV file as input, which should contain a column named 'InstancePathId'.
    The CSV file is expected to be located at "C:\Temp\AuthorizedUSBs.csv".
    The XML file is expected to be located at "C:\Temp\AuthorizedUSBs.xml".
    The script will overwrite the existing XML file with the new data.
.OUTPUTS
   The script outputs the updated XML file to "C:\Temp\AuthorizedUSBs.xml".
   The XML file will contain a root element with a child element "DescriptorIdList", which contains multiple "InstancePathId" elements.
.NOTES
    Name:Build-AuthorizedList.ps1
    Authors/Contributors:Tungsten66
    DateCreated: 3/11/2025
    Revisions:1.0
#>

# Define the paths to the CSV and XML files
$csvPath = "C:\Temp\AuthorizedUSBs.csv"
$xmlPath = "C:\Temp\AuthorizedUSBs.xml"

# Load the CSV file
$csvData = Import-Csv -Path $csvPath

# Load the XML file
try {
    [xml]$xmlData = Get-Content -Path $xmlPath
}
catch {
    Write-Error "Failed to load XML file from $xmlPath. Please ensure the file is well-formed."
    exit 1
}

# Clear existing elements in DescriptorIdList
$descriptorIdList = $xmlData.SelectSingleNode("//DescriptorIdList")
if ($null -ne $descriptorIdList) {
    $descriptorIdList.RemoveAll()
}

# Add each InstancePathId from the CSV to the DescriptorIdList
foreach ($csvRow in $csvData) {
    $newElement = $xmlData.CreateElement("InstancePathId")
    # & character needs to be escaped in xml; replacing it with &amp;
    # Replace the last digit in InstancePathId with a wildcard to account for variable USB slot numbers
    if ($csvRow.InstancePathId -like 'USBSTOR*') {
        $newElement.InnerText = ($csvRow.InstancePathId -replace '\d$', '*')
    } else {
        $newElement.InnerText = $csvRow.InstancePathId
    }
    $descriptorIdList.AppendChild($newElement)
}

# Save the updated XML file
try {
    $xmlData.Save($xmlPath)
    Write-Output "XML file saved successfully."
}
catch {
    Write-Error "Failed to save XML file to $xmlPath. Please check if the file is locked or if there are permission issues."
}
