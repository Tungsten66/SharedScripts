
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
   Get the latest image version from the Azure Market Place -1; this example is specific to 2016-Datacenter
.DESCRIPTION
    This was created as a workaround to get the latest -1 version number so you can get an older version number to deploy out VM via template.
    https://docs.microsoft.com/en-us/azure/virtual-machines/windows/cli-ps-findimage
.INPUTS
   Run each section and populate the next line with the information you want to target
.OUTPUTS
   Version output to screen
.NOTES
    Name: Get-VMImageVersion-1(2016-Datacenter).ps1
    Authors/Contributors: Tungsten66
    DateCreated: 6/9/2021
    Revisions:
#>

#List the image publishers
$locName = "eastus" #Get-AzLocation
Get-AzVMImagePublisher -Location $locName | Select-Object PublisherName

#For a given publisher, list their offers
$pubName = "MicrosoftWindowsServer"
Get-AzVMImageOffer -Location $locName -PublisherName $pubName | Select-Object Offer

#For a given publisher and offer, list the SKUs available
$offerName = "WindowsServer"
Get-AzVMImageSku -Location $locName -PublisherName $pubName -Offer $offerName | Select-Object Skus

#For a SKU, list the versions of the image
$skuName = "2016-Datacenter"
Get-AzVMImage -Location $locName -PublisherName $pubName -Offer $offerName -Sku $skuName | Select-Object Version

#Get 'Latest -1 image verion number
$versionList = Get-AzVMImage -location $locName -PublisherName $pubName -offer $offerName -Skus $skuName | Select-Object Version 
Write-Host "Latest '-1' version: $($versionList[1].Version)"
