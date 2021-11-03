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
   Update distribution group membership in new domain
.DESCRIPTION
    In this example we are migrating users from Fabrikam.com to Contoso.com and Exchange resource domain of Northwindtraders.com
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Update-Distros.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 9/16/2021
    Revisions:
#>

##Parameters##

#Browse File location
Write-Warning "****** Select file with distribution groups that need membership updated  ******"
Add-Type -AssemblyName System.Windows.Forms
$FileBrowse = New-Object System.Windows.Forms.OpenFileDialog
$FileBrowse.filter = "txt (*.txt)| *.txt"
$Null = $FileBrowse.ShowDialog()
$Groups = Get-Content $FileBrowse.FileName

#Credentials
$NorthwindtradersCred = Get-Credential -Message "Enter Exchange credentials for Northwindtraders"

#DCs
$FabrikamDC = "DC1.Fabrikam.com"
$NorthwindtradersDC = "DC1.Northwindtraders.com"

#Logging
$outfile = "$PSScriptRoot\logs\$(Get-Date -format 'ddMMMyy_HHmm')_DistroMembershipUpdate.log"
Start-Transcript -Path $outfile

Foreach ($Group in $Groups) {

    Get-ADGroupMember $Group -Server $FabrikamDC | ForEach-Object { Add-ADGroupMember -Identity $Group -Members $_.SamAccountName -Server $NorthwindtradersDC -Credential $NorthwindtradersCred} -ErrorAction Stop
    Write-Host "$Group Updated" -ForegroundColor Green

}

Stop-Transcript