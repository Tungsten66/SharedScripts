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
   Report on Bitlocker Recovery Keys published to AD
.DESCRIPTION
    Bitlocker was previously enabled and keys stored in MBAM and a script was ran to save the recovery keys to AD.  This script is reporting on which computers have the bitlocker recoery key in AD.
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Get-BitlockerMigrationStatus.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 2/15/2022
    Revisions:
#>

#Variables

$outfile = "$PSScriptRoot\logs\$(Get-Date -format 'ddMMMyy')_BitlockerMigrationStatus.log"
"ComputerName`tStatus" | out-file $outfile -Append

$computers = get-adcomputer -SearchBase "OU=Clients,OU=_contoso,DC=contoso,DC=com" -Filter *

#Script

foreach($computer in $computers){

$bitlocker = Get-ADObject -filter {objectclass -eq 'msFVE-RecoveryInformation'} -searchbase $computer.distinguishedname -Properties *

if ($bitlocker.'msFVE-RecoveryPassword') {$status = "Published2AD"}

Else{$status = $null}

$($Computer.name)+"`t"+"$status" | Out-File $outfile -Append

$status = $null
$computer = $null

}