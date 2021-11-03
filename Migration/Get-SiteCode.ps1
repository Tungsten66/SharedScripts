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
    Check SCCM site code on migrated clients
.DESCRIPTION
    Run this against the OU in the domain you migrated computers to checking that the SCCM site code was successfully changed
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Get-SiteCode.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 9/2/2021
    Revisions:
#> 

$computers = Get-ADComputer -SearchBase "OU=Clients,OU=_Contoso,DC=Contoso,DC=com" -Filter *
$outfile = "$PSScriptRoot\logs\$(Get-Date -format 'ddMMMyy_HHmm')_SMSsiteCode.log"
"Name`tSiteCode" | out-file $outfile -Append


foreach ($computer in $computers) {

    TRY {
        Resolve-Path \\$($Computer.Name)\C$ -ErrorAction Stop
        $AvData = Invoke-Command -ComputerName $computer.Name -ScriptBlock { Get-ItemProperty HKLM:\SOFTWARE\Microsoft\SMS\DP } | select SiteCode
        Write-host  "$($computer.name) $($AvData.SiteCode)"
        $($computer.name) + "`t" + $($AvData.SiteCode) | Out-File $outfile -Append
    }
    CATCH {
        Write-Host "$($computer.name) is offline"
    }

}