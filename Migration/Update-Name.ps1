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
    Rename Users
.DESCRIPTION
       Rename users to match displayname after the displayname was updated by a user logon script
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Update-Name.ps1
    Authors/Contributors: Tungsten66
    DateCreated: 9/2/2021
    Revisions:
#> 

#Parameters

$outfile = "$PSScriptRoot\Logs\$(Get-Date -format 'ddMMMyy_HHmm')_Check-Name.log"
"SamAccountName`tOldName`tNewName`tStatus" | out-file $outfile -Append

# DCs
$ContosoDC = "DC1.Contoso.com"

$users = Get-ADUser -SearchBase "OU=Users,OU=_Contoso,DC=Contoso,DC=com" -Filter * -Server $ContosoDC -Properties displayname


#Script

foreach ($user in $users)
{
    If ($user.Name -notlike $user.DisplayName) {
    
        $User.SamAccountName + "`t" + $($user.Name) + "`t" + $($user.DisplayName) + "`t" + "Updated" | Out-File $outfile -Append
        Rename-ADObject $user -NewName $user.DisplayName -Server $ContosoDC -Credential $ContosoCred

    }
}