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
   Export Scheduled Tasks
.DESCRIPTION
    This script is an example of how to backup all scheduled tasks created by admins on a server and exclude the tasks that have been created by the OS.
    Run this on a scheduled task server that is used to perform Admin automation functions
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Export-AllTasks.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 7/30/2021
    Revisions:
#>

#Variables

#Script

Get-ScheduledTask | Where-Object { ($_ -notmatch "Microsoft") -and ($_ -notmatch "Optimize Start Menu Cache Files*") -and ($_ -notmatch "User_Feed_Synchronization*") } | ForEach-Object { Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | Out-File (Join-Path "$PSScriptRoot" "$($_.TaskName).xml") }
