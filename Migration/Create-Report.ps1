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
    Create reporting on user/computer migration
.DESCRIPTION
    Select a pre-migration list of users and computers you tried to migrate and select the computer migration status log and it will build a consolidated report.
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Create-Report.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 9/1/2021
    Revisions:
#> 

##Parameters##

#Browse File location for User/Computer report
Write-Warning "****** Select Migration CSV to get count ******"
Add-Type -AssemblyName System.Windows.Forms
$FileBrowse = New-Object System.Windows.Forms.OpenFileDialog
$FileBrowse.filter = "csv (*.csv)| *.csv"
$Null = $FileBrowse.ShowDialog()
$Objects = Import-Csv $FileBrowse.FileName

#Browse File location for Computer migration status
Write-Warning "****** Select MigrateComputer.log to get count ******"
Add-Type -AssemblyName System.Windows.Forms
$FileBrowse1 = New-Object System.Windows.Forms.OpenFileDialog
$FileBrowse1.filter = "Log (*.log)| *.log"
$Null = $FileBrowse1.ShowDialog()
$Computers = Get-Content $FileBrowse1.FileName

$outfile = "$PSScriptRoot\logs\$(Get-Date -format 'ddMMMyy_HHmm')_MigrationReport.csv"
$outfileComputer = "$PSScriptRoot\logs\$(Get-Date -format 'ddMMMyy_HHmm')_ComputerMigrationReport.txt"


$dataobj = $Null

$outputobj = @()

#User/Computer report
#output - ComputerName,SamAccountName,DisplayName,EmailAddress,UserPrincipalName
foreach ($Object in $Objects) {
    $dataobj = New-Object -TypeName psobject
    
    #Check to see if the computer has been migrated
    $ComputerStatus = $Null  

    #if(Get-ADComputer $($Object.ComputerName)){$ComputerStatus = "Migrated"}
    TRY {
        Get-ADComputer $($Object.ComputerName) -ErrorAction Stop
        $ComputerStatus = "Migrated"
    }
    CATCH {
        $ComputerStatus = $Null
    }

    $User = Get-ADUser $($Object.SamAccountName) -Properties *
    Add-Member -InputObject $dataobj -MemberType NoteProperty -Name ComputerName -Value $($Object.ComputerName)
    Add-Member -InputObject $dataobj -MemberType NoteProperty -Name ComputerStatus -Value $ComputerStatus
    Add-Member -InputObject $dataobj -MemberType NoteProperty -Name SamAccountName -Value $($User.SamAccountName)
    Add-Member -InputObject $dataobj -MemberType NoteProperty -Name DisplayName -Value $($User.DisplayName)
    Add-Member -InputObject $dataobj -MemberType NoteProperty -Name NewEmailAddress -Value $($User.EmailAddress)
    Add-Member -InputObject $dataobj -MemberType NoteProperty -Name UPN -Value $($User.UserPrincipalName)

    $outputobj += $dataobj
    $dataobj = $Null 
    $User = $Null
    $ComputerStatus = $Null  

}

#$outputobj | Write-Output

$outputobj | Export-Csv $outfile -NoTypeInformation

#Computer migration status
$Migrated = Select-String -InputObject $Computers -Pattern "Migrated" -AllMatches
$NotInAD = Select-String -InputObject $Computers -Pattern "Cannot find an object with identity" -AllMatches
$Offline = Select-String -InputObject $Computers -Pattern "Cannot find path" -AllMatches
$WMI = Select-String -InputObject $Computers -Pattern "Cannot establish the WMI connection to the computer" -AllMatches
$FailedtoUnjoin = Select-String -InputObject $Computers -Pattern "Failed to unjoin computer" -AllMatches


"Log Location $($FileBrowse.FileName)" | Out-File $outfileComputer -Append
"$($Migrated.Matches.Count) Migrated" | Out-File $outfileComputer -Append
"$($NotInAD.Matches.Count) NotInAD" | Out-File $outfileComputer -Append
"$($Offline.Matches.Count) Offline" | Out-File $outfileComputer -Append
"$($WMI.Matches.Count) Cannot establish the WMI connection" | Out-File $outfileComputer -Append
"$($FailedtoUnjoin.Matches.Count) FailedtoUnjoin" | Out-File $outfileComputer -Append