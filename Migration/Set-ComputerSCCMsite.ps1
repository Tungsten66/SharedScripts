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
    Post-migration computer steps
.DESCRIPTION
       Script performs the following actions:
        -Switches SCCM site
        -Checks for the GPRequestedSiteAssignmentCode registery key and deletes if exists
        -Restarts the computer
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Get-SiteCode.ps1
    Authors/Contributors: Tungsten66
    DateCreated: 9/2/2021
    Revisions:
#> 

#Browse File location
Write-Warning "****** Select file with computers to run post migration steps ******"
Add-Type -AssemblyName System.Windows.Forms
$FileBrowse = New-Object System.Windows.Forms.OpenFileDialog
$FileBrowse.filter = "Csv (*.csv)| *.csv"
$Null = $FileBrowse.ShowDialog()

$computers = Import-Csv $FileBrowse.FileName

$outfile = "$PSScriptRoot\logs\$(Get-Date -format 'ddMMMyy_HHmm')_MigrateComputerSCCMSite.log"
"Name`tStatus" | out-file $outfile -Append

#Progress Count
$Count = $null
$TotalObjects = ($Computers.ComputerName).count


foreach ($Computer in $Computers)
{

    #Progress
    $Count += 1
    Write-Progress -Activity "Migrating Computer" -Status "$count of $TotalObjects"
    
    TRY {
        # Test-Connection failed because ICMP is blocked so checking path
        Resolve-Path \\$($Computer.ComputerName)\C$ -ErrorAction Stop

        # Migrate to new SCCM site
        Copy-Item C:\_Migration\Scripts\Reassign.vbs -Destination \\$($Computer.ComputerName)\C$\Hold
    
        # Check for registry key and if exist delete
        $SMSReg = Invoke-Command -ComputerName $($Computer.ComputerName) -ScriptBlock { (get-itemproperty 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client').GPRequestedSiteAssignmentCode }
        if ($SMSReg -cnotlike $null) { Invoke-Command -ComputerName $($Computer.ComputerName) -ScriptBlock { Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client' -Name GPRequestedSiteAssignmentCode } }

        Invoke-Command -ComputerName $($Computer.ComputerName) -ScriptBlock { cscript.exe "C:\Hold\Reassign.vbs" } -ErrorAction Stop
        Restart-Computer -ComputerName $($Computer.ComputerName) -Force -ErrorAction Stop

        Write-Host " $($Computer.ComputerName) SMS site migrated" -ForegroundColor Green
        $($Computer.ComputerName) + "`t" + "Migrated" | Out-File $outfile -Append
    }

    CATCH {
        Write-Host "$($error[0].exception.Message)" -ForegroundColor DarkRed
        $($Computer.ComputerName) + "`t" + "$($error[0].exception.Message)" | Out-File $outfile -Append

    }

}