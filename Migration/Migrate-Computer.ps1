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
    Migrate computer to another domain
.DESCRIPTION
    This script can be used to migrate computers from one domain to another.  
    In this example we are migrating from Fabrikam.com to Contoso.com 
    https://docs.microsoft.com/en-us/powershell/module/microContosot.powershell.management/add-Computer?view=powershell-5.1

    Script performs the following actions:
        -Update lockscreen image to Contoso
        -Update User Account Picture to Contoso
        -Delete current domain Computer cert for Cisco ISE
        -Migrate Computer
        -Restart Computer
        -Remove Computer object from AD for Cisco ISE
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Migrate-Computer.ps1
    Authors/Contributors: Tungsten66
    DateCreated: 3/15/2021
    Revisions:
#> 

#Parameters

#Browse File location
Write-Warning "****** Select file with computers to migrate ******"
Add-Type -AssemblyName System.Windows.Forms
$FileBrowse = New-Object System.Windows.Forms.OpenFileDialog
$FileBrowse.filter = "Csv (*.csv)| *.csv"
$Null = $FileBrowse.ShowDialog()
$Computers = Import-Csv $FileBrowse.FileName

$ContosoCred = Get-Credential Contoso\ -Message "Enter admin account credentials that has permissions to both domains"

$OUPath = "OU=Clients,OU=_Contoso,DC=Contoso,DC=COM"

#Reporting
$outfile = "$PSScriptRoot\Logs\$(Get-Date -format 'ddMMMyy')_MigrateComputer.log"
$outfilesuccess = "$PSScriptRoot\Logs\$(Get-Date -format 'ddMMMyy')_MigrateComputerSuccess.csv"
if (!(Test-Path $outfile)) {
    "TimeStamp`tComputerName`tStatus" | out-file $outfile -Append
}
if (!(Test-Path $outfilesuccess)) {
    "ComputerName" | out-file $outfilesuccess -Append
}

#Progress Count
$Count = $null
$TotalObjects = ($Computers.ComputerName).count

#script

foreach ($Computer in $Computers)
{

    #Progress
    $Count += 1
    Write-Progress -Activity "Migrating Computer" -Status "$count of $TotalObjects"

    TRY {
        # Check if a computer object exists in Fabrikam
        Get-ADComputer $($Computer.ComputerName) -ErrorAction Stop
        # Test-Connection failed because ICMP is blocked so updated to check access to path
        Resolve-Path \\$($Computer.ComputerName)\C$ -ErrorAction Stop

        # Update lockscreen image to Contoso
        Copy-Item C:\_Migration\Scripts\Images\lockscreen.jpg \\$($Computer.ComputerName)\c$\windows\web\screen\backgroundDefault.jpg
        # Update Background image to Contoso
        takeown.exe /S $($Computer.ComputerName)$($Computer.ComputerName) /A /F c:\Windows\Web\Wallpaper\Windows\img0.jpg
        icacls.exe  \\$($Computer.ComputerName)\c$\Windows\Web\Wallpaper\Windows\img0.jpg /inheritance:e
        Copy-Item C:\_Migration\Scripts\Images\img0.jpg \\$($Computer.ComputerName)\c$\Windows\Web\Wallpaper\Windows\img0.jpg

        # Update User Account Picture to Contoso
        Copy-Item C:\_Migration\Scripts\Images\user* "\\$($Computer.ComputerName)\c$\ProgramData\Microsoft\User Account Pictures"
        Copy-Item C:\_Migration\Scripts\Images\guest* "\\$($Computer.ComputerName)\c$\ProgramData\Microsoft\User Account Pictures"

        # Delete current domain Computer cert for Cisco ISE
        Invoke-Command -ComputerName $($Computer.ComputerName) -ScriptBlock { Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.'Subject' -like "*.fabrikam.com" } | Remove-Item -Verbose }
    
        # Migrate Computer
        Add-Computer -DomainName Contoso.COM -Credential $ContosoCred -UnjoinDomainCredential $ContosoCred -ComputerName $($Computer.ComputerName) -OUPath $OUPath -ErrorAction Stop
        Write-Host "Waiting for Netlogon service to be up before restarting" -ForegroundColor DarkGreen
    
        While ((Get-Service Netlogon).Status -ne "Running") {
            Start-Sleep -Milliseconds 600
        }
    
        # Restart Computer
        Restart-Computer -ComputerName $($Computer.ComputerName) -Credential $ContosoCred -Force
    
        # Remove Computer object from AD for Cisco ISE
        Get-ADComputer $($Computer.ComputerName) | Remove-ADObject -Recursive -Confirm:$false

        Write-Host " $($Computer.ComputerName) Migrated Successfully" -ForegroundColor Green
        $(Get-Date -format 'ddMMMyy_HHmm') + "`t" + $($Computer.ComputerName) + "`t" + "Migrated" | Out-File $outfile -Append
        $($Computer.ComputerName) | Out-File $outfilesuccess -Append

    }

    CATCH {
        Write-Host "$($error[0].exception.Message)" -ForegroundColor DarkRed
        $(Get-Date -format 'ddMMMyy_HHmm') + "`t" + $($Computer.ComputerName) + "`t" + "$($error[0].exception.Message)" | Out-File $outfile -Append

    }

}