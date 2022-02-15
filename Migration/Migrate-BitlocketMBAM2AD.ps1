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
   Backup Bitlocker key to AD
.DESCRIPTION
    This script is an example of how to backup backup a bitlocker key to AD on computers that previously have Bitlocker enabled and managed by MBAM.  
    The policy setting to configure storage of BitLocker recovery inforamtion to AD DS must be applied on the computers before running this script on the computers.
    https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings#choose-how-bitlocker-protected-operating-system-drives-can-be-recovered
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Migrate-BitlockerMBAM2AD.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 2/15/2022
    Revisions:
#>

#Variables

$BitLocker = Get-BitLockerVolume -MountPoint $env:SystemDrive

#Script

    if($BitLocker.VolumeStatus -eq "FullyEncrypted"){
        
    $RecoveryProtector = $BitLocker.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
    Backup-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $RecoveryProtector.KeyProtectorID
    Write-Host "BitLockerKeyProtector backup to AD for $env:COMPUTERNAME successfull" -ForegroundColor Green
    }