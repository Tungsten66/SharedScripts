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
against any claims or lawsuits, including attorneys' fees, that arise or result
from the use or distribution of the Sample Code.

This posting is provided "AS IS" with no warranties, and confers no rights. Use
of included script samples are subject to the terms specified
at https://www.microsoft.com/en-us/legal/copyright.

##############################################################################>

<#
.SYNOPSIS
Finds SYSVOL GPO folders that no longer have matching Group Policy objects in AD.

.DESCRIPTION
Compares GUID-named folders under C:\Windows\SYSVOL\sysvol\<domain>\Policies
to existing GPO objects in Active Directory. Folders with no matching AD GPO
are flagged as orphaned (SYSVOL-only) to support safe cleanup validation.

Excludes non-GPO folders by matching only GUID-formatted folder names.
Includes LastWriteTime to help assess stale artifacts.

.INPUTS
None. This script does not accept pipeline or parameter input.

.OUTPUTS
System.Management.Automation.PSCustomObject
Properties: GUID, DisplayName, Status, Modified

.NOTES
    Name: Get-OrphanedSysvolGPOs.ps1
    Authors/Contributors: 
    DateCreated: 2026-06-17
    Revisions:
        2026-06-17 - Added legal disclaimer and populated help template.
#>

#Requires -Modules GroupPolicy

$domain       = (Get-ADDomain).DNSRoot
$sysvolPolicies = "C:\Windows\SYSVOL\sysvol\$domain\Policies"

Get-ChildItem -Path $sysvolPolicies -Directory |
    Where-Object { $_.Name -match '^\{[0-9A-Fa-f\-]{36}\}$' } |  # only GUID-named folders, excludes PolicyDefinitions
    ForEach-Object {
        $guid = $_.Name.Trim('{}')
        $gpo  = Get-GPO -Guid $guid -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            GUID        = $_.Name
            DisplayName = if ($gpo) { $gpo.DisplayName } else { "*** NOT FOUND IN AD ***" }
            Status      = if ($gpo) { "Active" } else { "ORPHANED - SYSVOL only" }
            Modified    = $_.LastWriteTime
        }
    } | Sort-Object Status | Format-Table -AutoSize


# ── BONUS: Find all OUs/domain root still linking a deleted GPO GUID ──────────
# Uncomment and set $orphanedGuid to use.
#
# $orphanedGuid = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
# $targets = @((Get-ADDomain).DistinguishedName) +
#            (Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty DistinguishedName)
# foreach ($dn in $targets) {
#     $links = (Get-GPInheritance -Target $dn).GpoLinks | Where-Object { $_.GpoId -eq $orphanedGuid }
#     if ($links) { Write-Host "Orphaned link found at: $dn" }
# }
