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
    Check client DNS servers settings before migrating
.DESCRIPTION
    This script was created after we found several clients being migrated were pointing to the wrong DNS servers.
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Get-ClientDNSsettings.ps1
    Authors/Contributors: Tungsten66
    DateCreated: 9/27/2021
    Revisions:
#> 

#Browse File location for Computer list
Write-Warning "****** Select Migration CSV to get count ******"
Add-Type -AssemblyName System.Windows.Forms
$FileBrowse = New-Object System.Windows.Forms.OpenFileDialog
$FileBrowse.filter = "csv (*.csv)| *.csv"
$Null = $FileBrowse.ShowDialog()
$Computers = Import-Csv $FileBrowse.FileName

$outfile = "$PSScriptRoot\Logs\$(Get-Date -format 'ddMMMyy')_ClientDNSsettings.log"
"ComputerName`tIPv4Address`tDNSservers" | Out-File $outfile

foreach($Computer in $Computers){

$IPv4address = Get-ADComputer $Computer.computername -properties ipv4address | Select-Object ipv4address
$DNSInfo = Get-DnsClientServerAddress -CimSession $computer.computername | Where-Object {($_.AddressFamily -eq 2) -and ($_.ServerAddresses -like "*192.168.*")} | Select-Object ServerAddresses 

if($DNSInfo) {$($Computer.computername)+"`t"+$IPv4address.ipv4address+"`t"+$DNSinfo.ServerAddresses | Out-File $outfile -Append
}

}