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
    Example of how to create a base buildout of Active Directory OUs and groups
.DESCRIPTION
    This script creates a base buildout of Active Directory OUs and groups. It creates a base OU and sub-OUs for Users, Clients, Groups, Privileged, and Services. It also creates task groups and role groups within the Privileged OU.
.INPUTS
   Modify $base to set the base OU name. The script will create the base OU and sub-OUs under the domain distinguished name.
.OUTPUTS
   
.NOTES
    Name: BaseBuildout.ps1
    Authors/Contributors:
    DateCreated:
    Revisions:
#>


$domain = Get-ADDomain
$rootdse = Get-ADRootDSE
$PDCe = $domain.PDCEmulator
$domainDN = $domain.distinguishedname
$ous = @()
$ous = "Users","Clients","Groups","Privileged","Services"
$base = "_CORP"
New-ADOrganizationalUnit -Name $base -Path $domainDN -ProtectedFromAccidentalDeletion $false -Server $PDCe
foreach($ou in $ous){
    $ou
    New-ADOrganizationalUnit -name $ou -Path "OU=$base,$domainDN" -ProtectedFromAccidentalDeletion $false -Server $PDCe
    if($ou -eq "Privileged"){
        New-ADOrganizationalUnit -Name "Role Groups" -Path "OU=$ou,OU=$base,$domainDN"  -ProtectedFromAccidentalDeletion $false -Server $PDCe
        New-ADOrganizationalUnit -Name "Task Groups" -Path "OU=$ou,OU=$base,$domainDN" -ProtectedFromAccidentalDeletion $false -Server $PDCe
        New-ADOrganizationalUnit -Name "Users" -Path "OU=$ou,OU=$base,$domainDN" -ProtectedFromAccidentalDeletion $false -Server $PDCe
    }
}

#Create Task Groups
New-ADGroup -Name ds_client_mgmt -GroupScope Global -Path "OU=Task Groups,OU=Privileged,OU=$base,$domainDN" -Server $PDCe
New-ADGroup -Name ds_user_mgmt -GroupScope Global -Path "OU=Task Groups,OU=Privileged,OU=$base,$domainDN" -Server $PDCe
New-ADGroup -Name ds_group_mgmt -GroupScope Global -Path "OU=Task Groups,OU=Privileged,OU=$base,$domainDN" -Server $PDCe
New-ADGroup -Name La_ent_all_clients_admin -Description "Local admin of Clients" -GroupScope Global -Path "OU=Task Groups,OU=Privileged,OU=$base,$domainDN" -Server $PDCe
New-ADGroup -Name La_ent_all_svr_admin -Description "Local Admin on Servers" -GroupScope Global -Path "OU=Task Groups,OU=Privileged,OU=$base,$domainDN" -Server $PDCe

#Create Role Groups
New-ADGroup -Name "Enterprise AD Administrators" -Description "Members are responsible for administration and maintenance of the Active Directory Service" -GroupScope Global -Path "OU=Role Groups,OU=Privileged,OU=$base,$domainDN" -Server $PDCe
New-ADGroup -Name "Enterprise AD Object Managers" -Description "Members are responsible for the management of user, computer, and group objects" -GroupScope Global -Path "OU=Role Groups,OU=Privileged,OU=$base,$domainDN" -Server $PDCe
New-ADGroup -Name "Enterprise Client Administrators" -Description "Members are responsible for client AD objects and local administration of clients" -GroupScope Global -Path "OU=Role Groups,OU=Privileged,OU=$base,$domainDN" -Server $PDCe
New-ADGroup -Name "Enterprise Server Administrators" -Description "Members are responsible for server AD objects and local administration of servers" -GroupScope Global -Path "OU=Role Groups,OU=Privileged,OU=$base,$domainDN" -Server $PDCe
New-ADGroup -Name "Enterprise Service Desk" -Description "Members are able to create/delete/modify user, computer, and group objects" -GroupScope Global -Path "OU=Role Groups,OU=Privileged,OU=$base,$domainDN" -Server $PDCe

