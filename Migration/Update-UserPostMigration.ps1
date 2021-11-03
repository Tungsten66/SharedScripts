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
Contosotware product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your Contosotware product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneysâ€™ fees, that arise or result
from the use or distribution of the Sample Code.
 
This posting is provided "AS IS" with no warranties, and confers no rights. Use
of included script samples are subject to the terms specified
at https://www.microContosot.com/en-us/legal/copyright.
##############################################################################>

<#
.SYNOPSIS
   Update distribution group membership in new domain
.DESCRIPTION
    In this example we are migrating users from Fabrikam.com to Contoso.com and Exchange resource domain of Northwindtraders.com
    ADMT was used to migrate user accounts to contoso.com and northwindtraders.com before this script was ran
    Contoso admins were delegated permissions to manage Fabrikam users
    This script will perform the following:
        -set user attributes in Contoso and Northwintraders
        -re-ACL permissions of home drives for Contoso user
        -Move user objects in each domain in or out of AAD Connect sync OUs 
.INPUTS
   
.OUTPUTS
   
.NOTES
    Name: Update-UserPostMigration.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 8/19/2021
    Revisions:
#>

##Parameters##

#Browse File location
Write-Warning "****** Select file with users to update attributes ******"
Add-Type -AssemblyName System.Windows.Forms
$FileBrowse = New-Object System.Windows.Forms.OpenFileDialog
$FileBrowse.filter = "Csv (*.csv)| *.csv"
$Null = $FileBrowse.ShowDialog()
$users = Import-Csv $FileBrowse.FileName

#Reporting
$outfile = "$PSScriptRoot\logs\$(Get-Date -format 'ddMMMyy_HHmm')_UserPostMigration.log"
"Name`tStatus" | out-file $outfile -Append

#Credentials
$ContosoCred = Get-Credential "Enter Contoso credential"
$NorthwintradersCred = Get-Credential -Message "Enter Northwindtraders credential"

#DCs
$FabrikamDC = "DC1.Fabrikam.com"
$ContosoDC = "DC1.Contoso.com"
$NorthwintradersDC = "DC1.Northwintraders.com"

#OUs
$FabrikamOU = "OU=NoAADCSync,OU=Fabrikam Users,OU=_Fabrikam,DC=Fabrikam,DC=com" 
$NorthwintradersOU = "OU=Accounts,OU=_Northwindtraders,DC=Northwintraders,DC=com"

#Progress Count
$Count = $null
$TotalObjects = ($Users.SamAccountName).count

##Script##

foreach ($user in $users)
{

    #Progress
    $Count += 1
    Write-Progress -Activity "Migrating User" -Status "$count of $TotalObjects"

    #Retrieve Mail attribute from Northwintraders
    $NorthwintradersUser = Get-ADUser $($User.SamAccountName) -server $NorthwintradersDC -Properties mail

    TRY {
    
        ##Determine Contoso User OU destination location
        $OriginalFabrikamOU = $User.FabrikamOU
        if ($OriginalFabrikamOU -eq "Fabrikam.com/Fabrikam Users/Org1") { $ContosoOU = "OU=Org1,OU=Users,OU=_Contoso,DC=Contoso,DC=com" }
        if ($OriginalFabrikamOU -eq "Fabrikam.com/Fabrikam Users/Org2") { $ContosoOU = "OU=Org2,OU=Users,OU=_Contoso,DC=Contoso,DC=com" }

        ##Update User Attributes##
    
        #Contoso UPN suffix
        $ContosoUser = Get-ADUser $($User.SamAccountName) -Properties msExchMasterAccountSid -Server $ContosoDC
        $oldSuffix = "contosoltd.com"
        $newSuffix = "contoso.com"
        $NewUPN = $ContosoUser.UserPrincipalName.Replace($oldSuffix, $newSuffix)
    
        #Check for Visitor Account
        $checkVisitor = Get-ADUser -SearchBase "OU=Visitor,DC=Contoso,DC=com" -Filter { UserPrincipalName -like $NewUPN } -Server $ContosoDC

        if ($checkVisitor) {
            Get-ADUser $checkVisitor -Server $ContosoDC | Remove-ADUser -Confirm:$false
            Write-Host "$($User.SamAccountName) Deleting Visitor Account" -ForegroundColor DarkRed
        }

        #Update Contoso attributes Mail, PasswordNeverExpires, UPN, SmartcardLogonRequired
        if ($NorthwintradersUser) { Set-ADUser $($User.SamAccountName) -EmailAddress $NorthwintradersUser.mail -PasswordNeverExpires $false -UserPrincipalName $NewUPN -Server $ContosoDC -SmartcardLogonRequired $true -ChangePasswordAtLogon:$false }
        else { Set-ADUser $($User.SamAccountName) -PasswordNeverExpires $false -UserPrincipalName $NewUPN -Server $ContosoDC -SmartcardLogonRequired $true -ChangePasswordAtLogon:$false }
        Write-Host "$($User.SamAccountName) attributes updated" -ForegroundColor Green
    
        #Update NorthwintradersUser attributes msExchMasterAccountSid, PasswordNeverExpires
        $UserSID = ($ContosoUser).SID
        if ($NorthwintradersUser) {
            $NorthwintradersUser | Set-ADUser -Replace @{msExchMasterAccountSid = "$UserSID" } -PasswordNeverExpires $false -Server $NorthwintradersDC -Credential $NorthwintradersCred
            Write-Host "$($User.SamAccountName) msExchMasterAccountSid set" -ForegroundColor Green
        }

        ##Re-ACL User Home Drive##
        If (Resolve-Path "\\FileServer.Fabrikam.com\users\$($User.SamAccountName)") {
            #get the current ACL
            $acl = ((Get-Item "\\FileServer.Fabrikam.com\users\$($User.SamAccountName)").GetAccessControl('Access'))
            #build the new ACE granting full control to the TARGET identity
            $targetuser = "Contoso\$($User.SamAccountName)"
            $ace = New-Object System.Security.AccessControl.FileSystemAccessRule($targetuser, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            #add the new ACE to the ACL
            $acl.SetAccessRule($ace)
            #write the changes to the folder
            Set-Acl -Path "\\FileServer.Fabrikam.com\users\$($User.SamAccountName)" -AclObject $acl
            Write-Host "$($User.SamAccountName) Home Drive re-ACL successfully" -ForegroundColor Green
        }
    
        ##Move User Objects##   
        #Move source domain AD object into NoSyncOU and disable account
        $FabrikamUser = Get-ADUser $($User.SamAccountName) -server $FabrikamDC -Properties description 
        $FabrikamUser | Set-ADUser -Enabled $false -server $FabrikamDC -Credential $ContosoCred -Description ("DO NOT RE-ENABLE Migrated to Contoso " + "$(Get-Date -format 'ddMMMyy_HHmm') | " + $FabrikamUser.description)
        $FabrikamUser | Move-ADObject -TargetPath "$FabrikamOU" -Server $FabrikamDC -Credential $ContosoCred -ErrorAction Stop
        Write-Host "$($User.SamAccountName) Fabrikam Account Moved" -ForegroundColor Green
        # Move target domain AD object out of NoSyncOU
        $ContosoUser | Move-ADObject -TargetPath "$ContosoOU" -Server $ContosoDC -ErrorAction Stop
        Write-Host "$($User.SamAccountName) Contoso Account Moved" -ForegroundColor Green
        # Move Northwintraders AD object
        if ($NorthwintradersUser) {
            $NorthwintradersUser | Move-ADObject -TargetPath "$NorthwintradersOU" -Server $NorthwintradersDC -Credential $NorthwintradersCred -ErrorAction Stop
            Write-Host "$($User.SamAccountName) Northwintraders Account Moved" -ForegroundColor Green
            Write-Host "$($User.SamAccountName) Migration Complete"  
    
        }
    
        $($User.SamAccountName) + "`t" + "Updated" | Out-File $outfile -Append

        $NorthwintradersUser = $Null

    }
    CATCH {
        Write-Host "$($User.SamAccountName) Failed" -ForegroundColor DarkRed
        $($User.SamAccountName) + "`t" + "Failed" | Out-File $outfile -Append

    }


}

