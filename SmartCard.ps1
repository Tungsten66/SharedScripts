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
    Report on user's not required to use a smart card for interactive logon with the option to to enable SmartcardLogonRequired.
.DESCRIPTION
    This function will evaluate the defined AD Object's SmartcardLogonRequired $True or $False.
    Optional switch of enable will will set SmartcardLogonRequired $True on any user object in the domain that is not in the defined exception group
	Writen to help comply with:
    Windows Server 2016 Vul ID: V-73617
    Windows Server 2012/2012 R2 Domain Controller Vul ID: V-15488
    Example: get-smartcard -enable -SendEmail
.INPUTS
   -enable will enable SmartcardLogonRequired for users
   -SendEmail will e-mail out the report
   -bcc can be used in conjunction with -sendmail if you want to add an e-mail address to send to in bcc
.OUTPUTS
   Reports will be located in a Reports folder in the scripts location
   An ActionLog for the function will provide what the script has done in the scripts location called SmartCard_action.log
.NOTES
    Name: SmartCard.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 11/2/2017
    Revisions:
#>

#Parameters
function Get-SmartCard {

    param
    (
        [Parameter(Mandatory = $false)]
        [switch]$enable,
        [Parameter(Mandatory = $false)]
        [switch] $SendEmail
    )

    #Update for environment
    $UsersOU = "OU=Users,OU=CORP,DC=contoso,DC=com"
    $PrivUsersOU = "OU=PrivUsers,OU=CORP,DC=contoso,DC=com"
    $smtpserver = "smtp.contoso.com"
    $from = "Active Directory Administration <noreply@contoso.com>"
    $bcc = "Enterprise AD Team <enterprise-ad-team@contoso.com>"

    import-module activedirectory
    $report = @()
    $allobjects = @()
    $actionlog = "$PSScriptRoot\SmartCard_action.log"
    $basename = "SmartCard.csv"
    $date = get-date -Format ddMMMyyyy
    $filename = "$date" + "_" + "$basename"
    $path = "$PSScriptRoot\Reports\$filename"

    #Create Report location
    if (!(get-item "$PSScriptRoot\Reports" -ErrorAction Ignore)) {
        New-Item "$PSScriptRoot\Reports" -ItemType Directory
    }

        
    $exemptUsersgroup = "CAC Exempt Users" #members of this group will not require a smart card
    try {
        $exemptUsers = Get-ADGroupMember -Identity $ExemptusersGroup -Recursive
        $msg = "$(get-date):Got Exempt Users: Count = [$($exemptUsers.count)]"
        $msg | Out-File -FilePath $actionlog -Append -NoClobber
    }
    catch {
        $msg = "Error:$(get-date):Exception getting the group members. $_"
        $msg | Out-File -FilePath $actionlog -Append -NoClobber
        exit
    }
    $Users = Get-ADUser -Filter { SmartcardlogonRequired -eq "False" } -SearchBase $UsersOU -SearchScope Subtree -Properties *
    $PrivUsers = Get-ADUser -Filter { SmartcardlogonRequired -eq "False" } -SearchBase $PrivUsersOU -SearchScope Subtree -Properties *
    [array]$allobjects += $Users
    [array]$allobjects += $PrivUsers
    $msg = "$(get-date):Building User Report]"
    $msg | Out-File -FilePath $actionlog -Append -NoClobber
    foreach ($User in $allObjects) {
        #build hash table for reporting.
        $report += $User |
        select-object @{Name = 'Username'; expression = { $_.name.ToString() } }, `
        @{Name = 'DN'; expression = { $_.DistinguishedName.ToString() } }, `
        @{Name = 'Exempt'; expression = { if ($ExemptUsers.sid.contains($User.sid)) { "True" } else { "False" } } }
        if ($enable) {
            #control switch from param
            try {
                if (!$exemptUsers.sid.contains($User.sid) -and $exemptUsers.Count -gt 1) {
                    # Looking for a name match in the exempt group and that the exempt group has members.
                    try {
                        $user | Set-ADUser -SmartCardLogonRequired $True 
                        $msg = "$(get-date):Enabling smart card logon $($user.name)"
                        $msg | Out-File -FilePath $actionlog -Append -NoClobber
                    }
                    catch {
                        $msg = "Error:$(get-date):$_"
                        $msg | Out-File -FilePath $actionlog -Append -NoClobber
                    }
                }
                else {
                    $msg = "$(get-date) This User is either in the Exemption Group or the Exemption group is empty.User:$($user.name);Group:$ExemptGroup"
                    $msg | Out-File -FilePath $actionlog -Append -NoClobber
                }
            }
            catch {
                $msg = "Error:$(get-date):If statement for exempt Users [$($user.name)]:$_"
                $msg | Out-File -FilePath $actionlog -Append -NoClobber
            } 
        }
    }
    $report | export-csv $path -NoTypeInformation
       

    #region SendMail
    if ($sendEmail) {

        $to = "@"        
        $subject = "<ACTION REQUIRED> Enforce Smart Card"
        $Body = "CLASSIFICATION:UNCLASSIFIED`nCaveats: NONE`n`n Please see the attached CSV, review for any account that you know should not require a smart card for interactive logon`n`nTo submit an exception follow the ALTERNATIVE SMART CARD LOGON (ASCL) TOKEN EXEMPTION STANDARD OPERATING PROCEDURE (SOP)`n`nCLASSIFICATION:UNCLASSIFIED`nCaveats: NONE"
        $attachment = $path
        
        try {
            Send-MailMessage -Attachments $attachment -Body $Body -SmtpServer $smtpserver -To $to -From $from -Bcc $bcc -Subject $subject -ErrorAction SilentlyContinue
            $msg = "$(get-date):Sending Mail:To $to ; $bcc"
            $msg | Out-File -FilePath $actionlog -Append -NoClobber
        }
        catch {
            $msg = "Error:$(get-date):Sending Mail failed:$_"
            $msg | Out-File -FilePath $actionlog -Append -NoClobber
        }
    }


}
