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
   Deploys App Control policies to specified computers in Audit or Enforce mode.
.DESCRIPTION
    This script allows you to deploy App Control policies to one or more computers in either Audit or Enforce mode.
    It checks for the existence of the specified policy files, copies them to the target computers, and invokes a refresh
    of the policy using RefreshPolicy.exe. If in Audit mode, it prompts the user to optionally add the computer to an exemption group.
    The script also logs actions and statuses to a log file.
.INPUTS
    The script accepts the following parameters:
    - ComputerNames: An array of computer names to which the policy will be deployed. If not provided, it prompts for input.
    - Mode: A string that specifies the mode of deployment, either "Audit" or "Enforce". If not provided, it prompts for input.
    The script also requires access to the specified source files for each mode and the RefreshPolicy.exe executable.
.OUTPUTS
    The script outputs log entries to a specified log file, detailing the actions taken and their statuses for each computer.
    It also provides console output indicating the progress of the deployment.
.NOTES
    Name:Apply-Policy.ps1
    Authors/Contributors:Tungsten66
    DateCreated: 6/20/2025
    Revisions:1.1 - 6/23/2025 added $RefreshExeAdmShare  
#>


# Parameters

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$ComputerNames,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Audit", "Enforce")]
    [string]$Mode
)

# Variables
## Define the files for each mode.
$auditFile = "\\lab-ap1\artifacts\AppControl\Server2022\Audit\{A244370E-44C9-4C06-B551-F6016E563076}.cip"
$enforceFile = "\\lab-ap1\artifacts\AppControl\Server2022\Enforce\{A244370E-44C9-4C06-B551-F6016E563076}.cip"

## Define log file path
$logFile = "\\lab-ap1\artifacts\AppControl\Logs\PolicyDeploymentLog.txt"

## Define Souce location for RefreshPolicy.exe is missing from the remote computer.
$RefreshExeSource = "\\lab-ap1\artifacts\AppControl\RefreshPolicy.exe"
## Define RefreshPolicy.exe file location on Remote computer
$RefreshExe = "C:\_Hold\RefreshPolicy.exe"
# Replace C:\ with C$\
$RefreshExeAdmShare = $RefreshExe -replace '^C:\\', 'C$\'

## Define the security group for adding servers that are exempt from enforcement policy for specific time
$ExemptionGroup = "AppControl-ServerExemption"

# Prerequisites
## Check for AD module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Error "Active Directory module is not available. Please install RSAT: Active Directory tools."
    exit 1
}

# Prompt for destination computer(s) if not provided.
if (-not $ComputerNames) {
    $computerInput = Read-Host "Enter the destination computer name(s), separated by commas"
    $ComputerNames = $computerInput -split '\s*,\s*'
}

# Prompt for mode if not provided
if (-not $Mode) {
    $policyMode = Read-Host "Enter 'A' for Audit mode or 'E' for Enforce mode"
    switch ($policyMode.ToUpper()) {
        'A' { $Mode = 'Audit' }
        'E' { $Mode = 'Enforce' }
        default {
            Write-Error "Invalid input. Please enter 'A' or 'E'."
            exit 1
        }
    }

    # Select the source file based on the provided mode.
    switch ($Mode) {
        "Audit" { $SourceFile = $auditFile }
        "Enforce" { $SourceFile = $enforceFile }
    }

    # Verify the selected source file exists.
    if (-not (Test-Path $SourceFile)) {
        Write-Error "Source file for mode '$Mode' does not exist: $SourceFile"
        exit 1
    }

    # Ensure the directory for the log file exists
    if (-not (Test-Path (Split-Path $logFile))) {
        New-Item -Path (Split-Path $logFile) -ItemType Directory -Force | Out-Null
    }

    # Add header if the log file does not exist
    if (-not (Test-Path $logFile)) {
        "timestamp`tcurrentUser`tComputer`tAction`tStatus" | Out-File -FilePath $logFile -Encoding UTF8
    }


    function Write-Log {
        param (
            [string]$Computer,
            [string]$Action,
            [string]$Status
        )
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $logEntry = "$timestamp`t$currentUser`t$Computer`t$Action`t$Status"
        Add-Content -Path $logFile -Value $logEntry
    }

    foreach ($computer in $ComputerNames) {
        $DestinationPath = "\\$computer\c$\Windows\System32\CodeIntegrity\CiPolicies\Active\"

        if (-not (Test-Path $DestinationPath)) {
            Write-Error "Destination path does not exist on $computer : $DestinationPath"
            Write-Log -Computer $computer -Action "Verify Destination Path" -Status "Failed"
            continue
        }
        try {
            Write-Host "Copying [$Mode] file to $computer" -ForegroundColor Cyan
            Copy-Item -Path $SourceFile -Destination $DestinationPath -Force
            Write-Host "File copied successfully to $computer." -ForegroundColor Green
            # Check and copy RefreshPolicy.exe if missing, then invoke it
            if (-Not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
                Write-Error "Cannot reach $computer"
            } 
            else {
                $fileExists = Invoke-Command -ComputerName $computer -ScriptBlock {
                    Test-Path -Path $using:RefreshExe
                }

                if (-Not $fileExists) {
                    Copy-Item -Path $RefreshExeSource -Destination "\\$computer\$RefreshExeAdmShare"
                }

                # Now invoke the command
                Invoke-Command -ComputerName $computer -ScriptBlock {
                    & $using:RefreshExe
                } -Verbose

                Write-Log -Computer $computer -Action "Deploy $Mode Policy" -Status "Success"

                # If Audit mode, prompt for exemption
                if ($Mode -eq "Audit") {
                    $setExemption = Read-Host "Do you want to exempt $computer from enforcement? (Y/N)"
                    if ($setExemption -match '^(Y|y)$') {
                        $days = Read-Host "Enter the number of days to exempt $computer from enforcement"
                        if ($days -match '^\d+$') {
                            $ttl = [TimeSpan]::FromDays([int]$days)
                            try {
                                Add-ADGroupMember -Identity $ExemptionGroup -Members "$computer$" -MemberTimeToLive $ttl
                                Write-Host "$computer added to '$ExemptionGroup' group for $days day(s)." -ForegroundColor Yellow
                                Write-Log -Computer $computer -Action "Add to Exemption Group" -Status "Success ($days days)"
                            }
                            catch {
                                Write-Error "Failed to add $computer to exemption group: $_"
                                Write-Log -Computer $computer -Action "Add to Exemption Group" -Status "Failed: $_"
                            }
                        }
                        else {
                            Write-Warning "Invalid number of days entered. Skipping exemption for $computer."
                            Write-Log -Computer $computer -Action "Add to Exemption Group" -Status "Skipped (invalid input)"
                        }
                    }
                    else {
                        Write-Host "No exemption set for $computer."
                        Write-Log -Computer $computer -Action "Add to Exemption Group" -Status "Skipped (user declined)"
                    }
                }
            }
        }
        catch {
            Write-Error "An error occurred on $computer : $_"
            Write-Log -Computer $computer -Action "Deploy $Mode Policy" -Status "Failed: $_"
        }
    }

}
