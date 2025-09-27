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
    Executes a PowerShell script on a remote computer with optional cleanup.
.DESCRIPTION
    This script copies a local PowerShell script to a remote computer, executes it,
    and optionally removes it after execution. Uses New-PSSession for connectivity
    testing and all remote operations.
.INPUTS
    Computer name (string), Local script path (string), Remote folder path (string)
.OUTPUTS
    Execution status messages and script output
.NOTES
    Name: Invoke-RemoteScript.ps1
    Authors/Contributors: Nick OConnor
    DateCreated:
    Revisions: 2025-09-27 - Initial version
#>

<#
.SYNOPSIS
    Executes a PowerShell script on a remote computer with optional cleanup.

.DESCRIPTION
    This script copies a local PowerShell script to a remote computer, executes it,
    and optionally removes it after execution. Uses New-PSSession for connectivity
    testing and all remote operations.

.NOTES
    Author: System Administrator
    Date: 2025-09-27
    Version: 2.0
    Requirements: PowerShell 5.1+, WinRM enabled on target computer
#>

# Clear any previous errors
$Error.Clear()

# Script banner
Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host "     Remote PowerShell Script Executor v2.0" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "This script will copy and execute a PS1 file on a remote computer`n" -ForegroundColor Gray

#region Step 1: Prompt for remote computer name
Write-Host "[Step 1] Remote Computer Configuration" -ForegroundColor Yellow
Write-Host "--------------------------------------" -ForegroundColor Gray

$remoteComputer = Read-Host "Enter the remote computer name or IP address"

# Validate computer name is not empty
if ([string]::IsNullOrWhiteSpace($remoteComputer)) {
    Write-Host "`n[ERROR] Computer name cannot be empty!" -ForegroundColor Red
    Write-Host "Script terminated.`n" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Target computer: $remoteComputer" -ForegroundColor Green
#endregion

#region Step 2: Configure local script path
Write-Host "`n[Step 2] Local Script Configuration" -ForegroundColor Yellow
Write-Host "-----------------------------------" -ForegroundColor Gray

# Variable for local PS1 script location
# IMPORTANT: Update this path to point to your actual script
$localScriptPath = "C:\_Hold\YourScript.ps1"  # << MODIFY THIS PATH

# Alternative: Uncomment below to prompt for script path
# $localScriptPath = Read-Host "Enter the full path to the local PS1 script"

# Check if local script exists
if (-not (Test-Path -Path $localScriptPath -PathType Leaf)) {
    Write-Host "`n[ERROR] Local script not found at: $localScriptPath" -ForegroundColor Red
    Write-Host "Please update the `$localScriptPath variable with the correct path" -ForegroundColor Yellow
    Write-Host "Script terminated.`n" -ForegroundColor Red
    exit 1
}

# Get script filename for later use
$scriptFileName = Split-Path -Path $localScriptPath -Leaf
Write-Host "[OK] Local script found: $scriptFileName" -ForegroundColor Green
#endregion

#region Step 3: Configure remote folder location
Write-Host "`n[Step 3] Remote Folder Configuration" -ForegroundColor Yellow
Write-Host "------------------------------------" -ForegroundColor Gray

# Default remote folder location
$defaultRemoteFolder = "C:\windows\Temp" # << MODIFY THIS PATH IF NEEDED

Write-Host "Default remote folder: $defaultRemoteFolder" -ForegroundColor Cyan
$userInput = Read-Host "Press [Enter] to use default or type a custom path"

# Use default if user pressed Enter, otherwise use their input
if ([string]::IsNullOrWhiteSpace($userInput)) {
    $remoteFolder = $defaultRemoteFolder
    Write-Host "[OK] Using default folder: $remoteFolder" -ForegroundColor Green
} else {
    $remoteFolder = $userInput.Trim()
    Write-Host "[OK] Using custom folder: $remoteFolder" -ForegroundColor Green
}

# Build the complete remote script path
$remoteScriptPath = Join-Path -Path $remoteFolder -ChildPath $scriptFileName
#endregion

#region Step 4: Test connectivity and validate remote folder
Write-Host "`n[Step 4] Testing Connectivity & Validating Remote Folder" -ForegroundColor Yellow
Write-Host "--------------------------------------------------------" -ForegroundColor Gray

$session = $null

try {
    Write-Host "Establishing connection to $remoteComputer..." -NoNewline
    
    # Create a PSSession - this tests connectivity
    # If this fails, it means we cannot connect to the remote computer
    $session = New-PSSession -ComputerName $remoteComputer -ErrorAction Stop
    Write-Host " SUCCESS" -ForegroundColor Green
    Write-Host "[OK] Connected to remote computer successfully" -ForegroundColor Green
    
    Write-Host "`nChecking if folder exists: $remoteFolder..." -NoNewline
    
    # Check if the folder exists on the remote computer
    $folderExists = Invoke-Command -Session $session -ScriptBlock {
        param($folder)
        Test-Path -Path $folder -PathType Container
    } -ArgumentList $remoteFolder -ErrorAction Stop
    
    if (-not $folderExists) {
        Write-Host " NOT FOUND" -ForegroundColor Red
        Write-Host "`n[ERROR] The folder '$remoteFolder' does not exist on '$remoteComputer'" -ForegroundColor Red
        Write-Host "Please create the folder on the remote computer or specify a different path" -ForegroundColor Yellow
        Write-Host "`nTo create the folder remotely, run this command:" -ForegroundColor Cyan
        Write-Host "  Invoke-Command -ComputerName $remoteComputer -ScriptBlock {New-Item -Path '$remoteFolder' -ItemType Directory -Force}" -ForegroundColor White
        Write-Host "`nScript terminated.`n" -ForegroundColor Red
        
        # Clean up session before exiting
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
        exit 1
    }
    
    Write-Host " EXISTS" -ForegroundColor Green
    Write-Host "[OK] Remote folder validated successfully" -ForegroundColor Green
    
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "`n[ERROR] Cannot connect to remote computer '$remoteComputer'" -ForegroundColor Red
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    
    Write-Host "`nTroubleshooting steps:" -ForegroundColor Yellow
    Write-Host "  1. Verify the computer name or IP address is correct" -ForegroundColor Yellow
    Write-Host "  2. Ensure the remote computer is powered on and connected to network" -ForegroundColor Yellow
    Write-Host "  3. Enable WinRM on the remote computer (run as Administrator):" -ForegroundColor Yellow
    Write-Host "     Enable-PSRemoting -Force" -ForegroundColor White
    Write-Host "  4. Check if Windows Firewall is blocking WinRM (port 5985/5986)" -ForegroundColor Yellow
    Write-Host "  5. Ensure you have administrative privileges on '$remoteComputer'" -ForegroundColor Yellow
    Write-Host "  6. Verify both computers are in the same domain or workgroup" -ForegroundColor Yellow
    Write-Host "  7. For non-domain computers, you may need to add to TrustedHosts:" -ForegroundColor Yellow
    Write-Host "     Set-Item WSMan:\localhost\Client\TrustedHosts -Value '$remoteComputer' -Force" -ForegroundColor White
    Write-Host "`nScript terminated.`n" -ForegroundColor Red
    
    # Clean up session if it was created
    if ($session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
    exit 1
}
#endregion

#region Step 5: Copy script to remote computer
Write-Host "`n[Step 5] Copying Script to Remote Computer" -ForegroundColor Yellow
Write-Host "------------------------------------------" -ForegroundColor Gray

try {
    Write-Host "Copying '$scriptFileName' to remote computer..." -NoNewline
    
    # Copy the file using the existing session
    Copy-Item -Path $localScriptPath -Destination $remoteScriptPath -ToSession $session -Force -ErrorAction Stop
    
    Write-Host " COMPLETE" -ForegroundColor Green
    Write-Host "[OK] Script copied to: $remoteScriptPath" -ForegroundColor Green
    
} catch {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "`n[ERROR] Failed to copy script: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Script terminated.`n" -ForegroundColor Red
    
    # Clean up session
    if ($session) {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
    exit 1
}
#endregion

#region Step 6: Execute script on remote computer
Write-Host "`n[Step 6] Executing Script on Remote Computer" -ForegroundColor Yellow
Write-Host "--------------------------------------------" -ForegroundColor Gray

$executionSuccess = $false

try {
    Write-Host "Executing '$scriptFileName'..." -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor Gray
    
    # Execute the script and capture output
    $scriptOutput = Invoke-Command -Session $session -ScriptBlock {
        param($scriptPath)
        
        # Temporarily set execution policy for this process
        Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue
        
        # Execute the script and return any output
        & $scriptPath
        
    } -ArgumentList $remoteScriptPath -ErrorAction Stop
    
    # Display the output if any
    if ($scriptOutput) {
        Write-Host $scriptOutput
    } else {
        Write-Host "(No output returned from script)" -ForegroundColor Gray
    }
    
    Write-Host "=" * 50 -ForegroundColor Gray
    Write-Host "[OK] Script executed successfully!" -ForegroundColor Green
    $executionSuccess = $true
    
} catch {
    Write-Host "=" * 50 -ForegroundColor Gray
    Write-Host "[ERROR] Script execution failed: $($_.Exception.Message)" -ForegroundColor Red
    $executionSuccess = $false
}
#endregion

#region Step 7: Cleanup - Delete script from remote computer (if execution was successful)
if ($executionSuccess) {
    Write-Host "`n[Step 7] Cleanup Options" -ForegroundColor Yellow
    Write-Host "------------------------" -ForegroundColor Gray
    
    # Prompt for cleanup only after successful execution
    Write-Host "The script has been executed successfully." -ForegroundColor Green
    Write-Host "Do you want to delete the script from the remote computer?" -ForegroundColor Cyan
    Write-Host "Remote path: $remoteScriptPath" -ForegroundColor Gray
    
    $cleanup = Read-Host "`nDelete '$scriptFileName' from $remoteComputer`? (Y/N)"
    
    if ($cleanup -eq 'Y' -or $cleanup -eq 'y') {
        try {
            Write-Host "`nDeleting script from remote computer..." -NoNewline
            
            # Delete the script using the same session
            Invoke-Command -Session $session -ScriptBlock {
                param($scriptPath)
                
                if (Test-Path -Path $scriptPath) {
                    Remove-Item -Path $scriptPath -Force -ErrorAction Stop
                    return $true
                } else {
                    return $false
                }
            } -ArgumentList $remoteScriptPath -ErrorAction Stop | Out-Null
            
            Write-Host " COMPLETE" -ForegroundColor Green
            Write-Host "[OK] Script deleted from remote computer" -ForegroundColor Green
            
        } catch {
            Write-Host " FAILED" -ForegroundColor Red
            Write-Host "[WARNING] Could not delete script: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Host "You may need to manually delete: $remoteScriptPath" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n[INFO] Script retained at: $remoteScriptPath" -ForegroundColor Cyan
        Write-Host "Remember to clean it up later if needed" -ForegroundColor Gray
    }
} else {
    Write-Host "`n[INFO] Skipping cleanup due to execution failure" -ForegroundColor Yellow
    Write-Host "The script remains at: $remoteScriptPath" -ForegroundColor Yellow
    Write-Host "You may want to manually investigate or remove it" -ForegroundColor Yellow
}
#endregion

#region Cleanup and finish
# Always clean up the PSSession
if ($session) {
    Write-Host "`nClosing remote session..." -NoNewline
    Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    Write-Host " DONE" -ForegroundColor Green
}

# Final summary
Write-Host "`n=================================================" -ForegroundColor Cyan
if ($executionSuccess) {
    Write-Host "         EXECUTION COMPLETED SUCCESSFULLY!" -ForegroundColor Green
} else {
    Write-Host "         EXECUTION COMPLETED WITH ERRORS" -ForegroundColor Yellow
}
Write-Host "=================================================" -ForegroundColor Cyan

# Display summary information
Write-Host "`nExecution Summary:" -ForegroundColor White
Write-Host "  Remote Computer: $remoteComputer" -ForegroundColor Gray
Write-Host "  Script Name: $scriptFileName" -ForegroundColor Gray
Write-Host "  Local Source: $localScriptPath" -ForegroundColor Gray
Write-Host "  Remote Location: $remoteScriptPath" -ForegroundColor Gray

if ($executionSuccess) {
    Write-Host "  Execution Status: " -NoNewline -ForegroundColor Gray
    Write-Host "Success" -ForegroundColor Green
    
    if ($cleanup -eq 'Y' -or $cleanup -eq 'y') {
        Write-Host "  Cleanup Status: " -NoNewline -ForegroundColor Gray
        Write-Host "Deleted" -ForegroundColor Green
    } else {
        Write-Host "  Cleanup Status: " -NoNewline -ForegroundColor Gray
        Write-Host "Retained" -ForegroundColor Yellow
    }
} else {
    Write-Host "  Execution Status: " -NoNewline -ForegroundColor Gray
    Write-Host "Failed" -ForegroundColor Red
    Write-Host "  Cleanup Status: " -NoNewline -ForegroundColor Gray
    Write-Host "Not performed" -ForegroundColor Gray
}

Write-Host "`nTimestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host ""
#endregion