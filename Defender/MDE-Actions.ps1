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
    Microsoft Defender for Endpoint Machine Actions GUI Tool
   
.DESCRIPTION
    PowerShell GUI tool for performing machine actions on MDE-enrolled devices.
    Supports both Azure Commercial and Azure Government clouds using OAuth 2.0 
    Device Code Flow authentication.

.INPUTS
    None. Interactive GUI-based tool.
   
.OUTPUTS
    Activity logs displayed in GUI and console output.
   
.NOTES
    Name: MDE-Actions.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 11/14/2025
    Revisions: Initial version
    Requires: PowerShell 5.1 or higher
#>

#Requires -Version 5.1

# Import required assemblies for Windows Forms
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

#region Configuration
$script:Config = @{
    Commercial = @{
        Authority = "https://login.microsoftonline.com/common"
        ResourceId = "https://api.securitycenter.microsoft.com"
        ApiEndpoint = "https://api.securitycenter.microsoft.com"
    }
    Government = @{
        Authority = "https://login.microsoftonline.us/common"
        ResourceId = "https://api-gov.securitycenter.microsoft.us"
        ApiEndpoint = "https://api-gov.securitycenter.microsoft.us"
    }
    # OPTION 1: Using Azure CLI public client ID (multi-tenant, Microsoft-maintained)
    # Works out-of-the-box but all organizations share the same client ID
    ClientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" # Azure CLI
    
    # OPTION 2: Create your own app registration (RECOMMENDED for production)
    # Follow these steps to create your own app:
    # 1. Navigate to https://portal.azure.com > Microsoft Entra ID > App registrations > New registration
    # 2. Name: "MDE Machine Actions Tool" (or your preferred name)
    # 3. Supported account types: "Accounts in this organizational directory only"
    # 4. Redirect URI: Select "Public client/native (mobile & desktop)" and enter "urn:ietf:wg:oauth:2.0:oob"
    # 5. After creation, go to API Permissions > Add permission > APIs my organization uses > search "WindowsDefenderATP"
    # 6. Select Delegated permissions and add the following:
    #    - Alert.Read.All (or Alert.Read)
    #    - Machine.Read.All (or Machine.Read)
    #    - Machine.Scan
    #    - Machine.CollectForensics
    #    - Machine.Isolate
    #    - Machine.RestrictExecution
    #    - Machine.Offboard
    #    - Machine.StopAndQuarantine (optional, for Stop and Quarantine File action)
    #    - Machine.LiveResponse (optional, for Live Response action)
    # 7. Click "Grant admin consent" button
    # 8. Copy the Application (client) ID from the Overview page and replace the ClientId value below
    # 9. (Optional) Copy the Directory (tenant) ID and update Authority from "/common" to "/{tenantId}"
    
    # To use your own app, uncomment and replace with your Application (client) ID:
    # ClientId = "YOUR-APP-CLIENT-ID-HERE"
}

$script:AccessToken = $null
$script:SelectedEnvironment = $null
#endregion

#region Authentication Functions
function Get-MDEAccessToken {
    <#
    .SYNOPSIS
        Acquires access token for Microsoft Defender for Endpoint API using OAuth 2.0 Device Code Flow
    #>
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Commercial', 'Government')]
        [string]$Environment
    )
    
    try {
        $envConfig = $script:Config[$Environment]
        $tokenEndpoint = "$($envConfig.Authority)/oauth2/v2.0/token"
        $deviceCodeEndpoint = "$($envConfig.Authority)/oauth2/v2.0/devicecode"
        
        # Request device code
        $deviceCodeBody = @{
            client_id = $script:Config.ClientId
            scope = "offline_access $($envConfig.ResourceId)/.default"
        }
        
        Write-Log "Requesting device code for authentication..." -Level Info
        
        try {
            $deviceCodeResponse = Invoke-RestMethod -Uri $deviceCodeEndpoint -Method Post -Body $deviceCodeBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        }
        catch {
            $errorDetails = $_.ErrorDetails.Message
            Write-Log "Device code request failed. Error: $errorDetails" -Level Error
            throw
        }
        
        # Display device code to user
        $message = @"
To sign in, use a web browser to open the page:
$($deviceCodeResponse.verification_uri)

And enter the code: $($deviceCodeResponse.user_code)

Waiting for authentication...
"@
        
        $codeForm = New-Object System.Windows.Forms.Form
        $codeForm.Text = "Device Authentication - $Environment"
        $codeForm.Size = New-Object System.Drawing.Size(550, 300)
        $codeForm.StartPosition = "CenterScreen"
        $codeForm.FormBorderStyle = 'FixedDialog'
        $codeForm.MaximizeBox = $false
        $codeForm.MinimizeBox = $false
        $codeForm.TopMost = $true
        
        $codeTextBox = New-Object System.Windows.Forms.TextBox
        $codeTextBox.Location = New-Object System.Drawing.Point(20, 20)
        $codeTextBox.Size = New-Object System.Drawing.Size(490, 140)
        $codeTextBox.Multiline = $true
        $codeTextBox.ReadOnly = $true
        $codeTextBox.Text = $message
        $codeTextBox.Font = New-Object System.Drawing.Font("Consolas", 10)
        $codeForm.Controls.Add($codeTextBox)
        
        $copyCodeButton = New-Object System.Windows.Forms.Button
        $copyCodeButton.Location = New-Object System.Drawing.Point(20, 175)
        $copyCodeButton.Size = New-Object System.Drawing.Size(150, 35)
        $copyCodeButton.Text = "Copy Code"
        $copyCodeButton.Add_Click({
            [System.Windows.Forms.Clipboard]::SetText($deviceCodeResponse.user_code)
            Write-Log "Device code copied to clipboard" -Level Info
        })
        $codeForm.Controls.Add($copyCodeButton)
        
        $openBrowserButton = New-Object System.Windows.Forms.Button
        $openBrowserButton.Location = New-Object System.Drawing.Point(190, 175)
        $openBrowserButton.Size = New-Object System.Drawing.Size(150, 35)
        $openBrowserButton.Text = "Open Browser"
        $openBrowserButton.Add_Click({
            Start-Process $deviceCodeResponse.verification_uri
            Write-Log "Opened browser for authentication" -Level Info
        })
        $codeForm.Controls.Add($openBrowserButton)
        
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(360, 175)
        $cancelButton.Size = New-Object System.Drawing.Size(150, 35)
        $cancelButton.Text = "Cancel"
        $cancelButton.Add_Click({
            $codeForm.Tag = "Cancelled"
            $codeForm.Close()
        })
        $codeForm.Controls.Add($cancelButton)
        
        $statusLabel = New-Object System.Windows.Forms.Label
        $statusLabel.Location = New-Object System.Drawing.Point(20, 220)
        $statusLabel.Size = New-Object System.Drawing.Size(490, 40)
        $statusLabel.Text = "Waiting for you to complete authentication in your browser..."
        $statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
        $codeForm.Controls.Add($statusLabel)
        
        # Show form non-blocking
        $codeForm.Show()
        [System.Windows.Forms.Application]::DoEvents()
        
        # Poll for token
        $interval = [int]$deviceCodeResponse.interval
        $expiresIn = [int]$deviceCodeResponse.expires_in
        $timeout = [DateTime]::Now.AddSeconds($expiresIn)
        
        $tokenBody = @{
            client_id = $script:Config.ClientId
            grant_type = "urn:ietf:params:oauth:grant-type:device_code"
            device_code = $deviceCodeResponse.device_code
        }
        
        $authenticationSucceeded = $false
        
        while ([DateTime]::Now -lt $timeout -and $codeForm.Visible -and $codeForm.Tag -ne "Cancelled") {
            Start-Sleep -Seconds $interval
            [System.Windows.Forms.Application]::DoEvents()
            
            try {
                $tokenResponse = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                
                if ($tokenResponse.access_token) {
                    $script:AccessToken = $tokenResponse.access_token
                    $script:SelectedEnvironment = $Environment
                    $authenticationSucceeded = $true
                    Write-Log "Successfully authenticated to $Environment environment" -Level Success
                    $codeForm.Close()
                    return $true
                }
            }
            catch {
                $errorResponse = $_.ErrorDetails.Message
                if ($errorResponse) {
                    try {
                        $errorObj = $errorResponse | ConvertFrom-Json
                        if ($errorObj.error -eq "authorization_pending") {
                            # Still waiting for user to authenticate
                            $statusLabel.Text = "Still waiting... Please complete authentication in your browser."
                            continue
                        }
                        elseif ($errorObj.error -eq "slow_down") {
                            # Increase polling interval
                            $interval += 5
                            continue
                        }
                        elseif ($errorObj.error -eq "expired_token") {
                            Write-Log "Authentication timeout - device code expired" -Level Error
                            $codeForm.Close()
                            [System.Windows.Forms.MessageBox]::Show(
                                "Authentication timed out. Please try again.",
                                "Timeout",
                                [System.Windows.Forms.MessageBoxButtons]::OK,
                                [System.Windows.Forms.MessageBoxIcon]::Warning
                            )
                            return $false
                        }
                        else {
                            throw
                        }
                    }
                    catch {
                        # If we can't parse the error, re-throw
                        throw
                    }
                }
            }
        }
        
        # Check if authentication succeeded (might have closed form in race condition)
        if ($authenticationSucceeded) {
            return $true
        }
        
        # Check if user cancelled
        if ($codeForm.Tag -eq "Cancelled") {
            Write-Log "Authentication cancelled by user" -Level Warning
            $codeForm.Close()
            return $false
        }
        
        # Only show timeout if form is still visible (not closed by successful auth)
        if ($codeForm.Visible) {
            Write-Log "Authentication timeout - no response received" -Level Error
            $codeForm.Close()
            [System.Windows.Forms.MessageBox]::Show(
                "Authentication timed out. Please try again.",
                "Timeout",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
        }
        
        return $false
    }
    catch {
        Write-Log "Authentication failed: $($_.Exception.Message)" -Level Error
        [System.Windows.Forms.MessageBox]::Show(
            "Authentication failed: $($_.Exception.Message)",
            "Authentication Error",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        )
        return $false
    }
}
#endregion

#region API Functions
function Get-MachineIdByName {
    <#
    .SYNOPSIS
        Resolves machine name to machine ID via MDE API
    #>
    param(
        [Parameter(Mandatory)]
        [string]$MachineName
    )
    
    try {
        $apiEndpoint = $script:Config[$script:SelectedEnvironment].ApiEndpoint
        $uri = "$apiEndpoint/api/machines?`$filter=computerDnsName eq '$MachineName'"
        
        $headers = @{
            Authorization = "Bearer $script:AccessToken"
            'Content-Type' = 'application/json'
        }
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
        
        if ($response.value.Count -gt 0) {
            return $response.value[0].id
        }
        else {
            Write-Log "Machine '$MachineName' not found" -Level Warning
            return $null
        }
    }
    catch {
        Write-Log "Failed to resolve machine '$MachineName': $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Invoke-MachineAction {
    <#
    .SYNOPSIS
        Executes a machine action via MDE API
    #>
    param(
        [Parameter(Mandatory)]
        [string]$MachineId,
        
        [Parameter(Mandatory)]
        [ValidateSet('RunAntiVirusScan', 'CollectInvestigationPackage', 'StartAutomatedInvestigation', 
                     'IsolateDevice', 'ReleaseFromIsolation', 'RestrictAppExecution', 'RemoveAppRestriction')]
        [string]$Action,
        
        [string]$Comment,
        
        [ValidateSet('Quick', 'Full')]
        [string]$ScanType = 'Full',
        
        [ValidateSet('Selective', 'Full')]
        [string]$IsolationType = 'Selective'
    )
    
    try {
        $apiEndpoint = $script:Config[$script:SelectedEnvironment].ApiEndpoint
        $uri = "$apiEndpoint/api/machines/$MachineId/$(Convert-ActionToEndpoint $Action)"
        
        $headers = @{
            Authorization = "Bearer $script:AccessToken"
            'Content-Type' = 'application/json'
        }
        
        # Get authenticated user's name from token if not provided in comment
        if (-not $Comment) {
            try {
                # Decode JWT token to get user info
                $tokenParts = $script:AccessToken.Split('.')
                $tokenPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($tokenParts[1].PadRight($tokenParts[1].Length + (4 - $tokenParts[1].Length % 4) % 4, '=')))
                $tokenData = $tokenPayload | ConvertFrom-Json
                $userName = if ($tokenData.upn) { $tokenData.upn } elseif ($tokenData.unique_name) { $tokenData.unique_name } else { $env:USERNAME }
                $Comment = "Action initiated via PowerShell GUI by $userName"
            }
            catch {
                $Comment = "Action initiated via PowerShell GUI by $env:USERNAME"
            }
        }
        
        $body = @{
            Comment = $Comment
        }
        
        # Add scan type for antivirus scan
        if ($Action -eq 'RunAntiVirusScan') {
            $body.ScanType = $ScanType
        }
        
        # Add isolation type for device isolation
        if ($Action -eq 'IsolateDevice') {
            $body.IsolationType = $IsolationType
        }
        
        $jsonBody = $body | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri $uri -Headers $headers -Method Post -Body $jsonBody
        
        Write-Log "Action '$Action' initiated successfully on machine ID: $MachineId (Action ID: $($response.id))"
        return $response
    }
    catch {
        Write-Log "Failed to execute action '$Action' on machine ID '$MachineId': $($_.Exception.Message)" -Level Error
        throw
    }
}

function Convert-ActionToEndpoint {
    <#
    .SYNOPSIS
        Converts action name to API endpoint
    #>
    param([string]$Action)
    
    switch ($Action) {
        'RunAntiVirusScan'            { return 'runAntiVirusScan' }
        'CollectInvestigationPackage' { return 'collectInvestigationPackage' }
        'StartAutomatedInvestigation' { return 'startInvestigation' }
        'IsolateDevice'               { return 'isolate' }
        'ReleaseFromIsolation'        { return 'unisolate' }
        'RestrictAppExecution'        { return 'restrictCodeExecution' }
        'RemoveAppRestriction'        { return 'unrestrictCodeExecution' }
    }
}
#endregion

#region Logging
function Write-Log {
    <#
    .SYNOPSIS
        Writes messages to log textbox
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    if ($script:LogTextBox) {
        $script:LogTextBox.AppendText("$logMessage`r`n")
        $script:LogTextBox.SelectionStart = $script:LogTextBox.Text.Length
        $script:LogTextBox.ScrollToCaret()
    }
    
    # Also write to console
    Write-Host $logMessage
}
#endregion

#region GUI Functions
function Import-MachinesFromCSV {
    <#
    .SYNOPSIS
        Opens file dialog and imports machine names from CSV
    #>
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $openFileDialog.Title = "Select CSV File with Machine Names"
    
    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $csv = Import-Csv -Path $openFileDialog.FileName
            
            # Try to find machine name column
            $machineColumn = $csv[0].PSObject.Properties.Name | Where-Object { 
                $_ -match 'machine|computer|device|hostname' 
            } | Select-Object -First 1
            
            if (-not $machineColumn) {
                $machineColumn = $csv[0].PSObject.Properties.Name[0]
            }
            
            $machines = $csv | ForEach-Object { $_.$machineColumn } | Where-Object { $_ }
            
            if ($machines) {
                $script:DeviceTextBox.Text = ($machines -join "`r`n")
                Write-Log "Imported $($machines.Count) machine(s) from CSV" -Level Success
            }
            else {
                [System.Windows.Forms.MessageBox]::Show(
                    "No machine names found in CSV file.",
                    "Import Error",
                    [System.Windows.Forms.MessageBoxButtons]::OK,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                "Failed to import CSV: $($_.Exception.Message)",
                "Import Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            )
        }
    }
}

function Invoke-SelectedAction {
    <#
    .SYNOPSIS
        Executes the selected action on all specified machines
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Action
    )
    
    # Validate authentication
    if (-not $script:AccessToken) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please authenticate first by selecting a cloud environment.",
            "Authentication Required",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    # Get machine names
    $machineNames = $script:DeviceTextBox.Text -split "`r`n" | Where-Object { $_.Trim() }
    
    if ($machineNames.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Please enter at least one machine name.",
            "No Machines Specified",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    # Prompt for scan type if running antivirus scan
    $scanType = 'Full'
    if ($Action -eq 'RunAntiVirusScan') {
        $scanTypeForm = New-Object System.Windows.Forms.Form
        $scanTypeForm.Text = "Select Scan Type"
        $scanTypeForm.Size = New-Object System.Drawing.Size(350, 200)
        $scanTypeForm.StartPosition = "CenterScreen"
        $scanTypeForm.FormBorderStyle = 'FixedDialog'
        $scanTypeForm.MaximizeBox = $false
        $scanTypeForm.MinimizeBox = $false
        
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20, 20)
        $label.Size = New-Object System.Drawing.Size(300, 30)
        $label.Text = "Select the type of antivirus scan to perform:"
        $scanTypeForm.Controls.Add($label)
        
        $quickRadio = New-Object System.Windows.Forms.RadioButton
        $quickRadio.Location = New-Object System.Drawing.Point(40, 60)
        $quickRadio.Size = New-Object System.Drawing.Size(250, 20)
        $quickRadio.Text = "Quick Scan (faster, common locations)"
        $quickRadio.Checked = $false
        $scanTypeForm.Controls.Add($quickRadio)
        
        $fullRadio = New-Object System.Windows.Forms.RadioButton
        $fullRadio.Location = New-Object System.Drawing.Point(40, 90)
        $fullRadio.Size = New-Object System.Drawing.Size(250, 20)
        $fullRadio.Text = "Full Scan (thorough, all files)"
        $fullRadio.Checked = $true
        $scanTypeForm.Controls.Add($fullRadio)
        
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(90, 125)
        $okButton.Size = New-Object System.Drawing.Size(75, 30)
        $okButton.Text = "OK"
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $scanTypeForm.Controls.Add($okButton)
        $scanTypeForm.AcceptButton = $okButton
        
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(180, 125)
        $cancelButton.Size = New-Object System.Drawing.Size(75, 30)
        $cancelButton.Text = "Cancel"
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $scanTypeForm.Controls.Add($cancelButton)
        $scanTypeForm.CancelButton = $cancelButton
        
        $result = $scanTypeForm.ShowDialog()
        
        if ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
            Write-Log "Scan action cancelled by user" -Level Warning
            return
        }
        
        $scanType = if ($quickRadio.Checked) { 'Quick' } else { 'Full' }
        Write-Log "Selected scan type: $scanType" -Level Info
    }
    
    # Prompt for isolation type if isolating device
    $isolationType = 'Selective'
    if ($Action -eq 'IsolateDevice') {
        $isolationForm = New-Object System.Windows.Forms.Form
        $isolationForm.Text = "Select Isolation Type"
        $isolationForm.Size = New-Object System.Drawing.Size(400, 200)
        $isolationForm.StartPosition = "CenterScreen"
        $isolationForm.FormBorderStyle = 'FixedDialog'
        $isolationForm.MaximizeBox = $false
        $isolationForm.MinimizeBox = $false
        
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(20, 20)
        $label.Size = New-Object System.Drawing.Size(350, 30)
        $label.Text = "Select the type of device isolation:"
        $isolationForm.Controls.Add($label)
        
        $selectiveRadio = New-Object System.Windows.Forms.RadioButton
        $selectiveRadio.Location = New-Object System.Drawing.Point(40, 60)
        $selectiveRadio.Size = New-Object System.Drawing.Size(320, 20)
        $selectiveRadio.Text = "Selective (allows Outlook, Teams, Skype)"
        $selectiveRadio.Checked = $true
        $isolationForm.Controls.Add($selectiveRadio)
        
        $fullIsolationRadio = New-Object System.Windows.Forms.RadioButton
        $fullIsolationRadio.Location = New-Object System.Drawing.Point(40, 90)
        $fullIsolationRadio.Size = New-Object System.Drawing.Size(320, 20)
        $fullIsolationRadio.Text = "Full (complete network isolation)"
        $fullIsolationRadio.Checked = $false
        $isolationForm.Controls.Add($fullIsolationRadio)
        
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(115, 125)
        $okButton.Size = New-Object System.Drawing.Size(75, 30)
        $okButton.Text = "OK"
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $isolationForm.Controls.Add($okButton)
        $isolationForm.AcceptButton = $okButton
        
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(205, 125)
        $cancelButton.Size = New-Object System.Drawing.Size(75, 30)
        $cancelButton.Text = "Cancel"
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $isolationForm.Controls.Add($cancelButton)
        $isolationForm.CancelButton = $cancelButton
        
        $result = $isolationForm.ShowDialog()
        
        if ($result -eq [System.Windows.Forms.DialogResult]::Cancel) {
            Write-Log "Isolation action cancelled by user" -Level Warning
            return
        }
        
        $isolationType = if ($fullIsolationRadio.Checked) { 'Full' } else { 'Selective' }
        Write-Log "Selected isolation type: $isolationType" -Level Info
    }
    
    Write-Log "Starting action '$Action' on $($machineNames.Count) machine(s)..." -Level Info
    
    $successCount = 0
    $failCount = 0
    
    foreach ($machineName in $machineNames) {
        $machineName = $machineName.Trim()
        Write-Log "Processing machine: $machineName"
        
        # Resolve machine name to ID
        $machineId = Get-MachineIdByName -MachineName $machineName
        
        if (-not $machineId) {
            Write-Log "Skipping machine '$machineName' - not found in MDE" -Level Warning
            $failCount++
            continue
        }
        
        # Execute action
        try {
            if ($Action -eq 'RunAntiVirusScan') {
                $result = Invoke-MachineAction -MachineId $machineId -Action $Action -ScanType $scanType
                Write-Log "Action completed for '$machineName' - $scanType scan (Action ID: $($result.id))" -Level Success
            }
            elseif ($Action -eq 'IsolateDevice') {
                $result = Invoke-MachineAction -MachineId $machineId -Action $Action -IsolationType $isolationType
                Write-Log "Action completed for '$machineName' - $isolationType isolation (Action ID: $($result.id))" -Level Success
            }
            else {
                $result = Invoke-MachineAction -MachineId $machineId -Action $Action
                Write-Log "Action completed for '$machineName' (Action ID: $($result.id))" -Level Success
            }
            $successCount++
        }
        catch {
            Write-Log "Action failed for '$machineName': $($_.Exception.Message)" -Level Error
            $failCount++
        }
    }
    
    Write-Log "Action summary: $successCount succeeded, $failCount failed" -Level Info
}

function New-MDEActionsGUI {
    <#
    .SYNOPSIS
        Creates the main GUI form
    #>
    
    # Create main form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Microsoft Defender for Endpoint - Machine Actions"
    $form.Size = New-Object System.Drawing.Size(800, 700)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    
    # Cloud Environment Section
    $cloudLabel = New-Object System.Windows.Forms.Label
    $cloudLabel.Location = New-Object System.Drawing.Point(20, 20)
    $cloudLabel.Size = New-Object System.Drawing.Size(150, 20)
    $cloudLabel.Text = "Cloud Environment:"
    $form.Controls.Add($cloudLabel)
    
    $cloudComboBox = New-Object System.Windows.Forms.ComboBox
    $cloudComboBox.Location = New-Object System.Drawing.Point(180, 18)
    $cloudComboBox.Size = New-Object System.Drawing.Size(250, 25)
    $cloudComboBox.DropDownStyle = 'DropDownList'
    $cloudComboBox.Items.AddRange(@('Azure Commercial', 'Azure Government'))
    $cloudComboBox.SelectedIndex = 0
    $form.Controls.Add($cloudComboBox)
    
    $authButton = New-Object System.Windows.Forms.Button
    $authButton.Location = New-Object System.Drawing.Point(450, 16)
    $authButton.Size = New-Object System.Drawing.Size(120, 28)
    $authButton.Text = "Authenticate"
    $authButton.Add_Click({
        $env = if ($cloudComboBox.SelectedItem -eq 'Azure Commercial') { 'Commercial' } else { 'Government' }
        if (Get-MDEAccessToken -Environment $env) {
            [System.Windows.Forms.MessageBox]::Show(
                "Authentication successful!",
                "Success",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    })
    $form.Controls.Add($authButton)
    
    # Device Names Section
    $deviceLabel = New-Object System.Windows.Forms.Label
    $deviceLabel.Location = New-Object System.Drawing.Point(20, 60)
    $deviceLabel.Size = New-Object System.Drawing.Size(300, 20)
    $deviceLabel.Text = "Machine Names (one per line):"
    $form.Controls.Add($deviceLabel)
    
    $script:DeviceTextBox = New-Object System.Windows.Forms.TextBox
    $script:DeviceTextBox.Location = New-Object System.Drawing.Point(20, 85)
    $script:DeviceTextBox.Size = New-Object System.Drawing.Size(550, 100)
    $script:DeviceTextBox.Multiline = $true
    $script:DeviceTextBox.ScrollBars = 'Vertical'
    $form.Controls.Add($script:DeviceTextBox)
    
    $csvButton = New-Object System.Windows.Forms.Button
    $csvButton.Location = New-Object System.Drawing.Point(590, 85)
    $csvButton.Size = New-Object System.Drawing.Size(170, 30)
    $csvButton.Text = "Import from CSV"
    $csvButton.Add_Click({ Import-MachinesFromCSV })
    $form.Controls.Add($csvButton)
    
    # Actions Section
    $actionsGroupBox = New-Object System.Windows.Forms.GroupBox
    $actionsGroupBox.Location = New-Object System.Drawing.Point(20, 200)
    $actionsGroupBox.Size = New-Object System.Drawing.Size(740, 195)
    $actionsGroupBox.Text = "Machine Actions"
    $form.Controls.Add($actionsGroupBox)
    
    # Action Buttons
    $actionButtons = @(
        @{ Text = "Run Antivirus Scan";             Action = "RunAntiVirusScan";             X = 20;  Y = 30;  Width = 160 },
        @{ Text = "Collect Investigation Package";  Action = "CollectInvestigationPackage";  X = 200; Y = 30;  Width = 160 },
        @{ Text = "Start Automated Investigation";  Action = "StartAutomatedInvestigation";  X = 380; Y = 30;  Width = 160 },
        @{ Text = "Isolate Device";                 Action = "IsolateDevice";                X = 560; Y = 30;  Width = 160 },
        @{ Text = "Release from Isolation";         Action = "ReleaseFromIsolation";         X = 20;  Y = 75;  Width = 160 },
        @{ Text = "Restrict App Execution";         Action = "RestrictAppExecution";         X = 200; Y = 75;  Width = 160 },
        @{ Text = "Remove App Restriction";         Action = "RemoveAppRestriction";         X = 380; Y = 75;  Width = 160 }
    )
    
    foreach ($btnConfig in $actionButtons) {
        $button = New-Object System.Windows.Forms.Button
        $button.Location = New-Object System.Drawing.Point($btnConfig.X, $btnConfig.Y)
        $button.Size = New-Object System.Drawing.Size($btnConfig.Width, 35)
        $button.Text = $btnConfig.Text
        $button.Tag = $btnConfig.Action
        $button.Add_Click({
            Invoke-SelectedAction -Action $this.Tag
        })
        $actionsGroupBox.Controls.Add($button)
    }
    
    # Log Section
    $logLabel = New-Object System.Windows.Forms.Label
    $logLabel.Location = New-Object System.Drawing.Point(20, 410)
    $logLabel.Size = New-Object System.Drawing.Size(100, 20)
    $logLabel.Text = "Activity Log:"
    $form.Controls.Add($logLabel)
    
    $script:LogTextBox = New-Object System.Windows.Forms.TextBox
    $script:LogTextBox.Location = New-Object System.Drawing.Point(20, 435)
    $script:LogTextBox.Size = New-Object System.Drawing.Size(740, 195)
    $script:LogTextBox.Multiline = $true
    $script:LogTextBox.ScrollBars = 'Vertical'
    $script:LogTextBox.ReadOnly = $true
    $script:LogTextBox.BackColor = [System.Drawing.Color]::White
    $form.Controls.Add($script:LogTextBox)
    
    # Initial log message
    Write-Log "MDE Machine Actions Tool initialized. Please authenticate to begin." -Level Info
    
    # Show form
    $form.ShowDialog() | Out-Null
}
#endregion

#region Main Execution
# Launch the GUI
New-MDEActionsGUI
#endregion