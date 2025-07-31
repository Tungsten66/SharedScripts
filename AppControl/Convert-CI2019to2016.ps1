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
    Convert 2019 App control policy to support Server 2016
.DESCRIPTION
    This script converts a Server 2019 App Control policy XML file to a format compatible with Server 2016.
    It removes unsupported rules, updates the policy name and ID, and creates a binary policy file.
    
    The script prompts the user to select the Server 2019 XML policy file and the folder to save the converted Server 2016 policy.
    It then modifies the XML file accordingly and generates a .p7b binary file.
.INPUTS
    None. The script prompts the user to select the input XML file and output folder.
.OUTPUTS
    A converted Server 2016 App Control policy XML file and a .p7b binary file.
.NOTES
    ScriptName: Convert-CI2019to2016.ps1
    Authors/Contributors: Tungsten66
    DateCreated: 7/31/2025
    Revisions: 
#>

# Variables
# Prompt user for file paths for the Server 2019 XML policy file
Write-Host "NOTE: A prompt window may appear behind other windows. Please check your taskbar if you don't see it." -ForegroundColor Yellow
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.MessageBox]::Show("Please select the Server 2019 policy XML file you want to convert.", "Select Policy", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
$OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
$OpenFileDialog.Filter = "XML files (*.xml)|*.xml|All files (*.*)|*.*"
$OpenFileDialog.Title = "Select the XML Policy File"
if ($OpenFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $XMLFilePath2019 = $OpenFileDialog.FileName
} else {
    Write-Host "No file selected. Exiting script."
    exit
}
# Prompt user for file paths for the Server 2016 XML policy file
Write-Host "NOTE: A prompt window may appear behind other windows. Please check your taskbar if you don't see it." -ForegroundColor Yellow
[System.Windows.Forms.MessageBox]::Show("Please select the location to save the new Server 2016 policy.", "Select Save Location", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
$FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
$FolderBrowser.Description = "Select the folder to save the converted Server 2016 policy"
if ($FolderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $SaveFolder = $FolderBrowser.SelectedPath
    $XMLFileName = [System.IO.Path]::GetFileName($XMLFilePath2019)
    $XMLFilePath2016 = Join-Path -Path $SaveFolder -ChildPath $XMLFileName
} else {
    Write-Host "No folder selected. Exiting script."
    exit
}
$BinaryFilePath = Join-Path -Path $SaveFolder -ChildPath "SiPolicy.p7b"

# copy the original XML file to the new location
Copy-Item -Path $XMLFilePath2019 -Destination $XMLFilePath2016 -Force
# Removing Rules that are not supported in 2016
Set-RuleOption -FilePath $XMLFilePath2016 -Option 11 -Delete #11 Disabled:Script Enforcement
Set-RuleOption -FilePath $XMLFilePath2016 -Option 13 -Delete #13 Enabled:Managed Installer
Set-RuleOption -FilePath $XMLFilePath2016 -Option 16 -Delete #16 Enabled:Update Policy No Reboot
# Update name of the policy to server 2016 and version to include the date this was ran.
$PolicyName = "Server 2016 App Control Policy"
$PolicyId = "$(Get-Date -Format 'yyyy-MM-dd')"
Set-CIPolicyIdInfo -FilePath $XMLFilePath2016 -PolicyName $PolicyName -PolicyId $PolicyId
# Creating p7b
ConvertFrom-CIPolicy -XmlFilePath $XMLFilePath2016 -BinaryFilePath $BinaryFilePath
# Output the paths of the created files
Write-Host "Converted Server 2016 App Control policy XML file created at: $XMLFilePath2016" -ForegroundColor Green
Write-Host "Binary policy file created at: $BinaryFilePath" -ForegroundColor Green