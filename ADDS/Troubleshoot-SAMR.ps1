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
    Identifies GPO configurations that drive excessive SAMR requests on Domain Controllers.

.DESCRIPTION
    Scans all Group Policy Objects in the domain and reports on configurations known to
    generate high volumes of SAMR (Security Account Manager Remote) calls, which can
    spike Domain Controller CPU usage. Checks include:

    1. Item-Level Targeting (ILT) using security group membership
    2. WMI filters, security group filtering, ILT registry checks, and enforced/block inheritance
    3. Loopback processing in Merge mode on workstation OUs
    4. User-targeted GPOs linked to computer-only OUs
    5. High-frequency background GPO refresh intervals
    6. GP Preferences drive mappings using Replace instead of Update
    7. GP Preferences registry items using Replace instead of Update

.INPUTS
    None. Requires the GroupPolicy and ActiveDirectory PowerShell modules.

.OUTPUTS
    Console report summarizing GPO configurations that may cause excessive SAMR traffic.

.NOTES
    Name: Troubleshoot-SAMR.ps1
    Authors/Contributors: Nick OConnor
    DateCreated: 2026-03-13
    Revisions: v1.1 - Added checks for GP Preferences Replace actions; improved reporting format.

    Prerequisites:
    - Run from a domain-joined machine with RSAT tools installed
    - GroupPolicy module (Import-Module GroupPolicy)
    - ActiveDirectory module (Import-Module ActiveDirectory)
    - Appropriate permissions to read GPOs and AD objects
#>

#Requires -Modules GroupPolicy, ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Domain to scan. Defaults to current domain.")]
    [string]$DomainName = $env:USERDNSDOMAIN,

    [Parameter(HelpMessage = "Export results to CSV at this path.")]
    [string]$ExportPath
)

# ── Helper: Parse GPO XML report for Item-Level Targeting ──────────────────
function Get-ILTSecurityGroupTargeting {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$GpoXml,

        [Parameter(Mandatory)]
        [string]$GpoName
    )

    $findings = @()
    $xmlText = $GpoXml.OuterXml

    # Look for security-group-based Item-Level Targeting (FilterGroup nodes)
    # Extract group names via regex from the raw XML for reliability
    $groupMatches = [regex]::Matches($xmlText, '<FilterGroup[^>]*?name="([^"]+)"')
    if ($groupMatches.Count -gt 0) {
        foreach ($m in $groupMatches) {
            $groupName = $m.Groups[1].Value
            $findings += [PSCustomObject]@{
                GPOName  = $GpoName
                Check    = "ILT - Security Group Targeting"
                Detail   = "Item-Level Targeting references security group: $groupName"
                Severity = "High"
            }
        }
    }
    elseif ($xmlText -match 'FilterGroup') {
        # FilterGroup tag present but couldn't parse name attribute
        $findings += [PSCustomObject]@{
            GPOName  = $GpoName
            Check    = "ILT - Security Group Targeting"
            Detail   = "GPO XML contains Item-Level Targeting with security group filters (FilterGroup detected)."
            Severity = "High"
        }
    }

    return $findings
}

# ── Helper: Check for ILT registry-based checks in GPO XML ────────────────
function Get-ILTRegistryChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$GpoXml,

        [Parameter(Mandatory)]
        [string]$GpoName
    )

    $findings = @()
    $xmlText = $GpoXml.OuterXml

    # FilterRegistry nodes indicate registry-based ILT
    if ($xmlText -match 'FilterRegistry') {
        $findings += [PSCustomObject]@{
            GPOName  = $GpoName
            Check    = "ILT - Registry Check"
            Detail   = "Item-Level Targeting uses registry-based filters. These evaluate on every GP refresh cycle."
            Severity = "Medium"
        }
    }

    return $findings
}

# ── Helper: Detect loopback processing settings in GPO XML ────────────────
function Get-LoopbackProcessing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$GpoXml,

        [Parameter(Mandatory)]
        [string]$GpoName
    )

    $findings = @()
    $xmlText = $GpoXml.OuterXml

    # Registry value: HKLM\Software\Policies\Microsoft\Windows\Group Policy\{UserPolicyMode}
    # Value 1 = Replace, Value 2 = Merge
    # Also check for the "User Group Policy loopback processing mode" setting
    if ($xmlText -match 'UserPolicyMode' -or $xmlText -match 'User Group Policy loopback processing mode') {
        $mode = "Unknown"
        if ($xmlText -match '<Value>2</Value>' -or $xmlText -match 'Merge') {
            $mode = "Merge"
        }
        elseif ($xmlText -match '<Value>1</Value>' -or $xmlText -match 'Replace') {
            $mode = "Replace"
        }

        if ($mode -eq "Merge") {
            $findings += [PSCustomObject]@{
                GPOName  = $GpoName
                Check    = "Loopback Processing - Merge Mode"
                Detail   = "Loopback processing is set to MERGE mode. This causes the DC to evaluate all user GPOs PLUS computer-OU-linked user GPOs, doubling SAMR lookups for security group membership."
                Severity = "High"
            }
        }
        elseif ($mode -eq "Replace") {
            $findings += [PSCustomObject]@{
                GPOName  = $GpoName
                Check    = "Loopback Processing - Replace Mode"
                Detail   = "Loopback processing is set to Replace mode. Lower SAMR impact than Merge but still generates additional lookups."
                Severity = "Medium"
            }
        }
        else {
            $findings += [PSCustomObject]@{
                GPOName  = $GpoName
                Check    = "Loopback Processing - Detected"
                Detail   = "Loopback processing configuration detected but mode could not be determined from XML."
                Severity = "Medium"
            }
        }
    }

    return $findings
}

# ── Helper: Detect high-frequency GP refresh intervals ─────────────────────
function Get-HighFrequencyRefresh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$GpoXml,

        [Parameter(Mandatory)]
        [string]$GpoName
    )

    $findings = @()
    $xmlText = $GpoXml.OuterXml

    # Check for Group Policy refresh interval settings
    # Registry: HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
    # "MaxNoGPListChangesInterval" or standard "GroupPolicyRefreshTime" / "GroupPolicyRefreshOffset"
    # Also look for: "Set Group Policy refresh interval for computers"

    $refreshPatterns = @(
        'GroupPolicyRefreshTime',
        'GroupPolicyRefreshOffset',
        'MaxNoGPListChangesInterval',
        'Group Policy refresh interval'
    )

    foreach ($pattern in $refreshPatterns) {
        if ($xmlText -match [regex]::Escape($pattern)) {
            # Try to extract the numeric value (handle namespace-prefixed elements like <q1:Value>)
            $escapedPattern = [regex]::Escape($pattern)
            $valueMatch = [regex]::Match($xmlText,
                "$escapedPattern.*?<\w*:?Value>(\d+)</\w*:?Value>",
                [System.Text.RegularExpressions.RegexOptions]::Singleline)
            $interval = if ($valueMatch.Success) { $valueMatch.Groups[1].Value } else { "Unknown" }

            # Default is 90 minutes; anything under 30 minutes is aggressive
            $severity = "Low"
            if ($interval -ne "Unknown" -and [int]$interval -lt 30) {
                $severity = "High"
                $detail = "GP background refresh interval set to $interval minutes (default: 90). Intervals below 30 minutes significantly increase SAMR traffic."
            }
            elseif ($interval -ne "Unknown" -and [int]$interval -lt 60) {
                $severity = "Medium"
                $detail = "GP background refresh interval set to $interval minutes (default: 90). Consider increasing to reduce SAMR load."
            }
            else {
                $detail = "GP refresh setting detected ($pattern). Interval: $interval minutes."
            }

            $findings += [PSCustomObject]@{
                GPOName  = $GpoName
                Check    = "High-Frequency GP Refresh"
                Detail   = $detail
                Severity = $severity
            }
            break  # Avoid duplicate findings for the same GPO
        }
    }

    return $findings
}

# ── Helper: Detect GP Preferences drive mappings using Replace action ──────
function Get-DriveMapReplaceAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$GpoXml,

        [Parameter(Mandatory)]
        [string]$GpoName
    )

    $findings = @()
    $xmlText = $GpoXml.OuterXml

    # GP Preferences drive maps use <Drive> elements with a Properties child
    # whose action attribute is R (Replace), U (Update), C (Create), D (Delete)
    $driveMatches = [regex]::Matches($xmlText,
        '<Drive\b[^>]*>.*?<Properties\s[^>]*action="R"[^>]*/?>',
        [System.Text.RegularExpressions.RegexOptions]::Singleline)

    if ($driveMatches.Count -gt 0) {
        # Try to pull the drive letter / path from each match
        foreach ($dm in $driveMatches) {
            $letter = ""
            $path   = ""
            if ($dm.Value -match 'letter="([^"]+)"') { $letter = $Matches[1] }
            if ($dm.Value -match 'path="([^"]+)"')   { $path   = $Matches[1] }
            $label = if ($letter) { "${letter}: -> $path" } else { $path }
            if (-not $label) { $label = "(details not parsed)" }

            $findings += [PSCustomObject]@{
                GPOName  = $GpoName
                Check    = "Drive Map - Replace Action"
                Detail   = "Mapped drive '$label' uses the REPLACE action. Replace deletes and recreates the mapping every GP refresh, triggering SAMR calls for share ACL resolution. Switch to UPDATE so the drive is only modified when the configuration differs."
                Severity = "High"
            }
        }
    }

    return $findings
}

# ── Helper: Detect GP Preferences registry items using Replace action ──────
function Get-RegistryPrefReplaceAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$GpoXml,

        [Parameter(Mandatory)]
        [string]$GpoName
    )

    $findings = @()
    $xmlText = $GpoXml.OuterXml

    # GP Preferences registry entries use <RegistrySettings> / <Registry> elements
    # with a Properties child whose action attribute is R (Replace)
    $regMatches = [regex]::Matches($xmlText,
        '<Registry\b[^>]*>.*?<Properties\s[^>]*action="R"[^>]*/?>',
        [System.Text.RegularExpressions.RegexOptions]::Singleline)

    if ($regMatches.Count -gt 0) {
        # Collect unique key paths to avoid flooding the report
        $keyPaths = @()
        foreach ($rm in $regMatches) {
            $key = ""
            if ($rm.Value -match 'key="([^"]+)"') { $key = $Matches[1] }
            if ($key -and $key -notin $keyPaths) { $keyPaths += $key }
        }

        if ($keyPaths.Count -gt 0) {
            $detail = "Registry preferences using REPLACE action ($($regMatches.Count) item(s)). Keys include: $($keyPaths[0..([math]::Min(4, $keyPaths.Count - 1))] -join '; ')"
            if ($keyPaths.Count -gt 5) { $detail += " ... and $($keyPaths.Count - 5) more" }
        }
        else {
            $detail = "Registry preferences using REPLACE action ($($regMatches.Count) item(s))."
        }
        $detail += ". Replace deletes and rewrites registry values every GP refresh cycle. Switch to UPDATE so values are only written when they differ."

        $findings += [PSCustomObject]@{
            GPOName  = $GpoName
            Check    = "Registry Pref - Replace Action"
            Detail   = $detail
            Severity = "Medium"
        }
    }

    return $findings
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN SCRIPT
# ══════════════════════════════════════════════════════════════════════════════

Write-Host "`n=== SAMR Traffic - GPO Configuration Audit ===" -ForegroundColor Cyan
Write-Host "Domain: $DomainName" -ForegroundColor Cyan
Write-Host "Scan started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Cyan

$allFindings = @()

# ── 1. Retrieve all GPOs ──────────────────────────────────────────────────
Write-Host "[*] Retrieving all GPOs from domain..." -ForegroundColor Yellow
try {
    $allGPOs = Get-GPO -All -Domain $DomainName -ErrorAction Stop
}
catch {
    Write-Error "Failed to retrieve GPOs: $_"
    return
}
Write-Host "    Found $($allGPOs.Count) GPOs.`n" -ForegroundColor Green

# ── 2. Retrieve all GPO links and OU structure ────────────────────────────
Write-Host "[*] Enumerating OU structure and GPO links..." -ForegroundColor Yellow
$allOUs = Get-ADOrganizationalUnit -Filter * -Properties gpLink, gpOptions, Name, DistinguishedName -Server $DomainName

# Also check domain root for linked GPOs
$domainDN = (Get-ADDomain -Server $DomainName).DistinguishedName
$domainRoot = Get-ADObject -Identity $domainDN -Properties gpLink, gpOptions -Server $DomainName

Write-Host "    Found $($allOUs.Count) OUs.`n" -ForegroundColor Green

# ── 3. Per-GPO analysis ──────────────────────────────────────────────────
Write-Host "[*] Analyzing each GPO for SAMR-impacting configurations...`n" -ForegroundColor Yellow

$gpoCount = 0
foreach ($gpo in $allGPOs) {
    $gpoCount++
    Write-Progress -Activity "Analyzing GPOs" -Status "$($gpo.DisplayName)" -PercentComplete (($gpoCount / $allGPOs.Count) * 100)

    # Get full XML report for deep inspection
    try {
        [xml]$gpoXml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -Domain $DomainName -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not retrieve XML report for '$($gpo.DisplayName)': $_"
        continue
    }

    # ── Check 1: Item-Level Targeting with Security Groups ────────────
    $allFindings += Get-ILTSecurityGroupTargeting -GpoXml $gpoXml -GpoName $gpo.DisplayName

    # ── Check 2a: WMI Filter attached ─────────────────────────────────
    if ($gpo.WmiFilter) {
        $allFindings += [PSCustomObject]@{
            GPOName  = $gpo.DisplayName
            Check    = "WMI Filter"
            Detail   = "WMI filter attached: $($gpo.WmiFilter.Name). WMI filters execute on every GP refresh and can trigger SAMR lookups depending on query content."
            Severity = "Medium"
        }
    }

    # ── Check 2b: Security Group Filtering (non-default permissions) ──
    try {
        $gpoPerms = Get-GPPermission -Guid $gpo.Id -All -Domain $DomainName -ErrorAction Stop
        $nonDefaultApply = $gpoPerms | Where-Object {
            $_.Permission -eq 'GpoApply' -and
            $_.Trustee.Name -ne 'Authenticated Users' -and
            $_.Trustee.SidType -ne 'WellKnownGroup'
        }
        $authUsersDenied = $gpoPerms | Where-Object {
            $_.Trustee.Name -eq 'Authenticated Users' -and $_.Permission -eq 'GpoApply' -and $_.Denied -eq $true
        }
        $authUsersRemoved = -not ($gpoPerms | Where-Object {
            $_.Trustee.Name -eq 'Authenticated Users' -and $_.Permission -eq 'GpoApply'
        })

        if ($nonDefaultApply -or $authUsersDenied -or $authUsersRemoved) {
            $targetGroups = ($nonDefaultApply | ForEach-Object { $_.Trustee.Name }) -join ', '
            $detail = "Security group filtering detected."
            if ($targetGroups) { $detail += " GpoApply granted to: $targetGroups." }
            if ($authUsersDenied) { $detail += " 'Authenticated Users' GpoApply is DENIED." }
            if ($authUsersRemoved) { $detail += " 'Authenticated Users' does not have GpoApply." }
            $detail += " Each filtered group triggers SAMR membership lookups on the DC."

            $allFindings += [PSCustomObject]@{
                GPOName  = $gpo.DisplayName
                Check    = "Security Group Filtering"
                Detail   = $detail
                Severity = "High"
            }
        }
    }
    catch {
        Write-Warning "Could not read permissions for '$($gpo.DisplayName)': $_"
    }

    # ── Check 2c: ILT Registry Checks ────────────────────────────────
    $allFindings += Get-ILTRegistryChecks -GpoXml $gpoXml -GpoName $gpo.DisplayName

    # ── Check 5: Loopback Processing ─────────────────────────────────
    $allFindings += Get-LoopbackProcessing -GpoXml $gpoXml -GpoName $gpo.DisplayName

    # ── Check 6: High-Frequency GP Refresh ───────────────────────────
    $allFindings += Get-HighFrequencyRefresh -GpoXml $gpoXml -GpoName $gpo.DisplayName

    # ── Check 7: Drive Maps using Replace action ─────────────────────
    $allFindings += Get-DriveMapReplaceAction -GpoXml $gpoXml -GpoName $gpo.DisplayName

    # ── Check 8: Registry Preferences using Replace action ───────────
    $allFindings += Get-RegistryPrefReplaceAction -GpoXml $gpoXml -GpoName $gpo.DisplayName
}
Write-Progress -Activity "Analyzing GPOs" -Completed

# ── 4. Check for Enforced GPOs and Block Inheritance ──────────────────────
Write-Host "[*] Checking for enforced GPO links and block inheritance..." -ForegroundColor Yellow

# Check all OUs plus domain root
$linkSources = @($domainRoot) + @($allOUs)

foreach ($ou in $linkSources) {
    $ouDN = $ou.DistinguishedName
    $ouName = if ($ou.Name) { $ou.Name } else { "Domain Root" }

    # Block inheritance check (gpOptions bit 0x01)
    if ($ou.gpOptions -band 1) {
        $allFindings += [PSCustomObject]@{
            GPOName  = "N/A (OU: $ouName)"
            Check    = "Block Inheritance"
            Detail   = "Block Inheritance is enabled on OU '$ouDN'. This can cause unexpected GPO evaluation order and additional SAMR lookups when combined with enforced GPOs."
            Severity = "Medium"
        }
    }

    # Parse gpLink to find enforced links
    if ($ou.gpLink) {
        $linkMatches = [regex]::Matches($ou.gpLink, '\[LDAP://cn=\{([0-9a-fA-F\-]+)\},.*?\;(\d+)\]')
        foreach ($match in $linkMatches) {
            $linkedGuid = $match.Groups[1].Value
            $linkFlags = [int]$match.Groups[2].Value
            # Bit 0x02 = Enforced
            if ($linkFlags -band 2) {
                $linkedGpo = $allGPOs | Where-Object { $_.Id -eq $linkedGuid }
                $gpoDisplayName = if ($linkedGpo) { $linkedGpo.DisplayName } else { $linkedGuid }
                $allFindings += [PSCustomObject]@{
                    GPOName  = $gpoDisplayName
                    Check    = "Enforced GPO Link"
                    Detail   = "GPO is enforced (link enforcement) on '$ouDN'. Enforced GPOs override block inheritance and always apply, increasing the evaluation workload and SAMR queries."
                    Severity = "Medium"
                }
            }
        }
    }
}

# ── 5. Detect User-Targeted GPOs Linked to Computer-Only OUs ─────────────
Write-Host "[*] Detecting user-targeted GPOs linked to computer-only OUs..." -ForegroundColor Yellow

foreach ($ou in $allOUs) {
    # Determine if OU contains only computer objects (no user objects)
    $userCount = @(Get-ADUser -Filter * -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Server $DomainName -ErrorAction SilentlyContinue).Count
    $computerCount = @(Get-ADComputer -Filter * -SearchBase $ou.DistinguishedName -SearchScope OneLevel -Server $DomainName -ErrorAction SilentlyContinue).Count

    $isComputerOnlyOU = ($computerCount -gt 0 -and $userCount -eq 0)

    if ($isComputerOnlyOU -and $ou.gpLink) {
        $linkMatches = [regex]::Matches($ou.gpLink, '\[LDAP://cn=\{([0-9a-fA-F\-]+)\},.*?\;(\d+)\]')
        foreach ($match in $linkMatches) {
            $linkedGuid = $match.Groups[1].Value
            $linkFlags = [int]$match.Groups[2].Value
            # Skip disabled links (bit 0x01 = link disabled)
            if ($linkFlags -band 1) { continue }

            $linkedGpo = $allGPOs | Where-Object { $_.Id -eq $linkedGuid }
            if (-not $linkedGpo) { continue }

            # Check if GPO has user configuration enabled
            if ($linkedGpo.User.DSVersion -gt 0 -or $linkedGpo.User.SysvolVersion -gt 0) {
                # Verify user side is not disabled
                $userEnabled = $linkedGpo.GpoStatus -in @('AllSettingsEnabled', 'ComputerSettingsDisabled')
                if ($userEnabled) {
                    $allFindings += [PSCustomObject]@{
                        GPOName  = $linkedGpo.DisplayName
                        Check    = "User GPO on Computer-Only OU"
                        Detail   = "GPO has user-side settings enabled and is linked to computer-only OU '$($ou.DistinguishedName)'. Without loopback processing, these settings won't apply but the DC still evaluates them, generating unnecessary SAMR traffic. With loopback Merge mode, this doubles SAMR lookups."
                        Severity = "High"
                    }
                }
            }
        }
    }
}

# ── 6. Check Loopback Processing GPOs Linked to Workstation-Like OUs ─────
Write-Host "[*] Cross-referencing loopback GPOs with workstation OUs..." -ForegroundColor Yellow

$loopbackGPOs = $allFindings | Where-Object { $_.Check -like "Loopback Processing*" }
foreach ($lbFinding in $loopbackGPOs) {
    # Find which OUs this GPO is linked to
    foreach ($ou in $allOUs) {
        if (-not $ou.gpLink) { continue }
        $linkedGuids = [regex]::Matches($ou.gpLink, '\[LDAP://cn=\{([0-9a-fA-F\-]+)\}') |
            ForEach-Object { $_.Groups[1].Value }

        $matchingGpo = $allGPOs | Where-Object { $_.DisplayName -eq $lbFinding.GPOName }
        if ($matchingGpo -and $linkedGuids -contains $matchingGpo.Id.ToString()) {
            # Check if OU name suggests workstations
            $ouName = $ou.Name
            $wsKeywords = @('workstation', 'desktop', 'laptop', 'client', 'endpoint', 'pc', 'computer')
            $isWorkstationOU = $wsKeywords | Where-Object { $ouName -match $_ }

            if ($isWorkstationOU) {
                $allFindings += [PSCustomObject]@{
                    GPOName  = $lbFinding.GPOName
                    Check    = "Loopback Merge on Workstation OU"
                    Detail   = "Loopback processing GPO is linked to workstation-like OU '$($ou.DistinguishedName)'. Every workstation GP refresh in this OU triggers SAMR calls for both computer AND user policy evaluation."
                    Severity = "High"
                }
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# REPORT
# ══════════════════════════════════════════════════════════════════════════════

Write-Host ("`n" + ("=" * 80)) -ForegroundColor Cyan
Write-Host "=== SAMR Impact Analysis Report ===" -ForegroundColor Cyan
Write-Host ("=" * 80) -ForegroundColor Cyan

if ($allFindings.Count -eq 0) {
    Write-Host "`n[OK] No SAMR-impacting GPO configurations found.`n" -ForegroundColor Green
}
else {
    # Summary counts by severity
    $highCount   = @($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = @($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount    = @($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count

    Write-Host "`nTotal findings: $($allFindings.Count)" -ForegroundColor White
    Write-Host "  High:   $highCount" -ForegroundColor Red
    Write-Host "  Medium: $mediumCount" -ForegroundColor Yellow
    Write-Host "  Low:    $lowCount`n" -ForegroundColor Gray

    # Summary by check type
    Write-Host "--- Findings by Category ---" -ForegroundColor Cyan
    $allFindings | Group-Object -Property Check | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
    }
    Write-Host ""

    # Detailed findings sorted by severity
    Write-Host "--- Detailed Findings ---" -ForegroundColor Cyan
    $severityOrder = @{ 'High' = 1; 'Medium' = 2; 'Low' = 3 }
    $sortedFindings = $allFindings | Sort-Object { $severityOrder[$_.Severity] }, GPOName

    foreach ($finding in $sortedFindings) {
        $color = switch ($finding.Severity) {
            'High'   { 'Red' }
            'Medium' { 'Yellow' }
            'Low'    { 'Gray' }
            default  { 'White' }
        }
        Write-Host "  [$($finding.Severity.ToUpper())] " -ForegroundColor $color -NoNewline
        Write-Host "$($finding.GPOName)" -ForegroundColor White -NoNewline
        Write-Host " - $($finding.Check)" -ForegroundColor DarkGray
        Write-Host "         $($finding.Detail)" -ForegroundColor Gray
        Write-Host ""
    }

    # Export to CSV if requested
    if ($ExportPath) {
        try {
            $sortedFindings | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
            Write-Host "[*] Results exported to: $ExportPath`n" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export CSV: $_"
        }
    }
}

# ── Recommendations ──────────────────────────────────────────────────────────
Write-Host "--- Recommendations to Reduce SAMR Load ---" -ForegroundColor Cyan
Write-Host @"
  1. MINIMIZE ILT SECURITY GROUP CHECKS: Replace ILT security group targeting
     with OU-based targeting where possible. Each ILT group check = SAMR call.

  2. REDUCE SECURITY GROUP FILTERING: Use OU structure to scope GPOs instead of
     security group filtering. Move objects to dedicated OUs.

  3. AVOID LOOPBACK MERGE ON LARGE OUs: If loopback is needed, prefer Replace
     mode or limit Merge mode to small, scoped OUs.

  4. DISABLE UNUSED USER SETTINGS: On GPOs linked to computer-only OUs, disable
     the user configuration side (GPO Status -> Computer Settings Only).

  5. INCREASE GP REFRESH INTERVAL: Default 90 minutes is sufficient for most
     environments. Avoid intervals below 60 minutes unless required.

  6. CONSOLIDATE WMI FILTERS: Combine WMI queries where possible and cache
     results. Consider replacing WMI filters with OU-based targeting.

  7. REVIEW ENFORCED/BLOCK INHERITANCE: Minimize use of enforcement and block
     inheritance to reduce evaluation complexity.

  8. SWITCH DRIVE MAPS FROM REPLACE TO UPDATE: Drive mappings set to Replace
     delete and recreate on every refresh, triggering SAMR calls for share ACL
     checks. Change to Update so the drive is only modified when needed.

  9. SWITCH REGISTRY PREFS FROM REPLACE TO UPDATE: Registry preferences set
     to Replace delete and rewrite keys every cycle. Update writes only when
     the value differs, eliminating unnecessary processing.

"@ -ForegroundColor Gray

Write-Host "Scan completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Cyan
