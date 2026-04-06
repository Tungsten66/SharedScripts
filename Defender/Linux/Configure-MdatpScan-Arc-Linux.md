# Configure MDATP Weekly Scan — Azure Arc-Connected Linux

Deploys a weekly Microsoft Defender for Endpoint (MDATP) quick scan schedule to **Azure Arc-connected Linux servers**.

Two methods are covered:

- **Method 1 — Azure Policy (DeployIfNotExists)**: Deploys the cron job to Arc-connected Linux machines via `DeployIfNotExists` policy. New or updated machines are handled by the assignment. Existing machines require a remediation task. It does not re-apply if the cron job is later removed because compliance reflects Run Command execution state, not cron job presence.
- **Method 2 — Machine Configuration (Continuous)**: Uses Azure Policy with `ApplyAndAutoCorrect` to continuously enforce the cron job on **Azure Arc-connected Linux servers**. For Arc custom packages, the supported secure package access model is a **SAS URL**. You can still keep the storage account private by routing Arc-connected machines to the blob endpoint over private connectivity and private DNS if your network design supports it.

**Recommended approach:** Use Method 1 if you want the simplest Arc deployment with no custom package hosting. Use Method 2 when you need continuous drift correction and can operate secure SAS-based package delivery.

---

## Prerequisites

### Method 1 — Azure Policy

All scripts in this guide are written for **PowerShell**. Run from Azure Cloud Shell (PowerShell session) or a local PowerShell session with the Az module installed.

- **PowerShell Az module:** `Install-Module Az -Scope CurrentUser` (pre-installed in Cloud Shell)
- **RBAC roles (for you):** `Resource Policy Contributor` and `Management Group Contributor`
- **RBAC roles (policy managed identity):** granted automatically by the script:
  - `Azure Connected Machine Resource Administrator` — Arc machines

### Method 2 — Machine Configuration

- **PowerShell 7.2+** and modules:

  ```powershell
  Install-Module GuestConfiguration -Force
  Install-Module nx -Force
  ```

- Azure Storage Account, PowerShell Az module, and RBAC roles — see [Method 2 Prerequisites](#prerequisites-method-2)

---

## Method 1 — Azure Policy (DeployIfNotExists)

Uses Azure Policy `DeployIfNotExists` to deploy the cron job to target machines via Run Command. New or updated matching machines can be handled automatically after policy evaluation. Existing matching machines require a remediation task.

**Important limitation:** Compliance state reflects whether the Run Command executed successfully — not whether the cron job currently exists. If the cron job is later removed manually, the machine remains Compliant (the Run Command resource already succeeded). Use Method 2 if continuous drift correction is required.

**Important targeting note:** Method 1 now targets **all Arc-connected Linux machines** in scope. The Run Command script checks whether `/usr/bin/mdatp` exists before writing the cron entry. Machines without MDE installed will be targeted, the script will fail, and those machines will remain **Non-compliant** until they are excluded from scope or MDE is installed.

Two files are used:

| File | Purpose |
| --- | --- |
| [`Deploy-MdatpScan-ArcPolicy.ps1`](./Deploy-MdatpScan-ArcPolicy.ps1) | Creates definitions, assignments, and role assignments in one run |
| [`mdatp-scan-arc-policy-rule.json`](./mdatp-scan-arc-policy-rule.json) | Policy rule for Arc-connected Linux machines |

---

### Step 1 — Clone or download the files

Ensure both files are in the same directory on your machine or Cloud Shell session.

---

### Step 2 — Run the deployment script

Open Azure Cloud Shell (PowerShell) or a local PowerShell session, then run:

The first set of examples below creates the policy definition and assignment. The remediation examples that follow add `-CreateRemediationTasks` for existing machines.

**Assign at management group scope** (covers all subscriptions under the MG — recommended):

```powershell
.\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus'
```

**Assign at a single subscription:**

```powershell
.\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
    -AssignmentScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy'
```

**Assign at a resource group:**

```powershell
.\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
    -AssignmentScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy/resourceGroups/<resource-group-name>'
```

**Azure Government:**

```powershell
.\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'usgovvirginia' `
    -Environment 'AzureUSGovernment'
```

The script runs in three phases by default and prints progress for each:

1. Creates the Arc policy definition at the management group
2. Creates the Arc policy assignment at the specified scope with a system-assigned managed identity
3. Grants the required role assignment to that managed identity

If you use `-CreateRemediationTasks`, the script adds a fourth phase that starts remediation for existing machines.

When the assignment scope is a **management group**, the script automatically creates one remediation task per child **subscription** under that management group so it can use `ReEvaluateCompliance`. When the assignment scope is a **subscription** or **resource group**, the script creates the remediation task at that same scope. You can override this behavior with `-RemediationScope`.

Re-running the script is safe for definitions, assignments, and role assignments. If you use `-CreateRemediationTasks`, existing remediation task names are detected and skipped.

**Assign at management group scope and remediate existing resources across child subscriptions:**

```powershell
.\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
  -CreateRemediationTasks
```

**Assign at a single subscription and remediate existing resources in that subscription:**

```powershell
.\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
  -AssignmentScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy' `
  -CreateRemediationTasks
```

**Assign at a resource group and remediate existing resources in that resource group:**

```powershell
.\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
  -AssignmentScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy/resourceGroups/<resource-group-name>' `
  -CreateRemediationTasks
```

**Assign at management group scope and remediate only a specific subscription:**

```powershell
.\Deploy-MdatpScan-ArcPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
  -CreateRemediationTasks `
  -RemediationScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy'
```

---

### Check Compliance

After assignment, Azure Policy compliance can take some time to refresh. To view compliance state:

**Azure Policy** → **Compliance** → filter by assignment name `deploy-mdatp-cron-arc`.

### Trigger Immediate Remediation

To deploy to existing non-compliant machines without waiting for a later policy cycle:

**Azure Policy** → **Remediation** → **New remediation task** → select the assignment → **Remediate**.

For PowerShell, use `ReEvaluateCompliance` so existing resources are rediscovered before remediation starts when the remediation scope is **subscription scope or below**:

```powershell
Start-AzPolicyRemediation `
  -Name 'remediate-arc' `
  -PolicyAssignmentId '<arc-policy-assignment-id>' `
  -Scope '<assignment-scope>' `
  -ResourceDiscoveryMode ReEvaluateCompliance
```

For a policy assigned at **management group scope**, create remediation tasks at **subscription scope** or **resource group scope** rather than at management group scope. This allows `ReEvaluateCompliance` to rediscover matching resources after you update the policy.

---

## Method 2 — Machine Configuration (Continuous, Azure Arc)

Uses Azure Policy `ApplyAndAutoCorrect` to continuously enforce the cron job on Azure Arc-connected Linux servers. The guest assignment is checked every 5 minutes, and settings are rechecked about every 15 minutes after assignment. If the cron job is removed, it is reinstalled on the next machine configuration evaluation.

**Important scope note:** For Arc custom Machine Configuration packages, Microsoft documents secure package access by using a **SAS URL**. User-assigned managed identity is documented for Azure VMs, not Arc-connected machines. Keep that distinction explicit when designing package delivery. See [How to provide secure access to custom machine configuration packages](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/develop-custom-package/5-access-package), which states that unlike Azure VMs, Arc-connected machines currently do not support user-assigned managed identities for this scenario.

### How It Works

1. A custom Machine Configuration package is built from an InSpec audit profile and a DSC `nxScript` set script
2. The package is published to an Azure Storage Account
3. A read-only **user delegation SAS** is generated for the package blob
4. An Azure Policy (`ApplyAndAutoCorrect`) definition is created from the package and assigned at management group scope
5. The Machine Configuration agent on each Arc-connected Linux server processes the guest assignment:
   - **Audit**: InSpec checks whether the `# MDATP_WEEKLY_SCAN` cron entry exists in the root crontab
   - **Set**: If the cron entry is missing, the `nxScript` SetScript installs it automatically
6. Machines with the cron job present are **Compliant**; machines with it absent are **Non-compliant** and remediated on the next evaluation cycle — no manual remediation task required

### Prerequisites (Method 2)

- **PowerShell 7.2+** on your local machine
- **PowerShell modules:**

  ```powershell
  Install-Module GuestConfiguration -Force
  Install-Module nx -Force          # Linux DSC resources (provides nxScript)
  ```

- **Azure Storage Account** to host the configuration package
  - Public blob access must remain disabled
  - All storage operations must use **Azure AD authentication** (`--auth-mode login`)
  - Package access for Arc guest assignments must follow Microsoft-supported custom package access guidance. For Arc custom packages, use a **SAS URL** for the package blob.
  - Keep SAS as narrow as possible: read-only, package-blob scope only, short expiry, and rotate it when you publish a new package version.
  - If you use private endpoints for the storage account, Arc-connected machines must have network path and private DNS resolution to the blob endpoint.
  - **Azure Government:** use sovereign blob endpoints such as `*.blob.core.usgovcloudapi.net` and the matching private DNS zone for Blob private endpoints.
- **MDE deployed** on each Linux machine (`/usr/bin/mdatp` present) before the package runs
- **Azure Arc Connected Machine agent** installed and connected on each target Linux server
- **Machine Configuration enabled** on each Arc-connected server. The guest configuration capability is provided by the Connected Machine agent; no separate Azure VM extension is required.
- **RBAC roles:**
  - `Resource Policy Contributor` — to create and assign the policy
  - `Management Group Contributor` — to create the definition at management group scope
  - `Storage Blob Data Contributor` — to upload the package to the storage account
  - `Contributor` on target machines/scope — required for the policy assignment managed identity to apply configuration (audit+set requires write access, unlike audit-only)

### Step 1 — Prepare Azure Arc-connected Servers

Arc-connected servers include guest configuration capability through the Azure Connected Machine agent. There is no separate Azure VM extension to deploy for this method.

- Ensure each target Linux server is onboarded to Azure Arc
- Ensure the agent remains in full mode and guest configuration has not been disabled
- If you use Azure Arc Private Link Scope, remember that package storage private access is configured separately from Arc service connectivity

**Azure Government:** Arc guest configuration endpoints use sovereign domains such as `*.guestconfiguration.azure.us`. If you also use Arc private link, some endpoints such as Microsoft Entra ID and Azure Resource Manager still require access through the appropriate sovereign public endpoints.

---

### Step 2 — Author the Package

Create the following directory and files locally:

```text
MdatpWeeklyScan/
  MdatpWeeklyScan.ps1     (DSC configuration — audit+set logic)
  inspec/
    inspec.yml
    controls/
      mdatp_cron.rb
```

### DSC Configuration — `MdatpWeeklyScan.ps1`

The `nxScript` resource provides `TestScript` (audit) and `SetScript` (remediation) as bash. The InSpec profile handles the compliance state reported to Azure Policy.

```powershell
Configuration MdatpWeeklyScan {
    Import-DscResource -ModuleName nx

    Node localhost {
        nxScript InstallMdatpCronJob {
            GetScript  = "crontab -l -u root 2>/dev/null | grep 'MDATP_WEEKLY_SCAN' || echo ''"
            TestScript = "crontab -l -u root 2>/dev/null | grep -qF 'MDATP_WEEKLY_SCAN' && exit 0 || exit 1"
            SetScript  = @'
#!/bin/bash
set -euo pipefail
CRON_MARKER="# MDATP_WEEKLY_SCAN"
MDATP_CMD="/usr/bin/mdatp"
SCAN_TYPE="quick"
if [[ ! -x "$MDATP_CMD" ]]; then echo "[ERROR] mdatp not found at $MDATP_CMD"; exit 1; fi
HOUR=$(( RANDOM % 12 ))
MINUTE=$(( RANDOM % 60 ))
EXISTING=$(crontab -l 2>/dev/null || echo "")
FILTERED=$(echo "$EXISTING" | grep -Fv "$CRON_MARKER" || true)
ENTRY="${MINUTE} ${HOUR} * * 0 ${MDATP_CMD} scan ${SCAN_TYPE} ${CRON_MARKER}"
if [[ -n "$FILTERED" ]]; then
  printf '%s\n%s\n' "$FILTERED" "$ENTRY" | crontab -
else
  echo "$ENTRY" | crontab -
fi
'@
        }
    }
}

# Compile the DSC configuration to MOF
MdatpWeeklyScan -OutputPath './MdatpWeeklyScan'
```

> **Note:** The same cron entry logic used in `SetScript` is available as a standalone script for direct or manual execution — see [`schedule_mdatp_scan.sh`](./schedule_mdatp_scan.sh).

### InSpec Audit Profile

**`inspec/inspec.yml`**

```yaml
name: MdatpWeeklyScan
title: MDATP Weekly Scan Cron Job
maintainer: Your Name
summary: Verifies the MDATP weekly quick scan cron entry exists in the root crontab
version: 1.0.0
supports:
  - os-family: linux
```

**`inspec/controls/mdatp_cron.rb`**

```ruby
title 'MDATP Weekly Scan - Root Crontab'

describe command('crontab -l -u root 2>/dev/null || true') do
  its('stdout') { should match(/\/usr\/bin\/mdatp scan quick.*MDATP_WEEKLY_SCAN/) }
end
```

---

### Step 3 — Build and Publish the Package

```powershell
# Compile the DSC configuration (if not already done in Step 2)
. ./MdatpWeeklyScan/MdatpWeeklyScan.ps1

# Build the Machine Configuration package (audit+set)
New-GuestConfigurationPackage `
  -Name 'MdatpWeeklyScan' `
  -Configuration './MdatpWeeklyScan/localhost.mof' `
  -ChefInspecProfilePath './MdatpWeeklyScan/inspec' `
  -Type AuditAndSet `
  -Force

# Capture the content hash — required by Azure Policy for package integrity validation
$PackageHash = (Get-FileHash './MdatpWeeklyScan.zip' -Algorithm SHA256).Hash.ToLower()

# Upload to Azure Storage using Azure AD auth (no shared key/SAS)
$StorageAccount = "<storage-account-name>"
$Container      = "guestconfig"

az storage blob upload `
  --account-name $StorageAccount `
  --container-name $Container `
  --name "MdatpWeeklyScan.zip" `
  --file "./MdatpWeeklyScan.zip" `
  --auth-mode login `
  --overwrite

# Set an expiry for a read-only user delegation SAS
$SasExpiry = (Get-Date).ToUniversalTime().AddDays(30).ToString('yyyy-MM-ddTHH:mmZ')

# Get a full blob URI with a read-only user delegation SAS
$PackageUri = az storage blob generate-sas `
  --account-name $StorageAccount `
  --container-name $Container `
  --name "MdatpWeeklyScan.zip" `
  --permissions r `
  --expiry $SasExpiry `
  --auth-mode login `
  --as-user `
  --full-uri `
  --output tsv
```

> **Security note:** The SAS in `$PackageUri` is the package retrieval credential for Arc machines. Limit expiry, keep permissions to `r`, publish a new package URI when you version the package, and remove stale SAS URLs from old assignments.

### Example — Azure Government SAS Generation and Rotation

Use sovereign cloud login before you upload the package or generate the SAS:

```powershell
Connect-AzAccount -Environment AzureUSGovernment
az cloud set --name AzureUSGovernment
az login --environment AzureUSGovernment
```

Generate a short-lived **user delegation SAS** for the current package version:

```powershell
$StorageAccount = "<storage-account-name>"
$Container      = "guestconfig"
$BlobName       = "MdatpWeeklyScan-1.0.0.zip"
$SasExpiry      = (Get-Date).ToUniversalTime().AddDays(14).ToString('yyyy-MM-ddTHH:mmZ')

$PackageUri = az storage blob generate-sas `
  --account-name $StorageAccount `
  --container-name $Container `
  --name $BlobName `
  --permissions r `
  --expiry $SasExpiry `
  --auth-mode login `
  --as-user `
  --full-uri `
  --output tsv
```

Rotate the package cleanly when you publish an update:

1. Upload the new package as a new blob name such as `MdatpWeeklyScan-1.0.1.zip`.
2. Generate a new short-lived SAS for that new blob.
3. Re-run `New-GuestConfigurationPolicy` and update the policy definition so `-ContentUri` points to the new SAS URL.
4. Increment `-PolicyVersion` so the guest assignment picks up the new package.
5. After all target machines report the expected version, delete the old assignment or old blob and let the previous SAS expire.

If your storage account uses a private endpoint in Azure Government, validate DNS resolution for the blob endpoint under `*.blob.core.usgovcloudapi.net` from the Arc-connected network before assigning the policy.

---

### Step 4 — Create and Assign the Policy

```powershell
# Generate the policy definition JSON from the published package
New-GuestConfigurationPolicy `
  -ContentUri $PackageUri `
  -ContentHash $PackageHash `
  -DisplayName "Configure: MDATP Weekly Scan Cron on Linux" `
  -Description "Audits and configures the MDATP weekly quick scan cron entry in the root crontab of Arc-connected Linux machines." `
  -PolicyId (New-Guid).Guid `
  -PolicyVersion "1.0.0" `
  -Path "./MdatpWeeklyScanPolicy" `
  -Platform Linux `
  -Mode ApplyAndAutoCorrect

# Locate the generated policy rule JSON in the output folder
$GeneratedPolicyRules = Get-ChildItem './MdatpWeeklyScanPolicy' -Filter '*.json'
if ($GeneratedPolicyRules.Count -ne 1) {
  throw "Expected exactly one generated policy rule JSON file in ./MdatpWeeklyScanPolicy. Inspect the folder and set --rules to the correct file path."
}
$GeneratedPolicyRulesPath = $GeneratedPolicyRules[0].FullName

# Create the policy definition at management group scope
az policy definition create `
  --name "configure-mdatp-scan-arc-linux" `
  --display-name "Configure: MDATP Weekly Scan Cron on Linux" `
  --description "Audits and configures the MDATP weekly quick scan cron entry on Arc-connected Linux machines." `
  --mode Indexed `
  --rules "@$GeneratedPolicyRulesPath" `
  --management-group "<management-group-id>"

# Get the definition ID
$PolicyId = az policy definition show `
  --name "configure-mdatp-scan-arc-linux" `
  --management-group "<management-group-id>" `
  --query id --output tsv

# Assign at management group scope
# Note: --name must be 24 characters or fewer
az policy assignment create `
  --name "config-mdatp-cron-arc" `
  --display-name "Configure: MDATP Weekly Scan Cron on Linux" `
  --policy $PolicyId `
  --scope "/providers/Microsoft.Management/managementGroups/<management-group-id>" `
  --mi-system-assigned `
  --location "<location>" `
  --identity-scope "/providers/Microsoft.Management/managementGroups/<management-group-id>" `
  --role "Contributor"
```

**Note:** The example above resolves the generated policy rule JSON from `./MdatpWeeklyScanPolicy` instead of assuming a specific filename.

**Note:** Review the generated policy before creating the definition and confirm it only targets `Microsoft.HybridCompute/machines` resources.

**Note:** If your storage account is reachable only through a private endpoint, confirm the Arc-connected machines resolve the blob FQDN to the private IP and have a route to that network over VPN or ExpressRoute.

**Note:** In Azure Government, use sovereign cloud login and endpoint values consistently when generating the SAS URL and policy assignment.

**Note:** `ApplyAndAutoCorrect` assignments require the managed identity to have `Contributor` on the target scope. Audit-only assignments only need `Reader`.

---

### Step 5 — Check Compliance

```powershell
az policy state list `
  --management-group "<management-group-id>" `
  --filter "policyAssignmentName eq 'config-mdatp-cron-arc'" `
  --query "[].{machine:resourceId, state:complianceState, reason:complianceReasonCode}" `
  --output table
```

Machines marked **Non-compliant** are remediated automatically by the Machine Configuration agent. No manual remediation task is required — this is a key difference from the DeployIfNotExists approach.
Machines marked **Non-compliant** are corrected by the Machine Configuration agent on its next evaluation. Guest assignments are typically checked every 5 minutes and settings are rechecked about every 15 minutes.

---

## Validate the Cron Job on a Linux Device

After either method deploys the configuration, confirm the cron job is in place.

### Check the Root Crontab

```bash
sudo crontab -l
```

Expected output will include a line with the `# MDATP_WEEKLY_SCAN` marker, similar to:

```text
47 3 * * 0 /usr/bin/mdatp scan quick # MDATP_WEEKLY_SCAN
```

The hour and minute will vary since the SetScript generates a random time.

### Confirm Only One Entry Exists

```bash
sudo crontab -l | grep "MDATP_WEEKLY_SCAN"
```

Should return exactly one line. If it returns more than one, the deduplication marker was not matched correctly — re-applying the configuration will reset to a clean state.

### Verify MDE Is Running

```bash
mdatp health
```

| Field | Expected value |
| --- | --- |
| `healthy` | `true` |
| `real_time_protection_enabled` | `true` |
| `org_id` | Your tenant/org ID |

### Run a Manual Quick Scan to Test

```bash
sudo /usr/bin/mdatp scan quick
```

A successful scan will output status messages and exit with code `0`.

---

## Updating the Scan Schedule

### Update Method 1 — Azure Policy

The cron schedule is controlled by the `script` field inside `mdatp-scan-arc-policy-rule.json`. The relevant lines are:

```bash
HOUR=$(( RANDOM % 12 ))       # Random hour between 0–11 (midnight to 11 AM)
MINUTE=$(( RANDOM % 60 ))     # Random minute between 0–59
ENTRY="${MINUTE} ${HOUR} * * 0 ${MDATP_CMD} scan quick ${CRON_MARKER}"
#                         ^ day of week: 0 = Sunday
```

The cron entry format is: `<minute> <hour> <day-of-month> <month> <day-of-week>`

**To change the day** — replace the `0` in `* * 0`:

| Value | Day |
| --- | --- |
| `0` or `7` | Sunday |
| `1` | Monday |
| `2` | Tuesday |
| `3` | Wednesday |
| `4` | Thursday |
| `5` | Friday |
| `6` | Saturday |

**To set a fixed time instead of random** — replace the `RANDOM` lines with hardcoded values:

```bash
HOUR=2      # 2 AM
MINUTE=30   # :30
```

After editing the JSON files, follow the update steps below to redeploy.

To update it:

> **Important:** All three steps below are required. Updating the policy definition alone (step 2) has no effect on machines that are already compliant — the policy will not re-run the script unless the Run Command resource is deleted first (step 3).

1. Modify the `script` field in [`mdatp-scan-arc-policy-rule.json`](./mdatp-scan-arc-policy-rule.json).
2. Re-run `Deploy-MdatpScan-ArcPolicy.ps1` to push the updated script content to the policy definition.
3. **Delete the existing Run Command resource on each machine.** The policy's `existenceCondition` checks whether a Run Command named `ScheduleMdatpQuickScan` exists with `provisioningState = Succeeded`. Once that condition is met, the policy considers the machine compliant and will **not** re-run the script — even if the script content has changed. Deleting the Run Command resource causes the machine to appear non-compliant and triggers a fresh deployment with the updated script.

   ```powershell
   # Arc machines
   Remove-AzConnectedMachineRunCommand `
     -ResourceGroupName "<resource-group>" `
     -MachineName "<machine-name>" `
     -RunCommandName "ScheduleMdatpQuickScan"
   ```

4. Trigger remediation or wait for Azure Policy to reevaluate compliance. The policy will detect the missing Run Command, execute the updated script, and recreate the resource.

### Update Method 2 — Machine Configuration

Because the SetScript uses the `# MDATP_WEEKLY_SCAN` deduplication marker, re-applying the configuration overwrites the existing cron entry cleanly.

To push an updated schedule:

1. Modify the `SetScript` in `MdatpWeeklyScan.ps1` if needed
2. Re-run Steps 3–4 with an incremented `PolicyVersion` in `New-GuestConfigurationPolicy`
3. Machines will pick up the updated package on the next evaluation cycle

---

## Cleanup

### Cleanup Method 1 — Azure Policy

Remove in this order: assignments first (they reference the definitions), then the definitions. If you granted RBAC manually or through the deployment script, remove those role assignments separately.

Use the same assignment scope you originally deployed with. The policy definition is always created at the management group, but the assignment might be at management group, subscription, or resource group scope.

**If the assignment was created at management group scope:**

```powershell
$ManagementGroupId = '<management-group-id>'
$AssignmentScope   = "/providers/Microsoft.Management/managementGroups/$ManagementGroupId"

# 1 — Remove policy assignments
Remove-AzPolicyAssignment -Name 'deploy-mdatp-cron-arc' -Scope $AssignmentScope

# 2 — Remove policy definitions
Remove-AzPolicyDefinition -Name 'deploy-mdatp-scan-arc-linux' -ManagementGroupName $ManagementGroupId -Force
```

**If the assignment was created at subscription scope:**

```powershell
$ManagementGroupId = '<management-group-id>'
$AssignmentScope   = '/subscriptions/<subscription-id>'

# 1 — Remove policy assignment
Remove-AzPolicyAssignment -Name 'deploy-mdatp-cron-arc' -Scope $AssignmentScope

# 2 — Remove policy definition
Remove-AzPolicyDefinition -Name 'deploy-mdatp-scan-arc-linux' -ManagementGroupName $ManagementGroupId -Force
```

**If the assignment was created at resource group scope:**

```powershell
$ManagementGroupId = '<management-group-id>'
$AssignmentScope   = '/subscriptions/<subscription-id>/resourceGroups/<resource-group-name>'

# 1 — Remove policy assignment
Remove-AzPolicyAssignment -Name 'deploy-mdatp-cron-arc' -Scope $AssignmentScope

# 2 — Remove policy definition
Remove-AzPolicyDefinition -Name 'deploy-mdatp-scan-arc-linux' -ManagementGroupName $ManagementGroupId -Force
```

If you created multiple assignments at different scopes, remove all of those assignments before deleting the management-group policy definition.

If you used `Deploy-MdatpScan-ArcPolicy.ps1`, remove the Arc managed-identity role assignment separately after deleting the assignment.

> **Note:** Removing the assignments and definitions does **not** remove the cron job from machines that were already remediated. The Run Command resource will also remain on each machine. To remove the cron job from machines, delete it manually or via a separate script:
>
> ```bash
> sudo crontab -l | grep -Fv '# MDATP_WEEKLY_SCAN' | crontab -
> ```

To also remove the Run Command resources left on machines:

```powershell
# Arc machines
Remove-AzConnectedMachineRunCommand `
  -ResourceGroupName "<resource-group>" `
  -MachineName "<machine-name>" `
  -RunCommandName "ScheduleMdatpQuickScan"
```

---

### Cleanup Method 2 — Machine Configuration

```powershell
$ManagementGroupId = '<management-group-id>'

# 1 — Remove policy assignment
az policy assignment delete `
  --name "config-mdatp-cron-arc" `
  --scope "/providers/Microsoft.Management/managementGroups/$ManagementGroupId"

# 2 — Remove policy definition
az policy definition delete `
  --name "configure-mdatp-scan-arc-linux" `
  --management-group $ManagementGroupId
```

> **Note:** Removing the assignment stops future enforcement but does **not** remove the cron job from already-compliant machines. Remove it manually if needed:
>
> ```bash
> sudo crontab -l | grep -Fv '# MDATP_WEEKLY_SCAN' | crontab -
> ```

---

## References

- [Azure Policy deployIfNotExists effect](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-deploy-if-not-exists)
- [Remediate non-compliant resources with Azure Policy](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources)
- [Azure Machine Configuration prerequisites](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview/02-setup-prerequisites)
- [Azure Machine Configuration network requirements](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview/03-network-requirements)
- [Remediation options for machine configuration](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/concepts/remediation-options)
- [How to provide secure access to custom machine configuration packages](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/develop-custom-package/5-access-package)
- [Azure Arc network requirements](https://learn.microsoft.com/en-us/azure/azure-arc/network-requirements-consolidated)
- [Use Azure Private Link to securely connect servers to Azure Arc](https://learn.microsoft.com/en-us/azure/azure-arc/servers/private-link-security)
- [Schedule antivirus scans with crontab](https://learn.microsoft.com/en-us/defender-endpoint/schedule-antivirus-scan-crontab)
- [Azure Government — available services](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-services)
