# Configure MDATP Weekly Scan — Azure and Arc Linux

Deploys a weekly Microsoft Defender for Endpoint (MDATP) quick scan schedule to **Azure Linux virtual machines** and **Azure Arc-connected Linux servers**.

Two methods are covered:

- **Method 1 — Azure Policy (DeployIfNotExists)**: Deploys the cron job to target machines via `DeployIfNotExists` policy. New or updated machines are handled by the assignment. Existing machines require a remediation task. It does not re-apply if the cron job is later removed because compliance reflects Run Command execution state, not cron job presence.
- **Method 2 — Machine Configuration (Continuous)**: Uses Azure Policy with `ApplyAndAutoCorrect` to continuously enforce the cron job. Under the tenant controls described in this guide, this method is currently practical for **Azure Linux VMs**. For **Arc-connected Linux servers**, private custom package access requires a SAS URL or a supported identity pattern that is not available here, so Arc coverage should be treated as unsupported until validated in your environment.

**Recommended approach:** Use Method 1 for mixed Azure VM and Arc coverage today. Use Method 2 for Azure VM-only continuous enforcement when you need drift correction.

---

## Prerequisites

### Method 1 — Azure Policy

All scripts in this guide are written for **PowerShell**. Run from Azure Cloud Shell (PowerShell session) or a local PowerShell session with the Az module installed.

- **PowerShell Az module:** `Install-Module Az -Scope CurrentUser` (pre-installed in Cloud Shell)
- **RBAC roles (for you):** `Resource Policy Contributor` and `Management Group Contributor`
- **RBAC roles (policy managed identity):** granted automatically by the script:
  - `Azure Connected Machine Resource Administrator` — Arc machines
  - `Virtual Machine Contributor` — Azure VMs

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

Three files are used:

| File | Purpose |
|------|---------|
| [`Deploy-MdatpScanPolicy.ps1`](./Deploy-MdatpScanPolicy.ps1) | Creates definitions, assignments, and role assignments in one run |
| [`mdatp-scan-arc-policy-rule.json`](./mdatp-scan-arc-policy-rule.json) | Policy rule for Arc-connected Linux machines |
| [`mdatp-scan-vm-policy-rule.json`](./mdatp-scan-vm-policy-rule.json) | Policy rule for Azure VM Linux machines |

---

### Step 1 — Clone or download the files

Ensure all three files are in the same directory on your machine or Cloud Shell session.

---

### Step 2 — Run the deployment script

Open Azure Cloud Shell (PowerShell) or a local PowerShell session, then run:

**Assign at management group scope** (covers all subscriptions under the MG — recommended):

```powershell
.\Deploy-MdatpScanPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus'
```

**Assign at a single subscription:**

```powershell
.\Deploy-MdatpScanPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
    -AssignmentScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy'
```

**Assign at a resource group:**

```powershell
.\Deploy-MdatpScanPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'eastus' `
    -AssignmentScope '/subscriptions/yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy/resourceGroups/<resource-group-name>'
```

**Azure Government:**

```powershell
.\Deploy-MdatpScanPolicy.ps1 -ManagementGroupId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -Location 'usgovvirginia' `
    -Environment 'AzureUSGovernment'
```

The script runs in three phases by default and prints progress for each:

1. Creates both policy definitions at the management group
2. Creates both policy assignments at the specified scope with system-assigned managed identities
3. Grants the required role assignments to each managed identity

If you use `-CreateRemediationTasks`, the script adds a fourth phase that starts remediation for existing machines with `ReEvaluateCompliance`.

Re-running the script is safe for definitions, assignments, and role assignments. If you use `-CreateRemediationTasks`, existing remediation task names are detected and skipped.

---

### Check Compliance

After assignment, Azure Policy compliance can take some time to refresh. To view compliance state:

**Azure Policy** → **Compliance** → filter by assignment name `deploy-mdatp-cron-arc` or `deploy-mdatp-cron-vm`.

### Trigger Immediate Remediation

To deploy to existing non-compliant machines without waiting for a later policy cycle:

**Azure Policy** → **Remediation** → **New remediation task** → select the assignment → **Remediate**.

For PowerShell, use `ReEvaluateCompliance` so existing resources are rediscovered before remediation starts:

```powershell
Start-AzPolicyRemediation `
  -Name 'remediate-arc' `
  -PolicyAssignmentId '<arc-policy-assignment-id>' `
  -Scope '<assignment-scope>' `
  -ResourceDiscoveryMode ReEvaluateCompliance
```

---

## Method 2 — Machine Configuration (Continuous, Azure VMs)

Uses Azure Policy `ApplyAndAutoCorrect` to continuously enforce the cron job on Azure Linux VMs. The guest assignment is checked every 5 minutes, and settings are rechecked about every 15 minutes after assignment. If the cron job is removed, it is reinstalled on the next machine configuration evaluation.

**Important scope note:** Under the storage restrictions described in this guide, Method 2 should be treated as **Azure VM-only**. Arc-connected Linux servers require a package access model that is not covered here.

### How It Works

1. A custom Machine Configuration package is built from an InSpec audit profile and a DSC `nxScript` set script
2. The package is published to an Azure Storage Account
3. An Azure Policy (`ApplyAndAutoCorrect`) definition is created from the package and assigned at management group scope
4. The Machine Configuration agent on each Azure VM processes the guest assignment:
   - **Audit**: InSpec checks whether the `# MDATP_WEEKLY_SCAN` cron entry exists in the root crontab
   - **Set**: If the cron entry is missing, the `nxScript` SetScript installs it automatically
5. Machines with the cron job present are **Compliant**; machines with it absent are **Non-compliant** and remediated on the next evaluation cycle — no manual remediation task required

### Prerequisites (Method 2)

- **PowerShell 7.2+** on your local machine
- **PowerShell modules:**
  ```powershell
  Install-Module GuestConfiguration -Force
  Install-Module nx -Force          # Linux DSC resources (provides nxScript)
  ```
- **Azure Storage Account** to host the configuration package
  - Public blob access must remain disabled
  - If your tenant blocks SAS for storage access, treat this method as Azure VM-only unless you validate an alternative supported package access pattern
  - All storage operations must use **Azure AD authentication** (`--auth-mode login`)
  - Package access for guest assignments must follow Microsoft-supported custom package access guidance. Azure VMs can use a supported identity-based path. Arc package access should be validated separately before rollout.
  - **Azure VMs:** System-assigned managed identity must be enabled on each VM
- **MDE deployed** on each Linux machine (`/usr/bin/mdatp` present) before the package runs
- **Machine Configuration extension** deployed on each target Azure VM (see Step 1)
- **RBAC roles:**
  - `Resource Policy Contributor` — to create and assign the policy
  - `Management Group Contributor` — to create the definition at management group scope
  - `Storage Blob Data Contributor` — to upload the package to the storage account
  - `Contributor` on target machines/scope — required for the managed identity to apply configuration (audit+set requires write access, unlike audit-only)

### Step 1 — Deploy the Machine Configuration Agent on Azure VMs

Each Azure VM requires the Machine Configuration extension. Check for `AzurePolicyforLinux` in the portal:

- **Azure VMs:** Virtual Machines → *select VM* → **Extensions + applications**

### Azure VMs

```powershell
$ResourceGroup = "<resource-group>"
$vms = az vm list `
  --resource-group $ResourceGroup `
  --query "[?storageProfile.osDisk.osType=='Linux'].{name:name, location:location}" `
  --output json | ConvertFrom-Json

foreach ($vm in $vms) {
  az vm extension set `
    --resource-group $ResourceGroup `
    --vm-name $vm.name `
    --name "ConfigurationForLinux" `
    --extension-instance-name "AzurePolicyforLinux" `
    --publisher "Microsoft.GuestConfiguration" `
    --enable-auto-upgrade true
}
```

**Arc note:** Arc-enabled servers include guest configuration services through the Connected Machine agent, but custom package rollout for this method should not be assumed to work under the tenant storage restrictions in this guide without separate validation.

---

### Step 2 — Author the Package

Create the following directory and files locally:

```
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

> **Tenant policy compliance:** Tenant policies block shared key access and anonymous blob access on all storage accounts. All `az storage` commands below use `--auth-mode login` (Azure AD) for upload and management operations. Package download for guest assignments must still follow a Microsoft-supported custom package access pattern. If your tenant disallows SAS and you need Arc support, validate that design separately before rollout.

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

# Get the blob URI for the package
$PackageUri = az storage blob url `
  --account-name $StorageAccount `
  --container-name $Container `
  --name "MdatpWeeklyScan.zip" `
  --auth-mode login `
  --output tsv
```

### Grant Access to the Package for Azure VMs

For Azure VMs using a supported identity-based package access model, grant the required blob read permissions to the identity you use for package retrieval.

**Enable system-assigned managed identity on Azure VMs:**

```powershell
$ResourceGroup = "<resource-group>"
$vms = az vm list `
  --resource-group $ResourceGroup `
  --query "[?storageProfile.osDisk.osType=='Linux'].name" `
  --output tsv

foreach ($vm in $vms) {
  az vm identity assign `
    --resource-group $ResourceGroup `
    --name $vm
}
```

**Grant Storage Blob Data Reader to each Azure VM identity:**

```powershell
$StorageAccount = "<storage-account-name>"
$ResourceGroup  = "<storage-resource-group>"
$Container      = "guestconfig"

$ContainerResourceId = "/subscriptions/$(az account show --query id -o tsv)/resourceGroups/$ResourceGroup/providers/Microsoft.Storage/storageAccounts/$StorageAccount/blobServices/default/containers/$Container"

# Azure VMs
$vms = az vm list `
  --resource-group "<vm-resource-group>" `
  --query "[?storageProfile.osDisk.osType=='Linux'].{name:name, identity:identity.principalId}" `
  --output json | ConvertFrom-Json

foreach ($vm in $vms) {
  az role assignment create `
    --assignee $vm.identity `
    --role "Storage Blob Data Reader" `
    --scope $ContainerResourceId
}

```

**Arc note:** Do not assume the same system-assigned identity pattern works for Arc custom packages in this design. Validate Arc package access separately before adding Arc machines to Method 2 scope.

---

### Step 4 — Create and Assign the Policy

```powershell
# Generate the policy definition JSON from the published package
New-GuestConfigurationPolicy `
  -ContentUri $PackageUri `
  -ContentHash $PackageHash `
  -DisplayName "Configure: MDATP Weekly Scan Cron on Linux" `
  -Description "Audits and configures the MDATP weekly quick scan cron entry in the root crontab of Azure and Arc-connected Linux machines." `
  -PolicyId (New-Guid).Guid `
  -PolicyVersion "1.0.0" `
  -Path "./MdatpWeeklyScanPolicy" `
  -Platform Linux `
  -Mode ApplyAndAutoCorrect

# Create the policy definition at management group scope
az policy definition create `
  --name "configure-mdatp-scan-linux" `
  --display-name "Configure: MDATP Weekly Scan Cron on Linux" `
  --description "Audits and configures the MDATP weekly quick scan cron entry on Azure and Arc-connected Linux machines." `
  --mode Indexed `
  --rules "@./MdatpWeeklyScanPolicy/configure-mdatp-scan-linux.json" `
  --management-group "<management-group-id>"

# Get the definition ID
$PolicyId = az policy definition show `
  --name "configure-mdatp-scan-linux" `
  --management-group "<management-group-id>" `
  --query id --output tsv

# Assign at management group scope
# Note: --name must be 24 characters or fewer
az policy assignment create `
  --name "config-mdatp-cron-linux" `
  --display-name "Configure: MDATP Weekly Scan Cron on Linux" `
  --policy $PolicyId `
  --scope "/providers/Microsoft.Management/managementGroups/<management-group-id>" `
  --mi-system-assigned `
  --location "<location>" `
  --identity-scope "/providers/Microsoft.Management/managementGroups/<management-group-id>" `
  --role "Contributor"
```

**Note:** `New-GuestConfigurationPolicy` generates the policy rule JSON in the output path. The filename will match the policy display name slug — adjust `--rules` if the generated filename differs.

**Note:** This assignment example is intended for Azure VM scope. If you need Arc support, validate the generated policy parameters and package access model first.

**Note:** `ApplyAndAutoCorrect` assignments require the managed identity to have `Contributor` on the target scope. Audit-only assignments only need `Reader`.

---

### Step 5 — Check Compliance

```powershell
az policy state list `
  --management-group "<management-group-id>" `
  --filter "policyAssignmentName eq 'config-mdatp-cron-linux'" `
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

```
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
|-------|----------------|
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

### Method 1 — Azure Policy

The cron schedule is controlled by the `script` field inside `mdatp-scan-arc-policy-rule.json` and `mdatp-scan-vm-policy-rule.json`. The relevant lines are:

```bash
HOUR=$(( RANDOM % 12 ))       # Random hour between 0–11 (midnight to 11 AM)
MINUTE=$(( RANDOM % 60 ))     # Random minute between 0–59
ENTRY="${MINUTE} ${HOUR} * * 0 ${MDATP_CMD} scan quick ${CRON_MARKER}"
#                         ^ day of week: 0 = Sunday
```

The cron entry format is: `<minute> <hour> <day-of-month> <month> <day-of-week>`

**To change the day** — replace the `0` in `* * 0`:

| Value | Day |
|-------|-----|
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

1. Modify the `script` field in [`mdatp-scan-arc-policy-rule.json`](./mdatp-scan-arc-policy-rule.json), [`mdatp-scan-vm-policy-rule.json`](./mdatp-scan-vm-policy-rule.json), or both.
2. Re-run `Deploy-MdatpScanPolicy.ps1` to push the updated script content to the policy definition.
3. **Delete the existing Run Command resource on each machine.** The policy's `existenceCondition` checks whether a Run Command named `ScheduleMdatpQuickScan` exists with `provisioningState = Succeeded`. Once that condition is met, the policy considers the machine compliant and will **not** re-run the script — even if the script content has changed. Deleting the Run Command resource causes the machine to appear non-compliant and triggers a fresh deployment with the updated script.
   ```powershell
   # Arc machines
   Remove-AzConnectedMachineRunCommand `
     -ResourceGroupName "<resource-group>" `
     -MachineName "<machine-name>" `
     -RunCommandName "ScheduleMdatpQuickScan"

   # Azure VMs
   Remove-AzVMRunCommand `
     -ResourceGroupName "<resource-group>" `
     -VMName "<vm-name>" `
     -RunCommandName "ScheduleMdatpQuickScan"
   ```
4. Trigger remediation or wait for Azure Policy to reevaluate compliance. The policy will detect the missing Run Command, execute the updated script, and recreate the resource.

### Method 2 — Machine Configuration

Because the SetScript uses the `# MDATP_WEEKLY_SCAN` deduplication marker, re-applying the configuration overwrites the existing cron entry cleanly.

To push an updated schedule:
1. Modify the `SetScript` in `MdatpWeeklyScan.ps1` if needed
2. Re-run Steps 3–4 with an incremented `PolicyVersion` in `New-GuestConfigurationPolicy`
3. Machines will pick up the updated package on the next evaluation cycle

---

## Cleanup

### Method 1 — Azure Policy

Remove in this order: assignments first (they reference the definitions), then the definitions. If you granted RBAC manually or through the deployment script, remove those role assignments separately.

```powershell
$ManagementGroupId = '<management-group-id>'
$AssignmentScope   = "/providers/Microsoft.Management/managementGroups/$ManagementGroupId"

# 1 — Remove policy assignments
Remove-AzPolicyAssignment -Name 'deploy-mdatp-cron-arc' -Scope $AssignmentScope
Remove-AzPolicyAssignment -Name 'deploy-mdatp-cron-vm'  -Scope $AssignmentScope

# 2 — Remove policy definitions
Remove-AzPolicyDefinition -Name 'deploy-mdatp-scan-arc-linux' -ManagementGroupName $ManagementGroupId -Force
Remove-AzPolicyDefinition -Name 'deploy-mdatp-scan-vm-linux'  -ManagementGroupName $ManagementGroupId -Force
```

If you used `Deploy-MdatpScanPolicy.ps1`, remove the two managed-identity role assignments separately after deleting the assignments.

> **Note:** Removing the assignments and definitions does **not** remove the cron job from machines that were already remediated. The Run Command resource will also remain on each machine. To remove the cron job from machines, delete it manually or via a separate script:
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

# Azure VMs
Remove-AzVMRunCommand `
  -ResourceGroupName "<resource-group>" `
  -VMName "<vm-name>" `
  -RunCommandName "ScheduleMdatpQuickScan"
```

---

### Method 2 — Machine Configuration

```powershell
$ManagementGroupId = '<management-group-id>'

# 1 — Remove policy assignment
az policy assignment delete `
  --name "config-mdatp-cron-linux" `
  --scope "/providers/Microsoft.Management/managementGroups/$ManagementGroupId"

# 2 — Remove policy definition
az policy definition delete `
  --name "configure-mdatp-scan-linux" `
  --management-group $ManagementGroupId
```

> **Note:** Removing the assignment stops future enforcement but does **not** remove the cron job from already-compliant machines. Remove it manually if needed:
> ```bash
> sudo crontab -l | grep -Fv '# MDATP_WEEKLY_SCAN' | crontab -
> ```

---

## References

- [Azure Policy deployIfNotExists effect](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-deploy-if-not-exists)
- [Remediate non-compliant resources with Azure Policy](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources)
- [Azure Machine Configuration prerequisites](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview/02-setup-prerequisites)
- [Remediation options for machine configuration](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/concepts/remediation-options)
- [Azure Machine Configuration extension](https://learn.microsoft.com/en-us/azure/virtual-machines/extensions/guest-configuration)
- [How to provide secure access to custom machine configuration packages](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/how-to/develop-custom-package/5-access-package)
- [Schedule antivirus scans with crontab](https://learn.microsoft.com/en-us/defender-endpoint/schedule-antivirus-scan-crontab)
- [Azure Government — available services](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-services)
