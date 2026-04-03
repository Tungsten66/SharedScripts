# Configure MDATP Weekly Scan — Azure and Arc Linux

Deploys a weekly Microsoft Defender for Endpoint (MDATP) quick scan schedule to **Azure Linux virtual machines** and **Azure Arc-connected Linux servers**.

Two methods are covered:

- **Method 1 — Azure Policy (DeployIfNotExists)**: Deploys the cron job to target machines via `DeployIfNotExists` policy. Covers machines at assignment scope — current and future. Does not re-apply if the cron job is later removed (compliance reflects Run Command execution state, not cron job presence).
- **Method 2 — Machine Configuration (Continuous)**: Uses Azure Policy with `ApplyAndAutoCorrect` to continuously enforce the cron job. Covers all machines at assignment scope — current and future — and automatically reinstalls the cron entry if it is removed. Requires more setup but is the recommended long-term solution.

**Recommended approach:** Use Method 2 for all environments. Use Method 1 when you want policy-based coverage without the complexity of Machine Configuration package authoring.

---

## Prerequisites

### Azure Government CLI Cloud Setup

All CLI commands in this guide are written for **PowerShell**. Run from a local PowerShell session, the VS Code integrated terminal, or Azure Cloud Shell (PowerShell session).

If targeting Azure Government, set the active cloud before running any `az` commands:

```powershell
az cloud set --name AzureUSGovernment
az login
az account set --subscription "<your-subscription-id>"
```

### Method 1 — Azure Policy

- Azure CLI
- **RBAC roles (for you):** `Resource Policy Contributor` and `Management Group Contributor`
- **RBAC roles (policy managed identity):** assigned automatically via `--role` in the assignment command:
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

Uses Azure Policy `DeployIfNotExists` to deploy the cron job to target machines via Run Command. The policy evaluates every ~24 hours and deploys to any machine that hasn't had a successful run.

**Important limitation:** Compliance state reflects whether the Run Command executed successfully — not whether the cron job currently exists. If the cron job is later removed manually, the machine remains Compliant (the Run Command resource already succeeded). Use Method 2 if continuous drift correction is required.

Two policy definitions are provided — one for Arc-connected machines and one for Azure VMs:
- [`mdatp-scan-policy-arc.json`](./mdatp-scan-policy-arc.json)
- [`mdatp-scan-policy-vm.json`](./mdatp-scan-policy-vm.json)

Both ARM templates can be deployed through the Azure portal using **Deploy a custom template** — no CLI required.

Two templates are provided:

| Template | Deployment scope | Purpose |
|----------|-----------------|--------|
| [`mdatp-scan-policy-definitions.json`](./mdatp-scan-policy-definitions.json) | Management group | Creates both policy definitions. Run once. |
| [`mdatp-scan-policy-assignments-mg.json`](./mdatp-scan-policy-assignments-mg.json) | Management group | Assigns both policies at management group scope. Covers all subscriptions under the MG. |
| [`mdatp-scan-policy-assignments.json`](./mdatp-scan-policy-assignments.json) | Subscription | Assigns both policies at subscription (or resource group) scope. Redeploy per scope. |

---

### Step 1 — Deploy Policy Definitions (management group scope)

Run once. Re-running is safe — ARM will update the definitions if the template changes.

1. In the Azure portal, search for **Deploy a custom template** and select it.
2. Click **Build your own template in the editor**, paste the full contents of [`mdatp-scan-policy-definitions.json`](./mdatp-scan-policy-definitions.json), then click **Save**.
3. Under **Scope**, set the deployment scope to **Management group** and select your management group.
4. Set **Region** to your preferred Azure region.
5. Under **Parameters**, set `managementGroupId` to your management group ID.
6. Click **Review + create**, then **Create**.

---

### Step 2 — Deploy Policy Assignments

Two templates are available depending on the desired assignment scope.

#### Option A — Management group scope (recommended)

Use [`mdatp-scan-policy-assignments-mg.json`](./mdatp-scan-policy-assignments-mg.json). A single deployment covers all subscriptions and machines under the management group — no need to redeploy per subscription.

1. In the Azure portal, search for **Deploy a custom template** and select it.
2. Click **Build your own template in the editor**, paste the full contents of [`mdatp-scan-policy-assignments-mg.json`](./mdatp-scan-policy-assignments-mg.json), then click **Save**.
3. Under **Scope**, set the deployment scope to **Management group** and select your management group.
4. Set **Region** to the same location used in Step 1.
5. Under **Parameters**, fill in the following:

   | Parameter | Value |
   |-----------|-------|
   | `definitionManagementGroupId` | Management group ID where definitions were deployed (Step 1) |
   | `assignmentManagementGroupId` *(optional)* | Management group to assign the policies to. Defaults to the deployment management group — leave blank if they are the same. |
   | `location` | Same region as Step 1 |

6. Click **Review + create**, then **Create**.

#### Option B — Subscription or resource group scope

Use [`mdatp-scan-policy-assignments.json`](./mdatp-scan-policy-assignments.json). Repeat for each subscription you want to target.

1. In the Azure portal, search for **Deploy a custom template** and select it.
2. Click **Build your own template in the editor**, paste the full contents of [`mdatp-scan-policy-assignments.json`](./mdatp-scan-policy-assignments.json), then click **Save**.
3. Under **Scope**, select **Subscription** and choose the target subscription.
4. Set **Region** to the same location used in Step 1.
5. Under **Parameters**, fill in the following:

   | Parameter | Value |
   |-----------|-------|
   | `definitionManagementGroupId` | Management group ID where definitions were deployed (Step 1) |
   | `location` | Same region as Step 1 |
   | `assignmentScope` *(optional)* | To narrow to a resource group: `/subscriptions/<subscription-id>/resourceGroups/<rg-name>`. Leave blank to target the full subscription. |

6. Click **Review + create**, then **Create**.

Both templates create the managed identity role assignments automatically at the same scope as the assignment.

---

### Check Compliance

After assignment, Azure Policy evaluates machines within ~24 hours. To view compliance state:

**Azure Policy** → **Compliance** → filter by assignment name `deploy-mdatp-cron-arc` or `deploy-mdatp-cron-vm`.

### Trigger Immediate Remediation

To deploy to non-compliant machines without waiting for the next evaluation cycle:

**Azure Policy** → **Remediation** → **New remediation task** → select the assignment → **Remediate**.

---

## Method 2 — Machine Configuration (Continuous)

Uses Azure Policy `ApplyAndAutoCorrect` to continuously enforce the cron job on every evaluation cycle (~24 hours). Covers all machines at assignment scope — current and future. If the cron job is removed, it is reinstalled automatically on the next cycle without any manual action.

### How It Works

1. A custom Machine Configuration package is built from an InSpec audit profile and a DSC `nxScript` set script
2. The package is published to an Azure Storage Account
3. An Azure Policy (`ApplyAndAutoCorrect`) definition is created from the package and assigned at management group scope
4. The `AzurePolicyforLinux` extension on each machine runs the package every ~24 hours:
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
  - Public blob access and shared key (SAS token) access **must not be used** — tenant policies `StorageAccount_BlobAnonymousAccess_Modify` and `StorageAccount_DisableLocalAuth_Modify` enforce `allowBlobPublicAccess = false` and `allowSharedKeyAccess = false`
  - All storage operations must use **Azure AD authentication** (`--auth-mode login`)
  - Each target machine downloads the package using its **system-assigned managed identity** — grant `Storage Blob Data Reader` on the container to each machine identity (see Step 3)
  - **Azure VMs:** System-assigned managed identity must be enabled on each VM
  - **Arc machines:** System-assigned managed identity is enabled automatically
- **MDE deployed** on each Linux machine (`/usr/bin/mdatp` present) before the package runs
- **`AzurePolicyforLinux` extension** deployed on each target machine (see Step 1)
- **RBAC roles:**
  - `Resource Policy Contributor` — to create and assign the policy
  - `Management Group Contributor` — to create the definition at management group scope
  - `Storage Blob Data Contributor` — to upload the package to the storage account
  - `Contributor` on target machines/scope — required for the managed identity to apply configuration (audit+set requires write access, unlike audit-only)

### Step 1 — Deploy the Machine Configuration Agent

Each machine requires the `AzurePolicyforLinux` extension. Check for it in the portal:

- **Arc machines:** Azure Arc → Servers → *select machine* → **Extensions**
- **Azure VMs:** Virtual Machines → *select VM* → **Extensions + applications**

### Arc-connected machines

```powershell
$ResourceGroup = "<resource-group>"
$machines = az connectedmachine list `
  --resource-group $ResourceGroup `
  --query "[].{name:name, location:location}" `
  --output json | ConvertFrom-Json

foreach ($machine in $machines) {
  az connectedmachine extension create `
    --resource-group $ResourceGroup `
    --machine-name $machine.name `
    --name "AzurePolicyforLinux" `
    --type "AzurePolicyforLinux" `
    --publisher "Microsoft.GuestConfiguration" `
    --location $machine.location
}
```

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
    --name "AzurePolicyforLinux" `
    --publisher "Microsoft.GuestConfiguration" `
    --enable-auto-upgrade true
}
```

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

> **Tenant policy compliance:** Tenant policies block shared key access and anonymous blob access on all storage accounts. All `az storage` commands below use `--auth-mode login` (Azure AD). SAS tokens cannot be used — the `contentUri` must be a plain blob URI authenticated by each machine's system-assigned managed identity at download time.

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

# Get the plain blob URI (no SAS token — machines authenticate using their managed identity)
$PackageUri = az storage blob url `
  --account-name $StorageAccount `
  --container-name $Container `
  --name "MdatpWeeklyScan.zip" `
  --auth-mode login `
  --output tsv
```

### Grant Storage Blob Data Reader to Machine Identities

Each machine uses its system-assigned managed identity to download the package on every evaluation cycle. Grant `Storage Blob Data Reader` on the container to all target machine identities.

**Enable system-assigned managed identity on Azure VMs** (Arc machines have this automatically):

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

**Grant Storage Blob Data Reader to each machine's managed identity:**

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

# Arc machines
$arcMachines = az connectedmachine list `
  --resource-group "<arc-resource-group>" `
  --query "[].{name:name, identity:identity.principalId}" `
  --output json | ConvertFrom-Json

foreach ($machine in $arcMachines) {
  az role assignment create `
    --assignee $machine.identity `
    --role "Storage Blob Data Reader" `
    --scope $ContainerResourceId
}
```

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

Machines marked **Non-compliant** will be remediated automatically on the next evaluation cycle (~24 hours). No manual remediation task is required — this is a key difference from the DeployIfNotExists approach.

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

Should return exactly one line. If it returns more than one, the idempotency marker was not matched correctly — re-applying the configuration will reset to a clean state.

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

The cron schedule is embedded in the policy JSON (`mdatp-scan-policy-arc.json` / `mdatp-scan-policy-vm.json`). To update it:

1. Modify the `script` field in the relevant policy JSON file(s)
2. Re-deploy the definitions template via **Deploy a custom template** (Step 1) — re-running is safe and idempotent.
3. Delete the existing Run Command resource on each machine — the `existenceCondition` is satisfied once the Run Command succeeds and will not trigger redeployment unless the resource is absent:
   ```powershell
   # Arc machines
   az connectedmachine run-command delete `
     --resource-group "<resource-group>" `
     --machine-name "<machine-name>" `
     --run-command-name "ScheduleMdatpQuickScan" `
     --yes

   # Azure VMs
   az vm run-command delete `
     --resource-group "<resource-group>" `
     --vm-name "<vm-name>" `
     --run-command-name "ScheduleMdatpQuickScan"
   ```
4. Trigger remediation or wait for the next evaluation cycle

### Method 2 — Machine Configuration

Because the SetScript uses the `# MDATP_WEEKLY_SCAN` idempotency marker, re-applying the configuration overwrites the existing cron entry cleanly.

To push an updated schedule:
1. Modify the `SetScript` in `MdatpWeeklyScan.ps1` if needed
2. Re-run Steps 3–4 with an incremented `PolicyVersion` in `New-GuestConfigurationPolicy`
3. Machines will pick up the updated package on the next evaluation cycle

---

## References

- [Azure Machine Configuration overview](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview)
- [Azure Machine Configuration — authoring packages](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/machine-configuration-create)
- [Azure Machine Configuration — policy effects (ApplyAndAutoCorrect)](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/machine-configuration-policy-effects)
- [Azure Machine Configuration — Arc-connected servers](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/machine-configuration-arc)
- [Schedule antivirus scans with crontab – Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/schedule-antivirus-scan-crontab)
- [Azure Government — available services](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-services)
