# Schedule MDATP Quick Scans on Arc-Connected Linux Devices

This guide covers three methods for deploying a weekly Microsoft Defender for Endpoint (MDATP) quick scan schedule to Linux devices managed by Azure Arc:

- **Method 1 — Arc Run Command**: Point-in-time deployment to machines that are online at the time the command runs. Does not cover machines onboarded after deployment.
- **Method 2 — Azure Policy (DeployIfNotExists)**: Continuously enforced — covers all existing machines and any future machines onboarded to Arc. This is the recommended long-term solution.
- **Method 3 — Azure Machine Configuration (Continuous Audit)**: Continuously verifies the cron entry is actually present on the machine on every policy evaluation cycle (~24 hours). Does not replace Method 2 — use alongside it when continuous tampering detection is required.

**Recommended approach:** Use Method 2 (Azure Policy) as the primary solution for all environments. It automatically deploys to all current and future Arc-onboarded Linux machines with no additional action. Method 1 can be used for immediate ad-hoc deployment while policy propagates. Add Method 3 only if your environment requires continuous verification that the cron job has not been removed after deployment (e.g., compliance or insider threat requirements).

---

## Prerequisites

- Linux devices onboarded to [Azure Arc](https://learn.microsoft.com/en-us/azure/azure-arc/servers/overview)
- Microsoft Defender for Endpoint installed and onboarded on each Linux device (`/usr/bin/mdatp` present)
- Azure CLI installed locally (`az` command) with the `connectedmachine` extension (preview required for `run-command` subcommands):
  ```powershell
  az extension add --name connectedmachine --allow-preview True
  ```
- Appropriate RBAC roles:
  - `Azure Connected Machine Resource Administrator` — to use Run Command
  - `Resource Policy Contributor` — to create and assign Policy
  - `Management Group Contributor` — to create the policy definition at management group scope
- Script file: [`schedule_mdatp_scan.sh`](./schedule_mdatp_scan.sh) (in this directory)

### Azure Government CLI Cloud Setup

All commands in this guide are written for **PowerShell**. They can be run from a local PowerShell session, the PowerShell integrated terminal in VS Code, or Azure Cloud Shell (PowerShell session).

If targeting Azure Government, set the active cloud before running any `az` commands:

```powershell
az cloud set --name AzureUSGovernment
az login
az account set --subscription "<your-subscription-id>"
```

---

## Method 1 — Arc Run Command (Point-in-Time)

**Scope:** Targets only machines that exist and are online at the time the command runs. Any machines onboarded to Arc after this runs will **not** be configured automatically. Use Method 2 (Azure Policy) to ensure ongoing and future coverage.

Deploys the cron job directly to Arc-connected machines. After the script runs once on the device, the cron job handles all future scans locally with no further Azure involvement.

### Deploy to a Single Machine

```powershell
az connectedmachine run-command create `
  --resource-group "<resource-group>" `
  --machine-name "<arc-machine-name>" `
  --run-command-name "ScheduleMdatpQuickScan" `
  --script "@schedule_mdatp_scan.sh" `
  --location "<location>"
```

**Note:** `--location` must match the region where the Arc machine is registered (e.g., `usgovvirginia`).

### Deploy to All Machines in a Resource Group

```powershell
$ResourceGroup = "<resource-group>"

$machines = az connectedmachine list `
  --resource-group $ResourceGroup `
  --query "[].name" `
  --output tsv

foreach ($machine in $machines) {
  Write-Host "Deploying to: $machine"
  az connectedmachine run-command create `
    --resource-group $ResourceGroup `
    --machine-name $machine `
    --run-command-name "ScheduleMdatpQuickScan" `
    --script "@schedule_mdatp_scan.sh" `
    --no-wait
}
```

### Deploy to All Machines Across a Subscription

```powershell
$machines = az connectedmachine list `
  --query "[].{name:name, rg:resourceGroup}" `
  --output json | ConvertFrom-Json

foreach ($machine in $machines) {
  Write-Host "Deploying to: $($machine.name) (RG: $($machine.rg))"
  az connectedmachine run-command create `
    --resource-group $machine.rg `
    --machine-name $machine.name `
    --run-command-name "ScheduleMdatpQuickScan" `
    --script "@schedule_mdatp_scan.sh" `
    --no-wait
}
```

### Verify Deployment

Check the result of the run command on a specific machine:

```powershell
az connectedmachine run-command show `
  --resource-group "<resource-group>" `
  --machine-name "<arc-machine-name>" `
  --run-command-name "ScheduleMdatpQuickScan" `
  --query "{status:instanceView.executionState, output:instanceView.output, error:instanceView.error}"
```

### Updating the Scan Schedule

The script is idempotent — re-running it removes the existing cron entry and installs a new one. To update the schedule, simply re-run the deploy steps above. The `# MDATP_WEEKLY_SCAN` marker in the crontab ensures no duplicate entries are created.

---

## Method 2 — Azure Policy (DeployIfNotExists)

Azure Policy continuously evaluates machines for compliance and automatically deploys the cron job to any machine that doesn't have it. This is the recommended approach for ensuring new Arc-onboarded machines are automatically configured.

> **Prerequisite dependency:** The policy's `if` condition requires the `MDE.Linux` Arc extension to be present with a `provisioningState` of `Succeeded` before deployment is attempted. This prevents the policy from running and marking a machine compliant before Defender for Endpoint is actually installed. Machines where MDE was onboarded manually (not via the Arc extension) will not be evaluated by this policy.

> **Compliance reporting:** The policy uses an `existenceCondition` that checks `instanceView.executionState equals Succeeded` on the deployed RunCommand resource. A machine is only marked **Compliant** if the cron job script executed successfully. If the script fails, the machine remains **Non-compliant** and the policy will redeploy on the next remediation cycle. `evaluationDelay: AfterProvisioningSuccess` prevents a race condition where policy evaluates before the script has finished running.

> **Known limitation:** Once a machine is marked Compliant, the policy does not continuously verify that the cron job is still present. If the cron entry is manually removed, the RunCommand resource still exists with `executionState: Succeeded`, so the machine will remain Compliant until the RunCommand resource itself is deleted and remediation is re-triggered. Use **Method 3 (Azure Machine Configuration)** alongside this policy if continuous detection of cron job removal is required.

### How It Works

1. A **Policy Definition** is created at the **management group** scope — this makes it available for assignment at any level beneath it (management group, subscription, or resource group)
2. A **Policy Assignment** applies the definition to a chosen scope (subscription or resource group)
3. A **Managed Identity** is granted the permissions needed to execute remediation
4. **Remediation Tasks** are triggered automatically for non-compliant machines (or manually on demand)

### Step 1 — Create the Policy Definition

The policy definition file [`mdatp-scan-policy-arc.json`](./mdatp-scan-policy-arc.json) is included in this directory. Its contents are shown below for reference:

```json
{
  "mode": "All",
  "displayName": "Schedule MDATP Weekly Quick Scan on Arc Linux",
  "description": "Deploys a weekly MDATP quick scan cron job to Arc-connected Linux machines using Run Command.",
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.HybridCompute/machines"
        },
        {
          "field": "Microsoft.HybridCompute/machines/osName",
          "contains": "linux"
        },
        {
          "count": {
            "field": "Microsoft.HybridCompute/machines/extensions[*]",
            "where": {
              "allOf": [
                {
                  "field": "Microsoft.HybridCompute/machines/extensions[*].type",
                  "equals": "MDE.Linux"
                },
                {
                  "field": "Microsoft.HybridCompute/machines/extensions[*].provisioningState",
                  "equals": "Succeeded"
                }
              ]
            }
          },
          "greaterOrEquals": 1
        }
      ]
    },
    "then": {
      "effect": "deployIfNotExists",
      "details": {
        "type": "Microsoft.HybridCompute/machines/runCommands",
        "name": "ScheduleMdatpQuickScan",
        "evaluationDelay": "AfterProvisioningSuccess",
        "existenceCondition": {
          "field": "Microsoft.HybridCompute/machines/runCommands/properties/instanceView/executionState",
          "equals": "Succeeded"
        },
        "roleDefinitionIds": [
          "/providers/Microsoft.Authorization/roleDefinitions/cd570a14-e51a-42ad-bac8-bafd67325302"
        ],
        "deployment": {
          "properties": {
            "mode": "incremental",
            "template": {
              "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
              "contentVersion": "1.0.0.0",
              "parameters": {
                "machineName": { "type": "string" },
                "location": { "type": "string" }
              },
              "resources": [
                {
                  "type": "Microsoft.HybridCompute/machines/runCommands",
                  "apiVersion": "2024-07-10",
                  "name": "[concat(parameters('machineName'), '/ScheduleMdatpQuickScan')]",
                  "location": "[parameters('location')]",
                  "properties": {
                    "source": {
                      "script": "#!/bin/bash\nset -euo pipefail\nCRON_MARKER='# MDATP_WEEKLY_SCAN'\nMDATP_CMD='/usr/bin/mdatp'\nSCAN_TYPE='quick'\nif [[ $EUID -ne 0 ]]; then echo '[ERROR] Must run as root'; exit 1; fi\nif [[ ! -x \"$MDATP_CMD\" ]]; then echo '[ERROR] mdatp not found'; exit 1; fi\nHOUR=$(( RANDOM % 12 ))\nMINUTE=$(( RANDOM % 60 ))\nEXISTING=$(crontab -l 2>/dev/null || echo '')\nFILTERED=$(echo \"$EXISTING\" | grep -Fv \"$CRON_MARKER\" || true)\nENTRY=\"${MINUTE} ${HOUR} * * 0 ${MDATP_CMD} scan ${SCAN_TYPE} ${CRON_MARKER}\"\nif [[ -n \"$FILTERED\" ]]; then\n  printf '%s\\n%s\\n' \"$FILTERED\" \"$ENTRY\" | crontab -\nelse\n  echo \"$ENTRY\" | crontab -\nfi\nif ! crontab -l 2>/dev/null | grep -Fq \"$CRON_MARKER\"; then echo '[ERROR] Crontab entry not found after install'; exit 1; fi\necho \"[INFO] Scheduled: Sunday at $(printf '%02d:%02d' $HOUR $MINUTE)\""
                    },
                    "runAsUser": "root",
                    "timeoutInSeconds": 120
                  }
                }
              ],
              "outputs": {}
            },
            "parameters": {
              "machineName": { "value": "[field('name')]" },
              "location": { "value": "[field('location')]" }
            }
          }
        }
      }
    }
  }
}
```

Create the policy definition at the **management group** scope. This is the recommended best practice — it makes the definition available to assign at management group, subscription, or resource group level without needing to recreate it:

```powershell
az policy definition create `
  --name "schedule-mdatp-scan-arc-linux" `
  --display-name "Schedule MDATP Weekly Quick Scan on Arc Linux" `
  --description "Deploys a weekly MDATP quick scan cron job to Arc-connected Linux machines using Run Command." `
  --mode All `
  --rules mdatp-scan-policy-arc.json `
  --management-group "<management-group-id>"
```

**Note:** `mdatp-scan-policy-arc.json` contains only the `policyRule` object (the `if`/`then` block). The `--mode`, `--display-name`, and `--description` values are passed as separate CLI arguments.

### Step 2 — Assign the Policy

The definition was created at management group scope, so it can be assigned at any level beneath it. The example below shows management group scope (recommended) so the policy covers all subscriptions under the group. See the scope table below if you need to limit coverage to a subscription or resource group.

```powershell
# Get the policy definition ID from the management group
$PolicyId = az policy definition show `
  --name "schedule-mdatp-scan-arc-linux" `
  --management-group "<management-group-id>" `
  --query id --output tsv

# Assign at management group scope
# Note: --name must be 24 characters or fewer
az policy assignment create `
  --name "mdatp-scan-arc-linux" `
  --display-name "Assign: Schedule MDATP Quick Scan on Arc Linux" `
  --policy $PolicyId `
  --scope "/providers/Microsoft.Management/managementGroups/<management-group-id>" `
  --mi-system-assigned `
  --location "<location>" `
  --identity-scope "/providers/Microsoft.Management/managementGroups/<management-group-id>" `
  --role "Azure Connected Machine Resource Administrator"
```

To assign at a narrower scope, change `--scope` and `--identity-scope` to one of:

| Scope | Value |
|-------|-------|
| Management group | `/providers/Microsoft.Management/managementGroups/<management-group-id>` |
| Subscription | `/subscriptions/<subscription-id>` |
| Resource group | `/subscriptions/<subscription-id>/resourceGroups/<resource-group>` |

### Step 3 — Trigger Remediation

New non-compliant machines are remediated automatically, but you can also trigger an immediate remediation task.

The assignment was created at management group scope, so the remediation must also be retrieved and created at that scope — otherwise it will only target the subscription level.

```powershell
# Retrieve the assignment ID from management group scope
$AssignmentId = az policy assignment show `
  --name "mdatp-scan-arc-linux" `
  --scope "/providers/Microsoft.Management/managementGroups/<management-group-id>" `
  --query id --output tsv

# Create remediation at management group scope
# Note: ReEvaluateCompliance is only supported at subscription scope and below.
# Use ExistingNonCompliant at management group scope.
az policy remediation create `
  --name "remediate-mdatp-scan-arc-linux" `
  --policy-assignment $AssignmentId `
  --management-group "<management-group-id>" `
  --resource-discovery-mode ExistingNonCompliant
```

**Note:** If `--scope` in `az policy assignment show` does not match the scope the assignment was created at, the command will fail or return no results. Always use the same scope the assignment was created at.

### Step 4 — Check Compliance

Since the assignment was created at management group scope, compliance must also be queried at that scope:

```powershell
az policy state list `
  --management-group "<management-group-id>" `
  --filter "policyAssignmentName eq 'mdatp-scan-arc-linux'" `
  --query "[].{machine:resourceId, state:complianceState, reason:complianceReasonCode}" `
  --output table
```

---

## Method 3 — Azure Machine Configuration (Continuous Audit)

**Use this when** your environment requires continuous verification that the cron job is still present on every machine — not just at initial deployment. Method 2 only checks for the RunCommand resource artifact, not whether the cron entry still exists in the crontab. Method 3 evaluates the actual machine state on every policy cycle (~24 hours) and surfaces cron job removal as Non-compliant.

**This does not replace Method 2.** Method 3 is audit-only — it detects that the cron job is missing but does not redeploy it. Run both together: Method 3 detects drift, Method 2 remediates it when the RunCommand resource is deleted and re-triggered.

### Additional Prerequisites

- PowerShell 7.2+ on your local machine
- `GuestConfiguration` PowerShell module:
  ```powershell
  Install-Module GuestConfiguration -Force
  ```
- Azure Storage Account to host the configuration package (the policy managed identity needs `Storage Blob Data Reader` on the container)
- `AzurePolicyforLinux` extension deployed on each Arc machine (the Machine Configuration agent)

### Step 1 — Deploy the Machine Configuration Agent

Each Arc machine requires the `AzurePolicyforLinux` extension. Check for it in the portal:

> **Azure Arc** → **Servers** → *select machine* → **Extensions**

Deploy to all machines in a resource group via CLI:

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

### Step 2 — Author the InSpec Profile

Create the following directory and files locally:

```
MdatpWeeklyScan/
  inspec.yml
  controls/
    mdatp_cron.rb
```

**`inspec.yml`**
```yaml
name: MdatpWeeklyScan
title: MDATP Weekly Scan Cron Job
maintainer: Your Name
summary: Verifies the MDATP weekly quick scan cron entry exists in the root crontab
version: 1.0.0
supports:
  - os-family: linux
```

**`controls/mdatp_cron.rb`**
```ruby
title 'MDATP Weekly Scan - Root Crontab'

describe command('crontab -l -u root 2>/dev/null || true') do
  its('stdout') { should match(/\/usr\/bin\/mdatp scan quick.*MDATP_WEEKLY_SCAN/) }
end
```

### Step 3 — Build and Publish the Package

```powershell
# Build the Machine Configuration audit package from the InSpec profile
New-GuestConfigurationPackage `
  -Name 'MdatpWeeklyScan' `
  -Configuration './MdatpWeeklyScan' `
  -Type Audit `
  -Force

# Upload to Azure Storage
$StorageAccount = "<storage-account-name>"
$Container = "guestconfig"

az storage blob upload `
  --account-name $StorageAccount `
  --container-name $Container `
  --name "MdatpWeeklyScan.zip" `
  --file "./MdatpWeeklyScan/MdatpWeeklyScan.zip" `
  --overwrite

# Get the content hash (required by the policy)
$PackageHash = (Get-FileHash "./MdatpWeeklyScan/MdatpWeeklyScan.zip" -Algorithm SHA256).Hash.ToLower()

# Get the blob URI
$PackageUri = az storage blob url `
  --account-name $StorageAccount `
  --container-name $Container `
  --name "MdatpWeeklyScan.zip" `
  --output tsv
```

### Step 4 — Create and Assign the Policy

Use `New-GuestConfigurationPolicy` to generate the policy definition JSON from the published package, then deploy it:

```powershell
# Generate the policy definition files
New-GuestConfigurationPolicy `
  -ContentUri $PackageUri `
  -ContentHash $PackageHash `
  -DisplayName "Audit: MDATP Weekly Scan Cron Job on Arc Linux" `
  -Description "Audits that the MDATP weekly quick scan cron entry exists in the root crontab of Arc-connected Linux machines." `
  -PolicyId (New-Guid).Guid `
  -PolicyVersion "1.0.0" `
  -Path "./MdatpWeeklyScanPolicy" `
  -Platform Linux `
  -Mode Audit

# Create the policy definition at management group scope
az policy definition create `
  --name "audit-mdatp-scan-cron-arc-linux" `
  --display-name "Audit: MDATP Weekly Scan Cron on Arc Linux" `
  --description "Audits that the MDATP weekly quick scan cron entry exists in root crontab." `
  --mode Indexed `
  --rules "@./MdatpWeeklyScanPolicy/audit-mdatp-scan-cron-arc-linux.json" `
  --management-group "<management-group-id>"

# Get the definition ID
$AuditPolicyId = az policy definition show `
  --name "audit-mdatp-scan-cron-arc-linux" `
  --management-group "<management-group-id>" `
  --query id --output tsv

# Assign at management group scope
az policy assignment create `
  --name "audit-mdatp-cron" `
  --display-name "Audit: MDATP Weekly Scan Cron on Arc Linux" `
  --policy $AuditPolicyId `
  --scope "/providers/Microsoft.Management/managementGroups/<management-group-id>" `
  --mi-system-assigned `
  --location "<location>"
```

**Note:** `New-GuestConfigurationPolicy` generates the policy rule JSON in the output path. The filename will match the policy display name. Adjust the `--rules` path if the generated filename differs.

### Step 5 — Check Compliance

```powershell
az policy state list `
  --management-group "<management-group-id>" `
  --filter "policyAssignmentName eq 'audit-mdatp-cron'" `
  --query "[].{machine:resourceId, state:complianceState, reason:complianceReasonCode}" `
  --output table
```

A machine reporting **Non-compliant** here means the cron job is not present in the root crontab — trigger a Method 2 remediation after deleting the existing `ScheduleMdatpQuickScan` RunCommand resource from the machine to force redeployment.

> **Reference:** [Azure Machine Configuration — authoring packages](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/machine-configuration-create)

---

## Combined Deployment Strategy (Recommended)

Azure Policy (Method 2) is the primary solution. Once assigned, it automatically evaluates and remediates any new Arc-onboarded Linux machine going forward with no further action needed. However, **machines that were already enrolled at the time of assignment are not automatically remediated** — they require a manual remediation task to catch up.

Add Method 3 (Machine Configuration audit) if your environment requires continuous detection of cron job removal. Without it, a machine stays Compliant even if the cron job is manually deleted after initial deployment.

### Auto-remediation behavior

| Machine state | Remediated automatically? |
|---|---|
| Onboarded to Arc **after** policy assignment | Yes — evaluated and remediated automatically |
| Onboarded to Arc **before** policy assignment | No — requires a manual remediation task |

### Deployment steps

| Step | Action | Notes |
|------|--------|-------|
| 1 | Create policy definition at **management group** scope | `az policy definition create --management-group` |
| 2 | Assign policy at **management group** scope | `az policy assignment create` |
| 3 | Wait ~30 minutes for initial compliance evaluation to complete | Check with `az policy state list` — machines should appear as Non-compliant |
| 4 | Trigger remediation task for existing non-compliant machines | `az policy remediation create --resource-discovery-mode ExistingNonCompliant` |
| 5 | If remediation returns **0 out of 0**, evaluation hasn't completed yet — wait and re-trigger | Re-run Step 4 with a new `--name` value |
| 6 | Verify cron job on each machine | `sudo crontab -l \| grep MDATP_WEEKLY_SCAN` |
| 7 | *(Optional)* Deploy Method 3 Machine Configuration audit policy | Enables continuous detection if cron job is removed post-deployment |
| 8 | Monitor compliance over time | `az policy state list` for both assignments |

**Note:** Remediation task names must be unique within the scope. If you need to re-trigger (Step 5), increment the name — e.g. `remediate-mdatp-scan-arc-linux-2`.

---

## Validate the Cron Job on a Linux Device

After deploying via Run Command or Policy remediation, connect to the Linux machine and run the following commands to confirm the cron job was created successfully.

### Check the Root Crontab

The script installs the cron entry under the **root** user's crontab:

```bash
sudo crontab -l
```

Expected output will include a line containing the `# MDATP_WEEKLY_SCAN` marker, similar to:

```
47 3 * * 0 /usr/bin/mdatp scan quick # MDATP_WEEKLY_SCAN
```

The hour and minute will vary since the script generates a random time.

### Confirm Only One Entry Exists

```bash
sudo crontab -l | grep "MDATP_WEEKLY_SCAN"
```

This should return exactly one line. If it returns more than one, the idempotency marker was not matched correctly — re-run the script to reset to a clean state.

### Verify mdatp Is Installed and Running

```bash
mdatp health
```

Key fields to check:

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

### Validate via Arc Run Command (Remote)

To check the crontab remotely from Azure without logging into the machine:

```powershell
az connectedmachine run-command create `
  --resource-group "<resource-group>" `
  --machine-name "<arc-machine-name>" `
  --run-command-name "ValidateMdatpCron" `
  --script "sudo crontab -l | grep MDATP_WEEKLY_SCAN" `
  --location "<location>"

# Check the result
az connectedmachine run-command show `
  --resource-group "<resource-group>" `
  --machine-name "<arc-machine-name>" `
  --run-command-name "ValidateMdatpCron" `
  --query "{status:instanceView.executionState, output:instanceView.output, error:instanceView.error}"
```

If `output` contains the cron entry and `status` is `Succeeded`, the cron job is in place.

---

## Updating the Scan Schedule

Because the script uses an idempotent marker (`# MDATP_WEEKLY_SCAN`), re-deploying simply overwrites the existing cron entry. No manual cleanup is required on the devices.

To push an updated schedule:
1. Modify [`schedule_mdatp_scan.sh`](./schedule_mdatp_scan.sh) if needed
2. Re-run the Arc Run Command deployment against all machines
3. If using Policy, update the inline script in the policy definition and re-assign

---

## References

- [Schedule antivirus scans with crontab – Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/schedule-antivirus-scan-crontab)
- [Azure Arc-enabled servers – Run Command](https://learn.microsoft.com/en-us/azure/azure-arc/servers/run-command)
- [Azure Policy DeployIfNotExists effect](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effects#deployifnotexists)
- [Azure Machine Configuration overview](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/overview)
- [Azure Machine Configuration – authoring packages](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/machine-configuration-create)
- [Azure Machine Configuration – Arc-connected servers](https://learn.microsoft.com/en-us/azure/governance/machine-configuration/machine-configuration-policy-effects)
- [Azure Government – available services](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-services)
