# Hydden - Deprovision Account

![Hydden - Deprovision Account](../doc_files/Hydden_-_Deprovision_Account.png)

Runs when a Cortex issue indicates a compromised or otherwise high-risk account. Takes the account ID from the issue and calls `hydden-deprovision-account`.

Requires a **Hydden Control** integration instance.

## What it does

1. Reads the account identifier from `${xdm.target.user.identifier}`, then `incident.username` if that field is empty.
2. Stages that value under `Hydden.Input.AccountId`.
3. Calls `hydden-deprovision-account` with it as `account_id` (`POST /account-actions/deprovision?ref=`).
4. Writes `Hydden.Identity.deprovisioned` (`true` on success). If Hydden returns an error, the playbook fails.

This command is potentially harmful. Point an automation rule at this playbook only for issues you intend to deprovision.

## Inputs

 | **Name** | **Description** | **Required** |
 | --- | --- | --- |
 | AccountId | Cortex account identifier from the issue (defaults to `${xdm.target.user.identifier}`). | Required |
 | AccountIdFallback | Incident username if the alert fields are empty. | Optional |

## Outputs

 | **Path** | **Description** | **Type** |
 | --- | --- | --- |
 | Hydden.Identity.deprovisioned | Whether deprovisioning succeeded. | Boolean |
