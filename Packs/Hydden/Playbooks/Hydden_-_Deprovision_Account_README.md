# Hydden - Deprovision Account

![Hydden - Deprovision Account](../doc_files/Hydden_-_Deprovision_Account.png)

Runs when a Cortex issue indicates a compromised or otherwise high-risk account. Takes the account name or email from the alert and calls `hydden-deprovision-account`.

Requires a **Hydden Control** integration instance.

## What it does

1. Reads the account name or email from `${alert.username}`.
2. Coerces that value to a single identifier with Unique and atIndex, then stages it under `Hydden.Input.AccountId`.
3. If **RequireApproval** is `True` (the default), waits for an analyst to confirm on the *Confirm deprovision* task.
4. Calls `hydden-deprovision-account` with the identifier as `account_id`. The command looks up a Hydden UUID via `GET /accounts/lookup` and, if that returns exactly one UUID, calls `POST /account-actions/deprovision`. No matches or more than one match fails the task.
5. Writes `Hydden.Identity.deprovisioned` (`true` on success). If Hydden returns an error, the playbook fails.

This command is potentially harmful. Point an automation rule at this playbook only for issues you intend to deprovision. Leave **RequireApproval** at `True` unless the automation is already gated elsewhere.

## Inputs

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| AccountId | Cortex account name or email from the alert (defaults to `${alert.username}`). | Required |
| RequireApproval | When `True`, wait for an analyst to confirm before deprovisioning. Default `True`. | Optional |

## Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Hydden.Identity.deprovisioned | Whether deprovisioning succeeded. | Boolean |
