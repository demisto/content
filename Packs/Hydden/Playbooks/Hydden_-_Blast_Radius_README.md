# Hydden - Blast Radius

![Hydden - Blast Radius](../doc_files/Hydden_-_Blast_Radius.png)

Runs when a Cortex issue flags an account. Takes the account name or email from the alert and calls `hydden-blast-radius`.

Requires a **Hydden Control** integration instance.

## What it does

1. Reads the account name or email from `${alert.username}`.
2. Coerces that value to a single identifier with Unique and atIndex, then stages it under `Hydden.Input.AccountId`.
3. Calls `hydden-blast-radius` with it as `account_id`. The command looks up a Hydden UUID via `GET /accounts/lookup` and, if that returns exactly one UUID, calls `GET /blast-radius`. No matches or more than one match fails the task.
4. Writes `Hydden.Identity.blast_radius` (string) plus the remaining blast-radius fields (`score`, `reachable_resources`, `tenant_resources`, `share_of_tenant`, `denied_resources`, `subject_ref`, `subject_type`, `computed_at`). If Hydden returns an error, the playbook fails.

To run the playbook manually with an account identifier you choose, open it in the **Playbook Debugger**, open the *Get blast radius from Hydden* task, hover the `account_id` input, click **Override Input**, and enter the value. Running the playbook from **Run Automation** on a live issue does not accept input overrides.

## Inputs

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| AccountId | Cortex account name or email from the alert (defaults to `${alert.username}`). | Required |

## Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Hydden.Identity.blast_radius | The subject's blast radius score, as a string. | String |
| Hydden.Identity.score | The reach score for the subject. | Number |
| Hydden.Identity.reachable_resources | The number of resources the subject can reach. | Number |
| Hydden.Identity.tenant_resources | The total resources in the tenant. | Number |
| Hydden.Identity.share_of_tenant | The fraction of tenant resources the subject reaches. | Number |
| Hydden.Identity.denied_resources | Resources reachable by grant but blocked by a deny rule. | Number |
| Hydden.Identity.subject_ref | The ref the score was computed for. | String |
| Hydden.Identity.subject_type | The subject type the score was computed for. | String |
| Hydden.Identity.computed_at | When the score was computed. | Date |
