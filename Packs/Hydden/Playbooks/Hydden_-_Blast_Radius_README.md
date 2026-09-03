# Hydden - Blast Radius

![Hydden - Blast Radius](../doc_files/Hydden_-_Blast_Radius.png)

Runs when a Cortex issue flags an account. Takes the account ID from the issue and calls `hydden-blast-radius`.

Requires a **Hydden Control** integration instance.

## What it does

1. Reads the account identifier from `alert.user_name`, then `alert.username`, then `incident.username` if the earlier fields are empty. XDR Analytics identity issues populate `user_name`.
2. Stages that value under `Hydden.Input.AccountId`.
3. Calls `hydden-blast-radius` with it as `account_id`.
4. Writes `Hydden.Identity.blast_radius` (string) and the rest of the Hydden blast-radius payload. If Hydden returns an error, the playbook fails.

To run the playbook manually with an account identifier you choose, open it in the **Playbook Debugger**, open the *Get blast radius from Hydden* task, hover the `account_id` input, click **Override Input**, and enter the value. Running the playbook from **Run Automation** on a live issue does not accept input overrides.

## Inputs

 | **Name** | **Description** | **Required** |
 | --- | --- | --- |
 | AccountId | Cortex account identifier from the issue (defaults to `alert.user_name`, then `alert.username`). | Required |
 | AccountIdFallback | Incident username if the alert fields are empty. | Optional |

## Outputs

 | **Path** | **Description** | **Type** |
 | --- | --- | --- |
 | Hydden.Identity.blast_radius | Blast radius score from Hydden Control, as a string. | String |
