
![Logo](./../../doc_files/icon.png)
# Hydden Control

Calculate account blast radius and deprovision accounts from Cortex XSIAM using Hydden Control's identity fabric system of record.

## Configure Hydden Control in Cortex

| Parameter | Description |
| --- | --- |
| Hydden API URL | Public API root, for example `https://control.hydden.ai/api/public/v1` |
| Client ID | Client ID for the Hydden REST API |
| Client Secret | Client secret for the Hydden REST API |
| HTTP request timeout (seconds) | Optional, default `300`. A cold `blast-radius` call builds the tenant reachability graph and has been measured at over 3 minutes; later calls are sub-second. The Cortex default of 60s is not enough for a cold call |

## Commands

### hydden-blast-radius

Return the account's blast radius information as a string. Calls `GET /blast-radius?ref=<account_id>&type=<type>`.

#### Base Command

`hydden-blast-radius`

#### Input

| Argument Name | Description | Required |
| --- | --- | --- |
| account_id | Cortex Account ID. Sent as the `ref` query parameter | Required |
| type | Subject the ref names: `account` (default) or `group` | Optional |

#### Context Output

| Path | Type | Description |
| --- | --- | --- |
| Hydden.Identity.blast_radius | String | The subject's blast radius score, as a string |
| Hydden.Identity.score | Number | The reach score for the subject |
| Hydden.Identity.reachable_resources | Number | Resources the subject can reach |
| Hydden.Identity.tenant_resources | Number | Total tenant resources (denominator for share_of_tenant) |
| Hydden.Identity.share_of_tenant | Number | Fraction of tenant resources reached |
| Hydden.Identity.denied_resources | Number | Reachable by grant but blocked by a deny rule |
| Hydden.Identity.subject_ref | String | The ref the score was computed for |
| Hydden.Identity.subject_type | String | The subject type scored |
| Hydden.Identity.computed_at | Date | When the score was computed |

### hydden-deprovision-account

Deprovision an account across the fabric including disabling the account and removing the account from group and role memberships. Calls `POST /account-actions/deprovision?account_id=<account_id>`. This command is potentially harmful.

#### Base Command

`hydden-deprovision-account`

#### Input

| Argument Name | Description | Required |
| --- | --- | --- |
| account_id | Cortex Account ID | Required |

#### Context Output

| Path | Type | Description |
| --- | --- | --- |
| Hydden.Identity.deprovisioned | Boolean | Whether deprovisioning succeeded |
