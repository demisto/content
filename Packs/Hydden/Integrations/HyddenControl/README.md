
![Logo](./../../doc_files/icon.png)
# Hydden Control

Calculate account blast radius and deprovision accounts from Cortex XSIAM using Hydden Control's identity fabric system of record.

## Configure Hydden Control in Cortex

| Parameter | Description |
| --- | --- |
| Hydden API URL | Public API root, for example `https://control.hydden.ai/api/public/v1` |
| Client ID | Client ID for the Hydden REST API |
| Client Secret | Client secret for the Hydden REST API |

## Commands

### hydden-blast-radius

Return the account's blast radius information as a string. Calls `GET /blast-radius?account_id=<account_id>`.

#### Base Command

`hydden-blast-radius`

#### Input

| Argument Name | Description | Required |
| --- | --- | --- |
| account_id | Cortex Account ID | Required |

#### Context Output

| Path | Type | Description |
| --- | --- | --- |
| Hydden.Identity.blast_radius | String | Blast radius information |

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
