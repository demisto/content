
![Logo](./doc_files/icon.png)
# Hydden

Places the Hydden identity fabric system of record underneath Cortex XSIAM Identity Analytics and enables Hydden Control actions as manual or automated responses.

Other identity packs tell you what one product saw. This pack tells the analyst who the account actually is.

## What this pack does

- **Hydden Control** integration: return an account's blast radius information; optionally deprovision the account.
- **Hydden Mesh modeling rule**: maps `hydden_mesh_raw` events into Cortex XDM (actor, target, auth, alert, observer).
- **Hydden Identity System of Record** dashboard: XQL widgets on `hydden_mesh_raw` (new accounts, top events/actions/actors/targets).
- **Playbooks** for Identity Analytics issues: blast radius enrichment and account deprovision.

## Configure Hydden Control on Cortex XSIAM

1. Navigate to **Settings** > **Data Sources & Integrations**.
2. Search for Hydden Control.
3. Click **Add instance** to create and configure a new integration instance.

 | **Parameter** | **Description** | **Required** |
 | --- | --- | --- |
 | Hydden API URL | Public API root, for example `https://control.hydden.ai/api/public/v1`. | True |
 | Client ID / Client Secret | Credentials for a Hydden API user with `rest_api` access. | True |
 | HTTP request timeout (seconds) | Optional. Default 300. | False |
 | Trust any certificate (not secure) | Optional. | False |
 | Use system proxy settings | Optional. | False |

4. Click **Test**, then **Save & Exit**. Leave the instance enabled.

`hydden-deprovision-account` is marked potentially harmful.

## Modeling rules

**Hydden Mesh Modeling Rule** maps Mesh events in `hydden_mesh_raw` to XDM. Nested Mesh fields are read from the `mesh` JSON column; flat columns (`event_type`, `actor_*`, `target_*`, `outcome`, and so on) are used when present.

After install, confirm the rule is enabled under **Settings** → **Data Management** → **Data Model**. `datamodel dataset = hydden_mesh_raw` queries stay empty until Mesh events land.

## Dashboard

After install, open **Hydden Identity System of Record** from **Dashboards & Reports** → **Dashboards** (or **Dashboard Manager**). Widgets query `hydden_mesh_raw` and stay empty until Hydden Mesh events land.

## Playbooks

| **Cortex detection** | **Playbook ID** |
| --- | --- |
| Identity Analytics | Hydden - Blast Radius |
| Compromised or high-risk account | Hydden - Deprovision Account |

Both playbooks take the account identifier from the issue (`alert.user_name`, then `alert.username`, then `incident.username`) and pass it to one Hydden Control command. XDR Analytics identity issues populate `user_name`.

## Dependencies

Identity Analytics must be enabled: Cloud Identity Engine + Cortex Analytics, then **Settings** → **Configurations** → **Cortex XSIAM - Analytics** → **Enable Identity Analytics**.
