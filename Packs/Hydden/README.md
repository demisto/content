
![Logo](./doc_files/icon.png)
# Hydden

Places the Hydden identity fabric system of record underneath Cortex XSIAM Identity Analytics and enables Hydden Control actions as manual or automated responses.

Other identity packs tell you what one product saw. This pack tells the analyst who the account actually is.

## What this pack does

- **Hydden Control** integration: return an account's blast radius information; optionally deprovision the account.
- **Hydden Mesh modeling rule**: maps `hydden_mesh_raw` events into Cortex XDM (actor, target, auth, alert, observer).
- **Hydden Identity System of Record** dashboard: XQL widgets on `hydden_mesh_raw` (new accounts, top events/actions/actors/targets).
- **Playbooks** for Identity Analytics issues: blast radius enrichment and account deprovision.

## Configure Hydden Control

1. Install the pack.
2. **Settings → Data Sources & Integrations** → **Hydden Control** → **Add Instance**.
3. Set **Hydden API URL** to `https://control.hydden.ai/api/public/v1` and paste the **Client ID** and **Client Secret**.
4. **Test**, then **Save & Exit**. Leave the instance enabled.

The API user needs REST API access. `hydden-deprovision-account` is marked potentially harmful.

## Modeling rules

**Hydden Mesh Modeling Rule** maps Mesh events in `hydden_mesh_raw` to XDM. Nested Mesh fields are read from the `mesh` JSON column; flat columns (`event_type`, `actor_*`, `target_*`, `outcome`, and so on) are used when present.

After install, confirm the rule is enabled under **Settings → Data Management → Data Model**. `datamodel dataset = hydden_mesh_raw` queries stay empty until Mesh events land.

## Dashboard

After install, open **Hydden Identity System of Record** from **Dashboards & Reports → Dashboards** (or **Dashboard Manager**). Widgets query `hydden_mesh_raw` and stay empty until Hydden Mesh events land.

## Playbooks

| Cortex detection | Playbook ID |
| --- | --- |
| Identity Analytics | Hydden - Blast Radius |
| Compromised or high-risk account | Hydden - Deprovision Account |

Both playbooks take the account ID from the issue (`alert.username`, then `incident.username`) and pass it to one Hydden Control command.

## Dependencies

Identity Analytics must be enabled: Cloud Identity Engine + Cortex Analytics, then **Settings → Configurations → Cortex XSIAM - Analytics → Enable Identity Analytics**.
