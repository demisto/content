Sends a HTML email, using a template stored as a list item under **Lists (Settings -> Advanced -> Lists)**.
Placeholders are marked in DT format. For example, `${incident.id}` for the incident ID.

Examples of available placeholders:
- ${incident.labels.Email/from}
- ${incident.name}
- ${object.value}
See incident Context Data menu for available placeholders

Note: Sending emails requires an active `Mail Sender` integration instance.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | email, communication |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| listTemplate | The list where the template is stored. |
| key | The context key to store the HTML body. |
| object | The values object provided as stringified JSON. |
| removeNotFound | Whether to replace a path not found, if true, with an empty string, otherwise to leave it as is. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| htmlBody | The HTML body. | Unknown |
