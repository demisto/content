## Proofpoint Cloud Threat Response

Use this integration to fetch incidents from Proofpoint Cloud Threat Response (CTR) into Cortex XSOAR and to retrieve incident details on-demand.

### Prerequisites

Before configuring the integration, verify you have the following:

- **Proofpoint API credentials**: A valid **Client ID** and **Client Secret** generated from your Proofpoint Threat Response account. These credentials are used to obtain a Bearer token from `https://auth.proofpoint.com/v1/token` using the OAuth2 `client_credentials` grant.
- **API root URL**: The endpoint for your Proofpoint Cloud Threat Response instance. The default is `https://threatprotection-api.proofpoint.com`.

For details on generating API credentials, see [API Key Management](https://help.proofpoint.com/Admin_Portal/Settings/API_Key_Management).

### Permissions

The API credential (Client ID / Client Secret) is entitled **per module** in the Proofpoint Admin Portal (API Key Management). A token that works for one module can return `403 - No permission to perform this action.` on another. The commands in this integration fall into two separately-entitled modules — the key must be granted access to **each** module whose commands you intend to use.

| Module | Requirement | Commands |
| --- | --- | --- |
| **Cloud Threat Response (CTR) API** | Key entitled for the CTR APIs on the target cluster. | `proofpoint-ctr-incidents-list`, `proofpoint-ctr-incident-get`, `proofpoint-ctr-workflows-list`, `proofpoint-ctr-run-workflow`, `proofpoint-ctr-message-list`, `proofpoint-ctr-incident-upload-message`, `proofpoint-ctr-message-download` |
| **PPS Email Protection — Org Safe/Block List** | Separately entitled. Requires PPS release **8.20.X or greater** with cloud-based configuration management enabled. | `proofpoint-ctr-safelist-list`, `proofpoint-ctr-safelist-add-entry`, `proofpoint-ctr-safelist-remove-entry`, `proofpoint-ctr-blocklist-list`, `proofpoint-ctr-blocklist-add-entry`, `proofpoint-ctr-blocklist-remove-entry` |

The exact scope/permission names are configured in the Admin Portal's API Key Management page and are not exposed via the API. A `403` on a given endpoint means the key lacks entitlement for that module.

**Notes:**

- **`proofpoint-ctr-run-workflow`**: Only workflows listed in the **Manual Workflows** tab under **Responses -> Automation Workflows** can be triggered.
- **`proofpoint-ctr-message-download`**: Currently functional only for CTR instances hosted in the **US region**.