<~XSIAM>

## Overview

Okta Advanced Server Access provides Zero Trust identity and access management for cloud and on-premises infrastructure.
Using Okta as its source of truth, Advanced Server Access reconciles accounts to manage SSH and RDP access to Linux and Windows servers.

Advanced Server Access extends secure privileged access to users, automates lifecycle management for server accounts, and eliminates the need for credential management.

## This pack includes

Data normalization capabilities:

* Okta ASA audit logs that are ingested via the integration into Cortex XSIAM.
* The ingested Okta ASA logs can be queried in XQL Search using the *`okta_asa_raw`* dataset.
* Timestamp parsing support assumes a UTC +0000 format is used.

## Supported log categories

| Category          | Category Display Name                   |
|:------------------|:----------------------------------------|
| Credential Issue  | user_creds.issue, gateway_creds.issue, auth_token.issue |
| User Management   | user.`x`                                |
| Server Management | server.`x`                              |

***

## Data Collection

### Okta ASA side

In Okta ASA, create a service user and an API key.

1. From the **Advanced Server Access** dashboard, click **Users**.
2. Select the **Service Users** tab.
3. Click **Create Service User**.
4. In the **Create Service User** page, enter a username for the service user. Okta ASA automatically creates corresponding Linux and Windows usernames.
5. Click **Create Service User** to finish creating the service user.
6. Click **Create API Key**.
7. From the **API Secret Rotated** page, copy your API key ID and your API key secret and store them.

Note: You cannot retrieve this information after closing the window. If you lose this information, you must generate a new API ID and key.

For more information, see [here](https://developer.okta.com/docs/api/openapi/asa/).

### Cortex XSIAM side - Integration

To access the Okta ASA integration on your Cortex XSIAM tenant:

1. In the navigation pane, click **Settings** and then click **Data Sources**.
2. At the top-right corner, click **Add Data Source**.
3. Search for **Okta ASA** and click **Connect**.
4. Set the following values:

| **Parameter**                                 | **Description**                                        | **Required**  |
|-----------------------------------------------|--------------------------------------------------------|---------------|
| Server URL (e.g. https://app.scaleft.com)     |                                                        | True          |
| API Key ID                                    | The API key ID to use for connection.                  | True          |
| API Key Secret                                | The API key secret to use for connection.              | True          |
| Team Name                                     | A named group of users who can authenticate with Okta. | True          |
| The maximum number of audit events per fetch. |                                                        | False         |
| Trust any certificate (not secure)            |                                                        | False         |
| Use system proxy settings                     |                                                        | False         |

</~XSIAM>
