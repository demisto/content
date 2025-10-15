<~XSIAM>

## Overview

Okta Advanced Server Access provides Zero Trust identity and access management for cloud and on-premises infrastructure.
Using Okta as its source of truth, Advanced Server Access reconciles accounts to manage SSH and RDP access to Linux and Windows servers.

Advanced Server Access extends secure privileged access to users, automates lifecycle management for server accounts, and eliminates the need for credential management.

## This pack includes

Data normalization capabilities:

* Okta ASA audit logs that are ingested via the native collector into Cortex XSIAM.
* The ingested Okta ASA logs can be queried in XQL Search using the *`okta_asa_raw`* dataset.
* Timestamp parsing support is under the assumption that a UTC +0000 format is being used.

***

## Data Collection

### Okta ASA side

#### Create a service user and an API key

1. From the Advanced Server Access dashboard, click **Users**.
2. Select the **Service Users** tab.
3. Click **Create Service User**. The Create Service User page appears.
4. Enter a username for the service user. The system automatically creates corresponding Linux and Windows usernames.
5. Click **Create Service User** to finish creating the service user.
6. Click **Create API Key**. The API Key Secret Rotated page appears.
7. Copy and store your API key ID and your API key secret from this page.

Note: You cannot retrieve this information after closing the window. If you lose this information, you must generate a new API ID and key.

For more information, see [here](https://developer.okta.com/docs/api/openapi/asa/).

### Cortex XSIAM side - Native collector

To access the Okta ASA native collector on your Cortex XSIAM tenant:

1. In the navigation pane, click **Settings** and click **Data Sources**.
2. At the top-right corner, click **Add Data Source**.
3. Search for **Okta ASA** and click **Connect**.
4. Set the following values:

| **Parameter**                             | **Description**                                        | **Required** |
|-------------------------------------------|--------------------------------------------------------| --- |
| Server URL (e.g. https://app.scaleft.com) |                                                        | True |
| API Key ID                                | The API Key ID to use for connection.                  | True |
| API Key Secret                            | The API Key Secret to use for connection.              | True |
| Team Name                                 | A named group of users who can authenticate with Okta. | True |
| The maximum number of audit events per fetch. |                                                        | False |
| Trust any certificate (not secure)        |                                                        | False |
| Use system proxy settings                 |                                                        | False |

</~XSIAM>
