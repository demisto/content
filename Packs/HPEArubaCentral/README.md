<~XSIAM>

# HPE Aruba Central

## Overview

Aruba Central provides a centralized platform for the management and monitoring of network infrastructure.  
It includes comprehensive event collection and audit log management capabilities, allowing you to maintain detailed records of network changes, user activities, and security events.

## This Pack Includes

### Data Normalization and Querying Capabilities

* Data modeling rules to normalize Aruba Central logs that are ingested via the _HPEArubaCentralEventCollector_ integration into Cortex XSIAM.
* Querying ingested logs in XQL Search using the _aruba_central_raw_ dataset.

## Supported Log Category

* Audit
* Network

***

## Enable Data Collection

### Configure HPE Aruba Central

The pack includes the **HPE Aruba Central Event Collector** integration that allows you to fetch networking events and audit logs from Aruba Central.

#### How to generate Client ID and Client Secret

1. Go to the Aruba Central portal and navigate to Accounts Home > Global Settings > API Gateway.

    * Admin users: Navigate to System Apps & Tokens.
    * Non-admin users: Navigate to My Apps & Tokens.

2. Click **+ Add Apps & Tokens**.
3. Fill in the required details and click _Generate_.
4. Once created, the new credentials can be viewed in the My Apps & Tokens tab.  
For more details on how to create Application & Token click [here](https://developer.arubanetworks.com/central/docs/api-gateway-creating-application-token)

#### Product Documentation

* [Audit Logs](https://developer.arubanetworks.com/central/reference/apiget_audits)
* [Networking Logs](https://developer.arubanetworks.com/central/reference/apiexternal_controllerget_events_v2)
* [Obtaining Access Token via OAuth API](https://developer.arubanetworks.com/central/docs/api-oauth-access-token#obtaining-access-token-via-oauth-api)

### Configure Cortex XSIAM

1. Navigate to **Settings** -> **Data Sources**.
2. On the top right corner, click **+ Add Data Source**.
3. Search for HPE Aruba Central and click _Connect_.
4. Under _Connect_, insert the name for the instance.
5. Insert the **Server URL**.
6. Insert the **Client ID**.
7. Insert the **Client Secret**.
8. Insert the **Customer ID**.
9. Insert the **Username**.
10. Insert the **Password**.
11. Under _Collect_, select _Fetch events_ checkbox.
    11.1 Optional - under _Collect_, select _Fetch networking events_ checkbox.
12. Define Events Fetch Interval.
13. Click **Connect**.

For more information go to [Aruba Central Documentation](https://developer.arubanetworks.com/hpe-aruba-networking-central/docs/central-about)
</~XSIAM>
