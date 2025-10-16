<~XSIAM>

# Radware Cloud DDoS Protection Service

## Overview

Radware Cloud DDoS Protection Service provides a robust, multi-layered defense using advanced behavioral algorithms for swift detection and mitigation of volumetric and sophisticated application-layer DDoS threats.  
The service is delivered globally via a high-capacity scrubbing network, offering flexible deployment models including Always-On, On-Demand, and Hybrid to align with diverse organizational security requirements.

## This Pack Includes

### Data Normalization and Querying Capabilities

* Data modeling rules to normalize Radware Cloud DDoS Protection Service logs that are ingested via _RadwareCloudDDoSProtectionServices_ integration to Cortex XSIAM.
* Querying ingested logs in XQL Search using the _radware_cloud_ddos_raw_ dataset.

## Supported Log Categories

* Security Events
* Operational Alerts

***

## Enable Data Collection

### Configure Radware Cloud DDoS Protection Service

1. Navigate to **Accounts** -> **API Keys**.
2. Click on the _+_ icon to create a new API Key.
3. Fill out the form in the pane.
4. Click **Save**. The _Add New API Key dialog will appear_.
5. Copy the API Key that appears in the window.
6. Click Confirm to complete the creation of the new API key.

Note:  
For more information, search Cloud Services API USER GUIDE document [here](https://support.radware.com/).

### Configure Cortex XSIAM

To fetch events from Radware Cloud DDoS Protection Service, see the integration configuration details [here](https://xsoar.pan.dev/docs/reference/integrations/radware-cloud-d-do-s-protection-services).  

1. Navigate to **Settings** -> **Data Sources**.
2. On the top right corner, click on **+ Add Data Source**.
3. Search for _Radware Cloud DDoS Protection Service_ and click on the _Connect_ button.
4. Insert the **Server URL**, Default value is _https://api.radwarecloud.app_.
5. Insert the **Account ID**.
6. Insert the **API Key**.
7. Under _Collect_, select _Fetch events_ checkbox and choose event types from the drop down menu.

</~XSIAM>
