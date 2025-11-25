<~XSIAM>

# Saviynt Enterprise Identity Cloud (EIC)

## Overview

Saviynt Enterprise Identity Cloud (EIC) is an AI-driven, cloud-native identity security platform that unifies Identity Governance and Administration (IGA).  
It manages and secures all user and non-human access across hybrid IT environments to help organizations reduce risk and meet compliance mandates.

## This Pack Includes

### Data Normalization and Querying Capabilities

* Data modeling rules to normalize Saviynt Enterprise Identity Cloud logs that are ingested via _SaviyntEICEventCollector_ integration to Cortex XSIAM.
* Querying ingested logs in XQL Search using the _saviynt_eic_raw_ dataset.

## Supported Log Category

* Audit

***

## Enable Data Collection

### Configure Saviynt Enterprise Identity Cloud

To fetch audit logs from Saviynt Enterprise Identity Cloud (EIC), you must first create an Analytics Record within Saviynt and set up a dedicated user with appropriate permissions.  

For more detailed instructions, click [here](https://docs.saviyntcloud.com/bundle/EIC-Admin-25/page/Content/Chapter20-EIC-Integrations/Saviynt-SIEM-Integration.htm).

Note:  
The Saviynt API requires a username and password to obtain an authorization token before logs can be fetched.  
username: Specify the user name to log in to Saviynt Identity Cloud.  
password: Specify the password to log in to Saviynt Identity Cloud.

### Configure Cortex XSIAM

1. Navigate to **Settings** -> **Data Sources**.
2. On the top right corner, click **+ Add Data Source**.
3. Search for Saviynt Enterprise Identity Cloud and click _Connect_.
4. Under _Connect_, insert the name for the instance.
5. Insert the **Server URL**.
6. Insert the **Username**.
7. Insert the **Password**.
8. Under _Collect_, select _Fetch events_ checkbox, and click **Connect**.

</~XSIAM>
