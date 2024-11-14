Configure an API account on Ignite
-------------------------------

1. Login/Register at the [Ignite](https://app.flashpoint.io) platform.
2. Click your profile icon on the top right and select the **Manage API Tokens** option from the dropdown list. Alternatively, click <https://app.flashpoint.io/tokens> to be taken directly to the Generate Token page.
3. Click **Generate New Token**.
4. Enter the required details (i.e.,- Token Name, Ignite Username) and click "Generate Token".
5. Click **Copy Token to Clipboard** and paste it into the integration. 
6. Click **Save & Close** to save the generated token and close the token generation page.

An integration instance contains the compromised credential playbook, IOC & report lookup commands and either Automated Keyword Alert ingestion or Compromised Credential ingestion. If your Ignite subscription does not include Compromised Credentials, follow the instructions below for creating an Ignite Alerts integration.
**Note:** If you want Ignite Alerts and Compromised Credentials, you will need to create two integration instances, one for each setting.

### Recommended settings for Compromised Credentials fetch

In order to fetch compromised credentials alerts from Ignite, you need to enable the Fetch Incident. Fill out the required fields along with the following recommended settings:

1. Enable the "Fetches incidents" option.
2. Choose the "Flashpoint Compromised Credentials" option for the "Incident type (if classifier doesn't exist)" setting.
3. Choose the "Flashpoint Compromised Credentials - Incoming Mapper" option for the "Mapper (incoming)" setting .
4. To get the number of incidents per minute you can set a maximum of 200 for the "Maximum number of incidents per fetch" setting .
5. Choose the "Compromised Credentials" option for the "Fetch Type" setting.

### Recommended settings for Ignite Alerts fetch

In order to fetch Ignite alerts, you need to enable the Fetch Incident. Fill out the required fields along with the following recommended settings:

1. Enable the "Fetches incidents" option.
2. Choose the "Ignite Alert" option for the "Incident type (if classifier doesn't exist)" setting.
3. Choose the "Ignite Alert - Incoming Mapper" option for the "Mapper (incoming)" setting.
4. To get the number of incidents per minute you can set a maximum of 200 for the "Maximum number of incidents per fetch" setting.
5. Choose the "Alerts" option for the "Fetch Type" setting.

### Recommended settings for integration instance without fetch incident capability

If you don't want to enable alert or credential handling, create an integration instance with the appropriate settings as described below.

1. Click "Add instance". By default, "Do not fetch" option would be selected.
2. Add the "API Key" and save the instance.
