Configure an API account on Ignite
-------------------------------

- Login/Register at [Ignite](https://app.flashpoint.io) platform.
- Click on your profile icon on the top right and select the **Manage API Tokens** option from the dropdown. Alternatively, click on <https://app.flashpoint.io/tokens> to be taken directly to the Generate Token page.
- Click on the **Generate New Token** button.
- Enter the required details (i.e- Token Name, Ignite Username) and click on "Generate Token" button.
- Click on the Copy Token to Clipboard button and paste it into the integration, code, or API call. Then, click on the Save & Close button to save the generated token and close the token generation page.

An integration instance contains the compromised credential playbook, IOC & report lookup commands and either Automated Keyword Alert ingestion or Compromised Credential ingestion. If your Ignite subscription does not include Compromised Credentials, just follow the instructions below for creating Ignite Alerts integration.
**Please Note:** If you want Ignite Alerts and Compromised Credentials, you will need to create two integration instances, one for each setting.

### Recommended settings for Compromised Credentials fetch

In order to fetch compromised credentials alerts from Ignite, you need to enable the Fetch Incident. Fill out the required fields along with the below-recommended settings:

- Enable "Fetches incidents" option.
- Choose option "Flashpoint Compromised Credentials" for setting "Incident type (if classifier doesn't exist)".
- Choose option "Flashpoint Compromised Credentials - Incoming Mapper" for setting "Mapper (incoming)".
- To get the number of incidents per minute you can set max 200 for setting "Maximum number of incidents per fetch".
- Choose option "Compromised Credentials" for setting "Fetch Type".

### Recommended settings for Ignite Alerts fetch

In order to fetch Ignite alerts, you need to enable the Fetch Incident. Fill out the required fields along with below-recommended settings:

- Enable "Fetches incidents" option.
- Choose option "Ignite Alert" for setting "Incident type (if classifier doesn't exist)".
- Choose option "Ignite Alert - Incoming Mapper" for setting "Mapper (incoming)".
- To get the number of incidents per minute you can set max 200 for setting "Maximum number of incidents per fetch".
- Choose option "Alerts" for setting "Fetch Type".

If you don't want to enable alert or credential handling, create an integration instance with the appropriate settings described below.

### Recommended settings for integration instance without fetch incident capability

- Click on "Add instance".
- By default, "Do not fetch" option would be selected.
- Add "API Key" and save the instance.
