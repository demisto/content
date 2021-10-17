Configure an API account on Flashpoint
-------------------------------
 - Login/Register at [Flashpoint](https://fp.tools/) platform. 
 - Navigate to API & Integrations and select the **Manage API Tokens**.
 - Click on "GENERATE TOKEN" button and enter the required details to generate
    token. (i.e- token label,username and password)
 - Click on GENERATE button once all required data are entered.


An integration instance contains the compromised credential playbook, IOC & report lookup commands and either Automated Keyword Alert ingestion or Compromised Credential ingestion.  If your Flashpoint subscription does not include Compromised Credentials, just follow the instructions below for creating Flashpoint Alerts integration.  
**Please Note:** If you want Flashpoint Alerts and Compromised Credentials, you will need to create two integration instances, one for each setting.

### Recommended settings for Compromised Credentials fetch:

In order to fetch compromised credentials alerts from Flashpoint, you need to enable the Fetch Incident. Fill out the required fields along with the below-recommended settings:

- Enable "Fetches incidents" option.
- Choose option "Flashpoint Compromised Credentials" for setting "Incident type (if classifier doesn't exist)".
- Choose option "Flashpoint Compromised Credentials - Incoming Mapper" for setting "Mapper (incoming)".
- To get the number of incidents per minute you can set max 1000 for setting "Maximum number of incidents per fetch".
- Choose option "Compromised Credentials" for setting "Fetch Type".

### Recommended settings for Flashpoint Alerts fetch:

In order to fetch Flashpoint alerts, you need to enable the Fetch Incident. Fill out the required fields along with below-recommended settings:

- Enable "Fetches incidents" option.
- Choose option "Flashpoint Alerts" for setting "Incident type (if classifier doesn't exist)".
- Choose option "Flashpoint Alerts - Incoming Mapper" for setting "Mapper (incoming)".
- To get the number of incidents per minute you can set max 100 for setting "Maximum number of incidents per fetch".
- Choose option "Alerts" for setting "Fetch Type".


If you don't want to enable alert or credential handling, create an integration instance with the appropriate settings described below.
### Recommended settings for integration instance without fetch incident capability:

- Click on "Add instance".
- By default, "Do not fetch" option would be selected.
- Add "API Key" and save the instance.