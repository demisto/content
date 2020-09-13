### Using API Token authentication
In order to use the integration with an API token you'll first need to change the `Username / API Key (see '?')` field to `_api_token_key`. Following this step, you can now enter the API Token into the `Password` field - this value will be used as an API key.

### Fetch incidents:
To start fetching incidents, enable the parameter `Long running instance` - this will start a long running process that'll fetch incidents periodically.

You can apply additional (optional) filters for the fetch-incident query using the `Query to fetch offenses
` integration parameter. For more information on how to use the filter syntax, see the [QRadar filter documentation](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.3/com.ibm.qradar.doc/c_rest_api_filtering.html) and [QRadar offense documentation](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.2/com.ibm.qradar.doc/11.0--siem-offenses-GET.html).
* Incident IP Enrichment - When enabled, fetched incidents IP values (local source addresses and local destination addresses) will be fetched from QRadar instead of their ID values.
* Incident Asset Enrichment - When enabled, fetched offenses will also contain correlated assets.

### Required Permissions:
* Assets - Vulnerability Management *or* Assets
* Domains - Admin
* Offenses (Manage Closing Reason) - Manage Offense Closing Reasons
* Offenses (Assign Offenses to Users) - Assign Offenses to Users
* Offenses (Read) - Offenses
* References (Create/Update) - admin
* References (Read) - View Reference Data
