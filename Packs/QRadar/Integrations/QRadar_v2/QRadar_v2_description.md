### Using API Token authentication
In order to use the integration with an API token you'll first need to change the `Username / API Key (see '?')` field to `_api_token_key`. Following this step, you can now enter the API Token into the `Password` field - this value will be used as an API key.

### Fetch incidents:
You can apply additional (optional) filters for the fetch-incident query using the `Query to fetch offenses
` integration parameter. For more information on how to use the filter syntax, see the [QRadar filter documentation](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.3/com.ibm.qradar.doc/c_rest_api_filtering.html) and [QRadar offense documentation](https://www.ibm.com/support/knowledgecenter/SS42VS_7.3.1/com.ibm.archive.doc/SS42VS_7.3.1.zip).
* Full Incident Enrichment - Clear this checkbox to disable local source addresses and destination addresses enrichment performed in fetch-incidents. This might help if you encounter a timeout while fetching new incidents.

### Required Permissions:
* Assets - Vulnerability Management *or* Assets
* Domains - Admin
* Offenses (Manage Closing Reason) - Manage Offense Closing Reasons
* Offenses (Assign Offenses to Users) - Assign Offenses to Users
* Offenses (Read) - Offenses
* References (Create/Update) - admin
* References (Read) - View Reference Data
