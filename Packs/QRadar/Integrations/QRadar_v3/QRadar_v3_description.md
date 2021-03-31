### Use API token instead of Username and Password
- In the **Username / API Key** field, type **_api_token_key**.  
- In the **Password** field, type your API token.

### Fetch incidents
To start fetching incidents, enable the *Long running instance* parameter. This will start a long-running process that will fetch incidents periodically.
Depending on the system load, the initial fetch might take a long time.

#### Query to fetch offenses
You can apply additional (optional) filters for the fetch-incident query using the *Query to fetch offenses* integration parameter. For more information on how to use the filter syntax: 
- Visit [QRadar Filter Syntax Documentation](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.3/com.ibm.qradar.doc/c_rest_api_filtering.html) for explanation about filter syntax.
- Visit [QRadar Offense Documentation](https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html) for a list of all possible fields to be used in the filter.

#### Offense Enrichment
* Incident Enrichment (IP) - When enabled, fetched incidents IP values (local source addresses and local destination addresses) will be fetched from QRadar instead of their ID values.
* Incident Enrichment (Asset) - When enabled, fetched offenses will also contain correlated assets.

#### Reset the "last run" timestamp
To reset fetch incidents, run the ***qradar-reset-last-run*** command - This will reset the fetch to its initial state. (Will try to fetch the first available offense).

#### Required Permissions
| Component | Permission |
| --- | --- |
| Assets | Vulnerability Management *or* Assets |
| Domains | Admin |
| Offenses (Manage Closing Reason) | Manage Offense Closing Reasons |
| Offenses (Assign Offenses to Users) | Assign Offenses to Users |
| Offenses (Read) | Offenses |
| References (Create/Update) | Admin |
| References (Read) | View Reference Data |
