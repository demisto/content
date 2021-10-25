### Use API token instead of Username and Password
- In the **Username / API Key** field, type **_api_token_key**.  
- In the **Password** field, type your API token.

## Choose your API version
1. Visit the [QRadar API versions page](https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_getting_started.html) for a full list of available API versions according to the QRadar version.
2. Choose one of the API versions listed under **Supported REST API versions** column in the line corresponding to your QRadar version.

Note: If you're uncertain which API version to use, it is recommended to use the latest API version listed in the **Supported REST API versions** column in the line corresponding to your QRadar version.
### Fetch incidents
To start fetching incidents, enable the *Long running instance* parameter. This will start a long-running process that will fetch incidents periodically.
Depending on the system load, the initial fetch might take a long time.

#### Query to fetch offenses
You can apply additional (optional) filters for the fetch-incident query using the *Query to fetch offenses* integration parameter. For more information on how to use the filter syntax: 
- Visit [QRadar Filter Syntax Documentation](https://www.ibm.com/support/knowledgecenter/en/SS42VS_7.3.3/com.ibm.qradar.doc/c_rest_api_filtering.html) for explanation about filter syntax.
- Visit [QRadar Offense Documentation](https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi140.doc/14.0--siem-offenses-GET.html) for a list of all possible fields to be used in the filter.

#### Offense Enrichment
* Incident Enrichment (IP) - When enabled, fetched incidents IP values (local source addresses and local destination addresses) will be fetched from QRadar instead of their ID values.
* Incident Enrichment (Asset) - When enabled, fetched offenses will also contain correlated assets.

#### Reset the "last run" timestamp
To reset fetch incidents, run the ***qradar-reset-last-run*** command - This will reset the fetch to its initial state. (Will try to fetch the first available offense).

#### Mirroring offenses with events
To mirror offenses with events, enable the *Long running instance* parameter and set *Mirroring Options* to *Mirror Offense and Events*.
- When mirroring offenses with events it is advised to set the *Number of offenses to pull per API call* to a small value.

#### Mapping limitations for XSOAR users below 6.0.0
* For XSOAR users below 6.0.0 version, using 'Pull from instance' option when creating a new mapper is not supported.
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
