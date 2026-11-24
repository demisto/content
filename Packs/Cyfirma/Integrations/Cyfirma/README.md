# CYFIRMA
 
CYFIRMA is an AI-powered Preemptive External Threat Landscape Management platform that enables organizations to predict, identify, and prevent cyber threats by gaining visibility into external exposure and adversary intent. By transforming threat intelligence into predictive insights and actionable risk intelligence, CYFIRMA helps organizations reduce cyber risk, protect critical digital assets, and move from reactive defence to proactive threat prevention.
 
This integration fetches CYFIRMA alerts (attack surface, brand exposure, data breach and web monitoring, and social public exposure) and creates incidents in Cortex XSOAR / Cortex XSIAM. It also lets you parse alert details and manage take-down requests directly from Cortex.
 
This integration was integrated and tested with the CYFIRMA API.
 
## Prerequisites
 
- A CYFIRMA account with API access.
- A valid CYFIRMA API key.
- Network access from the Cortex engine or server to the CYFIRMA API URL (default: `https://api.cyfirma.com`).
## Configure CYFIRMA in Cortex
 
| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API URL (e.g. https://api.cyfirma.com) | The base URL of the CYFIRMA API. Default: `https://api.cyfirma.com`. | True |
| API Key | The API key used to authenticate with CYFIRMA. | True |
| Use system proxy settings | Use the system proxy settings for requests to the CYFIRMA API. | False |
| Trust any certificate (not secure) | Skip SSL certificate verification. Not recommended for production use. | False |
| Fetch incidents | Enable fetching of CYFIRMA alerts as incidents. | False |
| Fetch Attack Surface | Fetch Attack Surface alerts. Default: enabled. | False |
| Fetch Brand Exposure | Fetch Brand Exposure alerts. Default: enabled. | False |
| Fetch DataBreach & WebMonitor | Fetch Data Breach and Web Monitor alerts. Default: enabled. | False |
| Fetch Social public exposure | Fetch Social Public Exposure alerts. Default: enabled. | False |
| Include third party Alerts | Also fetch alerts that relate to third parties. | False |
| Incidents Fetch Interval | Interval, in minutes/hours/days, between incident fetches. Default: 5. | False |
| How much time before the first fetch to retrieve incidents | How far back to look on the first fetch. Options: 15, 30, 60, 90, 120, 160, or 180 days. Default: 60 days. | False |
| Maximum number of incidents per fetch | The maximum number of incidents to create in each fetch cycle. Default: 100. | False |
 
 
## Fetch Incidents
 
When **Fetch incidents** is enabled, the integration periodically retrieves alerts from CYFIRMA and creates an incident for each one.
 
- On the first run, the integration retrieves alerts going back by the period set in **How much time before the first fetch to retrieve incidents** (default: 60 days).
- On subsequent runs, only new alerts since the last fetch are retrieved.
- Each fetch creates at most the number of incidents set in **Maximum number of incidents per fetch** (default: 100).
- Use the **Fetch Attack Surface**, **Fetch Brand Exposure**, **Fetch DataBreach & WebMonitor**, and **Fetch Social public exposure** options to choose which alert categories are fetched.
- Enable **Include third party Alerts** to also include alerts related to third parties.
- Set **Incident type** to classify the created incidents.
## Commands
 
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
 
### cyfirma-alert-parser
 
***
Reads the `cyfirmaalertdetails` custom field of the current incident and writes it to the `Cyfirma.Alert` context dictionary. Exits with an error if the grid is empty.
 
#### Base Command
 
`cyfirma-alert-parser`
 
#### Input
 
There are no input arguments for this command.
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.Alert.Alertid | String | Unique identifier of the CYFIRMA alert. |
| Cyfirma.Alert.Severity | String | Severity level assigned to the alert, indicating the potential impact or risk. |
| Cyfirma.Alert.Category | String | Primary category of the alert, identifying the type of security exposure or threat. |
| Cyfirma.Alert.Subcategory | String | Subcategory providing more specific classification of the alert. |
| Cyfirma.Alert.Description | String | Detailed description of the alert, including relevant information about the identified security exposure or threat. |
| Cyfirma.Alert.Ip | String | IP address associated with the alert, if available. |
| Cyfirma.Alert.Domain | String | Domain associated with the alert, if available. |
| Cyfirma.Alert.Subdomain | String | Subdomain associated with the alert, if available. |
| Cyfirma.Alert.Thirdpartyrelated | String | Indicates whether the alert is associated with a third-party entity or not. |
| Cyfirma.Alert.Exposurescore | String | CYFIRMA exposure score associated with the alert, representing the assessed level of exposure. |
| Cyfirma.Alert.Firstseen | String | Timestamp indicating when the identified exposure or threat was first observed. |
| Cyfirma.Alert.Lastseen | String | Timestamp indicating when the identified exposure or threat was last observed. |
 
#### Command example
 
```
!cyfirma-alert-parser
```
 
### cyfirma-takedown-initiate
 
***
Create a take-down request for a CYFIRMA alert.
 
#### Base Command
 
`cyfirma-takedown-initiate`
 
#### Input
 
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The ID of the alert to take down. | Required |
| comment | Optional comment to send along with the take-down request. | Optional |
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.TakeDown.take_down_id | String | The ID of the created take-down ticket. |
| Cyfirma.TakeDown.message | String | Result message of the take-down request. |
 
#### Command example
 
```
!cyfirma-takedown-initiate alert_id=<alert_id> comment="Please take this down"
```
 
### cyfirma-takedown-list
 
***
List existing CYFIRMA take-down tickets.
 
#### Base Command
 
`cyfirma-takedown-list`
 
#### Input
 
| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Filter the tickets by domain. By default, all domains are returned. | Optional |
| size | Number of records per page. Default is 50. | Optional |
| page | Zero-based page number. Default is 0. | Optional |
 
#### Context Output
 
| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Cyfirma.TakeDownList.ticket_id | String | The ID of the take-down ticket. |
| Cyfirma.TakeDownList.sub_category | String | The take-down sub-category. |
| Cyfirma.TakeDownList.created_date | String | The date the ticket was created. |
| Cyfirma.TakeDownList.modified_date | String | The date the ticket was last modified. |
| Cyfirma.TakeDownList.status | String | The current status of the ticket. |
| Cyfirma.TakeDownList.domain | String | The domain the ticket relates to. |
| Cyfirma.TakeDownList.created_by | String | The user who created the ticket. |
| Cyfirma.TakeDownList.modified_by | String | The user who last modified the ticket. |
 
#### Command example
 
```
!cyfirma-takedown-list domain=example.com size=50 page=0
```
 
## Troubleshooting
 
- **Authorization or connection errors on Test:** Verify that the API URL is correct and that the API key is valid and active.
- **SSL errors:** Ensure the certificate chain is trusted. Use **Trust any certificate (not secure)** only for troubleshooting.
- **No incidents created:** Confirm that **Fetch incidents** is enabled, that an **Incident type** is selected, that at least one alert category is enabled, and that the first fetch period covers the time range of the alerts you expect.
- **`cyfirma-alert-parser` fails with an empty grid error:** Run the command from within a CYFIRMA incident whose `cyfirmaalertdetails` grid field is populated.
- **Proxy issues:** If your environment requires a proxy, enable **Use system proxy settings**.
 