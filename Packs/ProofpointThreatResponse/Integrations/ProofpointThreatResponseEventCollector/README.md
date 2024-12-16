Use the Proofpoint Threat Response integration to orchestrate and automate incident response.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure Proofpoint Threat Response Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g., https://192.168.0.1) |  | True |
| API Key for the authentication. |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | The time range for the initial data fetch. If timeout errors occur, consider changing this value. | False |
| Fetch limit - maximum number of incidents per fetch |  | False |
| Fetch delta - The delta time in each batch. e.g. 1 hour, 3 minutes. | The time range between create_after and created_before that is sent to the API when fetching older incidents. If timeout errors occur, consider changing this value. | False |
| Fetch incidents with specific event sources. Can be a list of comma-separated values. |  | False |
| Fetch incidents with specific 'Abuse Disposition' values. Can be a list of comma-separated values. |  | False |
| Fetch incident with specific states. |  | False |
| POST URL of the JSON alert source. | You can find this value by navigating to Sources -&amp;gt; JSON event source -&amp;gt; POST URL. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### proofpoint-trap-get-events
***
Retrieves all incident metadata from Threat Response by specifying filter criteria such as the state of the incident or time of closure.


#### Base Command

`proofpoint-trap-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Required | 
| state | The state of the incidents to retrieve. Possible values are: new, open, assigned, closed, ignored. | Optional | 
| created_after | Retrieve incidents that were created after this date, in ISO 8601 format (UTC). Example: 2020-02-22 or 2020-02-22T00:00:00Z.  | Optional | 
| created_before | Retrieve incidents that were created before this date, in ISO 8601 format (UTC). Example: 2020-02-22 or 2020-02-22T00:00:00Z. | Optional | 
| closed_after | Retrieve incidents that were closed after this date, in ISO 8601 format (UTC). Example: 2020-02-22 or 2020-02-22T00:00:00Z. | Optional | 
| closed_before | Retrieve incidents that were closed before this date, in ISO 8601 format (UTC). Example: 2020-02-22 or 2020-02-22T00:00:00Z. | Optional | 
| expand_events | If false, will return an array of event IDs instead of full event objects. This will significantly speed up the response time of the API for incidents with a large number of alerts. Possible values are: true, false. | Optional | 
| limit | The maximum number of incidents to return. Default is 100. | Required | 


#### Context Output

There is no context output for this command.