Cortex XDR is the world's first detection and response app that natively integrates network, endpoint, and cloud data to stop sophisticated attacks.
This integration was integrated and tested with version 2.6.5 of Cortex XDR - IR.

## Configure Palo Alto Networks Cortex XDR - Investigation and Response on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Palo Alto Networks Cortex XDR - Investigation and Response.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | Server URL (copy URL from XDR) |  | True |
    | API Key ID |  | False |
    | API Key |  | False |
    | Remove legacy incident fields | Unchecked for backwards compatibility, recommended to check. This will remove duplicated incident fields under file_artifacts, network_artifacts, and alerts (like client_id, clientid.) | False |
    | Incident Mirroring Direction |  | False |
    | Close Mirrored XSOAR Incident | When selected, closing the Cortex XDR incident is mirrored in Cortex XSOAR. | False |
    | Close Mirrored Cortex XDR Incident | When selected, closing the Cortex XSOAR incident is mirrored in Cortex XDR. If not selected, but "Close all related alerts in XDR" is selected, the incident will automatically be closed in Cortex XDR. | False |
    | XDR mirroring delay in minutes | In the event of a delay in mirroring incoming changes from XDR, use the xdr_delay parameter to extend the lookback period. However, be aware that this may result in increased latency when updating incidents. | False |
    | Custom close-reason mapping for mirrored **XSOAR -> XDR** incidents. | Define how to close the mirrored incidents from Cortex XSOAR into Cortex XDR with a custom close reason mapping. Enter a comma-separated close-reason mapping (acceptable format {Cortex XSOAR close reason}={Cortex XDR close reason}) to override the default close reason mapping defined by Cortex XSOAR. Note that the mapping must be configured accordingly with the existing close reasons in Cortex XSOAR and Cortex XDR. Not following this format will result in closing the incident with a default close reason. Example: "Resolved=Other". Default: "Other=Other,Duplicate=Duplicate Incident,False Positive=False Positive,Resolved=True Positive”. Refer to the integration documentation for possible close-reasons (`XDR Incident Mirroring, sec. 7`). | False |
    | Custom lose-reason mapping for mirrored **XDR -> XSOAR** incidents. | Define how to close the mirrored incidents from Cortex XDR into Cortex XSOAR with a custom close reason mapping. Enter a comma-separated list of close reasons (acceptable format {Cortex XDR close reason}={Cortex XSOAR close reason}) to override the default close reason mapping defined by Cortex XSOAR. Note that the mapping must be configured accordingly with the existing close reasons in Cortex XSOAR and Cortex XDR. Not following this format will result in closing the incident with a default close reason. Example: “Known Issue=Resolved". Default: “Known Issue=Other,Duplicate Incident=Duplicate,False Positive=False Positive,True Positive=Resolved,Security Testing=Other,Other=Other,Auto=Resolved". Refer to the integration documentation for possible close-reasons (`XDR Incident Mirroring, sec. 7`). | False |
    | Maximum number of incidents per fetch | The maximum number of incidents per fetch. Cannot exceed 100. | False |
    | Only fetch starred incidents |  | False |
    | Starred incidents fetch window | Starred fetch window timestamp \(&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days\). Fetches only starred incidents within the specified time range. | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
    | Sync Incident Owners | For Cortex XSOAR version 6.0.0 and above. If selected, for every incident fetched from Cortex XDR to Cortex XSOAR, the incident owners will be synced. Note that once this value is changed and synchronized between the systems, additional changes will not be reflected. For example, if you change the owner in Cortex XSOAR, the new owner will also be changed in Cortex XDR. However, if you now change the owner back in Cortex XDR, this additional change will not be reflected in Cortex XSOAR. In addition, for this change to be reflected, the owners must exist in both Cortex XSOAR and Cortex XDR. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Prevent Only Mode | Whether the Cortex XDR tenant mode is prevent only. | False |
    | Incident Statuses to Fetch | The statuses of the incidents that will be fetched. If no status is provided then incidents of all the statuses will be fetched. Note: An incident whose status was changed to a filtered status after its creation time will not be fetched. | False |
    | Minimize Incident Information | Whether to fetch only the essential incident's fields - without Network Artifacts and File Artifacts to minimize the incident's information. | False |
    | Minimize Alert Information | Whether to fetch only the essential alert fields in order to minimize the incident's information. Possible values: null_values to remove all null values from alerts data (recommended), or any other field of an alert.| False|
    | Close all related alerts in XDR | Close all related alerts in Cortex XDR once an incident has been closed in Cortex XSOAR. | False |

4. Click **Test** to validate the URLs, token, and connection.


## Configuration

---
You need to collect several pieces of information in order to configure the integration on Cortex XSOAR.

#### Generate an API Key and API Key ID

1. In your Cortex XDR platform, go to **Settings**.
2. Click the **+New Key** button in the top right corner.
3. Generate a key of type **Advanced**.
4. Copy and paste the key.
5. From the ID column, copy the Key ID.

*Note 1*: When Configuring a role for the API Key's permission you can create a custom role or use a builtin.
The highest privileged builtin role is the Instance Admin. 
For builtin role with less permission but maximum command running abilities, use the `Privileged Responder`.

*Note 2*: In case of missing updates in mirroring incoming changes from XDR, use the xdr_delay parameter to extend the delay period. However, be aware that this may result in increased latency when updating incidents.

#### URL

1. In your Cortex XDR platform, go to **Settings** > **Configurations** > **API key** page > **API Keys**.
2. Click the **Copy URL** button in the top right corner.

#### XDR & XSOAR

## Playbooks

---

#### Cortex XDR Incident Handling

The playbook syncs and updates new Cortex XDR alerts that construct the incident.
It enriches indicators using Threat Intelligence integrations and Palo Alto Networks
AutoFocus. The incident's severity is then updated based on the indicators reputation
and an analyst is assigned for manual investigation. If chosen, automated remediation
with Palo Alto Networks FireWall is initiated. After a manual review by the
SOC analyst, the Cortex XDR incident is closed automatically.

To utilize this playbook for handling Cortex XDR incidents, the classifier that should be selected is `Cortex XDR - Classifier`.
The selected Mapper (incoming) should be `XDR - Incoming Mapper`, and the selected Mapper (outgoing) should be Cortex `XDR - Outgoing Mapper`.

#### Cortex XDR Lite - Incident Handling

This playbook is a lite default playbook to handle Cortex XDR incidents, and it doesn't require additional integrations to run. The playbook is triggered by fetching a Palo Alto Networks Cortex XDR incident. First, the playbook performs enrichment on the incident’s indicators. Then, the playbook performs investigation and analysis on the command line and searches for related Cortex XDR alerts by Mitre tactics to identify malicious activity performed on the endpoint and by the user. Based on the enrichment and the investigation results, the playbooks sets the verdict of the incident. If malicious indicators are found, the playbook takes action to block these indicators and isolate the affected endpoint to prevent further damage or the spread of threats. If the verdict is not determined, it lets the analyst decide whether to continue to the remediation stage or close the investigation as benign. As part of this playbook, you'll receive a comprehensive layout that presents incident details, analysis, investigation findings, and the final verdict. Additionally, the layout offers convenient remediation buttons for quicker manual actions.

To utilize this playbook for handling XDR incidents, the classifier should be empty, and the selected incident type should be `Cortex XDR - Lite`.
The selected Mapper (incoming) should be `XDR - Incoming Mapper`, and the selected Mapper (outgoing) should be Cortex `XDR - Outgoing Mapper`.

## Use Cases

---

- Fetch incidents from Cortex XDR
- Enrich incident with alerts and incident from Cortex XDR
- Update incident in Cortex XDR
- Search for endpoints
- Isolate/unisolate endpoints
- Insert parsed alerts into Cortex XDR
- Insert CEF alerts into Cortex XDR
- Query for agent audit reports
- Query for audit management logs
- Create distribution
- Get distribution download URL
- Get distribution versions

## Automation

---
To sync incidents between Cortex XSOAR and Cortex XDR, you should use the **XDRSyncScript** script, which you can find in the automation page.

## Fetched Incidents Data

---

```
incident_id:31
creation_time:1564594008755
modification_time:1566339537617
detection_time:null
status:new
severity:low
description:6 'Microsoft Windows RPC Fragment Evasion Attempt' alerts detected by PAN NGFW on 6 hosts
assigned_user_mail:null
assigned_user_pretty_name:null
alert_count:6
low_severity_alert_count:0
med_severity_alert_count:6
high_severity_alert_count:0
user_count:1
host_count:6
notes:null
resolve_comment:null
manual_severity:low
manual_description:null
xdr_url:https://1111.paloaltonetworks.com/incident-view/31
```

## XDR Incident Mirroring

**Note this feature is available from Cortex XSOAR version 6.0.0**

You can enable incident mirroring between Cortex XSOAR incidents and Cortex XDR incidents.
To setup the mirroring follow these instructions:

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cortex XDR - IR and select your integration instance.
3. Enable **Fetches incidents**.
4. Under **Mapper (incoming)**, select `XDR - Incoming Mapper`.
5. Under **Mapper (outgoing)**, select `Cortex XDR - Outgoing Mapper`.
6. In the *Incident Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:
   - Incoming - Any changes in Cortex XDR incidents will be reflected in Cortex XSOAR incidents.
   - Outgoing - Any changes in Cortex XSOAR incidents will be reflected in Cortex XDR incidents.
   - Both - Changes in Cortex XSOAR and Cortex XDR incidents will be reflected in both directions.
   - None - Choose this to turn off incident mirroring.
   
7. Optional: Provide a custom close-reason mapping for mirrored XDR <-> XSOAR incidents. Please use only possible close-reasons to map: 
    
    | Possible Closure Reasons for Cortex XSOAR Incident |                      
    |----------------------------------------------------|
    | Resolved                                           |
    | False Positive                                     |
    | Duplicate                                          |
    | Security Testing                                   |
    | Other                                              |

    |Possible Closure Reasons for Cortex Cortex XDR Incident|
    |-----------------------------------|
    | True Positive                     |
    | False Positive                    |
    | Duplicate Incident                |
    | Security Testing                  |
    | Known Issue                       |
    | Other                             |
    | Auto                              |
    
    Failing to use only available values will result in using default mapping of closure reasons within the mirroring process.
    
  **Close-reason default mapping XSOAR -> XDR**: _Other=Other, Duplicate=Duplicate Incident, False Positive=False Positive, Resolved=True Positive_

  **Close-reason default mapping XDR -> XSOAR**: _Known Issue=Other, Duplicate Incident=Duplicate, False Positive=False Positive, True Positive=Resolved, Other=Other, Auto=Resolved_

8. Optional: Check the *Sync Incident Owners* integration parameter to sync the incident owners in both Cortex XDR and Cortex XSOAR.

   - Note: This feature will only work if the same users are registered in both Cortex XSOAR and Cortex XDR.

9. Newly fetched incidents will be mirrored in the chosen direction.

   - Note: This will not effect existing incidents.

### XDR Mirroring Notes, limitations and Troubleshooting

- While you can mirror changes in incident fields both in and out in each incident, you can only mirror in a single direction at a time. For example:
  If we have an incident with two fields (A and B) in Cortex XDR and Cortex XSOAR while *Incoming And Outgoing* mirroring is selected: 
  - I can mirror field A from Cortex XDR to Cortex XSOAR and field B from Cortex XSOAR to Cortex XDR.
  - I cannot mirror changes from field A in both directions.

  Initially all fields are mirrored in from Cortex XDR to Cortex XSOAR. Once they are changed in Cortex XSOAR, they can only be mirrored out.
- **Do not use the `XDRSyncScript` automation nor any playbook that uses this automation** 
  (e.g `Cortex XDR Incident Sync` or `Cortex XDR incident handling v2`), as it impairs the mirroring functionality.

- When migrating an existing instance to the mirroring feature, or in case the mirroring does not work as expected, make sure that:
  - The default playbook of the *Cortex XDR Incident* incident type is not *Cortex XDR Incident Sync*, change it to a 
     different playbook that does not use `XDRSyncScript`.
  - The Cortex XDR integration instance incoming mapper is set to `Cortex XDR - Incoming Mapper` and the outgoing mapper is set to `Cortex XDR - Outgoing Mapper`.
  - Mirroring impacts only incidents that were fetched after the mirroring was enabled for this instance. If incidents were fetched with the incorrect mapper, changing the mapper will not affect them. This can be resolved by resetting the last fetch run and re-fetching the incidents. New incidents will be created and the old ones will no longer be relevant.

- The API includes a limit rate of 10 API requests per minute. Therefore, in a case of a limit rate exception, the sync loop will stop and will resume from the last incident. 

- `Owner` and `closeReason` mappings are done using the integration code, therefore they are not part of the out-of-the-box mapper and should not be specified in any future mapper.

### Fetch Behavior vs Mirroring

Note: All incidents, including those with a "resolved" status, will be fetched into Cortex XSOAR as "active" incidents to enable the execution of our automations. However, the original resolved status of the incidents will be preserved in the incident details. If you prefer to keep certain incidents closed, you can utilize the "Incident Statuses to Fetch" filter during the configuration stage and choose not to import those specific incidents. Alternatively, you can utilize pre-processing rules to define specific types of incidents to be imported as closed.

Regarding mirroring, if you have already imported an incident and the mirroring feature is enabled, changing the incident's status to resolved on the Cortex XDR platform will trigger the mirroring process, resulting in the closure of the incident in Cortex XSOAR.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xdr-get-incidents

***
Returns a list of incidents, which you can filter by a list of incident IDs (max. 100), the time the incident was last modified, and the time the incident was created.
If you pass multiple filtering arguments, they will be concatenated using the AND condition. The OR condition is not supported.

##### Required Permissions

Required Permissions For API call:
`Alerts And Incidents` --> `View`
Builtin Roles with this permission includes: "Investigator", "Responder", "Privileged Investigator", "Privileged Responder", "Viewer", and "Instance Admin".

#### Base Command

`xdr-get-incidents`

#### Input

| **Argument Name** | **Description**                                                                                                                                                                                                            | **Required** |
| --- |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| lte_creation_time | A date in the format 2019-12-31T23:59:00 in UTC. Only incidents that were created on or before the specified date/time will be retrieved.                                                                                  | Optional | 
| gte_creation_time | A date in the format 2019-12-31T23:59:00 in UTC. Only incidents that were created on or after the specified date/time will be retrieved.                                                                                          | Optional | 
| lte_modification_time | Filters returned incidents that were created on or before the specified date/time, in the format 2019-12-31T23:59:00.                                                                                                      | Optional | 
| gte_modification_time | Filters returned incidents that were modified on or after the specified date/time, in the format 2019-12-31T23:59:00.                                                                                                      | Optional | 
| incident_id_list | An array or CSV string of incident IDs.                                                                                                                                                                                    | Optional | 
| since_creation_time | Filters returned incidents that were created on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on.                                                                                   | Optional | 
| since_modification_time | Filters returned incidents that were modified on or after the specified date/time range, for example, 1 month, 2 days, 1 hour, and so on.                                                                                  | Optional | 
| sort_by_modification_time | Sorts returned incidents by the date/time that the incident was last modified ("asc" - ascending, "desc" - descending). Possible values are: asc, desc.                                                                    | Optional | 
| sort_by_creation_time | Sorts returned incidents by the date/time that the incident was created ("asc" - ascending, "desc" - descending). Possible values are: asc, desc.                                                                          | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0.                                                                                                                                             | Optional | 
| limit | Maximum number of incidents to return per page. The default and maximum is 100. Default is 100.                                                                                                                            | Optional | 
| status | Filters only incidents in the specified status. The options are: new, under_investigation, resolved_known_issue, resolved_false_positive, resolved_true_positive resolved_security_testing, resolved_other, resolved_auto, resolved_auto_resolve. | Optional | 
| starred | Whether the incident is starred (Boolean value: true or false). Possible values are: true, false.                                                                                                                          | Optional | 
| starred_incidents_fetch_window | Starred fetch window timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days). Default is 3 days.                                                                                                              | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Incident.incident_id | String | Unique ID assigned to each returned incident. | 
| PaloAltoNetworksXDR.Incident.manual_severity | String | Incident severity assigned by the user. This does not affect the calculated severity. Can be "low", "medium", "high" | 
| PaloAltoNetworksXDR.Incident.manual_description | String | Incident description provided by the user. | 
| PaloAltoNetworksXDR.Incident.assigned_user_mail | String | Email address of the assigned user. | 
| PaloAltoNetworksXDR.Incident.high_severity_alert_count | String | Number of alerts with the severity HIGH. | 
| PaloAltoNetworksXDR.Incident.host_count | number | Number of hosts involved in the incident. | 
| PaloAltoNetworksXDR.Incident.xdr_url | String | A link to the incident view on Cortex XDR. | 
| PaloAltoNetworksXDR.Incident.assigned_user_pretty_name | String | Full name of the user assigned to the incident. | 
| PaloAltoNetworksXDR.Incident.alert_count | number | Total number of alerts in the incident. | 
| PaloAltoNetworksXDR.Incident.med_severity_alert_count | number | Number of alerts with the severity MEDIUM. | 
| PaloAltoNetworksXDR.Incident.user_count | number | Number of users involved in the incident. | 
| PaloAltoNetworksXDR.Incident.severity | String | Calculated severity of the incident. Valid values are: "low","medium","high" | 
| PaloAltoNetworksXDR.Incident.low_severity_alert_count | String | Number of alerts with the severity LOW. | 
| PaloAltoNetworksXDR.Incident.status | String | Current status of the incident. Valid values are: "new","under_investigation","resolved_known_issue","resolved_duplicate","resolved_false_positive","resolved_true_positive","resolved_security_testing" or "resolved_other".  | 
| PaloAltoNetworksXDR.Incident.description | String | Dynamic calculated description of the incident. | 
| PaloAltoNetworksXDR.Incident.resolve_comment | String | Comments entered by the user when the incident was resolved. | 
| PaloAltoNetworksXDR.Incident.notes | String | Comments entered by the user regarding the incident. | 
| PaloAltoNetworksXDR.Incident.creation_time | date | Date and time the incident was created on Cortex XDR. | 
| PaloAltoNetworksXDR.Incident.detection_time | date | Date and time that the first alert occurred in the incident. | 
| PaloAltoNetworksXDR.Incident.modification_time | date | Date and time that the incident was last modified. | 


##### Command Example

```!xdr-get-incidents gte_creation_time=2010-10-10T00:00:00 limit=3 sort_by_creation_time=desc```

##### Context Example

```
{
    "PaloAltoNetworksXDR.Incident": [
        {
            "host_count": 1, 
            "incident_id": "4", 
            "manual_severity": "medium", 
            "description": "5 'This alert from content  TestXDRPlaybook' alerts detected by Checkpoint - SandBlast  ", 
            "severity": "medium", 
            "modification_time": 1579290004178, 
            "assigned_user_pretty_name": null, 
            "notes": null, 
            "creation_time": 1577276587937, 
            "alert_count": 5, 
            "med_severity_alert_count": 1, 
            "detection_time": null, 
            "assigned_user_mail": null, 
            "resolve_comment": "This issue was solved in Incident number 192304", 
            "status": "new", 
            "user_count": 1, 
            "xdr_url": "https://some.xdr.url.com/incident-view/4", 
            "starred": false, 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 4, 
            "manual_description": null
        }, 
        {
            "host_count": 1, 
            "incident_id": "3", 
            "manual_severity": "medium", 
            "description": "'test 1' generated by Virus Total - Firewall", 
            "severity": "medium", 
            "modification_time": 1579237974014, 
            "assigned_user_pretty_name": "woo@test.com", 
            "notes": null, 
            "creation_time": 1576100096594, 
            "alert_count": 1, 
            "med_severity_alert_count": 0, 
            "detection_time": null, 
            "assigned_user_mail": "woo@test.com", 
            "resolve_comment": null, 
            "status": "new", 
            "user_count": 1, 
            "xdr_url": "https://some.xdr.url.com/incident-view/3", 
            "starred": false, 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 1, 
            "manual_description": null
        }, 
        {
            "host_count": 1, 
            "incident_id": "2", 
            "manual_severity": "high", 
            "description": "'Alert Name Example 333' along with 1 other alert generated by Virus Total - VPN & Firewall-3 and Checkpoint - SandBlast", 
            "severity": "high", 
            "modification_time": 1579288790259, 
            "assigned_user_pretty_name": null, 
            "notes": null, 
            "creation_time": 1576062816474, 
            "alert_count": 2, 
            "med_severity_alert_count": 0, 
            "detection_time": null, 
            "assigned_user_mail": null, 
            "resolve_comment": null, 
            "status": "under_investigation", 
            "user_count": 1, 
            "xdr_url": "https://some.xdr.url.com/incident-view/2", 
            "starred": false, 
            "low_severity_alert_count": 0, 
            "high_severity_alert_count": 2, 
            "manual_description": null
        }
    ]
}
```

##### Human Readable Output

>### Incidents

>|alert_count| assigned_user_mail | assigned_user_pretty_name |creation_time|description|detection_time|high_severity_alert_count|host_count|incident_id|low_severity_alert_count|manual_description|manual_severity|med_severity_alert_count|modification_time|notes|resolve_comment|severity|starred|status|user_count|xdr_url|
>|---|--------------------|---------------------------|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 5 |                    |                           | 1577276587937 | 5 'This alert from content  TestXDRPlaybook' alerts detected by Checkpoint - SandBlast   |  | 4 | 1 | 4 | 0 |  | medium | 1 | 1579290004178 |  | This issue was solved in Incident number 192304 | medium | false | new | 1 | `https://some.xdr.url.com/incident-view/4` |
>| 1 | woo@test.com       | woo@test.com              | 1576100096594 | 'test 1' generated by Virus Total - Firewall |  | 1 | 1 | 3 | 0 |  | medium | 0 | 1579237974014 |  |  | medium | false | new | 1 | `https://some.xdr.url.com/incident-view/3` |
>| 2 |                    |                           | 1576062816474 | 'Alert Name Example 333' along with 1 other alert generated by Virus Total - VPN & Firewall-3 and Checkpoint - SandBlast |  | 2 | 1 | 2 | 0 |  | high | 0 | 1579288790259 |  |  | high | false | under_investigation | 1 | `https://some.xdr.url.com/incident-view/2` |


### xdr-get-incident-extra-data

***
Returns additional data for the specified incident, for example, related alerts, file artifacts, network artifacts, and so on.

##### Required Permissions

Required Permissions For API call:
`Alerts And Incidents` --> `View`

Builtin Roles with this permission includes: "Investigator", "Responder", "Privileged Investigator", "Privileged Responder", "Viewer", and "Instance Admin".

#### Base Command

`xdr-get-incident-extra-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | The ID of the incident for which to get additional data. | Required | 
| alerts_limit | Maximum number of alerts to return. Default is 1000. | Optional | 
| return_only_updated_incident | Return data only if the incident was changed since the last time it was mirrored into Cortex XSOAR.  This flag should be used only from within a Cortex XDR incident. Default is False. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Incident.incident_id | String | Unique ID assigned to each returned incident. | 
| PaloAltoNetworksXDR.Incident.creation_time | Date | Date and time the incident was created on Cortex XDR. | 
| PaloAltoNetworksXDR.Incident.modification_time | Date | Date and time that the incident was last modified. | 
| PaloAltoNetworksXDR.Incident.detection_time | Date | Date and time that the first alert occurred in the incident. | 
| PaloAltoNetworksXDR.Incident.status | String | Current status of the incident. Valid values are:
"new","under_investigation","resolved_known_issue","resolved_duplicate","resolved_false_positive","resolved_true_positive","resolved_security_testing","resolved_other" | 
| PaloAltoNetworksXDR.Incident.severity | String | Calculated severity of the incident. Valid values are: "low","medium","high" | 
| PaloAltoNetworksXDR.Incident.description | String | Dynamic calculated description of the incident. | 
| PaloAltoNetworksXDR.Incident.assigned_user_mail | String | Email address of the assigned user. | 
| PaloAltoNetworksXDR.Incident.assigned_user_pretty_name | String | Full name of the user assigned to the incident. | 
| PaloAltoNetworksXDR.Incident.alert_count | Number | Total number of alerts in the incident. | 
| PaloAltoNetworksXDR.Incident.low_severity_alert_count | Number | Number of alerts with the severity LOW. | 
| PaloAltoNetworksXDR.Incident.med_severity_alert_count | Number | Number of alerts with the severity MEDIUM. | 
| PaloAltoNetworksXDR.Incident.high_severity_alert_count | Number | Number of alerts with the severity HIGH. | 
| PaloAltoNetworksXDR.Incident.user_count | Number | Number of users involved in the incident. | 
| PaloAltoNetworksXDR.Incident.host_count | Number | Number of hosts involved in the incident | 
| PaloAltoNetworksXDR.Incident.notes | Unknown | Comments entered by the user regarding the incident. | 
| PaloAltoNetworksXDR.Incident.resolve_comment | String | Comments entered by the user when the incident was resolved. | 
| PaloAltoNetworksXDR.Incident.manual_severity | String | Incident severity assigned by the user. This does not affect the calculated severity of low, medium, or high. | 
| PaloAltoNetworksXDR.Incident.manual_description | String | Incident description provided by the user. | 
| PaloAltoNetworksXDR.Incident.xdr_url | String | A link to the incident view on Cortex XDR. | 
| PaloAltoNetworksXDR.Incident.starred | Boolean | Incident starred. | 
| PaloAltoNetworksXDR.Incident.wildfire_hits.mitre_techniques_ids_and_names | String | Incident Mitre techniques IDs and names. | 
| PaloAltoNetworksXDR.Incident.wildfire_hits.mitre_tactics_ids_and_names | String | Incident Mitre tactics ids and names. | 
| PaloAltoNetworksXDR.Incident.alerts.alert_id | String | Unique ID for each alert. | 
| PaloAltoNetworksXDR.Incident.alerts.detection_timestamp | Date | Date and time that the alert occurred. | 
| PaloAltoNetworksXDR.Incident.alerts.source | String | Source of the alert. The product/vendor this alert came from. | 
| PaloAltoNetworksXDR.Incident.alerts.severity | String | Severity of the alert.Valid values are: "low","medium","high""" | 
| PaloAltoNetworksXDR.Incident.alerts.name | String | Calculated name of the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.category | String | Category of the alert, for example, Spyware Detected via Anti-Spyware profile. | 
| PaloAltoNetworksXDR.Incident.alerts.description | String | Textual description of the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.host_ip_list | Unknown | Host IP involved in the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.host_name | String | Host name involved in the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.user_name | String | User name involved with the alert. | 
| PaloAltoNetworksXDR.Incident.alerts.event_type | String | Event type. Valid values are: "Process Execution","Network Event","File Event","Registry Event","Injection Event","Load Image Event","Windows Event Log" | 
| PaloAltoNetworksXDR.Incident.alerts.action | String | The action that triggered the alert. Valid values are: "REPORTED", "BLOCKED", "POST_DETECTED", "SCANNED", "DOWNLOAD", "PROMPT_ALLOW", "PROMPT_BLOCK", "DETECTED", "BLOCKED_1", "BLOCKED_2", "BLOCKED_3", "BLOCKED_5", "BLOCKED_6", "BLOCKED_7", "BLOCKED_8", "BLOCKED_9", "BLOCKED_10", "BLOCKED_11", "BLOCKED_13", "BLOCKED_14", "BLOCKED_15", "BLOCKED_16", "BLOCKED_17", "BLOCKED_24", "BLOCKED_25", "DETECTED_0", "DETECTED_4", "DETECTED_18", "DETECTED_19", "DETECTED_20", "DETECTED_21", "DETECTED_22", "DETECTED_23" | 
| PaloAltoNetworksXDR.Incident.alerts.action_pretty | String | The action that triggered the alert. Valid values are: "Detected \(Reported\)" "Prevented \(Blocked\)" "Detected \(Post Detected\)" "Detected \(Scanned\)" "Detected \(Download\)" "Detected \(Prompt Allow\)" "Prevented \(Prompt Block\)" "Detected" "Prevented \(Denied The Session\)" "Prevented \(Dropped The Session\)" "Prevented \(Dropped The Session And Sent a TCP Reset\)" "Prevented \(Blocked The URL\)" "Prevented \(Blocked The IP\)" "Prevented \(Dropped The Packet\)" "Prevented \(Dropped All Packets\)" "Prevented \(Terminated The Session And Sent a TCP Reset To Both Sides Of The Connection\)" "Prevented \(Terminated The Session And Sent a TCP Reset To The Client\)" "Prevented \(Terminated The Session And Sent a TCP Reset To The Server\)" "Prevented \(Continue\)" "Prevented \(Block-Override\)" "Prevented \(Override-Lockout\)" "Prevented \(Override\)" "Prevented \(Random-Drop\)" "Prevented \(Silently Dropped The Session With An ICMP Unreachable Message To The Host Or Application\)" "Prevented \(Block\)" "Detected \(Allowed The Session\)" "Detected \(Raised An Alert\)" "Detected \(Syncookie Sent\)" "Detected \(Forward\)" "Detected \(Wildfire Upload Success\)" "Detected \(Wildfire Upload Failure\)" "Detected \(Wildfire Upload Skip\)" "Detected \(Sinkhole\)" | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_image_name | String | Image name. | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_command_line | String | Command line. | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_signature_status | String | Signature status. Valid values are: "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash". | 
| PaloAltoNetworksXDR.Incident.alerts.actor_process_signature_vendor | String | Signature vendor name. | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_image_name | String | Image name. | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_command_line | String | Command line. | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_signature_status | String | Signature status. Valid values are: "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash" | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_process_signature_vendor | String | Signature vendor. | 
| PaloAltoNetworksXDR.Incident.alerts.causality_actor_causality_id | Unknown | Causality ID. | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_name | String | Image name. | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_command_line | String | Command line. | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_image_sha256 | String | Image SHA256. | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_signature_status | String | Signature status. Valid values are: "Signed" "Invalid Signature" "Unsigned" "Revoked" "Signature Fail" "N/A" "Weak Hash" | 
| PaloAltoNetworksXDR.Incident.alerts.action_process_signature_vendor | String | Signature vendor name. | 
| PaloAltoNetworksXDR.Incident.alerts.action_file_path | String | File path. | 
| PaloAltoNetworksXDR.Incident.alerts.action_file_md5 | String | File MD5. | 
| PaloAltoNetworksXDR.Incident.alerts.action_file_sha256 | String | File SHA256. | 
| PaloAltoNetworksXDR.Incident.alerts.action_registry_data | String | Registry data. | 
| PaloAltoNetworksXDR.Incident.alerts.action_registry_full_key | String | Registry full key. | 
| PaloAltoNetworksXDR.Incident.alerts.action_local_ip | String | Local IP. | 
| PaloAltoNetworksXDR.Incident.alerts.action_local_port | Number | Local port. | 
| PaloAltoNetworksXDR.Incident.alerts.action_remote_ip | String | Remote IP. | 
| PaloAltoNetworksXDR.Incident.alerts.action_remote_port | Number | Remote port. | 
| PaloAltoNetworksXDR.Incident.alerts.action_external_hostname | String | External hostname. | 
| PaloAltoNetworksXDR.Incident.alerts.fw_app_id | Unknown | Firewall app id. | 
| PaloAltoNetworksXDR.Incident.alerts.is_whitelisted | String | Is the alert on allow list. Valid values are: "Yes" "No" | 
| PaloAltoNetworksXDR.Incident.alerts.starred | Boolean | Alert starred. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.type | String | Network artifact type. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_port | number | The remote port related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.alert_count | number | Number of alerts related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_remote_ip | String | The remote IP related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.is_manual | boolean | Whether the artifact was created by the user \(manually\). | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_domain | String | The domain related to the artifact. | 
| PaloAltoNetworksXDR.Incident.network_artifacts.type | String | The artifact type. Valid values are: "META", "GID", "CID", "HASH", "IP", "DOMAIN", "REGISTRY", "HOSTNAME" | 
| PaloAltoNetworksXDR.Incident.network_artifacts.network_country | String | The country related to the artifact. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_status | String | Digital signature status of the file. Valid values are: "SIGNATURE_UNAVAILABLE" "SIGNATURE_SIGNED" "SIGNATURE_INVALID" "SIGNATURE_UNSIGNED" "SIGNATURE_WEAK_HASH" | 
| PaloAltoNetworksXDR.Incident.file_artifacts.is_process | boolean | Whether the file artifact is related to a process execution. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_name | String | Name of the file. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_wildfire_verdict | String | The file verdict, calculated by Wildfire. Valid values are: "BENIGN" "MALWARE" "GRAYWARE" "PHISHING" "UNKNOWN". | 
| PaloAltoNetworksXDR.Incident.file_artifacts.alert_count | number | Number of alerts related to the artifact. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.is_malicious | boolean | Whether the artifact is malicious, as decided by the Wildfire verdict. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.is_manual | boolean | Whether the artifact was created by the user \(manually\). | 
| PaloAltoNetworksXDR.Incident.file_artifacts.type | String | The artifact type. Valid values are: "META" "GID" "CID" "HASH" "IP" "DOMAIN" "REGISTRY" "HOSTNAME" | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_sha256 | String | SHA256 hash of the file. | 
| PaloAltoNetworksXDR.Incident.file_artifacts.file_signature_vendor_name | String | File signature vendor name. | 
| Account.Username | String | The username in the relevant system. | 
| Endpoint.Hostname | String | The hostname that is mapped to this endpoint. | 
| Endpoint.ID | String | The agent ID of the endpoint. | 
| File.Path | String | The path where the file is located. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.Name | String | The full file name \(including file extension\). | 
| Process.Name | String | The name of the process. | 
| Process.MD5 | String | The MD5 hash of the process. | 
| Process.SHA256 | String | The SHA256 hash of the process. | 
| Process.PID | String | The PID of the process. | 
| Process.Path | String | The file system path to the binary file. | 
| Process.Start Time | String | The timestamp of the process start time. | 
| Process.CommandLine | String | The full command line \(including arguments\). | 
| Process.is_malicious | boolean | Whether the artifact is malicious, as decided by the Wildfire verdict. | 
| IP.Address | String | IP address. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| Domain.Name | String | The domain name, for example: "google.com". | 

##### Human Readable Output

>### Incident 4

>|alert_count|assigned_user_mail|assigned_user_pretty_name|creation_time|description|detection_time|high_severity_alert_count|host_count|incident_id|low_severity_alert_count|manual_description|manual_severity|med_severity_alert_count|modification_time|notes|resolve_comment|severity|starred|status|user_count|xdr_url|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 5 |  |  | 1577276587937 | 5 'This alert from content  TestXDRPlaybook' alerts detected by Checkpoint - SandBlast   |  | 4 | 1 | 4 | 0 |  | medium | 1 | 1579290004178 |  | This issue was solved in Incident number 192304 | medium | false | new | 1 | `https://some.xdr.url.com/incident-view/4` |
>
>### Alerts

>|action|action_external_hostname|action_file_md5|action_file_path|action_file_sha256|action_local_ip|action_local_port|action_pretty|action_process_image_command_line|action_process_image_name|action_process_image_sha256|action_process_signature_status|action_process_signature_vendor|action_registry_data|action_registry_full_key|action_remote_ip|action_remote_port|actor_process_command_line|actor_process_image_name|actor_process_signature_status|actor_process_signature_vendor|alert_id|category|causality_actor_causality_id|causality_actor_process_command_line|causality_actor_process_image_name|causality_actor_process_signature_status|causality_actor_process_signature_vendor|description|detection_timestamp|event_type|fw_app_id|host_ip_list|host_name|is_whitelisted|name|severity|source|starred|user_name|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| VALUE_NA,<br/>N/A |  |  |  |  | 196.168.0.1 | 7000 | VALUE_NA,<br/>N/A |  |  |  | N/A | N/A |  |  | 2.2.2.2 | 8000 |  |  | N/A | N/A | 6 |  |  |  |  | N/A | N/A | Test - alert generated by Test XDR Playbook | 1577276586921 | Network Event |  |  |  | No | Test - alert generated by Test XDR Playbook | medium | Cisco - Sandblast | false |  |
>| VALUE_NA,<br/>N/A |  |  |  |  | 196.168.0.111 | 2000 | VALUE_NA,<br/>N/A |  |  |  | N/A | N/A |  |  | 2.2.2.2 | 6000 |  |  | N/A | N/A | 7 |  |  |  |  | N/A | N/A | This alert from content  TestXDRPlaybook description | 1577776701589 | Network Event |  |  |  | No | This alert from content  TestXDRPlaybook | high | Checkpoint - SandBlast | false |  |
>| VALUE_NA,<br/>N/A |  |  |  |  | 196.168.0.111 | 2000 | VALUE_NA,<br/>N/A |  |  |  | N/A | N/A |  |  | 2.2.2.2 | 6000 |  |  | N/A | N/A | 8 |  |  |  |  | N/A | N/A | This alert from content  TestXDRPlaybook description | 1577958479843 | Network Event |  |  |  | No | This alert from content  TestXDRPlaybook | high | Checkpoint - SandBlast | false |  |
>| VALUE_NA,<br/>N/A |  |  |  |  | 196.168.0.111 | 2000 | VALUE_NA,<br/>N/A |  |  |  | N/A | N/A |  |  | 2.2.2.2 | 6000 |  |  | N/A | N/A | 9 |  |  |  |  | N/A | N/A | This alert from content  TestXDRPlaybook description | 1578123895414 | Network Event |  |  |  | No | This alert from content  TestXDRPlaybook | high | Checkpoint - SandBlast | false |  |
>| VALUE_NA,<br/>N/A |  |  |  |  | 196.168.0.111 | 2000 | VALUE_NA,<br/>N/A |  |  |  | N/A | N/A |  |  | 2.2.2.2 | 6000 |  |  | N/A | N/A | 10 |  |  |  |  | N/A | N/A | This alert from content  TestXDRPlaybook description | 1578927443615 | Network Event |  |  |  | No | This alert from content  TestXDRPlaybook | high | Checkpoint - SandBlast | false |  |
>
>### Network Artifacts

>|alert_count|is_manual|network_country|network_domain|network_remote_ip|network_remote_port|type|
>|---|---|---|---|---|---|---|
>| 5 | false |  |  | 2.2.2.2 | 8000 | IP |
>
>### File Artifacts

>**No entries.**

### xdr-update-incident

***
Updates one or more fields of a specified incident. Missing fields will be ignored. To remove the assignment for an incident, pass a null value in the assignee email argument.

##### Required Permissions

Required Permissions For API call:
`Alerts And Incidents` --> `View / Edit`

Builtin Roles with this permission includes: "Investigator", "Privileged Investigator", "Privileged Responder", and "Instance Admin".

#### Base Command

`xdr-update-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | XDR incident ID. You can get the incident ID from the output of the 'xdr-get-incidents' command or the 'xdr-get-incident-extra-details' command. | Required | 
| manual_severity | Severity to assign to the incident (LOW, MEDIUM, or HIGH). Possible values are: HIGH, MEDIUM, LOW. | Optional | 
| assigned_user_mail | Email address of the user to assign to the incident. | Optional | 
| assigned_user_pretty_name | Full name of the user assigned to the incident. To supply a new value in this field, you must also provide a value for the 'assigned_user_mail' argument. | Optional | 
| status | Status of the incident. Valid values are: NEW, UNDER_INVESTIGATION, RESOLVED_KNOWN_ISSUE, RESOLVED_DUPLICATE, RESOLVED_FALSE_POSITIVE, RESOLVED_TRUE_POSITIVE, RESOLVED_SECURITY_TESTING, RESOLVED_OTHER. Possible values are: NEW, UNDER_INVESTIGATION, RESOLVED_KNOWN_ISSUE, RESOLVED_DUPLICATE, RESOLVED_FALSE_POSITIVE, RESOLVED_TRUE_POSITIVE, RESOLVED_SECURITY_TESTING, RESOLVED_OTHER. | Optional | 
| resolve_comment | Comment explaining why the incident was resolved. This should be set when the incident is resolved. | Optional | 
| unassign_user | If true, will remove all assigned users from the incident. Possible values are: true. | Optional | 

##### Command Example

```!xdr-update-incident incident_id=4```

#### Context Output

There is no context output for this command.

##### Human Readable Output

```Incident 4 has been updated```

### xdr-insert-parsed-alert

***
Uploads an alert from external alert sources in Cortex XDR format. Cortex XDR displays alerts that are parsed
successfully in related incidents and views. You can send 600 alerts per minute. Each request can contain a
maximum of 60 alerts.

##### Required Permissions

Required Permissions For API call:
`External Alerts Mapping`--> `View`

Builtin Roles with this permission includes: "Instance Admin".

#### Base Command

`xdr-insert-parsed-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product | String value that defines the product. | Required | 
| vendor | String value that defines the vendor. | Required | 
| local_ip | String value for the source IP address. | Optional | 
| local_port | Integer value for the source port. | Required | 
| remote_ip | String value of the destination IP<br/>address. | Required | 
| remote_port | Integer value for the destination<br/>port. | Required | 
| event_timestamp | Integer value representing the time the alert occurred in milliseconds, or a string value in date format 2019-10-23T10:00:00. If not set, the event time will be defined as now. | Optional | 
| severity | String value of alert severity. Valid values are:<br/>Informational, Low, Medium or High. Possible values are: Informational, Low, Medium, High. Default is Medium. | Optional | 
| alert_name | String defining the alert name. | Required | 
| alert_description | String defining the alert description. | Optional | 


#### Context Output

There is no context output for this command.

### xdr-insert-cef-alerts

***
Upload alerts in CEF format from external alert sources. After you map CEF alert fields to Cortex XDR fields, Cortex XDR displays the alerts in related incidents and views. You can send 600 requests per minute. Each request can contain a maximum of 60 alerts.

##### Required Permissions

Required Permissions For API call:
`External Alerts Mapping`--> `View`

Builtin Roles with this permission includes: "Instance Admin".

#### Base Command

`xdr-insert-cef-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cef_alerts | List of alerts in CEF format. | Required | 


#### Context Output

There is no context output for this command.

### xdr-endpoint-isolate

***
Isolates the specified endpoint.

##### Required Permissions

Required Permissions For API call:
`Endpoint Administrations` --> `View`
`Action Center` --> `View/ Edit`
`Action Center` --> `Isolate`

Builtin Roles with this permission includes: "Privileged Responder" and "Instance Admin".


#### Base Command

`xdr-endpoint-isolate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_id | The endpoint ID (string) to isolate. You can retrieve the string from the xdr-get-endpoints command. | Required | 
| suppress_disconnected_endpoint_error | Whether to suppress an error when trying to isolate a disconnected endpoint. When sets to false, an error will be returned. Possible values are: true, false. Default is false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | For polling use. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Isolation.endpoint_id | String | The endpoint ID. | 

### xdr-endpoint-unisolate

***
Reverses the isolation of an endpoint.

##### Required Permissions

Required Permissions For API call:
`Endpoint Administrations` --> `View`
`Action Center` --> `View/ Edit`
`Action Center` --> `Isolate`

Builtin Roles with this permission includes: "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-endpoint-unisolate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_id | The endpoint ID (string) for which to reverse the isolation. You can retrieve it from the xdr-get-endpoints command. | Required | 
| suppress_disconnected_endpoint_error | Whether to suppress an error when trying to unisolate a disconnected endpoint. When sets to false, an error will be returned. Possible values are: true, false. Default is false. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | For polling use. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.UnIsolation.endpoint_id | String | Isolates the specified endpoint. | 

### xdr-get-endpoints

***
Gets a list of endpoints, according to the passed filters. If there are no filters, all endpoints are returned. Filtering by multiple fields will be concatenated using AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of endpoint from the start of the result set (start by counting from 0).

##### Required Permissions

Required Permissions For API call:
`Endpoint Administrations` --> `View`

Builtin Roles with this permission includes: "Privileged Responder", "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-endpoints`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | A comma-separated list of endpoints statuses to filter. Valid values are: connected, disconnected, lost, uninstalled, windows, linux, macos, android, isolated, unisolated. | Optional |
| endpoint_id_list | A comma-separated list of endpoint IDs. | Optional | 
| dist_name | A comma-separated list of distribution package names or installation package names.<br/>Example: dist_name1,dist_name2. | Optional | 
| ip_list | A comma-separated list of private IP addresses.<br/>Example: Example: 10.1.1.1,192.168.1.1. | Optional | 
| public_ip_list | A comma-separated list of public IP addresses that correlate to the last IPv4 address from which the Cortex XDR agent connected (know as `Last Origin IP`).<br/>Example: 8.8.8.8,1.1.1.1. | Optional | 
| group_name | The group name to which the agent belongs.<br/>Example: group_name1,group_name2. | Optional | 
| platform | The endpoint platform. Valid values are\: "windows", "linux", "macos", or "android". . Possible values are: windows, linux, macos, android. | Optional | 
| alias_name | A comma-separated list of alias names.<br/>Examples: alias_name1,alias_name2. | Optional | 
| isolate | Specifies whether the endpoint was isolated or unisolated. Possible values are: isolated, unisolated. | Optional | 
| hostname | Hostname<br/>Example: hostname1,hostname2. | Optional | 
| first_seen_gte | All the agents that were first seen after {first_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| first_seen_lte | All the agents that were first seen before {first_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_gte | All the agents that were last seen before {last_seen_gte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_lte | All the agents that were last seen before {last_seen_lte}.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | Maximum number of endpoints to return per page. The default and maximum is 30. Default is 30. | Optional | 
| sort_by | Specifies whether to sort endpoints by the first time or last time they were seen. Can be "first_seen" or "last_seen". Possible values are: first_seen, last_seen. | Optional | 
| sort_order | The order by which to sort results. Can be "asc" (ascending) or "desc" ( descending). Default set to asc. Possible values are: asc, desc. Default is asc. | Optional | 
| username | The usernames to query for, accepts a single user, or comma-separated list of usernames. | Optional | 
| all_results | Whether to return all endpoints. If true, will override the 'limit' and 'page' arguments. Possible values are: false, true. Default is false. | Optional | 
| use_hr_timestamps | Whether to return timestamp values in human-readable format as opposed to Unix epoch timestamp format. Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Endpoint.endpoint_id | String | The endpoint ID. | 
| PaloAltoNetworksXDR.Endpoint.endpoint_name | String | The endpoint name. | 
| PaloAltoNetworksXDR.Endpoint.endpoint_type | String | The endpoint type. | 
| PaloAltoNetworksXDR.Endpoint.endpoint_status | String | The status of the endpoint. | 
| PaloAltoNetworksXDR.Endpoint.os_type | String | The endpoint OS type. | 
| PaloAltoNetworksXDR.Endpoint.ip | Unknown | A list of IP addresses. | 
| PaloAltoNetworksXDR.Endpoint.users | Unknown | A list of users. | 
| PaloAltoNetworksXDR.Endpoint.domain | String | The endpoint domain. | 
| PaloAltoNetworksXDR.Endpoint.alias | String | The endpoint's aliases. | 
| PaloAltoNetworksXDR.Endpoint.first_seen | Unknown | First seen date/time in Epoch \(milliseconds\). | 
| PaloAltoNetworksXDR.Endpoint.last_seen | Date | Last seen date/time in Epoch \(milliseconds\). | 
| PaloAltoNetworksXDR.Endpoint.content_version | String | Content version. | 
| PaloAltoNetworksXDR.Endpoint.installation_package | String | Installation package. | 
| PaloAltoNetworksXDR.Endpoint.active_directory | String | Active directory. | 
| PaloAltoNetworksXDR.Endpoint.install_date | Date | Install date in Epoch \(milliseconds\). | 
| PaloAltoNetworksXDR.Endpoint.endpoint_version | String | Endpoint version. | 
| PaloAltoNetworksXDR.Endpoint.is_isolated | String | Whether the endpoint is isolated. | 
| PaloAltoNetworksXDR.Endpoint.group_name | String | The name of the group to which the endpoint belongs. | 
| PaloAltoNetworksXDR.Endpoint.count | String | Number of endpoints returned. | 
| Endpoint.Hostname | String | The hostname that is mapped to this endpoint. | 
| Endpoint.ID | String | The unique ID within the tool retrieving the endpoint. | 
| Endpoint.IPAddress | String | The IP address of the endpoint. | 
| Endpoint.Domain | String | The domain of the endpoint. | 
| Endpoint.OS | String | The endpoint's operation system. | 
| Account.Username | String | The username in the relevant system. | 
| Account.Domain | String | The domain of the account. | 
| Endpoint.Status | String | The endpoint's status. | 
| Endpoint.IsIsolated | String | The endpoint's isolation status. | 
| Endpoint.MACAddress | String | The endpoint's MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 

##### Command Example

```!xdr-get-endpoints isolate="unisolated" first_seen_gte="3 month" page="0" limit="30" sort_order="asc"```

##### Context Example

```
{
    "Endpoint": [
        {
            "Domain": "WORKGROUP",
            "Hostname": "aaaaa.compute.internal",
            "ID": "ea303670c76e4ad09600c8b346f7c804",
            "IPAddress": [
                "172.31.11.11"
            ],
            "OS": "Windows",
            "Status" : "Online",
            "IsIsolated" : "No",
            "Vendor": "Cortex XDR - IR"
        },
        {
            "Domain": "WORKGROUP",
            "Hostname": "EC2AMAZ-P7PPOI4",
            "ID": "f8a2f58846b542579c12090652e79f3d",
            "IPAddress": [
                "2.2.2.2"
            ],
            "OS": "Windows",
            "Status" : "Online",
            "IsIsolated" : "No",
            "Vendor": "Cortex XDR - IR"
        }
    ],
    "PaloAltoNetworksXDR.Endpoint": [
        {
            "domain": "", 
            "users": [
                "ec2-user"
            ], 
            "endpoint_name": "aaaaa.compute.internal", 
            "ip": [
                "172.31.11.11"
            ], 
            "install_date": 1575795969644, 
            "endpoint_version": "7.0.0.1915", 
            "group_name": null, 
            "installation_package": "linux", 
            "alias": "", 
            "active_directory": null, 
            "endpoint_status": "CONNECTED", 
            "os_type": "AGENT_OS_LINUX", 
            "endpoint_id": "ea303670c76e4ad09600c8b346f7c804", 
            "content_version": "111-17757", 
            "first_seen": 1575795969644, 
            "endpoint_type": "AGENT_TYPE_SERVER", 
            "is_isolated": "AGENT_UNISOLATED", 
            "last_seen": 1579290023629
        }, 
        {
            "domain": "WORKGROUP", 
            "users": [
                "Administrator"
            ], 
            "endpoint_name": "EC2AMAZ-P7PPOI4", 
            "ip": [
                "2.2.2.2"
            ], 
            "install_date": 1575796381739, 
            "endpoint_version": "7.0.0.27797", 
            "group_name": null, 
            "installation_package": "Windows Server 2016", 
            "alias": "", 
            "active_directory": null, 
            "endpoint_status": "CONNECTED", 
            "os_type": "AGENT_OS_WINDOWS", 
            "endpoint_id": "f8a2f58846b542579c12090652e79f3d", 
            "content_version": "111-17757", 
            "first_seen": 1575796381739, 
            "endpoint_type": "AGENT_TYPE_SERVER", 
            "is_isolated": "AGENT_UNISOLATED", 
            "last_seen": 1579289957412
        }
    ]
}
```

##### Human Readable Output

>### Endpoints

>|active_directory|alias|content_version|domain|endpoint_id|endpoint_name|endpoint_status|endpoint_type|endpoint_version|first_seen|group_name|install_date|installation_package|ip|is_isolated|last_seen|os_type|users|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  | 111-17757 |  | ea303670c76e4ad09600c8b346f7c804 | aaaaa.compute.internal | CONNECTED | AGENT_TYPE_SERVER | 7.0.0.1915 | 1575795969644 |  | 1575795969644 | linux | 172.31.11.11 | AGENT_UNISOLATED | 1579290023629 | AGENT_OS_LINUX | ec2-user |
>|  |  | 111-17757 | WORKGROUP | f8a2f58846b542579c12090652e79f3d | EC2AMAZ-P7PPOI4 | CONNECTED | AGENT_TYPE_SERVER | 7.0.0.27797 | 1575796381739 |  | 1575796381739 | Windows Server 2016 | 2.2.2.2 | AGENT_UNISOLATED | 1579289957412 | AGENT_OS_WINDOWS | Administrator |


### xdr-get-distribution-versions

***
Gets a list of all the agent versions to use for creating a distribution list.

##### Required Permissions

Required Permissions For API call:
`Endpoint Installations` --> `View`

Builtin Roles with this permission includes: "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-distribution-versions`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.DistributionVersions.windows | Unknown | A list of Windows agent versions. | 
| PaloAltoNetworksXDR.DistributionVersions.linux | Unknown | A list of Linux agent versions. | 
| PaloAltoNetworksXDR.DistributionVersions.macos | Unknown | A list of Mac agent versions. | 


##### Command Example

```!xdr-get-distribution-versions```

##### Context Example

```
{
    "PaloAltoNetworksXDR.DistributionVersions": {
        "windows": [
            "5.0.8.29673", 
            "5.0.9.30963", 
            "6.1.4.28751", 
            "7.0.0.28644"
        ], 
        "macos": [
            "6.1.4.1681", 
            "7.0.0.1914"
        ], 
        "linux": [
            "6.1.4.1680", 
            "7.0.0.1916"
        ]
    }
}
```

##### Human Readable Output

>### windows

>|versions|
>|---|
>| 5.0.8.29673 |
>| 5.0.9.30963 |
>| 6.1.4.28751 |
>| 7.0.0.28644 |
>
>
>### linux

>|versions|
>|---|
>| 6.1.4.1680 |
>| 7.0.0.1916 |
>
>
>### macos

>|versions|
>|---|
>| 6.1.4.1681 |
>| 7.0.0.1914 |


### xdr-create-distribution

***
Creates an installation package. This is an asynchronous call that returns the distribution ID. This does not mean that the creation succeeded. To confirm that the package has been created, check the status of the distribution by running the Get Distribution Status API.

##### Required Permissions

Required Permissions For API call:
`Endpoint Installations` --> `View/ Edit`

Builtin Roles with this permission includes: "Instance Admin".

#### Base Command

`xdr-create-distribution`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A string representing the name of the installation package. | Required | 
| platform | String, valid values are:<br/>• windows <br/>• linux<br/>• macos <br/>• android. Possible values are: windows, linux, macos, android. | Required | 
| package_type | A string representing the type of package to create.<br/>standalone - An installation for a new agent<br/>upgrade - An upgrade of an agent from ESM. Possible values are: standalone, upgrade. | Required | 
| agent_version | agent_version returned from xdr-get-distribution-versions. Not required for Android platform. | Required | 
| description | Information about the package. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Distribution.id | String | The installation package ID. | 
| PaloAltoNetworksXDR.Distribution.name | String | The name of the installation package. | 
| PaloAltoNetworksXDR.Distribution.platform | String | The installation OS. | 
| PaloAltoNetworksXDR.Distribution.agent_version | String | Agent version. | 
| PaloAltoNetworksXDR.Distribution.description | String | Information about the package. | 


##### Command Example

```!xdr-create-distribution agent_version=6.1.4.1680 name="dist_1" package_type=standalone platform=linux description="some description"```

##### Context Example

```
{
    "PaloAltoNetworksXDR.Distribution": {
        "description": "some description", 
        "package_type": "standalone", 
        "platform": "linux", 
        "agent_version": "6.1.4.1680", 
        "id": "43aede7f846846fa92b50149663fbb25", 
        "name": "dist_1"
    }
}
```

##### Human Readable Output

Distribution 43aede7f846846fa92b50149663fbb25 created successfully

### xdr-get-distribution-url

***
Gets the distribution URL for downloading the installation package.

##### Required Permissions

Required Permissions For API call:
`Endpoint Installations` --> `View`

Builtin Roles with this permission includes: "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-distribution-url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| distribution_id | The ID of the installation package.<br/>Copy the distribution_id from the "id" field on Endpoints &gt; Agent Installation page. | Required | 
| package_type | The installation package type. Valid<br/>values are:<br/>• upgrade<br/>• sh - For Linux<br/>• rpm - For Linux<br/>• deb - For Linux<br/>• pkg - For Mac<br/>• x86 - For Windows<br/>• x64 - For Windows. Possible values are: upgrade, sh, rpm, deb, pkg, x86, x64. | Required | 
| download_package | Supported only for package_type x64 or x86. Whether to download the installation package file. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Distribution.id | String | Distribution ID. | 
| PaloAltoNetworksXDR.Distribution.url | String | URL for downloading the installation package. | 

##### Command Example

```!xdr-get-distribution-url distribution_id=2c74c11b63074653aa01d575a82bf52a package_type=sh```


### xdr-get-create-distribution-status

***
Gets the status of the installation package.

##### Required Permissions

Required Permissions For API call:
`Endpoint Installations` --> `View`

Builtin Roles with this permission includes: "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-create-distribution-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| distribution_ids | A comma-separated list of distribution IDs to get the status for. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Distribution.id | String | Distribution ID. | 
| PaloAltoNetworksXDR.Distribution.status | String | The status of installation package. | 

##### Command Example

```!xdr-get-create-distribution-status distribution_ids=2c74c11b63074653aa01d575a82bf52a```

### xdr-get-audit-management-logs

***
Gets management logs. You can filter by multiple fields, which will be concatenated using the AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of management logs from the start of the result set (start by counting from 0).

##### Required Permissions

Required Permissions For API call:
`Auditing` --> `View`

Builtin Roles with this permission includes: "Viewer" and "Instance Admin".

##### Context Example

```
{
    "PaloAltoNetworksXDR.Distribution": [
        {
            "status": "Completed", 
            "id": "2c74c11b63074653aa01d575a82bf52a"
        }
    ]
}
```

##### Human Readable Output

>### Distribution Status

>|id|status|
>|---|---|
>| 2c74c11b63074653aa01d575a82bf52a | Completed |

#### Base Command

`xdr-get-audit-management-logs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | User’s email address. | Optional | 
| type | The audit log type. Possible values are: LIVE_TERMINAL, RULES, AUTH, RESPONSE, INCIDENT_MANAGEMENT, ENDPOINT_MANAGEMENT, ALERT_WHITELIST, PUBLIC_API, DISTRIBUTIONS, STARRED_INCIDENTS, POLICY_PROFILES, DEVICE_CONTROL_PROFILE, HOST_FIREWALL_PROFILE, POLICY_RULES, PROTECTION_POLICY, DEVICE_CONTROL_TEMP_EXCEPTIONS, DEVICE_CONTROL_GLOBAL_EXCEPTIONS, GLOBAL_EXCEPTIONS, MSSP, REPORTING, DASHBOARD, BROKER_VM. | Optional | 
| sub_type | The audit log subtype. | Optional | 
| result | Result type. Possible values are: SUCCESS, FAIL, PARTIAL. | Optional | 
| timestamp_gte | Return logs for which the timestamp is after 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| timestamp_lte | Return logs for which the timestamp is before the 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | Maximum number of audit logs to return per page. The default and maximum is 30. Default is 30. | Optional | 
| sort_by | Specifies the field by which to sort the results. By default the sort is defined as creation-time and DESC. Can be "type", "sub_type", "result", or "timestamp". Possible values are: type, sub_type, result, timestamp. | Optional | 
| sort_order | The sort order. Can be "asc" (ascending) or "desc" (descending). Default set to "desc". Possible values are: asc, desc. Default is desc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_ID | Number | Audit log ID. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_OWNER_NAME | String | Audit owner name. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_OWNER_EMAIL | String | Audit owner email address. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_ASSET_JSON | String | Asset JSON. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_ASSET_NAMES | String | Audit asset names. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_HOSTNAME | String | Host name. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_RESULT | String | Audit result. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_REASON | String | Audit reason. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_DESCRIPTION | String | Description of the audit. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_ENTITY | String | Audit entity \(e.g., AUTH, DISTRIBUTIONS\). | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_ENTITY_SUBTYPE | String | Entity subtype \(e.g., Login, Create\). | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_CASE_ID | Number | Audit case ID. | 
| PaloAltoNetworksXDR.AuditManagementLogs.AUDIT_INSERT_TIME | Date | Log's insert time. | 

### xdr-get-audit-agent-reports

***
Gets agent event reports. You can filter by multiple fields, which will be concatenated using the AND condition (OR is not supported). Maximum result set size is 100. Offset is the zero-based number of reports from the start of the result set (start by counting from 0).

##### Required Permissions

Required Permissions For API call:
`Auditing` --> `View`

Builtin Roles with this permission includes: "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-audit-agent-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | A comma-separated list of endpoint IDs. | Optional | 
| endpoint_names | A comma-separated list of endpoint names. | Optional | 
| type | The report type. Can be "Installation", "Policy", "Action", "Agent Service", "Agent Modules", or "Agent Status". Possible values are: Installation, Policy, Action, Agent Service, Agent Modules, Agent Status. | Optional | 
| sub_type | The report subtype. Possible values are: Install, Uninstall, Upgrade, Local Configuration, Content Update, Policy Update, Process Exception, Hash Exception, Scan, File Retrieval, File Scan, Terminate Process, Isolate, Cancel Isolation, Payload Execution, Quarantine, Restore, Stop, Start, Module Initialization, Local Analysis Model, Local Analysis Feature Extraction, Fully Protected, OS Incompatible, Software Incompatible, Kernel Driver Initialization, Kernel Extension Initialization, Proxy Communication, Quota Exceeded, Minimal Content, Reboot Required, Missing Disc Access. | Optional | 
| result | The result type. Can be "Success" or "Fail". If not passed, returns all event reports. Possible values are: Success, Fail. | Optional | 
| timestamp_gte | Return logs that their timestamp is greater than 'log_time_after'.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| timestamp_lte | Return logs for which the timestamp is before the 'timestamp_lte'.<br/><br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| page | Page number (for pagination). The default is 0 (the first page). Default is 0. | Optional | 
| limit | The maximum number of reports to return. Default and maximum is 30. Default is 30. | Optional | 
| sort_by | The field by which to sort results. Can be "type", "category", "trapsversion", "timestamp", or "domain"). Possible values are: type, category, trapsversion, timestamp, domain. | Optional | 
| sort_order | The sort order. Can be "asc" (ascending) or "desc" (descending). Default is "asc". Possible values are: asc, desc. Default is asc. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.AuditAgentReports.ENDPOINTID | String | Endpoint ID. | 
| PaloAltoNetworksXDR.AuditAgentReports.ENDPOINTNAME | String | Endpoint name. | 
| PaloAltoNetworksXDR.AuditAgentReports.DOMAIN | String | Agent domain. | 
| PaloAltoNetworksXDR.AuditAgentReports.TRAPSVERSION | String | Traps version. | 
| PaloAltoNetworksXDR.AuditAgentReports.RECEIVEDTIME | Date | Received time in Epoch time. | 
| PaloAltoNetworksXDR.AuditAgentReports.TIMESTAMP | Date | Timestamp in Epoch time. | 
| PaloAltoNetworksXDR.AuditAgentReports.CATEGORY | String | Report category \(e.g., Audit\). | 
| PaloAltoNetworksXDR.AuditAgentReports.TYPE | String | Report type \(e.g., Action, Policy\). | 
| PaloAltoNetworksXDR.AuditAgentReports.SUBTYPE | String | Report subtype \(e.g., Fully Protected,Policy Update,Cancel Isolation\). | 
| PaloAltoNetworksXDR.AuditAgentReports.RESULT | String | Report result. | 
| PaloAltoNetworksXDR.AuditAgentReports.REASON | String | Report reason. | 
| PaloAltoNetworksXDR.AuditAgentReports.DESCRIPTION | String | Agent report description. | 
| Endpoint.ID | String | The unique ID within the tool retrieving the endpoint. | 
| Endpoint.Hostname | String | The hostname that is mapped to this endpoint. | 
| Endpoint.Domain | String | The domain of the endpoint. | 

### xdr-blocklist-files

***
Block lists requested files which have not already been block listed or added to allow lists.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View/ Edit`
`Action Center` --> `Allow List/Block List`

Builtin Roles with this permission includes: "Responder", "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-blocklist-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the triggered incident. | Optional | 
| hash_list | String that represents a list of hashed files you want to block list. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 
| detailed_response | Choose either regular response or detailed response. Default value = false, regular response. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.blocklist.added_hashes | Number | Number of file hashes added to block list. | 
| PaloAltoNetworksXDR.blocklist.excluded_hashes | Number | Number of file hashes excluded from block list. | 

### xdr-allowlist-files

***
Adds requested files to allow list if they are not already on block list or allow list.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View/ Edit`
`Action Center` --> `Allow List/Block List`

Builtin Roles with this permission includes: "Responder", "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-allowlist-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the triggered incident. | Optional | 
| hash_list | String that represents a list of hashed files you want to add to allow lists. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 
| detailed_response | Choose either regular response or detailed response. Default value = false, regular response. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.allowlist.added_hashes | Number | Number of added file hashes to allowlist. | 
| PaloAltoNetworksXDR.allowlist.excluded_hashes | Number | Number of excluded file hashes from allowlist. | 

### xdr-file-quarantine

***
Quarantines a file on selected endpoints. You can select up to 1000 endpoints.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View/ Edit`
`Action Center` --> `Quarantine`

Builtin Roles with this permission includes: "Responder", "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-file-quarantine`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_id_list | List of endpoint IDs. | Required | 
| file_path | String that represents the path of the file you want to quarantine. | Required | 
| file_hash | String that represents the file's hash. Must be a valid SHA256 hash. | Required | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | The action IDs for polling use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### xdr-get-quarantine-status

***
Retrieves the quarantine status for a selected file.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View/ Edit`
`Action Center` --> `Quarantine`

Builtin Roles with this permission includes: "Responder", "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-get-quarantine-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | String the represents the endpoint ID. | Required | 
| file_hash | String that represents the file hash. Must be a valid SHA256 hash. | Required | 
| file_path | String that represents the file path. | Required | 


#### Context Output

There is no context output for this command.

### xdr-file-restore

***
Restores a quarantined file on requested endpoints.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View/ Edit`
`Action Center` --> `Quarantine`

Builtin Roles with this permission includes: "Responder", "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-file-restore`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| file_hash | The hash code of the file. Must be a valid SHA256 hash. | Required | 
| endpoint_id | String that represents the endpoint ID. If you do not enter a specific endpoint ID, the request will run restore on all endpoints that relate to the quarantined file you defined. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | The action IDs for polling use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### xdr-endpoint-scan-execute

***
Runs a scan on a selected endpoint. To scan all endpoints, run this command with argument all=true. Note: scanning all the endpoints may cause performance issues and latency.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View`
`Endpoint Administrations` --> `View/ Edit`
`Endpoint Administrations` --> `Endpoint Scan`

Builtin Roles with this permission includes: "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-endpoint-scan-execute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_id_list | List of endpoint IDs. | Optional | 
| dist_name | Name of the distribution list. | Optional | 
| gte_first_seen | Greater than or equal to first seen timestamp in milliseconds. | Optional | 
| gte_last_seen | Greater than or equal to last seen timestamp in milliseconds. | Optional | 
| lte_first_seen | Less than or equal to first seen timestamp in milliseconds. | Optional | 
| lte_last_seen | Less than or equal to last seen timestamp in milliseconds. | Optional | 
| ip_list | List of IP addresses. | Optional | 
| group_name | Name of the endpoint group. | Optional | 
| platform | Type of operating system. Possible values are: windows, linux, macos, android. | Optional | 
| alias | Endpoint alias name. | Optional | 
| isolate | Whether an endpoint has been isolated. Possible values are: isolated, unisolated. | Optional | 
| hostname | Name of the host. | Optional | 
| all | Whether to scan all of the endpoints. Scanning all of the endpoints may cause performance issues and latency. Possible values are: true, false. Default is false. | Optional | 
| action_id | The action IDs for polling use. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.endpointScan.actionId | Number | The action ID of the scan request. | 
| PaloAltoNetworksXDR.endpointScan.aborted | Boolean | Was the scan aborted? | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### xdr-endpoint-scan-abort

***
Cancels the scan of selected endpoints. A scan can only be aborted if the selected endpoints are Pending or In Progress. To scan all endpoints, run the command with the argument all=true. Note that scanning all of the endpoints may cause performance issues and latency.

##### Required Permissions

Required Permissions For API call:
`Endpoint Administrations` --> `View/ Edit`
`Endpoint Administrations` --> `Endpoint Scan`

Builtin Roles with this permission includes: "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-endpoint-scan-abort`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_id_list | List of endpoint IDs. | Optional | 
| dist_name | Name of the distribution list. | Optional | 
| gte_first_seen | GTE first seen timestamp in milliseconds. | Optional | 
| gte_last_seen | GTE last seen timestamp in milliseconds. | Optional | 
| lte_first_seen | LTE first seen timestamp in milliseconds. | Optional | 
| lte_last_seen | LTE last seen timestamp in milliseconds. | Optional | 
| ip_list | List of IP addresses. | Optional | 
| group_name | Name of the endpoint group. | Optional | 
| platform | Type of operating system. Possible values are: windows, linux, macos, android. | Optional | 
| alias | Endpoint alias name. | Optional | 
| isolate | Whether an endpoint has been isolated. Can be "isolated" or "unisolated". Possible values are: isolated, unisolated. | Optional | 
| hostname | Name of the host. | Optional | 
| all | Whether to scan all of the endpoints. Note: scanning all of the endpoints may cause performance issues and latency. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.endpointScan.actionId | Unknown | The action ID of the abort scan request. | 
| PaloAltoNetworksXDR.endpointScan.aborted | Boolean | Was the scan aborted? | 

### get-mapping-fields

***
Gets mapping fields from remote incident. Note: This method will not update the current incident, it's here for debugging purposes.


#### Base Command

`get-mapping-fields`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

### get-remote-data

***
Gets remote data from a remote incident. Note: This method will not update the current incident, it's here for debugging purposes.


#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The remote incident ID. | Required | 
| lastUpdate | UTC timestamp in seconds. The incident is only updated if it was modified after the last update time. Default is 0. | Optional | 


#### Context Output

There is no context output for this command.

### get-modified-remote-data

***
Gets the list of incidents that were modified since the last update. Note: This method is here for debugging purposes. get-modified-remote-data is used as part of a Mirroring feature, which is available since version 6.1.


#### Base Command

`get-modified-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| lastUpdate | Date string representing the local time.The incident is only returned if it was modified after the last update time. | Optional | 


#### Context Output

There is no context output for this command.

### xdr-get-policy

***
Gets the policy name for a specific endpoint.

##### Required Permissions

Required Permissions For API call:
`Endpoint Prevention Policies` --> `View`

Builtin Roles with this permission includes: "Privileged Investigator", "Privileged Responder", "Viewer", and "Instance Admin".

#### Base Command

`xdr-get-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_id | The endpoint ID. Can be retrieved by running the xdr-get-endpoints command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Policy | string | The policy allocated with the endpoint. | 
| PaloAltoNetworksXDR.Policy.policy_name | string | Name of the policy allocated with the endpoint. | 
| PaloAltoNetworksXDR.Policy.endpoint_id | string | Endpoint ID. | 

### xdr-get-scripts

***
Gets a list of scripts available in the scripts library.

##### Required Permissions

Required Permissions For API call:
`Agent Scripts library` --> `View`
`Endpoint Administrations` --> `View/ Edit`
`Endpoint Administrations` --> `Endpoint Scan`

Builtin Roles with this permission includes: "Privileged Responder", "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-scripts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_name | A comma-separated list of the script names. | Optional | 
| description | A comma-separated list of the script descriptions. | Optional | 
| created_by | A comma-separated list of the users who created the script. | Optional | 
| limit | The maximum number of scripts returned to the War Room. | Optional | 
| offset | (Int) Offset in the data set. | Optional | 
| windows_supported | Whether the script can be executed on a Windows operating system. Possible values are: true, false. | Optional | 
| linux_supported | Whether the script can be executed on a Linux operating system. Possible values are: true, false. | Optional | 
| macos_supported | Whether the script can be executed on a Mac operating system. Possible values are: true, false. | Optional | 
| is_high_risk | Whether the script has a high-risk outcome. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Scripts | Unknown | The scripts command results. | 
| PaloAltoNetworksXDR.Scripts.script_id | Unknown | Script ID. | 
| PaloAltoNetworksXDR.Scripts.name | string | Name of the script. | 
| PaloAltoNetworksXDR.Scripts.description | string | Description of the script. | 
| PaloAltoNetworksXDR.Scripts.modification_date | Unknown | Timestamp of when the script was last modified. | 
| PaloAltoNetworksXDR.Scripts.created_by | string | Name of the user who created the script. | 
| PaloAltoNetworksXDR.Scripts.windows_supported | boolean | Whether the script can be executed on a Windows operating system. | 
| PaloAltoNetworksXDR.Scripts.linux_supported | boolean | Whether the script can be executed on a Linux operating system. | 
| PaloAltoNetworksXDR.Scripts.macos_supported | boolean | Whether the script can be executed on Mac operating system. | 
| PaloAltoNetworksXDR.Scripts.is_high_risk | boolean | Whether the script has a high-risk outcome. | 
| PaloAltoNetworksXDR.Scripts.script_uid | string | Globally Unique Identifier of the script, used to identify the script when executing. | 

### xdr-delete-endpoints

***
Deletes selected endpoints in the Cortex XDR app. You can delete up to 1000 endpoints.

##### Required Permissions

Required Permissions For API call:
`Endpoint Administrations` --> `View/ Edit`

Builtin Roles with this permission includes: "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-delete-endpoints`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | A comma-separated list of endpoint IDs. You can retrieve the endpoint IDs from the xdr-get-endpoints command. | Required | 


#### Context Output

There is no context output for this command.

### xdr-get-endpoint-device-control-violations

***
Gets a list of device control violations filtered by selected fields. You can retrieve up to 100 violations.

##### Required Permissions

Required Permissions For API call:
`Device Control` --> `View`

Builtin Roles with this permission includes: "Privileged Investigator", "Privileged Responder", "Viewer", and "Instance Admin".

#### Base Command

`xdr-get-endpoint-device-control-violations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | A comma-separated list of endpoint IDs. You can retrieve the endpoint IDs from the xdr-get-endpoints command. | Optional | 
| type | Type of violation. Possible values are: "cd-rom", "disk drive", "floppy disk", and "portable device". Possible values are: cd-rom, disk drive, floppy disk, portable device. | Optional | 
| timestamp_gte | Timestamp of the violation. Violations that are greater than or equal to this timestamp will be returned. Values can be in either ISO date format, relative time, or epoch timestamp. For example:  "2019-10-21T23:45:00" (ISO date format), "3 days ago" (relative time) 1579039377301 (epoch time). | Optional | 
| timestamp_lte | Timestamp of the violation. Violations that are less than or equal to this timestamp will be returned. Values can be in either ISO date format, relative time, or epoch timestamp. For example:  "2019-10-21T23:45:00" (ISO date format), "3 days ago" (relative time) 1579039377301 (epoch time). | Optional | 
| ip_list | A comma-separated list of IP addresses. | Optional | 
| vendor | Name of the vendor. | Optional | 
| vendor_id | Vendor ID. | Optional | 
| product | Name of the product. | Optional | 
| product_id | Product ID. | Optional | 
| serial | Serial number. | Optional | 
| hostname | Hostname. | Optional | 
| violation_id_list | A comma-separated list of violation IDs. | Optional | 
| username | Username. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.EndpointViolations | Unknown | Endpoint violations command results. | 
| PaloAltoNetworksXDR.EndpointViolations.violations | Unknown | A list of violations. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.os_type | string | Type of the operating system. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.hostname | string | Host name of the violation. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.username | string | Username of the violation. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.ip | string | IP address of the violation. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.timestamp | number | Timestamp of the violation. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.violation_id | number | Violation ID. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.type | string | Type of violation. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.vendor_id | string | Vendor ID of the violation. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.vendor | string | Name of the vendor of the violation. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.product_id | string | Product ID of the violation. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.product | string | Name of the product of the violation. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.serial | string | Serial number of the violation. | 
| PaloAltoNetworksXDR.EndpointViolations.violations.endpoint_id | string | Endpoint ID of the violation. | 

### xdr-file-retrieve

***
Retrieves files from selected endpoints. You can retrieve up to 20 files, from no more than 10 endpoints. At least one endpoint ID and one file path are necessary in order to run the command. After running this command, you can use the xdr-action-status-get command with returned action_id, to check the action status.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View/ Edit`
`Action Center` --> `File Retrieval`

Builtin Roles with this permission includes: "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-file-retrieve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | A comma-separated list of endpoint IDs. | Required | 
| windows_file_paths | A comma-separated list of file paths on the Windows platform. | Optional | 
| linux_file_paths | A comma-separated list of file paths on the Linux platform. | Optional | 
| mac_file_paths | A comma-separated list of file paths on the Mac platform. | Optional | 
| generic_file_path | A comma-separated list of file paths in any platform. Can be used instead of the mac/windows/linux file paths. The order of the files path list must be parallel to the endpoints list order, so the first file path in the list is related to the first endpoint and so on. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | The action IDs for polling use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.RetrievedFiles.action_id | string | ID of the action to retrieve files from selected endpoints. | 
| PaloAltoNetworksXDR.RetrievedFiles.endpoint_id | string | Endpoint ID. Added only when the operation is successful. | 
| PaloAltoNetworksXDR.RetrievedFiles.file_link | string | Link to the file. Added only when the operation is successful. | 
| PaloAltoNetworksXDR.RetrievedFiles.status | string | The action status. Added only when the operation is unsuccessful. | 
| PaloAltoNetworksXDR.RetrievedFiles.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| PaloAltoNetworksXDR.RetrievedFiles.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| PaloAltoNetworksXDR.RetrievedFiles.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| PaloAltoNetworksXDR.RetrievedFiles.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| PaloAltoNetworksXDR.RetrievedFiles.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| PaloAltoNetworksXDR.RetrievedFiles.ErrorReasons.errorData | String | The error reason data. | 
| PaloAltoNetworksXDR.RetrievedFiles.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| PaloAltoNetworksXDR.RetrievedFiles.ErrorReasons.errorDescription | String | The error reason description. | 
| PaloAltoNetworksXDR.RetrievedFiles.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### xdr-retrieve-file-details

***
View the file retrieved by the xdr-retrieve-files command according to the action ID. Before running this command, you can use the xdr-action-status-get command to check if this action completed successfully.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View/ Edit`
`Action Center` --> `File Retrieval`

Builtin Roles with this permission includes: "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-retrieve-file-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action ID retrieved from the xdr-retrieve-files command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File | Unknown | The file details command results. | 
| File.Name | String | The full file name \(including the file extension\). | 
| File.EntryID | String | The ID for locating the file in the War Room. | 
| File.Size | Number | The size of the file in bytes. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Extension | String | The file extension. For example: "xls". | 
| File.Type | String | The file type, as determined by libmagic \(same as displayed in file entries\). | 

### xdr-get-script-metadata

***
Gets the full definition of a specific script in the scripts library.

##### Required Permissions

Required Permissions For API call:
`Agent Scripts library` --> `View`

Builtin Roles with this permission includes: "Privileged Responder", "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-script-metadata`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_uid | Unique identifier of the script, returned by the xdr-get-scripts command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptMetadata | Unknown | The script metadata command results. | 
| PaloAltoNetworksXDR.ScriptMetadata.script_id | number | Script ID. | 
| PaloAltoNetworksXDR.ScriptMetadata.name | string | Script name. | 
| PaloAltoNetworksXDR.ScriptMetadata.description | string | Script description. | 
| PaloAltoNetworksXDR.ScriptMetadata.modification_date | unknown | Timestamp of when the script was last modified. | 
| PaloAltoNetworksXDR.ScriptMetadata.created_by | string | Name of the user who created the script. | 
| PaloAltoNetworksXDR.ScriptMetadata.is_high_risk | boolean | Whether the script has a high-risk outcome. | 
| PaloAltoNetworksXDR.ScriptMetadata.windows_supported | boolean | Whether the script can be executed on a Windows operating system. | 
| PaloAltoNetworksXDR.ScriptMetadata.linux_supported | boolean | Whether the script can be executed on a Linux operating system. | 
| PaloAltoNetworksXDR.ScriptMetadata.macos_supported | boolean | Whether the script can be executed on a Mac operating system. | 
| PaloAltoNetworksXDR.ScriptMetadata.entry_point | string | Name of the entry point selected for the script. An empty string indicates  the script defined as just run. | 
| PaloAltoNetworksXDR.ScriptMetadata.script_input | string | Name and type for the specified entry point. | 
| PaloAltoNetworksXDR.ScriptMetadata.script_output_type | string | Type of the output. | 
| PaloAltoNetworksXDR.ScriptMetadata.script_output_dictionary_definitions | Unknown | If the script_output_type is a dictionary, an array with friendly name, name, and type for each output. | 

### xdr-get-script-code

***
Gets the code of a specific script in the script library.

##### Required Permissions

Required Permissions For API call:
`Agent Scripts library` --> `View`

Builtin Roles with this permission includes: "Privileged Responder", "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-script-code`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script_uid | Unique identifier of the script, returned by the xdr-get-scripts command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptCode | Unknown | The script code command results. | 
| PaloAltoNetworksXDR.ScriptCode.code | string | The code of a specific script in the script library. | 
| PaloAltoNetworksXDR.ScriptCode.script_uid | string | Unique identifier of the script. | 

### xdr-action-status-get

***
Retrieves the status of the requested actions according to the action ID.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View`

Builtin Roles with this permission includes: "Responder", "Privileged Investigator", "Privileged Responder", "Viewer", and "Instance Admin".

#### Base Command

`xdr-action-status-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | The action ID of the selected request. After performing an action, you will receive an action ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.GetActionStatus | Unknown | The action status command results. | 
| PaloAltoNetworksXDR.GetActionStatus.endpoint_id | string | Endpoint ID. | 
| PaloAltoNetworksXDR.GetActionStatus.status | string | The status of the specific endpoint ID. | 
| PaloAltoNetworksXDR.GetActionStatus.action_id | number | The specified action ID. | 

### xdr-run-script

***
Deprecated. Use the `xdr-script-run` command instead. Initiates a new endpoint script execution action using a script from the script library.


#### Base Command

`xdr-run-script`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_ids | A comma-separated list of endpoint IDs. Can be retrieved by running the xdr-get-endpoints command. | Required | 
| script_uid | Unique identifier of the script. Can be retrieved by running the xdr-get-scripts command. | Required | 
| parameters | Dictionary containing the parameter name as key and its value for this execution as the value. For example, {"param1":"param1_value","param2":"param2_value"}. | Optional | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksXDR.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 

### xdr-snippet-code-script-execute

***
Initiates a new endpoint script execution action using the provided snippet code.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View`

Builtin Roles with this permission includes: "Responder", "Privileged Investigator", "Privileged Responder", "Viewer", and "Instance Admin".

#### Base Command

`xdr-snippet-code-script-execute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_ids | A comma-separated list of endpoint IDs. Can be retrieved by running the xdr-get-endpoints command. | Required | 
| snippet_code | Section of a script to initiate on an endpoint (e.g., print("7")). | Required | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | Action IDs for polling use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksXDR.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### xdr-get-script-execution-status

***
Retrieves the status of a script execution action.

##### Required Permissions

Required Permissions For API call:
`Agent Scripts library` --> `View`

Builtin Roles with this permission includes: "Privileged Responder", "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-script-execution-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action IDs retrieved from the xdr-run-script command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptStatus.general_status | String | General status of the action, considering the status of all the endpoints. | 
| PaloAltoNetworksXDR.ScriptStatus.error_message | String | Error message regarding permissions for running APIs or the action doesn’t exist. | 
| PaloAltoNetworksXDR.ScriptStatus.endpoints_timeout | Number | Number of endpoints in "timeout" status. | 
| PaloAltoNetworksXDR.ScriptStatus.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksXDR.ScriptStatus.endpoints_pending_abort | Number | Number of endpoints in "pending abort" status. | 
| PaloAltoNetworksXDR.ScriptStatus.endpoints_pending | Number | Number of endpoints in "pending" status. | 
| PaloAltoNetworksXDR.ScriptStatus.endpoints_in_progress | Number | Number of endpoints in "in progress" status. | 
| PaloAltoNetworksXDR.ScriptStatus.endpoints_failed | Number | Number of endpoints in "failed" status. | 
| PaloAltoNetworksXDR.ScriptStatus.endpoints_expired | Number | Number of endpoints in "expired" status. | 
| PaloAltoNetworksXDR.ScriptStatus.endpoints_completed_successfully | Number | Number of endpoints in "completed successfully" status. | 
| PaloAltoNetworksXDR.ScriptStatus.endpoints_canceled | Number | Number of endpoints in "canceled" status. | 
| PaloAltoNetworksXDR.ScriptStatus.endpoints_aborted | Number | Number of endpoints in "aborted" status. | 

### xdr-get-script-execution-results

***
Retrieve the results of a script execution action.

##### Required Permissions

Required Permissions For API call:
`Agent Scripts library` --> `View`

Builtin Roles with this permission includes: "Privileged Responder", "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-script-execution-results`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action IDs retrieved from the xdr-run-script command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptResult.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksXDR.ScriptResult.results.retrieved_files | Number | Number of successfully retrieved files. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_ip_address | String | Endpoint IP address. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_name | String | Name of successfully retrieved files. | 
| PaloAltoNetworksXDR.ScriptResult.results.failed_files | Number | Number of files failed to retrieve. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_status | String | Endpoint status. | 
| PaloAltoNetworksXDR.ScriptResult.results.domain | String | Domain to which the endpoint belongs. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_id | String | Endpoint ID. | 
| PaloAltoNetworksXDR.ScriptResult.results.execution_status | String | Execution status of this endpoint. | 
| PaloAltoNetworksXDR.ScriptResult.results.return_value | String | Value returned by the script in case the type is not a dictionary. | 
| PaloAltoNetworksXDR.ScriptResult.results.standard_output | String | The STDOUT and the STDERR logged by the script during the execution. | 
| PaloAltoNetworksXDR.ScriptResult.results.retention_date | Date | Timestamp in which the retrieved files will be deleted from the server. | 

### xdr-get-script-execution-result-files

***
Gets the files retrieved from a specific endpoint during a script execution.

##### Required Permissions

Required Permissions For API call:
`Agent Scripts library` --> `View`

Builtin Roles with this permission includes: "Privileged Responder", "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-script-execution-result-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| action_id | Action ID retrieved from the xdr-run-script command. | Required | 
| endpoint_id | Endpoint ID. Can be retrieved by running the xdr-get-endpoints command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Size | String | The size of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Name | String | The name of the file. | 
| File.SSDeep | String | The SSDeep hash of the file. | 
| File.EntryID | String | EntryID of the file | 
| File.Info | String | Information about the file. | 
| File.Type | String | The file type. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.Extension | String | The extension of the file. | 

### xdr-script-commands-execute

***
Initiates a new endpoint script execution of shell commands.

#### Base Command

`xdr-script-commands-execute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_ids | A comma-separated list of endpoint IDs. Can be retrieved by running the xdr-get-endpoints command. | Required | 
| commands | A comma-separated list of shell commands to execute. Set the `is_raw_command` argument to `true` to prevent splitting by commas. (Useful when using `\|\|`, `&amp;&amp;`, `;` separators for controlling the flow of multiple commands). | Required | 
| is_raw_command | Whether to pass the command as-is. When false, the command is split by commas and sent as a list of commands, that are run independently. | Optional | 
| command_type | Type of shell command. Possible values are: powershell, native. | Optional | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | The action IDs for polling use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksXDR.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### xdr-file-delete-script-execute

***
Initiates a new endpoint script execution to delete the specified file.

#### Base Command

`xdr-file-delete-script-execute`

#### Input

| **Argument Name** | **Description**                                                                                                       | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------| --- |
| incident_id | Allows linking the response action to the incident that triggered it.                                                 | Optional | 
| endpoint_ids | A comma-separated list of endpoint IDs. Can be retrieved by running the xdr-get-endpoints command.                    | Required | 
| file_path | A comma-separated list of paths of the files to delete. All of the given file paths will run on all of the endpoints. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600.                                                            | Optional | 
| interval_in_seconds | Interval in seconds between each poll.                                                                                | Optional | 
| timeout_in_seconds | Polling timeout in seconds.                                                                                           | Optional | 
| action_id | The action IDs for polling use.                                                                                       | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksXDR.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### xdr-file-exist-script-execute

***
Initiates a new endpoint script execution to check if the file exists.

#### Base Command

`xdr-file-exist-script-execute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_ids | A comma-separated list of endpoint IDs. Can be retrieved by running the xdr-get-endpoints command. | Required | 
| file_path | A comma-separated list of paths of the files to check for existence. All of the given file paths will run on all of the endpoints. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | The action IDs for polling use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksXDR.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### xdr-kill-process-script-execute

***
Initiates a new endpoint script execution kill process.

#### Base Command

`xdr-kill-process-script-execute`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows to link the response action to the incident that triggered it. | Optional | 
| endpoint_ids | A comma-separated list of endpoint IDs. Can be retrieved by running the xdr-get-endpoints command. | Required | 
| process_name | Names of processes to kill. Will kill all of the given processes on all of the endpoints. | Required | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| interval_in_seconds | Interval in seconds between each poll. | Optional | 
| timeout_in_seconds | Polling timeout in seconds. | Optional | 
| action_id | The action IDs for polling use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptRun.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksXDR.ScriptRun.endpoints_count | Number | Number of endpoints the action was initiated on. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.bucket | String | The bucket in which the error occurred. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_name | String | The name of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_path | String | The path of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.file_size | Number | The size of the file that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.missing_files | Unknown | The missing files that caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorData | String | The error reason data. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminated_by | String | The instance ID which terminated the action and caused the error. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.errorDescription | String | The error reason description. | 
| PaloAltoNetworksXDR.GetActionStatus.ErrorReasons.terminate_result | Unknown | The error reason terminate result. | 

### endpoint

***
Returns information about an endpoint.

##### Required Permissions

Required Permissions For API call:
`Endpoint Administrations` --> `View`

Builtin Roles with this permission includes: "Privileged Responder", "Viewer" and "Instance Admin".

#### Base Command

`endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. | Optional | 
| ip | The endpoint IP address. | Optional | 
| hostname | The endpoint host name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint hostname. | 
| Endpoint.OS | String | The endpoint operation system. | 
| Endpoint.IPAddress | String | The endpoint IP address. | 
| Endpoint.ID | String | The endpoint ID. | 
| Endpoint.Status | String | The endpoint status. | 
| Endpoint.IsIsolated | String | The endpoint isolation status. | 
| Endpoint.MACAddress | String | The endpoint MAC address. | 
| Endpoint.Vendor | String | The integration name of the endpoint vendor. | 

### xdr-get-endpoints-by-status

***
Returns the number of the connected\disconnected endpoints.

##### Required Permissions

Required Permissions For API call:
`Endpoint Administrations` --> `View`

Builtin Roles with this permission includes: "Privileged Responder", "Viewer" and "Instance Admin".

#### Base Command

`xdr-get-endpoints-by-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the endpoint to filter. Possible values are: connected, disconnected, lost, uninstalled. | Required | 
| last_seen_gte | All the agents that were last seen before {last_seen_gte}. Supported<br/>        values: 1579039377301 (time in milliseconds) "3 days" (relative date) "2019-10-21T23:45:00"<br/>        (date). | Optional | 
| last_seen_lte | All the agents that were last seen before {last_seen_lte}. Supported<br/>        values: 1579039377301 (time in milliseconds) "3 days" (relative date) "2019-10-21T23:45:00"<br/>        (date). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.EndpointsStatus.status | String | The endpoint status. | 
| PaloAltoNetworksXDR.EndpointsStatus.count | Number | The number of endpoints with this status. | 

### xdr-get-cloud-original-alerts

***
Returns information about each alert ID.

##### Required Permissions

Required Permissions For API call:
`Alerts & Incidents` --> `View`

Builtin Roles with this permission includes: "Investigator", "Responder", "Privileged Investigator", "Privileged Responder", "Viewer", and "Instance Admin".

#### Base Command

`xdr-get-cloud-original-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | A comma-separated list of alert IDs. | Required | 
| events_from_decider_format | Whether to return events_from_decider context output as a dictionary (the raw API response) or as a list (improved for playbook automation) - relevant only when filter_alert_fields is set to False. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.OriginalAlert.event._time | String | The timestamp of the occurrence of the event. | 
| PaloAltoNetworksXDR.OriginalAlert.event.vendor | String | Vendor name. | 
| PaloAltoNetworksXDR.OriginalAlert.event.event_timestamp | Number | Event timestamp. | 
| PaloAltoNetworksXDR.OriginalAlert.event.event_type | Number | Event type \(static 500\). | 
| PaloAltoNetworksXDR.OriginalAlert.event.cloud_provider | String | The cloud provider - GCP, AZURE, or AWS. | 
| PaloAltoNetworksXDR.OriginalAlert.event.project | String | The project in which the event occurred. | 
| PaloAltoNetworksXDR.OriginalAlert.event.cloud_provider_event_id | String | The ID given to the event by the cloud provider, if the ID exists. | 
| PaloAltoNetworksXDR.OriginalAlert.event.cloud_correlation_id | String | The ID the cloud provider is using to aggregate events that are part of the same general event. | 
| PaloAltoNetworksXDR.OriginalAlert.event.operation_name_orig | String | The name of the operation that occurred, as supplied by the cloud provider. | 
| PaloAltoNetworksXDR.OriginalAlert.event.operation_name | String | The normalized name of the operation performed by the event. | 
| PaloAltoNetworksXDR.OriginalAlert.event.identity_orig | String | Contains the original identity related fields as provided by the cloud provider. | 
| PaloAltoNetworksXDR.OriginalAlert.event.identity_name | String | The name of the identity that initiated the action. | 
| PaloAltoNetworksXDR.OriginalAlert.event.identity_uuid | String | Same as identity_name but also contains the UUID of the identity if it exists. | 
| PaloAltoNetworksXDR.OriginalAlert.event.identity_type | String | An enum representing the type of the identity. | 
| PaloAltoNetworksXDR.OriginalAlert.event.identity_sub_type | String | An enum representing the sub-type of the identity, respective to its identity_type. | 
| PaloAltoNetworksXDR.OriginalAlert.event.identity_invoked_by_name | String | The name of the identity that invoked the action as it appears in the log. | 
| PaloAltoNetworksXDR.OriginalAlert.event.identity_invoked_by_uuid | String | The UUID of the identity that invoked the action as it appears in the log. | 
| PaloAltoNetworksXDR.OriginalAlert.event.identity_invoked_by_type | String | An enum that represents the type of identity event that invoked the action. | 
| PaloAltoNetworksXDR.OriginalAlert.event.identity_invoked_by_sub_type | String | An enum that represents the respective sub_type of the type of identity \(identity_type\) that has invoked the action. | 
| PaloAltoNetworksXDR.OriginalAlert.event.operation_status | String | Status of whether the operation has succeed or failed, if provided. | 
| PaloAltoNetworksXDR.OriginalAlert.event.operation_status_orig | String | The operation status code as it appears in the log, including lookup from code number to code name. | 
| PaloAltoNetworksXDR.OriginalAlert.event.operation_status_orig_code | String | The operation status code as it appears in the log. | 
| PaloAltoNetworksXDR.OriginalAlert.event.operation_status_reason_provided | String | Description of the error, if the log record indicates an error and the cloud provider supplied the reason. | 
| PaloAltoNetworksXDR.OriginalAlert.event.resource_type | String | The normalized type of the service that emitted the log row. | 
| PaloAltoNetworksXDR.OriginalAlert.event.resource_type_orig | String | The type of the service that omitted the log as provided by the cloud provider. | 
| PaloAltoNetworksXDR.OriginalAlert.event.resource_sub_type | String | The sub-type respective to the resource_type field, normalized across all cloud providers. | 
| PaloAltoNetworksXDR.OriginalAlert.event.resource_sub_type_orig | String | The sub-type of the service that emitted this log row as provided by the cloud provider. | 
| PaloAltoNetworksXDR.OriginalAlert.event.region | String | The cloud region of the resource that emitted the log. | 
| PaloAltoNetworksXDR.OriginalAlert.event.zone | String | The availability zone of the resource that emitted the log. | 
| PaloAltoNetworksXDR.OriginalAlert.event.referenced_resource | String | The cloud resource referenced in the audit log. | 
| PaloAltoNetworksXDR.OriginalAlert.event.referenced_resource_name | String | Same as referenced_resource but provides only the substring that represents the resource name instead of the full asset ID. | 
| PaloAltoNetworksXDR.OriginalAlert.event.referenced_resources_count | Number | The number of extracted resources referenced in this audit log. | 
| PaloAltoNetworksXDR.OriginalAlert.event.user_agent | String | The user agent provided in the call to the API of the cloud provider. | 
| PaloAltoNetworksXDR.OriginalAlert.event.caller_ip | String | The IP of the caller that performed the action in the log. | 
| PaloAltoNetworksXDR.OriginalAlert.event.caller_ip_geolocation | String | The geolocation associated with the caller_ip's value. | 
| PaloAltoNetworksXDR.OriginalAlert.event.caller_ip_asn | Number | The ASN of the caller_ip's value. | 
| PaloAltoNetworksXDR.OriginalAlert.event.caller_project | String | The project of the caller entity. | 
| PaloAltoNetworksXDR.OriginalAlert.event.raw_log | Unknown | The raw log that is being normalized. | 
| PaloAltoNetworksXDR.OriginalAlert.event.log_name | String | The name of the log that contains the log row. | 
| PaloAltoNetworksXDR.OriginalAlert.event.caller_ip_asn_org | String | The organization associated with the ASN of the caller_ip's value. | 
| PaloAltoNetworksXDR.OriginalAlert.event.event_base_id | String | Event base ID. | 
| PaloAltoNetworksXDR.OriginalAlert.event.ingestion_time | String | Ingestion time. | 

### xdr-remove-allowlist-files

***
Removes requested files from allow list.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View/ Edit`
`Action Center` --> `Allow List/Block List`

Builtin Roles with this permission includes: "Responder", "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-remove-allowlist-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the incident that triggered it. | Optional | 
| hash_list | String that represents a list of hashed files you want to add to allow list. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.allowlist.removed_hashes | Number | Removed file hash | 

### xdr-remove-blocklist-files

***
Removes requested files from block list.

##### Required Permissions

Required Permissions For API call:
`Action Center` --> `View/ Edit`
`Action Center` --> `Allow List/Block List`

Builtin Roles with this permission includes: "Responder", "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-remove-blocklist-files`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Links the response action to the incident that triggered it. | Optional | 
| hash_list | String that represents a list of hashed files you want to add to allow list. Must be a valid SHA256 hash. | Required | 
| comment | String that represents additional information regarding the action. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.blocklist.removed_hashes | Number | Removed fileHash from blocklist | 

There is no context output for this command.


### xdr-get-alerts

***
Returns a list of alerts and their metadata, which you can filter by built-in arguments or use the custom_filter to input a JSON filter object. 
Multiple filter arguments will be concatenated using the AND operator, while arguments that support a comma-separated list of values will use an OR operator between each value.

##### Required Permissions

Required Permissions For API call:
`Alerts & Incidents` --> `View`

Builtin Roles with this permission includes: "Investigator", "Responder", "Privileged Investigator", "Privileged Responder", "Viewer", and "Instance Admin".

#### Base Command

`xdr-get-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_id | The unique ID of the alert. | Optional | 
| severity | The severity of the alert. Possible values are: low, medium, high. | Optional | 
| custom_filter | a custom filter, when using this argument, other filter arguments are not relevant. example: <br/>`{<br/>                "OR": [<br/>                    {<br/>                        "SEARCH_FIELD": "actor_process_command_line",<br/>                        "SEARCH_TYPE": "EQ",<br/>                        "SEARCH_VALUE": "path_to_file"<br/>                    }<br/>                ]<br/>            }`. | Optional | 
| Identity_type | Account type. Possible values are: ANONYMOUS, APPLICATION, COMPUTE, FEDERATED_IDENTITY, SERVICE, SERVICE_ACCOUNT, TEMPORARY_CREDENTIALS, TOKEN, UNKNOWN, USER. | Optional | 
| agent_id | A unique identifier per agent. | Optional | 
| action_external_hostname | The host name to connect to. In case of a proxy connection, this value will differ from action_remote_ip. | Optional | 
| rule_id | A string identifying the user rule. | Optional | 
| rule_name | The name of the user rule. | Optional | 
| alert_name | The alert name. | Optional | 
| alert_source | The alert source. | Optional | 
| time_frame | Supports relative times or “custom” time option. If you choose the "custom" option, you should use start_time and end_time arguments. Possible values are: 60 minutes, 3 hours, 12 hours, 24 hours, 2 days, 7 days, 14 days, 30 days, custom. | Optional | 
| user_name | The name assigned to the user_id during agent runtime. | Optional | 
| actor_process_image_name | The file name of the binary file. | Optional | 
| causality_actor_process_image_command_line | CGO CMD. | Optional | 
| actor_process_image_command_line | Trimmed to 128 unicode chars during event serialization.<br/>Full value reported as part of the original process event. | Optional | 
| action_process_image_command_line | The command line of the process created. | Optional | 
| actor_process_image_sha256 | SHA256 of the binary file. | Optional | 
| causality_actor_process_image_sha256 | SHA256 of the binary file. | Optional | 
| action_process_image_sha256 | SHA256 of the binary file. | Optional | 
| action_file_image_sha256 | SHA256 of the file related to the event. | Optional | 
| action_registry_name | The name of the registry. | Optional | 
| action_registry_key_data | The key data of the registry. | Optional | 
| host_ip | The host IP. | Optional | 
| action_local_ip | The local IP address for the connection. | Optional | 
| action_remote_ip | Remote IP address for the connection. | Optional | 
| alert_action_status | Alert action status. Possible values are: detected, detected (allowed the session), detected (download), detected (forward), detected (post detected), detected (prompt allow), detected (raised an alert), detected (reported), detected (on write), detected (scanned), detected (sinkhole), detected (syncookie sent), detected (wildfire upload failure), detected (wildfire upload success), detected (wildfire upload skip), detected (xdr managed threat hunting), prevented (block), prevented (blocked), prevented (block-override), prevented (blocked the url), prevented (blocked the ip), prevented (continue), prevented (denied the session), prevented (dropped all packets), prevented (dropped the session), prevented (dropped the session and sent a tcp reset), prevented (dropped the packet), prevented (override), prevented (override-lockout), prevented (post detected), prevented (prompt block), prevented (random-drop), prevented (silently dropped the session with an icmp unreachable message to the host or application), prevented (terminated the session and sent a tcp reset to both sides of the connection), prevented (terminated the session and sent a tcp reset to the client), prevented (terminated the session and sent a tcp reset to the server), prevented (on write). | Optional | 
| action_local_port | The local IP address for the connection. | Optional | 
| action_remote_port | The remote port for the connection. | Optional | 
| dst_action_external_hostname | The hostname we connect to. In case of a proxy connection, this value will differ from action_remote_ip. | Optional | 
| sort_field | The field by which we sort the results. Default is source_insert_ts. | Optional | 
| sort_order | The order in which we sort the results. Possible values are: DESC, ASC. | Optional | 
| offset | The first page from which we bring the alerts. Default is 0. | Optional | 
| limit | The last page from which we bring the alerts. Default is 50. | Optional | 
| start_time | Relevant when "time_frame" argument is "custom". Supports Epoch timestamp and simplified extended ISO format (YYYY-MM-DDThh:mm:ss). | Optional | 
| end_time | Relevant when "time_frame" argument is "custom". Supports Epoch timestamp and simplified extended ISO format (YYYY-MM-DDThh:mm:ss). | Optional | 
| starred | Whether the alert is starred or not. Possible values are: true, false. | Optional | 
| mitre_technique_id_and_name | The MITRE attack technique. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Alert.internal_id | String | The unique ID of the alert. | 
| PaloAltoNetworksXDR.Alert.source_insert_ts | Number | The detection timestamp | 
| PaloAltoNetworksXDR.Alert.alert_name | String | The name of the alert. | 
| PaloAltoNetworksXDR.Alert.severity | String | The severity of the alert. | 
| PaloAltoNetworksXDR.Alert.alert_category | String | The category of the alert. | 
| PaloAltoNetworksXDR.Alert.alert_action_status | String | The alert action. Possible values.

DETECTED: detected
DETECTED_0: detected \(allowed the session\)
DOWNLOAD: detected \(download\)
DETECTED_19: detected \(forward\)
POST_DETECTED: detected \(post detected\)
PROMPT_ALLOW: detected \(prompt allow\)
DETECTED_4: detected \(raised an alert\)
REPORTED: detected \(reported\)
REPORTED_TRIGGER_4: detected \(on write\)
SCANNED: detected \(scanned\)
DETECTED_23: detected \(sinkhole\)
DETECTED_18: detected \(syncookie sent\)
DETECTED_21: detected \(wildfire upload failure\)
DETECTED_20: detected \(wildfire upload success\)
DETECTED_22: detected \(wildfire upload skip\)
DETECTED_MTH: detected \(xdr managed threat hunting\)
BLOCKED_25: prevented \(block\)
BLOCKED: prevented \(blocked\)
BLOCKED_14: prevented \(block-override\)
BLOCKED_5: prevented \(blocked the url\)
BLOCKED_6: prevented \(blocked the ip\)
BLOCKED_13: prevented \(continue\)
BLOCKED_1: prevented \(denied the session\)
BLOCKED_8: prevented \(dropped all packets\)
BLOCKED_2: prevented \(dropped the session\)
BLOCKED_3: prevented \(dropped the session and sent a tcp reset\)
BLOCKED_7: prevented \(dropped the packet\)
BLOCKED_16: prevented \(override\)
BLOCKED_15: prevented \(override-lockout\)
BLOCKED_26: prevented \(post detected\)
PROMPT_BLOCK: prevented \(prompt block\)
BLOCKED_17: prevented \(random-drop\)
BLOCKED_24: prevented \(silently dropped the session with an icmp unreachable message to the host or application\)
BLOCKED_9: prevented \(terminated the session and sent a tcp reset to both sides of the connection\)
BLOCKED_10: prevented \(terminated the session and sent a tcp reset to the client\)
BLOCKED_11: prevented \(terminated the session and sent a tcp reset to the server\)
BLOCKED_TRIGGER_4: prevented \(on write\)
 | 
| PaloAltoNetworksXDR.Alert.alert_action_status_readable | String | The alert action. | 
| PaloAltoNetworksXDR.Alert.alert_name | String | The alert name. | 
| PaloAltoNetworksXDR.Alert.alert_description | String | The alert description. | 
| PaloAltoNetworksXDR.Alert.agent_ip_addresses | String | The host IP. | 
| PaloAltoNetworksXDR.Alert.agent_hostname | String | The host name. | 
| PaloAltoNetworksXDR.Alert.mitre_tactic_id_and_name | String | The MITRE attack tactic. | 
| PaloAltoNetworksXDR.Alert.mitre_technique_id_and_name | String | The MITRE attack technique. | 
| PaloAltoNetworksXDR.Alert.starred | Boolean | Whether the alert is starred or not. | 

#### Command example

```!xdr-get-alerts severity="high" alert_action_status="detected (reported)" sort_field="source_insert_ts" offset="0" limit="1"```

#### Context Example

```json
{
    "PaloAltoNetworksXDR": {
        "Alert": {
            "action_country": [
                "UNKNOWN"
            ],
            "action_external_hostname": null,
            "action_file_macro_sha256": null,
            "action_file_md5": null,
            "action_file_name": null,
            "action_file_path": null,
            "action_file_sha256": null,
            "action_local_ip": null,
            "action_local_ip_v6": null,
            "action_local_port": null,
            "action_process_causality_id": null,
            "action_process_image_command_line": null,
            "action_process_image_md5": [
                "ddcd2be64212b10c3cf84496a879b098"
            ],
            "action_process_image_name": null,
            "action_process_image_path": [
                "C:\Users\administrator\Downloads\svchost.exe"
            ],
            "action_process_image_sha256": null,
            "action_process_instance_id": null,
            "action_process_os_pid": [
                5172
            ],
            "action_process_signature_status": [
                "SIGNATURE_UNAVAILABLE"
            ],
            "action_process_signature_vendor": null,
            "action_process_user_sid": null,
            "action_registry_data": null,
            "action_registry_full_key": null,
            "action_registry_key_name": null,
            "action_registry_value_name": null,
            "action_remote_ip": null,
            "action_remote_ip_v6": null,
            "action_remote_port": null,
            "activity_first_seen_at": null,
            "activity_last_seen_at": null,
            "actor_causality_id": null,
            "actor_effective_user_sid": null,
            "actor_effective_username": [
                "env1.local\administrator"
            ],
            "actor_process_causality_id": [
                "AdhDcc/XHpAAABQ0AAAAAA=="
            ],
            "actor_process_command_line": [
                "\"C:\Users\administrator\Downloads\svchost.exe\" "
            ],
            "actor_process_execution_time": [
                1648560911622
            ],
            "actor_process_image_md5": [
                "ddcd2be64212b10c3cf84496a879b098"
            ],
            "actor_process_image_name": [
                "svchost.exe"
            ],
            "actor_process_image_path": [
                "C:\Users\administrator\Downloads\svchost.exe"
            ],
            "actor_process_image_sha256": [
                "b013074d220d71877112b61e16927abbbb98ad29aa40609aca1b936332fbe4b7"
            ],
            "actor_process_instance_id": [
                "AdhDcc/XHpAAABQ0AAAAAA=="
            ],
            "actor_process_os_pid": [
                5172
            ],
            "actor_process_signature_status": [
                "SIGNATURE_UNSIGNED"
            ],
            "actor_process_signature_vendor": null,
            "actor_thread_thread_id": [
                2468
            ],
            "agent_data_collection_status": true,
            "agent_device_domain": "env1.local",
            "agent_fqdn": "DC1ENV1APC02.env1.local",
            "agent_host_boot_time": [
                0
            ],
            "agent_hostname": "DC1ENV1APC02",
            "agent_id": "63f88a9e797440ccac742a6adc926fb2",
            "agent_install_type": "STANDARD",
            "agent_ip_addresses": [
                "10.111.230.11"
            ],
            "agent_ip_addresses_v6": null,
            "agent_is_vdi": null,
            "agent_os_sub_type": "10.0.10240",
            "agent_os_type": "AGENT_OS_WINDOWS",
            "agent_version": "7.6.1.46600",
            "alert_action_status": "REPORTED",
            "alert_action_status_readable": "detected (reported)",
            "alert_category": "Malware",
            "alert_description": "Behavioral threat detected (rule: bioc.masquerade_svchost)",
            "alert_description_raw": "Behavioral threat detected (rule: bioc.masquerade_svchost)",
            "alert_is_fp": false,
            "alert_name": "Behavioral Threat",
            "alert_source": "TRAPS",
            "alert_sub_type": null,
            "alert_type": "Unclassified",
            "association_strength": [
                50
            ],
            "attack_techniques": null,
            "attempt_counter": 0,
            "audit_ids": null,
            "bioc_category_enum_key": null,
            "bioc_indicator": null,
            "caller_ip": null,
            "case_id": 48,
            "causality_actor_causality_id": [
                "AdhDcc/XHpAAABQ0AAAAAA=="
            ],
            "causality_actor_process_command_line": [
                "\"C:\Users\administrator\Downloads\svchost.exe\" "
            ],
            "causality_actor_process_execution_time": [
                1648560911622
            ],
            "causality_actor_process_image_md5": null,
            "causality_actor_process_image_name": [
                "svchost.exe"
            ],
            "causality_actor_process_image_path": [
                "C:\Users\administrator\Downloads\svchost.exe"
            ],
            "causality_actor_process_image_sha256": [
                "b013074d220d71877112b61e16927abbbb98ad29aa40609aca1b936332fbe4b7"
            ],
            "causality_actor_process_instance_id": [
                "AdhDcc/XHpAAABQ0AAAAAA=="
            ],
            "causality_actor_process_os_pid": [
                5172
            ],
            "causality_actor_process_signature_status": [
                "SIGNATURE_UNSIGNED"
            ],
            "causality_actor_process_signature_vendor": null,
            "cloud_provider": null,
            "cluster_name": null,
            "container_id": null,
            "contains_featured_host": [
                "NO"
            ],
            "contains_featured_ip": [
                "NO"
            ],
            "contains_featured_user": [
                "NO"
            ],
            "deduplicate_tokens": null,
            "detection_modules": null,
            "dns_query_name": null,
            "drilldown_max_ts": null,
            "drilldown_min_ts": null,
            "drilldown_query": null,
            "dss_country": null,
            "dss_department": null,
            "dss_groups": null,
            "dss_job_title": null,
            "dst_action_country": null,
            "dst_action_external_hostname": null,
            "dst_action_external_port": null,
            "dst_actor_process_image_name": null,
            "dst_actor_process_os_pid": null,
            "dst_agent_hostname": null,
            "dst_agent_id": null,
            "dst_agent_os_type": [
                "NO_HOST"
            ],
            "dst_association_strength": null,
            "dst_causality_actor_process_execution_time": null,
            "dst_os_actor_process_image_name": null,
            "dst_os_actor_process_os_pid": null,
            "dynamic_fields": {
                "action_country": [
                    "UNKNOWN"
                ],
                "action_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                ],
                "activated": "0001-01-01T00:00:00Z",
                "activatingingUserId": "",
                "actor_effective_username": [
                    "env1.local\administrator"
                ],
                "actor_process_command_line": [
                    "\"C:\Users\administrator\Downloads\svchost.exe\" "
                ],
                "actor_process_image_md5": [
                    "ddcd2be64212b10c3cf84496a879b098"
                ],
                "actor_process_image_name": [
                    "svchost.exe"
                ],
                "actor_process_image_path": [
                    "C:\Users\administrator\Downloads\svchost.exe"
                ],
                "actor_process_image_sha256": [
                    "b013074d220d71877112b61e16927abbbb98ad29aa40609aca1b936332fbe4b7"
                ],
                "actor_process_os_pid": [
                    5172
                ],
                "actor_process_signature_status": [
                    "SIGNATURE_UNSIGNED"
                ],
                "actor_thread_thread_id": [
                    2468
                ],
                "agent_device_domain": "env1.local",
                "agent_fqdn": "DC1ENV1APC02.env1.local",
                "agent_hostname": "DC1ENV1APC02",
                "agent_id": "63f88a9e797440ccac742a6adc926fb2",
                "agent_ip_addresses": [
                    "10.111.230.11"
                ],
                "agent_os_sub_type": "10.0.10240",
                "agent_os_type": "AGENT_OS_WINDOWS",
                "alert_action_status": "REPORTED",
                "alert_category": "Malware",
                "alert_description": "Behavioral threat detected (rule: bioc.masquerade_svchost)",
                "alert_name": "Behavioral Threat",
                "alert_source": "TRAPS",
                "alert_type": "Unclassified",
                "attachment": null,
                "category": "",
                "causality_actor_causality_id": [
                    "AdhDcc/XHpAAABQ0AAAAAA=="
                ],
                "causality_actor_process_command_line": [
                    "\"C:\Users\administrator\Downloads\svchost.exe\" "
                ],
                "causality_actor_process_image_name": [
                    "svchost.exe"
                ],
                "causality_actor_process_image_path": [
                    "C:\Users\administrator\Downloads\svchost.exe"
                ],
                "causality_actor_process_image_sha256": [
                    "b013074d220d71877112b61e16927abbbb98ad29aa40609aca1b936332fbe4b7"
                ],
                "causality_actor_process_signature_status": [
                    "SIGNATURE_UNSIGNED"
                ],
                "closeReason": "",
                "closed": "0001-01-01T00:00:00Z",
                "closingUserId": "",
                "contains_featured_host": [
                    "NO"
                ],
                "contains_featured_ip": [
                    "NO"
                ],
                "contains_featured_user": [
                    "NO"
                ],
                "dbotCurrentDirtyFields": null,
                "dbotDirtyFields": null,
                "dbotMirrorDirection": "",
                "dbotMirrorId": "",
                "dbotMirrorInstance": "",
                "dbotMirrorLastSync": "0001-01-01T00:00:00Z",
                "dbotMirrorTags": null,
                "droppedCount": 0,
                "dueDate": "0001-01-01T00:00:00Z",
                "event_type": [
                    1
                ],
                "feedBased": false,
                "fw_is_phishing": [
                    "NOT_AVAILABLE"
                ],
                "internal_id": 6887,
                "investigationId": "6887",
                "isDebug": false,
                "is_whitelisted": false,
                "labels": null,
                "lastJobRunTime": "0001-01-01T00:00:00Z",
                "lastOpen": "0001-01-01T00:00:00Z",
                "linkedCount": 0,
                "linkedIncidents": null,
                "mac": "00:50:56:89:8b:8e",
                "mitre_tactic_id_and_name": [
                    "TA0005 - Defense Evasion",
                    "TA0002 - Execution"
                ],
                "mitre_technique_id_and_name": [
                    "T1036.005 - Masquerading: Match Legitimate Name or Location"
                ],
                "module_id": [
                    "Behavioral Threat Protection"
                ],
                "notifyTime": "2022-09-21T06:45:17.746532863Z",
                "occurred": "0001-01-01T00:00:00Z",
                "openDuration": 0,
                "os_actor_process_signature_status": [
                    "SIGNATURE_UNAVAILABLE"
                ],
                "os_actor_thread_thread_id": [
                    2468
                ],
                "phase": "",
                "playbookId": "T1036 - Masquerading",
                "reason": "",
                "reminder": "0001-01-01T00:00:00Z",
                "resolution_comment": "",
                "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
                "runStatus": "error",
                "severity": "SEV_040_HIGH",
                "sla": 0,
                "sourceInstance": "",
                "source_insert_ts": 1648560949000,
                "starred": false
            },
            "end_match_attempt_ts": null,
            "event_id": null,
            "event_sub_type": null,
            "event_timestamp": [
                1648560949290
            ],
            "event_type": [
                1
            ],
            "events_length": 1,
            "external_id": "d4c2983dfab74741b087dce1bbffd8d5",
            "family_tags": null,
            "filter_rule_id": null,
            "forensics_artifact_type": null,
            "from_dml": null,
            "fw_app_category": null,
            "fw_app_id": null,
            "fw_app_subcategory": null,
            "fw_app_technology": null,
            "fw_device_name": null,
            "fw_email_recipient": null,
            "fw_email_sender": null,
            "fw_email_subject": null,
            "fw_interface_from": null,
            "fw_interface_to": null,
            "fw_is_phishing": [
                "NOT_AVAILABLE"
            ],
            "fw_misc": null,
            "fw_rule": null,
            "fw_rule_id": null,
            "fw_serial_number": null,
            "fw_url_domain": null,
            "fw_vsys": null,
            "fw_xff": null,
            "identity_invoked_by_type": null,
            "identity_name": null,
            "identity_sub_type": null,
            "identity_type": null,
            "image_name": null,
            "internal_id": "6887",
            "iot_pivot_url": null,
            "is_disintegrated": null,
            "is_pcap": false,
            "is_whitelisted": false,
            "is_xsoar_alert": false,
            "last_modified_ts": 1663742717853,
            "local_insert_ts": 1648560958017,
            "mac": "00:50:56:89:8b:8e",
            "matching_service_rule_id": null,
            "matching_status": "MATCHED",
            "mitre_tactic_id_and_name": [
                "TA0005 - Defense Evasion",
                "TA0002 - Execution"
            ],
            "mitre_technique_id_and_name": [
                "T1036.005 - Masquerading: Match Legitimate Name or Location"
            ],
            "module_id": [
                "Behavioral Threat Protection"
            ],
            "module_name": [
                "COMPONENT_DSE"
            ],
            "operation_name": null,
            "original_severity": "SEV_040_HIGH",
            "os_actor_causality_id": null,
            "os_actor_effective_username": null,
            "os_actor_process_causality_id": null,
            "os_actor_process_command_line": null,
            "os_actor_process_execution_time": null,
            "os_actor_process_image_md5": null,
            "os_actor_process_image_name": null,
            "os_actor_process_image_path": null,
            "os_actor_process_image_sha256": null,
            "os_actor_process_instance_id": null,
            "os_actor_process_os_pid": null,
            "os_actor_process_signature_status": [
                "SIGNATURE_UNAVAILABLE"
            ],
            "os_actor_process_signature_vendor": null,
            "os_actor_thread_thread_id": [
                2468
            ],
            "phone_number": null,
            "pivot_url": null,
            "playbook_suggestion_rule_id": null,
            "policy_id": null,
            "project": null,
            "query_tables": null,
            "referenced_resource": null,
            "remote_cid": null,
            "resolution_comment": "",
            "resolution_status": "STATUS_020_UNDER_INVESTIGATION",
            "resource_sub_type": null,
            "resource_type": null,
            "severity": "SEV_040_HIGH",
            "source_insert_ts": 1648560949290,
            "starred": false,
            "story_id": null,
            "suggested_playbook_id": null,
            "tim_main_indicator": null,
            "user_agent": null,
            "xpanse_asset_id": null,
            "xpanse_asset_name": null,
            "xpanse_policy_id": null,
            "xpanse_primary_asset_id": null,
            "xpanse_service_id": null
        }
    }
}
```

#### Human Readable Output

>### Alerts

>|Action|Alert ID|Category|Description|Detection Timestamp|Host IP|Host Name|Name|Severity|
>|---|---|---|---|---|---|---|---|---|
>| detected (reported) | 6887 | Malware | Behavioral threat detected (rule: bioc.masquerade_svchost) | 2022-03-29T13:35:49.000Z | 10.111.230.11 | DC1ENV1APC02 | Behavioral Threat | SEV_040_HIGH |


### xdr-get-contributing-event

***
Retrieves contributing events for a specific correlation alert.
Known limitation: the command is compatible **only** with correlation alerts, otherwise an error will be raised.

##### Required Permissions

Required Permissions For API call:
`Alerts & Incidents` --> `View`

Builtin Roles with this permission includes: "Investigator", "Responder", "Privileged Investigator", "Privileged Responder", "Viewer", and "Instance Admin".

#### Base Command

`xdr-get-contributing-event`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | The alert ID's from where to retrieve the contributing events. | Required | 
| limit | The maximum number of contributing events to retrieve. Default is 50. | Optional | 
| page_number | The page number to retrieve. Minimum is 1. Default is 1. | Optional | 
| page_size | The page size. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ContributingEvent.alertID | String | The alert ID. | 
| PaloAltoNetworksXDR.ContributingEvent.events | Unknown | Contributing events per alert. | 

#### Command example

```!xdr-get-contributing-event alert_ids=`[123456 , 123457]````

#### Context Example

```json
{
    "PaloAltoNetworksXDR": {
        "ContributingEvent": [
            {
                "alertID": "123456",
                "events": [
                    {
                        "Domain": "WIN10X64",
                        "Host_Name": "WIN10X64",
                        "Logon_Type": "7",
                        "Process_Name": "C:\\Windows\\System32\\svchost.exe",
                        "Raw_Message": "An account was successfully logged on.",
                        "Source_IP": "1.1.1.1",
                        "User_Name": "xsoar",
                        "111111": 15,
                        "222222": 165298280000,
                        "333333": "abcdef",
                        "444444": 1,
                        "555555": "ghijk",
                        "_is_cardable": true,
                        "_product": "XDR agent",
                        "_time": 165298280000,
                        "_vendor": "PANW",
                        "insert_timestamp": 165298280001
                    }
                ]
            },
            {
                "alert_id": "123457",
                "events": [
                    {
                        "Domain": "WIN10X64",
                        "Host_Name": "WIN10X64",
                        "Logon_Type": "7",
                        "Process_Name": "C:\\Windows\\System32\\svchost.exe",
                        "Raw_Message": "An account was successfully logged on",
                        "Source_IP": "1.1.1.1",
                        "User_Name": "xsoar",
                        "111111": 15,
                        "222222": 165298280000,
                        "333333": "abcdef",
                        "444444": 1,
                        "555555": "ghijk",
                        "_is_cardable": true,
                        "_product": "XDR agent",
                        "_time": 165298280000,
                        "_vendor": "PANW",
                        "insert_timestamp": 165298280001
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Contributing events

>|Alert _ Id|Events|
>|---|---|
>| 123456 | **-**	***Logon_Type***: 7<br/>	***User_Name***: xsoar<br/>	***Domain***: WIN10X64<br/>	***Source_IP***: 1.1.1.1<br/>	***Process_Name***: C:\Windows\System32\svchost.exe<br/>	***Host_Name***: WIN10X64<br/>	***Raw_Message***: An account was successfully logged on.	***_time***: 165298280000<br/>	***555555***: a1b2c3d4<br/>	***222222***: 165298280000<br/>	***333333***: abcdef<br/>	***111111***: 15<br/>	***444444***: 1<br/>	***insert_timestamp***: 165298280001<br/>	***_vendor***: PANW<br/>	***_product***: XDR agent<br/>	***_is_cardable***: true |
>| 123457 | **-**	***Logon_Type***: 7<br/>	***User_Name***: xsoar<br/>	***Domain***: WIN10X64<br/>	***Source_IP***: 1.1.1.1<br/>	***Process_Name***: C:\Windows\System32\svchost.exe<br/>	***Host_Name***: WIN10X64<br/>	***Raw_Message***: An account was successfully logged on.	***_time***: 165298280000<br/>	***555555***: ghijk<br/>	***222222***: 165298280000<br/>	***333333***: abcdef<br/>	***111111***: 15<br/>	***444444***: 1<br/>	***insert_timestamp***: 165298280001<br/>	***_vendor***: PANW<br/>	***_product***: XDR agent<br/>	***_is_cardable***: true |


### xdr-replace-featured-field

***
Replace the featured hosts\users\IP addresses\active directory groups listed in your environment.

##### Required Permissions

Required Permissions For API call:
`Alerts & Incidents` --> `View/ Edit`

Builtin Roles with this permission includes: "Investigator", "Privileged Investigator", "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-replace-featured-field`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| field_type | The field type to change. Possible values are: hosts, users, ip_addresses, ad_groups. | Required | 
| values | The string value, which defines the new field. Maximum length is 256 characters. | Required | 
| comments | The string value, which represents additional information regarding the featured alert field. | Optional | 
| ad_type | The string value to replace an active directory group or organizational unit. Possible values are: group, ou. Default is group. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.FeaturedField.fieldType | String | The field type that changed. | 
| PaloAltoNetworksXDR.FeaturedField.fields | String | String value that defines the new field. | 

#### Command example

```!xdr-replace-featured-field field_type=ip_addresses values=`["1.1.1.1"]` comments=`new ip address````

#### Context Example

```json
{
    "PaloAltoNetworksXDR": {
        "FeaturedField": {
            "fieldType": "ip_addresses",
            "fields": [
                {
                    "comment": "new ip address",
                    "value": "1.1.1.1"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Replaced featured: ip_addresses

>|Comment|Value|
>|---|---|
>| new ip address | 1.1.1.1 |

### xdr-list-users

***
Retrieve a list of the current users in the environment.  
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per GB.

#### Base Command

`xdr-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.User.user_email | string | Email address of the user | 
| PaloAltoNetworksXDR.User.user_first_name | string | First name of the user | 
| PaloAltoNetworksXDR.User.user_last_name | string | Last name of the user. | 
| PaloAltoNetworksXDR.User.role_name | string | Role name associated with the user. | 
| PaloAltoNetworksXDR.User.last_logged_in | Number | Timestamp of when the user last logged in. | 
| PaloAltoNetworksXDR.User.user_type | string | Type of user. | 
| PaloAltoNetworksXDR.User.groups | array | Name of user groups associated with the user, if applicable. | 
| PaloAltoNetworksXDR.User.scope | array | Name of scope associated with the user, if applicable. | 

#### Command example

```!xdr-list-users```

#### Context Example

```json
{
    "dummy": {
        "User": [
            {
                "groups": [],
                "last_logged_in": 1648158415051,
                "role_name": "dummy",
                "scope": [],
                "user_email": "dummy@dummy.com",
                "user_first_name": "dummy",
                "user_last_name": "dummy",
                "user_type": "dummy"
            },
             {
                "groups": [],
                "last_logged_in": null,
                "role_name": "dummy",
                "scope": [],
                "user_email": "dummy@dummy.com",
                "user_first_name": "dummy",
                "user_last_name": "dummy",
                "user_type": "dummy"
            }            
        ]
    }
}
```

#### Human Readable Output

>### Users

>|First Name|Groups|Last Name|Role|Type|User email|
>|---|---|---|---|---|---|
>| dummy |  | dummy | dummy | dummy | dummy |
>| dummy |  | dummy | dummy | dummy | dummy |



### xdr-list-risky-users

***
Retrieve the risk score of a specific user or list of users with the highest risk score in the environment along with the reason affecting each score.  
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per GB.

#### Base Command

`xdr-list-risky-users`

#### Input

| **Argument Name** | **Description**                                                                                                         | **Required** |
| --- |-------------------------------------------------------------------------------------------------------------------------| --- |
| user_id | Unique ID of a specific user.<br/>User ID could be either of the `foo/dummy` format, or just `dummy`.<br/>.             | Optional | 
| limit | Limit the number of users that will appear in the list. (Use limit when no specific host is requested.). Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.RiskyUser.type | String | Form of identification element. | 
| PaloAltoNetworksXDR.RiskyUser.id | String | Identification value of the type field. | 
| PaloAltoNetworksXDR.RiskyUser.score | Number | The score assigned to the user. | 
| PaloAltoNetworksXDR.RiskyUser.reasons.date created | String | Date when the incident was created. | 
| PaloAltoNetworksXDR.RiskyUser.reasons.description | String | Description of the incident. | 
| PaloAltoNetworksXDR.RiskyUser.reasons.severity | String | The severity of the incident | 
| PaloAltoNetworksXDR.RiskyUser.reasons.status | String | The incident status | 
| PaloAltoNetworksXDR.RiskyUser.reasons.points | Number | The score. | 

#### Command example

```!xdr-list-risky-users user_id=dummy```

#### Context Example

```json
{
    "PaloAltoNetworksXDR": {
        "RiskyUser": {
            "id": "dummy",
            "reasons": [],
            "score": 0,
            "type": "user"
        }
    }
}
```

#### Human Readable Output

>### Risky Users

>|User ID|Score|Description|
>|---|---|---|
>| dummy | 0 |  |


### xdr-list-risky-hosts

***
Retrieve the risk score of a specific host or list of hosts with the highest risk score in the environment along with the reason affecting each score.  
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per GB.

#### Base Command

`xdr-list-risky-hosts`

#### Input

| **Argument Name** | **Description**                                                                                                                                           | **Required** |
| --- |-----------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| host_id | The host name of a specific host.                                                                                                                         | Optional | 
| limit | Limit the number of hosts that will appear in the list. By default, the limit is 50 hosts.(Use limit when no specific host is requested.). Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.RiskyHost.type | String | Form of identification element. | 
| PaloAltoNetworksXDR.RiskyHost.id | String | Identification value of the type field. | 
| PaloAltoNetworksXDR.RiskyHost.score | Number | The score assigned to the host. | 
| PaloAltoNetworksXDR.RiskyHost.reasons.date created | String | Date when the incident was created. | 
| PaloAltoNetworksXDR.RiskyHost.reasons.description | String | Description of the incident. | 
| PaloAltoNetworksXDR.RiskyHost.reasons.severity | String | The severity of the incident | 
| PaloAltoNetworksXDR.RiskyHost.reasons.status | String | The incident status | 
| PaloAltoNetworksXDR.RiskyHost.reasons.points | Number | The score. | 

#### Command example

```!xdr-list-risky-hosts host_id=dummy```

#### Context Example

```json
{
    "PaloAltoNetworksXDR": {
        "RiskyHost": {
            "id": "dummy",
            "reasons": [],
            "score": 0,
            "type": "dummy"
        }
    }
}
```

#### Human Readable Output

>### Risky Hosts

>|Host ID|Score|Description|
>|---|---|---|
>| dummy | 0 |  |


### xdr-list-user-groups

***
Retrieve a list of the current user emails associated with one or more user groups in the environment.  
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per GB.

#### Base Command

`xdr-list-user-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_names | A comma-separated list of one or more user group names for which you want the associated users. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.UserGroup.group_name | String | Name of the user group. | 
| PaloAltoNetworksXDR.UserGroup.description | String | Description of the user group, if available. | 
| PaloAltoNetworksXDR.UserGroup.pretty_name | String | Name of the user group as it appears in the management console. | 
| PaloAltoNetworksXDR.UserGroup.insert_time | Number | Timestamp of when the user group was created. | 
| PaloAltoNetworksXDR.UserGroup.update_time | Number | Timestamp of when the user group was last updated. | 
| PaloAltoNetworksXDR.UserGroup.user_email | array | List of email addresses belonging to the users associated with the user group. | 
| PaloAltoNetworksXDR.UserGroup.source | String | Type of user group. | 

#### Command example

```!xdr-list-user-groups group_names=test```

#### Context Example

```json
{
    "PaloAltoNetworksXDR": {
        "UserGroup": {
            "description": "test",
            "group_name": "test",
            "insert_time": 1684746187678,
            "pretty_name": null,
            "source": "Custom",
            "update_time": 1684746209062,
            "user_email": [
                null
            ]
        }
    }
}
```

#### Human Readable Output

>### Groups

>|Group Name|Group Description|User email|
>|---|---|---|
>| test | test for demo |  |


### xdr-list-roles

***
Retrieve information about one or more roles created in the environment.  
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per GB.

#### Base Command

`xdr-list-roles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_names | A comma-separated list of one or more role names in your environment for which you want detailed information. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.Role.pretty_name | String | Name of the role as it appears in the management console. | 
| PaloAltoNetworksXDR.Role.permissions | array | List of permissions associated with this role. | 
| PaloAltoNetworksXDR.Role.insert_time | Number | Timestamp of when the role was created. | 
| PaloAltoNetworksXDR.Role.update_time | Number | Timestamp of when the role was last updated. | 
| PaloAltoNetworksXDR.Role.created_by | String | Email of the user who created the role. | 
| PaloAltoNetworksXDR.Role.description | String | Description of the role, if available. | 
| PaloAltoNetworksXDR.Role.groups | array | Group names associated with the role. | 
| PaloAltoNetworksXDR.Role.users | array | Email address of users associated with the role. | 

#### Command example

```!xdr-list-roles role_names=dummy```

#### Context Example

```json
{
    "PaloAltoNetworksXDR": {
        "Role": [
            [
                {
                    "created_by": "dummy dummy",
                    "description": "The user(s) have full access.",
                    "groups": [],
                    "insert_time": null,
                    "permissions": [
                        "dummy"
                    ],
                    "pretty_name": "dummy",
                    "update_time": null,
                    "users": []
                }
            ]
        ]
    }
}
```

#### Human Readable Output

>### Roles

>|Role Name|Description|Permissions|Users|Groups|
>|---|---|---|---|---|
>| dummy | The user(s) have full access. | ADMIN |  |  |


### xdr-set-user-role

***
Add one or more users to a role.  
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per GB.

#### Base Command

`xdr-set-user-role`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_emails | A comma-separated list of one or more user emails of users you want to add to a role. | Required | 
| role_name | Name of the role you want to add a user to. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!xdr-set-user-role role_name=dummy user_emails=dummy```

#### Human Readable Output

>Role was updated successfully for 1 user.

### xdr-remove-user-role

***
Remove one or more users from a role.  
Required license: Cortex XDR Pro per Endpoint, Cortex XDR Pro, or Cortex XDR Pro per GB.

#### Base Command

`xdr-remove-user-role`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_emails | A comma-separate list of one or more user emails of users you want to remove from a role. | Required | 

#### Context Output

There is no context output for this command.

#### Command example

```!xdr-remove-user-role user_emails=dummy```

#### Human Readable Output

>Role was removed successfully for 1 user.

### xdr-script-run

***
Initiates a new endpoint script execution action using a script from the script library and returns the results.

##### Required Permissions

Required Permissions For API call:
`Agent Scripts library` --> `View`

Builtin Roles with this permission includes: "Privileged Responder", "Viewer" and "Instance Admin".


#### Base Command

`xdr-script-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_ids | A comma-separated list of endpoint IDs. Can be retrieved by running the xdr-get-endpoints command. | Required | 
| script_uid | Unique identifier of the script. Can be retrieved by running the xdr-get-scripts command. | Required | 
| parameters | Dictionary containing the parameter name as key and its value for this execution as the value. For example, {"param1":"param1_value","param2":"param2_value"}. | Optional | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| polling_interval_in_seconds | Interval in seconds between each poll. Default is 10. | Optional | 
| polling_timeout_in_seconds | Polling timeout in seconds. Default is 600. | Optional | 
| action_id | action ID for polling. | Optional | 
| hide_polling_output | whether to hide the polling result (automatically filled by polling). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptResult.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksXDR.ScriptResult.results.retrieved_files | Number | Number of successfully retrieved files. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_ip_address | String | Endpoint IP address. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_name | String | Number of successfully retrieved files. | 
| PaloAltoNetworksXDR.ScriptResult.results.failed_files | Number | Number of files failed to retrieve. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_status | String | Endpoint status. | 
| PaloAltoNetworksXDR.ScriptResult.results.domain | String | Domain to which the endpoint belongs. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_id | String | Endpoint ID. | 
| PaloAltoNetworksXDR.ScriptResult.results.execution_status | String | Execution status of this endpoint. | 
| PaloAltoNetworksXDR.ScriptResult.results.return_value | String | Value returned by the script in case the type is not a dictionary. | 
| PaloAltoNetworksXDR.ScriptResult.results.standard_output | String | The STDOUT and the STDERR logged by the script during the execution. | 
| PaloAltoNetworksXDR.ScriptResult.results.retention_date | Date | Timestamp in which the retrieved files will be deleted from the server. | 

#### Base Command

`xdr-script-run`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Allows linking the response action to the incident that triggered it. | Optional | 
| endpoint_ids | A comma-separated list of endpoint IDs. Can be retrieved by running the xdr-get-endpoints command. | Required | 
| script_uid | Unique identifier of the script. Can be retrieved by running the xdr-get-scripts command. | Required | 
| parameters | Dictionary containing the parameter name as key and its value for this execution as the value. For example, {"param1":"param1_value","param2":"param2_value"}. | Optional | 
| timeout | The timeout in seconds for this execution. Default is 600. | Optional | 
| polling_interval_in_seconds | Interval in seconds between each poll. Default is 10. | Optional | 
| polling_timeout_in_seconds | Polling timeout in seconds. Default is 600. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.ScriptResult.action_id | Number | ID of the action initiated. | 
| PaloAltoNetworksXDR.ScriptResult.results.retrieved_files | Number | Number of successfully retrieved files. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_ip_address | String | Endpoint IP address. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_name | String | Number of successfully retrieved files. | 
| PaloAltoNetworksXDR.ScriptResult.results.failed_files | Number | Number of files failed to retrieve. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_status | String | Endpoint status. | 
| PaloAltoNetworksXDR.ScriptResult.results.domain | String | Domain to which the endpoint belongs. | 
| PaloAltoNetworksXDR.ScriptResult.results.endpoint_id | String | Endpoint ID. | 
| PaloAltoNetworksXDR.ScriptResult.results.execution_status | String | Execution status of this endpoint. | 
| PaloAltoNetworksXDR.ScriptResult.results.return_value | String | Value returned by the script in case the type is not a dictionary. | 
| PaloAltoNetworksXDR.ScriptResult.results.standard_output | String | The STDOUT and the STDERR logged by the script during the execution. | 
| PaloAltoNetworksXDR.ScriptResult.results.retention_date | Date | Timestamp in which the retrieved files will be deleted from the server. | 

#### Command example

```!xdr-script-run endpoint_ids=1 script_uid=123```

#### Human Readable Output

>Waiting for the script to finish running on the following endpoints: ['1']...

>### Script Execution Results - 10368

>|_return_value|domain|endpoint_id|endpoint_ip_address|endpoint_name|endpoint_status|execution_status|failed_files|retention_date|retrieved_files|standard_output|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Name: return value | WORKGROUP | 1 | 1.1.1.1 | WIN10X64 | STATUS_010_CONNECTED | COMPLETED_SUCCESSFULLY | 0 |  | 0 |  |


#### Context Example

```json
{
  "PaloAltoNetworksXDR": {
    "ScriptResult": {
      "results": [
        {
          "domain": "WORKGROUP",
          "endpoint_name": "WIN10X64",
          "retrieved_files": 0,
          "failed_files": 0,
          "standard_output": "",
          "_return_value": [
            "return_value"
          ],
          "command_output": [
            "command_output"
          ],
          "endpoint_status": "STATUS_010_CONNECTED",
          "command": "_return_value",
          "endpoint_id": "1",
          "endpoint_ip_address": [
            "1.1.1.1"
          ],
          "execution_status": "COMPLETED_SUCCESSFULLY",
          "retention_date": null
        }
      ],
      "action_id": 4444
    }
  }
}
```

### xdr-endpoint-tag-add

***
Adds a tag to specified endpoint_ids

##### Required Permissions

Required Permissions For API call:
`Endpoint Administrations` --> `View/ Edit`

Builtin Roles with this permission includes: "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-endpoint-tag-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | List of endpoint IDs. Supports comma-separated list. | Optional | 
| tag | Tag to add. | Optional | 


#### Context Output

There is no context output for this command.

### xdr-endpoint-tag-remove

***
Removes a tag from specified endpoint_ids.

##### Required Permissions

Required Permissions For API call:
`Endpoint Administrations` --> `View/ Edit`

Builtin Roles with this permission includes: "Privileged Responder" and "Instance Admin".

#### Base Command

`xdr-endpoint-tag-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| endpoint_ids | List of endpoint IDs. Supports comma separated list. | Optional | 
| tag | Tag to remove from specified endpoint_ids. | Optional | 


#### Context Output

There is no context output for this command.

### xdr-get-tenant-info

***
Provides information about the tenant. 


#### Base Command

`xdr-get-tenant-info`

#### Input

There are no arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PaloAltoNetworksXDR.TenantInformation.pro_per_endpoint_expiration | Date | Expiration time pro per endpoint. | 
| PaloAltoNetworksXDR.TenantInformation.purchased_pro_per_endpoint.agents | Number | Number of endpoints agent purchased. | 
| PaloAltoNetworksXDR.TenantInformation.data_enabled_pro_per_endpoint | Number | Enabled data per pro endpoint. | 
| PaloAltoNetworksXDR.TenantInformation.prevent_expiration | Number | Number of prevent expirations. | 
| PaloAltoNetworksXDR.TenantInformation.purchased_prevent | Number | Number of purchased prevents. | 
| PaloAltoNetworksXDR.TenantInformation.installed_prevent | Number | Number of installed prevents. | 
| PaloAltoNetworksXDR.TenantInformation.pro_tb_expiration | Date | pro_tb license expiration time. | 
| PaloAltoNetworksXDR.TenantInformation.purchased_pro_tb.tb | Number | Number of pro_tbs purchased. | 
| PaloAltoNetworksXDR.TenantInformation.installed_pro_tb | Number | Number of pro_tbs installed. | 
| PaloAltoNetworksXDR.TenantInformation.compute_unit_expiration | Date | Compute unit expiration time. | 
| PaloAltoNetworksXDR.TenantInformation.purchased_compute_unit | Number | Number of compute units purchased. | 
| PaloAltoNetworksXDR.TenantInformation.compute_unit_is_trial | Boolean | Whether the compute unit is a trial. | 
| PaloAltoNetworksXDR.TenantInformation.host_insights_expiration | Date | Host insight expiration time. | 
| PaloAltoNetworksXDR.TenantInformation.enabled_host_insights | Number | Number of host insights enabled. | 
| PaloAltoNetworksXDR.TenantInformation.purchased_host_insights | Number | Number of purchased host insights. | 
| PaloAltoNetworksXDR.TenantInformation.forensics_expiration | Date | Forensic expiration time. | 
| PaloAltoNetworksXDR.TenantInformation.purchased_forensics | Number | Number of forensics purchased. | 

#### Command example

```!xdr-get-tenant-info```

#### Context Example

```json
{
    "PaloAltoNetworksXDR": {
        "TenantInformation": {
            "compute_unit_expiration": 0,
            "data_enabled_pro_per_endpoint": 2,
            "forensics_expiration": 0,
            "installed_prevent": 2,
            "installed_pro_tb": 0,
            "prevent_expiration": 0,
            "pro_per_endpoint_expiration": "May 7th 2025 06:59:59",
            "pro_tb_expiration": "May 7th 2025 06:59:59",
            "purchased_compute_unit": 2000,
            "purchased_prevent": 0,
            "purchased_pro_per_endpoint": {
                "agents": 300
            },
            "purchased_pro_tb": {
                "tb": 1
            }
        }
    }
}
```

#### Human Readable Output

>### Tenant Information

>|Compute _ Unit _ Expiration|Data _ Enabled _ Pro _ Per _ Endpoint|Forensics _ Expiration|Installed _ Prevent|Installed _ Pro _ Tb|Prevent _ Expiration|Pro _ Per _ Endpoint _ Expiration|Pro _ Tb _ Expiration|Purchased _ Compute _ Unit|Purchased _ Prevent|Purchased _ Pro _ Per _ Endpoint|Purchased _ Pro _ Tb|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  |  |  |  |  | May 7th 2025 06:59:59 | May 7th 2025 06:59:59 |  |  | ***agents***: 300 | ***tb***: 1 |




## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Palo Alto Networks Cortex XDR - Investigation and Response corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.
2. In the *Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:

    | **Option** | **Description** |
    | --- | --- |
    | None | Turns off incident mirroring. |
    | Incoming | Any changes in Palo Alto Networks Cortex XDR - Investigation and Response events (mirroring incoming fields) will be reflected in Cortex XSOAR incidents. |
    | Outgoing | Any changes in Cortex XSOAR incidents will be reflected in Palo Alto Networks Cortex XDR - Investigation and Response events (outgoing mirrored fields). |
    | Both |  |


Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Palo Alto Networks Cortex XDR - Investigation and Response.

### xdr-endpoint-alias-change

***
Gets a list of endpoints according to the passed filters, and changes their alias name. Filtering by multiple fields will be concatenated using the AND condition (OR is not supported).


#### Base Command

`xdr-endpoint-alias-change`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | The status of the endpoint to use as a filter. Possible values are: connected, disconnected. | Optional | 
| endpoint_id_list | A comma-separated list of endpoint IDs to use as a filter. | Optional | 
| dist_name | A comma-separated list of distribution package names or installation package names to use as a filter.<br/>Example: dist_name1,dist_name2. | Optional | 
| ip_list | A comma-separated list of IP addresses to use as a filter.<br/>Example: 8.8.8.8,1.1.1.1. | Optional | 
| group_name | A comma-separated list of group names to which the agent belongs to use as a filter.<br/>Example: group_name1,group_name2. | Optional | 
| platform | The endpoint platform to use as a filter. Possible values are: windows, linux, macos, android. | Optional | 
| alias_name | A comma-separated list of alias names to use as a filter.<br/>Examples: alias_name1,alias_name2. | Optional | 
| isolate | Specifies whether the endpoint was isolated or unisolated to use as a filter. Possible values are: isolated, unisolated.  Note: This argument returns only the first endpoint that matches the filter. | Optional | 
| hostname | A comma-separated list of hostnames to use as a filter.<br/>Example: hostname1,hostname2. | Optional | 
| first_seen_gte | All the agents that were first seen after {first_seen_gte} to use as a filter.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| first_seen_lte | All the agents that were first seen before {first_seen_lte} to use as a filter.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_gte | All the agents that were last seen after {last_seen_gte} to use as a filter.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| last_seen_lte | All the agents that were last seen before {last_seen_lte} to use as a filter.<br/>Supported values:<br/>1579039377301 (time in milliseconds)<br/>"3 days" (relative date)<br/>"2019-10-21T23:45:00" (date). | Optional | 
| username | The usernames to query for to use as a filter. Accepts a single user, or comma-separated list of usernames. | Optional | 
| new_alias_name | The alias name to change to.  Note: If you send an empty field, (e.g new_alias_name=\"\") the current alias name is deleted.| Required | 
| scan_status | The scan status of the endpoint to use as a filter. Possible values are: none, pending, in_progress, canceled, aborted, pending_cancellation, success, error. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example

```!xdr-endpoint-alias-change new_alias_name=test scan_status=success ip_list=1.1.1.1```

#### Human Readable Output

>The endpoint alias was changed successfully.
Note: If there is no error in the process, then this is the output even when the specific endpoint does not exist.

### xdr-update-alert

***
Update one or more alerts. You can update up to 100 alerts per request. Missing fields are ignored. Required license: Cortex XDR Prevent, Cortex XDR Pro per Endpoint, or Cortex XDR Pro per GB.

#### Base Command

`xdr-update-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alert_ids | Comma-separated list of alert IDs. | Required | 
| severity | Severity of the incident which was closed. Possible values are: critical, high, medium, low. | Optional | 
| status | New status for updated alerts. Possible values are: new, resolved_threat_handled, under_investigation, resolved_security_testing, resolved_auto, resolved_auto_resolve, resolved_known_issue, resolved_duplicate, resolved_other, resolved_false_positive, resolved_true_positive. | Optional | 
| comment | Comment to append to updated alerts. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!xdr-update-alert alert_ids=35326 severity=low```

#### Human Readable Output

>Alerts with IDs 35326 have been updated successfully.
