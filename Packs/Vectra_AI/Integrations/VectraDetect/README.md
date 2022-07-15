This integration allows to create incidents based on Vectra Accounts/Detections/Hosts objects
This integration was integrated and tested with version 6.19 of Vectra Detect

## Configure Vectra Detect (Beta) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Vectra Detect (Beta).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Vectra Detect FQDN or IP | Enter the FQDN or IP to reach the Vectra Detect API. \(e.g. "my-vectra-box.local" or "192.168.1.1"\) | True |
    | API Token | Enter the API token that can be retrieved from the Vectra UI &amp;gt; My Profile &amp;gt; General \(tab\) &amp;gt; API Token. You can also use the XSOAR credentials wallet to store it. In that case, the token should be the password. | True |
    | API Token |  | True |
    | Trust any certificate (not secure) | When checked, no SSL certificates check will be done when interracting with the Vectra Detect API. It's insecure. \(Default - unchecked\) | False |
    | Use system proxy settings | Use the system proxy settings to reach with the Vectra Detect API. | False |
    | Fetch incidents |  | False |
    | Incident type |  | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | How far back in time you want to fetch alerts. \(default - 7 days\) | False |
    | Entity types to fetch | Choose what to fetch - Hosts and/or Detections. \(Default - Hosts\) | True |
    | Hosts fetch query | Only "active" Hosts matching this fetch query will be fetched. Will be used only if "Hosts" is selected in the "Entity types to fetch". \(default - host.threat:&amp;gt;=50 AND host.certainty:&amp;gt;=50\) | False |
    | Detections fetch query | Only "active" Detections matching this fetch query will be fetched. Will be used only if "Detections" is selected in the "Entity types to fetch". \(default - detection.threat:&amp;gt;=50 AND detection.certainty:&amp;gt;=50\) | False |
    | Max created incidents per fetch | How many new incidents do you want to create at max per fetch. This value would be split between selected "Entity types to fetch". \(Default - 50\) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### vectra-host-describe
***
Returns a single Host details


#### Base Command

`vectra-host-describe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Host ID you want to get details on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Host.Assignee | String | Vectra user account this Host is assigned to | 
| Vectra.Host.AssignedDate | String | Assignment date | 
| Vectra.Host.CertaintyScore | Number | Host certainty score | 
| Vectra.Host.HasActiveTraffic | Boolean | Whether this Host has active traffic | 
| Vectra.Host.Hostname | String | Host name | 
| Vectra.Host.ID | Number | Host ID \(Unique\) | 
| Vectra.Host.IP | String | Host IP address | 
| Vectra.Host.IsKeyAsset | Boolean | Whether this Host is seen as a key asset | 
| Vectra.Host.IsTargetingKeyAsset | Boolean | Whether this Host is targeting a key asset | 
| Vectra.Host.PrivilegeLevel | Number | Host privilege level \(from 1 to 10\) | 
| Vectra.Host.PrivilegeCategory | String | Host privilege category. \(Either 'Low', 'Medium' or 'High' - Privilege levels of 1-2 &gt; 'Low', 3-7 &gt; 'Medium', 8-10 &gt; 'High'\) | 
| Vectra.Host.ProbableOwner | String | Host probable owner | 
| Vectra.Host.SensorLUID | String | Sensor LUID that saw this Host | 
| Vectra.Host.SensorName | String | Sensor Name that saw this Host | 
| Vectra.Host.Sensor | String | Sensor details that have seen this Host | 
| Vectra.Host.Severity | String | Host severity according to scores \('Low', 'Medium', 'High', 'Critical'\) | 
| Vectra.Host.State | String | Host state \('active', 'inactive'\) | 
| Vectra.Host.Tags | String | Host tags | 
| Vectra.Host.ThreatScore | Number | Host threat score | 
| Vectra.Host.URL | String | Host URL to pivot to Vectra UI | 

### vectra-host-add-tags
***
Add tags to an Host


#### Base Command

`vectra-host-add-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Host ID you want to add tags on. | Optional | 
| tags | The tags list (comma separated). | Optional | 


#### Context Output

There is no context output for this command.
### vectra-host-del-tags
***
Delete tags from an Host


#### Base Command

`vectra-host-del-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Host ID you want to del tags from. | Optional | 
| tags | The tags list (comma separated). | Optional | 


#### Context Output

There is no context output for this command.
### vectra-detection-describe
***
Returns a single detection details


#### Base Command

`vectra-detection-describe`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Detection ID you want to get details on. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Vectra.Detection.Assignee | String | Vectra user account this detection is assigned to | 
| Vectra.Detection.AssignedDate | String | Assignment date | 
| Vectra.Detection.Category | String | Detection category \(Lateral, Exfil, ...\) | 
| Vectra.Detection.CertaintyScore | Number | Detection certainty score | 
| Vectra.Detection.Description | String | Detection description | 
| Vectra.Detection.FirstTimestamp | String | First time this detection has been seen | 
| Vectra.Detection.ID | Number | Detection ID \(unique\) | 
| Vectra.Detection.IsTargetingKeyAsset | Boolean | Whether this detection is targeting a key asset | 
| Vectra.Detection.LastTimestamp | String | Last time this detection has been seen | 
| Vectra.Detection.Name | String | The name of the detection. Would be a user defined name if this detection is triaged or the default type name instead | 
| Vectra.Detection.Severity | String | Detection severity according to scores \('Low', 'Medium', 'High', 'Critical'\) | 
| Vectra.Detection.SensorLUID | String | Sensor LUID that saw this etection | 
| Vectra.Detection.SensorName | String | Sensor Name that saw this Detection | 
| Vectra.Detection.SourceAccountID | String | Account ID relating to this detection | 
| Vectra.Detection.SourceHostID | String | Host ID relating to this detection | 
| Vectra.Detection.SourceIP | String | Source IP relating to this detection | 
| Vectra.Detection.State | String | Detection state \('active', 'inactive'\) | 
| Vectra.Detection.Tags | String | Detection tags | 
| Vectra.Detection.ThreatScore | Number | Detection threat score | 
| Vectra.Detection.TriageRuleID | String | Triage rule ID related to this detection | 
| Vectra.Detection.Type | String | Detection type \(Brute Force, Port Sweep, ...\) | 
| Vectra.Detection.URL | String | Detection URL to pivot to Vectra UI | 

### vectra-detection-get-pcap
***
Returns a Detection's PCAP file (if available)


#### Base Command

`vectra-detection-get-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The Detection ID you want to get the PCAP file from. | Optional | 


#### Context Output

There is no context output for this command.
### vectra-detection-markasfixed
***
Marks/Unmarks a Detection as fixed by providing the Detection ID


#### Base Command

`vectra-detection-markasfixed`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Detection ID you want to mark/unmark as fixed. | Optional | 
| fixed | The wanted detection status ("true", "false"). No default value. | Optional | 


#### Context Output

There is no context output for this command.
### vectra-detection-add-tags
***
Add tags to a Detection


#### Base Command

`vectra-detection-add-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Detection ID you want to add tags on. | Optional | 
| tags | The tags list (comma separated). | Optional | 


#### Context Output

There is no context output for this command.
### vectra-detection-del-tags
***
Delete tags from a Detection


#### Base Command

`vectra-detection-del-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Detection ID you want to del tags from. | Optional | 
| tags | The tags list (comma separated). | Optional | 


#### Context Output

There is no context output for this command.