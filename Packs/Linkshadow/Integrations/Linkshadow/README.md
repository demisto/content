## Configure Linkshadow in Cortex


To configure the connection to your Linkshadow instance, you will provide:

API Token, API Username from Linkshadow  ( Generate tokens from following url : https://Linkshadow-device-IP/settings/#general-settings ) under the "Generate API Key for LinkShadow" section)


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | Use API Token  | True |
| url | Server URL \(e.g. https://Linkshadow_IP/) | True |
| API Username | Use API Username | True |
| action | fetch_entity_anomalies | True |
| plugin_id | xsoar_integration_1604211382 | True |
| Incidents Fetch Interval | 01 Minutes | Default |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.
### Linkshadow-fetch-entity-anomalies
***
Linkshadow returns the full incident details referenced by timeframe (default = 60min) in an API response. Use of this command will return the JSON structure of the API response. 

#### Base Command

`Linkshadow-fetch-entity-anomalies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_frame | Time Period | Optional(default:60) | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Linkshadow.data.GlobalID | String | Unique ID of the Anomaly to track in Linkshadow | 
| Linkshadow.data.action_time | Date | Time of Anomaly Send to XSOAR | 
| Linkshadow.data.anomaly_flag | Number | Anomaly Flag Value 1 - Means Active Anomaly, 0 Means Fixed Anomaly | 
| Linkshadow.data.anomaly_id | Number | Anomaly ID for LinkShadow |
| Linkshadow.data.anomaly_type| String | Incident Type |
| Linkshadow.data.bandwidth| String | Bandwidth usage of the Anomalous session |
| Linkshadow.data.category| String | Additional Information for the anomaly |
| Linkshadow.data.data | String | Time of Anomaly seen |
| Linkshadow.data.desc | String | Description of anomaly from linkshadow |
| Linkshadow.data.dip | String | Destination Ip in the detected anomaly |
| Linkshadow.data.dmac | String | Destination mac address |
| Linkshadow.data.dport | String | Destination port number of the anomalous session |
| Linkshadow.data.id | String | NA |
| Linkshadow.data.inserted_time | Date | Time of Anomaly added to the database |
| Linkshadow.data.score | Number | Risk Score of the Anomaly - Typical value between 1-20 |
| Linkshadow.data.sip | String | Source IP in the detected Anomaly |
| Linkshadow.data.smac | String | Source Mac Address in the detected Anomaly |
| Linkshadow.data.sport | String | Source port number of the anomalous session |
| Linkshadow.data.time_seen |Date | Time of Anomaly seen |