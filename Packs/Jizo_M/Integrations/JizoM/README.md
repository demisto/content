This integration ensures interaction with the JizoM API.
This integration was integrated and tested with version 12.3 of JizoM.

## Configure JizoM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username | Reliability of the source providing the intelligence data. | True |
| Password |  | True |
| Server URL. e.g., <https://127.0.0.1:9001> |  | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incidents Fetch Interval |  | False |
| First fetch time (number, time unit, for example, 12 hours, 7 days, 3 months, 1 year) |  | False |
| Maximum number of alerts per fetch |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### jizo-m-protocols-get

***
Get the list of alerts sorted by protocols.

#### Base Command

`jizo-m-protocols-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_src | Ipv4 or Ipv6 of the source. | Optional | 
| ip_dest | Ipv4 or Ipv6 of the destination. | Optional | 
| datetime_from | Get the alerts that were occurred from this date, for example, "3 days ago", "2020-01-01-00:00:00". The default value is 7 days ago. | Optional | 
| datetime_to | Get the alerts that were occurred up to this date, for example, "3 days ago", "2020-01-01-00:00:00". The default is now. | Optional | 
| probe_name | The name of the jizo probe. | Optional | 
| page | A page number for pagination. | Optional | 
| limit | The maximum number of protocols to display per alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JizoM.Protocols.alerts_flows.count | Number | The number of displayed alerts. | 
| JizoM.Protocols.alerts_flows.data | String | The details of alerts. | 
| JizoM.Protocols.alerts_flows.total | Number | The total number of alerts. | 
| JizoM.Protocols.alerts_files.count | Number | The number of displayed alerts. | 
| JizoM.Protocols.alerts_files.data | String | The details of alerts. | 
| JizoM.Protocols.alerts_files.total | Number | The total number of alerts. | 
| JizoM.Protocols.alerts_usecase.count | Number | The number of displayed alerts. | 
| JizoM.Protocols.alerts_usecase.data | String | The details of alerts. | 
| JizoM.Protocols.alerts_usecase.total | Number | The total number of alerts. | 

### jizo-m-peers-get

***
Get list of IP addresses connected to a specific one.

#### Base Command

`jizo-m-peers-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_src | Ipv4 or Ipv6 of the source. | Optional | 
| ip_dest | Ipv4 or Ipv6 of the destination. | Optional | 
| datetime_from | Get the alerts that were occurred from this date, for example, "3 days ago", "2020-01-01-00:00:00". The default value is 7 days ago. | Optional | 
| datetime_to | Get the alerts that were occurred up to this date, for example, "3 days ago", "2020-01-01-00:00:00". The default is now. | Optional | 
| probe_name | The name of the jizo probe. | Optional | 
| page | A page number for pagination. | Optional | 
| limit | The maximum number of samples to display per alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JizoM.Peers.alerts_flows.count | Number | The number of displayed alerts. | 
| JizoM.Peers.alerts_flows.data | String | The details of alerts. | 
| JizoM.Peers.alerts_flows.total | Number | The total number of alerts. | 
| JizoM.Peers.alerts_files.count | Number | The number of displayed alerts. | 
| JizoM.Peers.alerts_files.data | String | The details of alerts. | 
| JizoM.Peers.alerts_files.total | Number | The total number of alerts. | 
| JizoM.Peers.alerts_usecase.count | Number | The number of displayed alerts. | 
| JizoM.Peers.alerts_usecase.data | String | The details of alerts. | 
| JizoM.Peers.alerts_usecase.total | Number | The total number of alerts. | 

### jizo-m-query-records-get

***
Retrieve all information available on Jizo M, mainly alerts.

#### Base Command

`jizo-m-query-records-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_src | Ipv4 or Ipv6 of the source. | Optional | 
| ip_dest | Ipv4 or Ipv6 of the destination. | Optional | 
| proto | The protocol. Possible values are: TCP, UDP, IP, IPSEC, ICMP, ARP. | Optional | 
| app_proto | The application protocol. Possible values are: HTTP, HTTPS, FTP, DNS, DHCP, DCERPC, SMB, SMTP, SNMP, SSL, SSH, SIP, RDP, RFB, NFS, MQTT, MSN, MODBUS, IMAP, TFTP, KRBS. | Optional | 
| port_src | The source port. | Optional | 
| port_dest | The destination port. | Optional | 
| flow_id | The id of the flow. | Optional | 
| sid | The id of the rule. | Optional | 
| probe_name | The name of the jizo probe. | Optional | 
| port | The alert port. | Optional | 
| datetime_from | Get the alerts that were occurred from this date, for example, "3 days ago", "2020-01-01-00:00:00". The default value is 7 days ago. | Optional | 
| datetime_to | Get the alerts that were occurred up to this date, for example, "3 days ago", "2020-01-01-00:00:00". The default is now. | Optional | 
| page | A page number for pagination. | Optional | 
| limit | The maximum number of samples to display per alert. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| JizoM.QueryRecords.alerts_flows.count | Number | The number of displayed alerts. | 
| JizoM.QueryRecords.alerts_flows.data | String | The details of alerts. | 
| JizoM.QueryRecords.alerts_flows.total | Number | The total number of alerts. | 
| JizoM.QueryRecords.alerts_files.count | Number | The number of displayed alerts. | 
| JizoM.QueryRecords.alerts_files.data | String | The details of alerts. | 
| JizoM.QueryRecords.alerts_files.total | Number | The total number of alerts. | 
| JizoM.QueryRecords.alerts_usecase.count | Number | The number of displayed alerts. | 
| JizoM.QueryRecords.alerts_usecase.data | String | The details of alerts. | 
| JizoM.QueryRecords.alerts_usecase.total | Number | The total number of alerts. | 