Data center breach detection.
This integration was integrated and tested with version v3.0 of GuardiCore API.
## Configure GuardiCore in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://192.168.0.1) | True |
| Username | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### guardicore-get-incidents
***
Display information about incidents (with filters).


#### Base Command

`guardicore-get-incidents`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| severity | Filter by severity. Possible values are: High, Low, Medium. | Optional | 
| tag | Filter by tag. | Optional | 
| from_time | From which date to fetch incidents, format is YYYY-MM-DD. | Optional | 
| to_time | Until which date to fetch incidents, format is YYYY-MM-DD. | Optional | 
| incident_type | Filter by type of incidents, e.g. Deception, Lateral Movement. | Optional | 
| source | Filter by source (hostname or IP address). | Optional | 
| destination | Filter by destination (hostname or IP address). | Optional | 


### guardicore-uncommon-domains
***
Display the uncommon domains.


#### Base Command

`guardicore-uncommon-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


### guardicore-unresolved-domains
***
Display the unresolved domains.


#### Base Command

`guardicore-unresolved-domains`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


### guardicore-show-endpoint
***
Display information about the endpoint given its ID.


#### Base Command

`guardicore-show-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | The host ID. | Required | 


### guardicore-dns-requests
***
Display the DNS requests.


#### Base Command

`guardicore-dns-requests`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


### guardicore-search-endpoint
***
Display information about the endpoint by its hostname or IP address.


#### Base Command

`guardicore-search-endpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_address | The IP address of the endpoint. | Optional | 
| name | The hostname of the endpoint. | Optional | 


### guardicore-misconfigurations
***
Display the misconfigurations.


#### Base Command

`guardicore-misconfigurations`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


### guardicore-get-incident
***
Display information about the given incident.


#### Base Command

`guardicore-get-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the incident. | Required | 


### guardicore-get-incident-iocs
***
Display the IOCs (Indicators of Compromise) of the given incident.


#### Base Command

`guardicore-get-incident-iocs`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the incident. | Required | 


### guardicore-get-incident-events
***
Display the events related to the given incidents.


#### Base Command

`guardicore-get-incident-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the incident. | Required | 


### guardicore-get-incident-pcap
***
Retrieve the PCAP file attached to the given incident.


#### Base Command

`guardicore-get-incident-pcap`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the incident. | Required | 


### guardicore-get-incident-attachments
***
Retrieve the files attached to the given incidents.


#### Base Command

`guardicore-get-incident-attachments`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the incident. | Required | 


### guardicore-search-network-log
***
Searches within the network log (with filters).


#### Base Command

`guardicore-search-network-log`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | Filter by source (hostname or IP address). | Optional | 
| destination | Filter by destination (hostname or IP address). | Optional | 
| port | Filter by port number. | Optional | 
| uuid | Filter by Event ID. | Optional | 