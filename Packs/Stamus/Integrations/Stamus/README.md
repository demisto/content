[Get Declaration of Compromises from Stamus Security Platform and build Incidents. Then get related artifacts, events and Host Insight information]
This integration was integrated and tested with version 39.0.1 of Stamus Security Platform

## Configure Stamus in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Stamus Central Server |  | True |
| API Key | The API Key to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Incident type |  | False |
| Fetch incidents |  | False |
| Maximum number of incidents per fetch |  | False |
| First fetch time |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### stamus-check-ioc

***
[Get events with IOC key/value filter]

#### Base Command

`stamus-check-ioc`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_key | [Indicator of Compromise key]. | Required | 
| indicator_value | [Indicator of Compromise value]. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| StamusIntegration.IOC | String | \[Fetch events matching an IOC.\] | 
| StamusIntegration.IOC.timestamp | String | \[Timestamp of the event\] | 
| StamusIntegration.IOC.src_ip | String | \[Source IP of the event\] | 
| StamusIntegration.IOC.dest_ip | String | \[Destination IP of the event\] | 
| StamusIntegration.IOC.event_type | String | \[Type of the event - can be multitude, example: HTTP,SMB,DNS,Flow,TLS,KRB5,FTP etc\] | 

### stamus-get-host-insight

***
[Get Host Insights information]

#### Base Command

`stamus-get-host-insight`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | [IP to get Host Insights information]. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| StamusIntegration.HostInsights | String | \[Fetch information about a host known by Host Insight module\] | 
| StamusIntegration.HostInsights.ip | String | \[Stamus Host Insights IP address\] | 
| StamusIntegration.HostInsights.host_id.client_service.first_seen | String | \[Timestamp of first time seen\] | 
| StamusIntegration.HostInsights.host_id.client_service | String | \[Client network service detected\] | 
| StamusIntegration.HostInsights.host_id.services.proto | String | \[Network services protocol\] | 
| StamusIntegration.HostInsights.host_id.services.port | String | \[Network services port\] | 
| StamusIntegration.HostInsights.host_id.services.values.first_seen | String | \[Network services for the corresponding application protocol first time seen\] | 
| StamusIntegration.HostInsights.host_id.services.values.last_seen | String | \[Network services for the corresponding application protocol last time seen\] | 
| StamusIntegration.HostInsights.host_id.services.values.app_proto | String | \[Network services application layer protocol\] | 
| StamusIntegration.HostInsights.host_id.services.services_count | Number | \[Number of network services detected on the host\] | 
| StamusIntegration.HostInsights.host_id.client_service.name | String | \[Type of client network service detected - can be HTTP,KRB5,TLS,DCERPC,SMB etc\] | 
| StamusIntegration.HostInsights.host_id.hostname.host | String | \[Hostname detected on the host\] | 
| StamusIntegration.HostInsights.host_id.username.user | String | \[Username detected loggin in on the host\] | 
| StamusIntegration.HostInsights.host_id.http\.user_agent.agent | String | \[HTTP User-Agent detected being used from the host\] | 
| StamusIntegration.HostInsights.host_id.tls\.ja3.hash | String | \[TLS JA3 hash detected being used from the host\] | 
| StamusIntegration.HostInsights.host_id.tls\.ja3s.hash | String | \[TLS JA3S hash detected being used from the host\] | 

### stamus-get-doc-events

***
[Get events for a Declaration of Compromise using the Stamus ID]

#### Base Command

`stamus-get-doc-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | [Stamus ID used to get related information]. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| StamusIntegration.RelatedEvents | String | \[Get events for a Declaration of Compromise.\] | 
| StamusIntegration.RelatedEvents.timestamp | String | \[Timestamp of the Stamus event\] | 
| StamusIntegration.RelatedEvents.stamus.asset | String | \[Stamus asset\] | 
| StamusIntegration.RelatedEvents.offender | String | \[Offender, against the Stamus asset\] | 
| StamusIntegration.RelatedEvents.killchain | String | \[Killchain stage\] | 
| StamusIntegration.RelatedEvents.method | String | \[Stamus method triggered\] | 
| StamusIntegration.RelatedEvents.info | String | \[Extra Information\] | 
| StamusIntegration.RelatedEvents.src_ip | String | \[Source IP of the event\] | 
| StamusIntegration.RelatedEvents.dest_ip | String | \[Destination IP of the event\] | 
| StamusIntegration.RelatedEvents.app_proto | String | \[Application protocol of the event\] | 