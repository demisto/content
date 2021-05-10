## Overview
---

CounterCraft Deception Solution detects advanced adversaries. Automate counterintelligence campaigns to discover targeted attacks with real-time active response.
This integration was integrated and tested with version 2.5.13 of CounterCraft Deception Director
## CounterCraft Deception Director Playbook
---

## Use Cases
---

* Query IOCs (objects) in your Deception Director
* Retrieve events from your deception campaigns
* Retrieve configuration from your Deception Director
* Retrieve alerts (notifications) from your Deception Director
* Create new deception campaigns
* Create new deception hosts
* Operate your campaigns, hosts, services and breadcrumbs

## Prerequisites
---

You need to obtain the following Deception Director information.

* Server URL
* API Key
* Secret Key

In order to obtain the API Key and the Secret Key you need to go to the user settings in the Deception Director
and copy both or generate a new pair if they are not already generated.

## Configure CounterCraft Deception Director on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for CounterCraft Deception Director.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Deception Director Domain or IP Address__: for example, https://192.168.1.1
    * __Fetch incidents__: if you select this option, your notifications in the Deception Director will be created as Demisto incidents.
    * __Incident type__
    * __API Key  for Deception Director connection__: paste your API Key.
    * __Secret Key for Deception Director connection__: paste your Secret Key.
    * __Ignore SSL Warnings__: in case the SSL certificate is self-signed.
    * __Use system proxy settings__: in case you need to connect through a proxy.
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. countercraft-list-campaigns
2. countercraft-list-hosts
3. countercraft-list-services
4. countercraft-list-breadcrumbs
5. countercraft-get-object
6. countercraft-get-events
7. countercraft-create-campaign
8. countercraft-list-dsns
9. countercraft-list-providers
10. countercraft-create-host-machine
11. countercraft-list-incidents
12. countercraft-manage-campaign
13. countercraft-manage-host
14. countercraft-manage-service
15. countercraft-manage-breadcrumb
### 1. countercraft-list-campaigns
---
List all deception campaigns
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to list only the campaigns you have access to.

##### Base Command

`countercraft-list-campaigns`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Campaign Name | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Campaign.ID | number | Campaign ID |
| CounterCraft.Campaign.Name | string | Campaign Name |
| CounterCraft.Campaign.Description | string | Campaign Description |
| CounterCraft.Campaign.StatusCode | string | Campaign Status |


##### Command Example
```!countercraft-list-campaigns ```

##### Human Readable Output

| **ID** | **Name** | **Description** | **StatusCode** |
| --- | --- | --- | --- |
| 1 | AntiPhishing | Gather intelligence from phishers | ACTIVE |
| 2 | External recoinassance | Collect pre-attack evidence | ACTIVE |
| 3 | Internal lateral movement | Detect lateral movement | ACTIVE |
| 4 | DMZ | DMZ activity | ACTIVE |
| 5 | VIP | VIP mobile protection | ACTIVE |


### 2. countercraft-list-hosts
---
Lists all deception hosts
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to list only the hosts you have access to.

##### Base Command

`countercraft-list-hosts`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| campaign_id | Campaign ID | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Host.ID | number | Host Id |
| CounterCraft.Host.Name | string | Host Name |
| CounterCraft.Host.Description | string | Host Description |
| CounterCraft.Host.StatusCode | string | Host Status |
| CounterCraft.Host.TypeCode | string | Host Type |


##### Command Example
```!countercraft-list-hosts campaign_id=2```

##### Human Readable Output

| **ID** | **Name** | **Description** | **StatusCode** | **TypeCode** |
| --- | --- | --- | --- | --- |
| 1 | Ubuntu Web | Wordpress | ACTIVE | MACHINE |
| 2 | Azure Windows 2019 | RDP with breadcrumbs | ACTIVE | MACHINE |
| 3 | Office365 tenant | Office365 with domain name | ACTIVE | CLOUD_ENTITY |
| 4 | Apache Struts | Vulnerable Apache Struts | ACTIVE | MACHINE |
| 5 | CFO | CFO persona | ACTIVE | IDENTITY |


### 3. countercraft-list-services
---
List services currently deployed on deception hosts
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to list only the services you have access to.

##### Base Command

`countercraft-list-services`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | Host Id | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Service.ID | number | Service ID |
| CounterCraft.Service.Name | string | Service Name |
| CounterCraft.Service.Description | string | Service.Description |
| CounterCraft.Service.StatusCode | string | Service Status |
| CounterCraft.Service.TypeCode | string | Service Type |


##### Command Example
```!countercraft-list-services host_id=1 ```

##### Human Readable Output

| **ID** | **Name** | **Description** | **StatusCode** | **TypeCode** |
| --- | --- | --- | --- | --- |
| 1 | Operating system | User events | ACTIVE | SYSTEM |
| 2 | WebApp | Web application | ACTIVE | WEB_SERVER |
| 8 | Tailored Service | Anonymous FTP | ACTIVE | FTP_SERVER |
| 9 | Phishing Sinkhole | Sinkhole | ACTIVE | SMTP_SERVER |


### 4. countercraft-list-breadcrumbs
---
List breadcrumbs in a campaign
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to list only the breadcrumbs you have access to.

##### Base Command

`countercraft-list-breadcrumbs`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| campaign_id | Campaign ID | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Breadcrumb.ID | number | Breadcrumb ID |
| CounterCraft.Breadcrumb.Name | string | Breadcrumb Name |
| CounterCraft.Breadcrumb.Description | string | Breadcrumb Description |
| CounterCraft.Breadcrumb.StatusCode | string | Breadcrumb Status |
| CounterCraft.Breadcrumb.TypeCode | string | Breadcrumb Type |


##### Command Example
```!countercraft-list-breadcrumbs campaign_id=1```

##### Human Readable Output

| **ID** | **Name** | **Description** | **StatusCode** | **TypeCode** |
| --- | --- | --- | --- | --- |
| 1 | Fake document |  | ACTIVE | DOCUMENT |
| 2 | Mobile App |  | ACTIVE | MOBILE_APP |
| 3 | SSL Certificate | | ACTIVE | SSL_CERTIFICATE |
| 4 | LinkedIn_persona | | ACTIVE | HONEYTOKEN |

### 5. countercraft-get-object
---
Get information about an object (IoC)
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to list only the objects you have access to.

##### Base Command

`countercraft-get-object`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | Object value | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Object.ID | number | Object ID |
| CounterCraft.Object.Value | string | Object value |
| CounterCraft.Object.Hits | number | Object hits |
| CounterCraft.Object.Score | number | Object score |
| CounterCraft.Object.TypeCode | string | Object type |
| CounterCraft.Object.FirstSeen | date | Object first seen |
| CounterCraft.Object.LastSeen | date | Object last seen |
| CounterCraft.Object.EventsCount | number | Object events count |
| CounterCraft.Object.Tags | string | Object tags |


##### Command Example
```!countercraft-get-object value=root```

##### Human Readable Output

| | |
| --- | --- |
| Id | 852 |
| Value | root |
| EventsCount | 7 |
| TypeCode | CC_USERNAME |
| Score | 0 |
| FirstSeen | Wed Jan 29 12:33:34 2020 |
| LastSeen | Wed Jan 29 12:53:19 2020 |
| Tags | |

### 6. countercraft-get-events
---
Get full list of Events
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to list only the objects you have access to.

##### Base Command

`countercraft-get-events`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| criteria | Search criteria | Required |
| max_results | Maximum number of results | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Event.ID | number | Event id |
| CounterCraft.Event.CampaignName | string | Campaign name |
| CounterCraft.Event.CategoryCode | string | Category Code |
| CounterCraft.Event.EventDate | date | Event date |
| CounterCraft.Event.HostName | string | Host name |
| CounterCraft.Event.ServiceName | string | Service name |
| CounterCraft.Event.TypeCode | string | Type |
| CounterCraft.Event.Score | number | Score |
| CounterCraft.Event.Tags | string | Tags |
| CounterCraft.Events.Data | unknown | Data |


##### Command Example
```!countercraft-get-events criteria="type_code:ValidAuth" max_results="1"```

##### Human Readable Output

| | |
| --- | --- |
| Id | 45 |
| Campaignname | External recoinassance |
| Hostname | Azure | Windows |
| Servicename | OS Logs (Azure | Windows) |
| Eventdate | Thu Jan 30 08:11:01 2020 |
| Score | 100 |
| Typecode | ValidAuth |
| Data | event: ValidAuth subject: A session was reconnected to a Window Station event_id: 4778 ...|
| Tags | attack.T1078 |


### 7. countercraft-create-campaign
---
Create a new deception campaign
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You can only create campaigns if you have the role ARCHITECT.

##### Base Command

`countercraft-create-campaign`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Campaign name | Required |
| description | Campaign description | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Campaign.ID | number | Campaign ID |
| CounterCraft.Campaign.Name | string | Name |
| CounterCraft.Campaign.Description | string | Description |
| CounterCraft.Campaign.StatusCode | string | Status Code |


##### Command Example
```!countercraft-create-campaign name="TestCampaign" description="Test Description"```

##### Human Readable Output

| | |
| --- | --- |
| Id | 5 |
| Name | TestCampaign |
| Description | Test Description |
| StatusCode | DESIGN |

### 8. countercraft-list-dsns
---
List Deception Support Nodes (DSNs)
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You can only create campaigns if you have the role ARCHITECT.

##### Base Command

`countercraft-list-dsns`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.DSN.ID | number | ID |
| CounterCraft.DSN.Name | string | Name |
| CounterCraft.DSN.Description | string | Description |
| CounterCraft.DSN.Hostname | string | Hostname |
| CounterCraft.DSN.Port | number | Port |


##### Command Example
```!countercraft-list-dsns```

##### Human Readable Output

| | |
| --- | --- |
| Id | 1 |
| Name | Local DSN |
| Description | Local DSN in the intranet |
| Hostname | 192.168.1.2 |
| Port | 4567 |


### 9. countercraft-list-providers
---
List providers (providers for hosts or services i.e. AWS or Office365)
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to list only the providers you have access to.

##### Base Command

`countercraft-list-providers`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ID | number | ID |
| CounterCraft.Provider.Name | string | Name |
| CounterCraft.Provider.Description | string | Description |
| CounterCraft.Provider.TypeCode | string | Type |
| CounterCraft.Provider.StatusCode | string | Status |


##### Command Example
```!countercraft-list-providers```

##### Human Readable Output

| **ID** | **Name** | **Description** | **StatusCode** | **TypeCode** |
| --- | --- | --- | --- | --- |
| 1 | Splunk | Internal Splunk | HEALTHY | SPLUNK_PROVIDER |
| 3 | Signal | Signal notifications | HEALTHY | SIGNAL_PROVIDER |
| 4 | Office365 | Office365 Tenant | HEALTHY | OFFICE365_PROVIDER |
| 5 | AWS | AWS EC2 | HEALTHY | AWS_PROVIDER |


### 10. countercraft-create-host-machine
---
Deploy a new deception host
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to create a host if you are MANAGER in a campaign.

##### Base Command

`countercraft-create-host-machine`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name | Required |
| description | Description | Optional |
| provider_id | Provider | Required |
| deception_support_node_id | Deception Support Node ID | Required |
| campaign_id | Campaign | Required |
| os_family | Operating System | Required |
| ip_address | IP Address | Required |
| port | Port | Required |
| username | Username | Required |
| password | Password | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Host.Id | number | Host ID |


##### Command Example
```!countercraft-create-host-machine campaign_id=2 deception_support_node_id=1 os_family=linux ip_address=192.168.1.2 port=22 name="Test host" description="Test Description" username="ubuntu" password="ubuntu provider_id=1"```

##### Human Readable Output

| | |
| --- | --- |
| Id | 8 |
| Name | Test Host |
| Description | Test Description |
| StatusCode | DESIGN |
| TypeCode | MACHINE |


### 11. countercraft-list-incidents
---
List all incidents currently active
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to list only the incidents you have access to.

##### Base Command

`countercraft-list-incidents`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| campaign_id | Campaign ID | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Incident.ID | number | Incident ID |
| CounterCraft.Incident.Name | string | Name |
| CounterCraft.Incident.Description | string | Description |
| CounterCraft.Incident.StatusCode | string | Status |
| CounterCraft.Incident.TLPCode | string | TLP code |


##### Command Example
```!countercraft-list-incidents campaign_id=1```

##### Human Readable Output

| **ID** | **Name** | **Description** | **StatusCode** | **TLPCode** | **Tags** |
| --- | --- | --- | --- | --- | --- |
| 1 | APT incident | State-sponsored | OPEN | AMBER | |
| 2 | Internal Fraud | SWIFT apps | CLOSED | AMBER | |

### 12. countercraft-manage-campaign
---
Manage Campaign parameters
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to manage only the campaigns you have access to.

##### Base Command

`countercraft-manage-campaign`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| campaign_id | Campaign ID | Required |
| operation | Operation | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Campaign.Message | string | Result message |
| CounterCraft.Campaign.ID | number | Campaign ID |


##### Command Example
```!countercraft-manage-campaign campaign_id=5 operation=activate```

##### Human Readable Output

| | |
| --- | --- |
| Id | 5 |
| Message | Campaign is currently in state: PAUSED. Action activate discarded |


### 13. countercraft-manage-host
---
Manage a deception host
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to manage only the hosts you have access to.

##### Base Command

`countercraft-manage-host`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | Host ID | Required |
| operation | Operation | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Host.Message | string | Result message |
| CounterCraft.Host.ID | number | Host ID |


##### Command Example
```!countercraft-manage-campaign host_id=5 operation=activate```

##### Human Readable Output

| | |
| --- | --- |
| Id | 5 |
| Message | Host is currently in state: PAUSED. Action activate discarded |


### 14. countercraft-manage-service
---
Manage a deception service
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to manage only the services you have access to.

##### Base Command

`countercraft-manage-service`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| service_id | Service ID | Required |
| operation | Operation | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Service.Message | string | Result message |
| CounterCraft.Service.ID | number | Service ID |


##### Command Example
```!countercraft-manage-campaign service_id=5 operation=activate```

##### Human Readable Output

| | |
| --- | --- |
| Id | 5 |
| Message | Service is currently in state: PAUSED. Action activate discarded |


### 15. countercraft-manage-breadcrumb
---
Manage  breadcrumb
##### Required Permissions

Any interaction will be based on your permissions on the Deception Director. Please consult
your Deception Director administrator in you have any questions.

You will be able to manage only the breadcrumbs you have access to.

##### Base Command

`countercraft-manage-breadcrumb`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| breadcrumb_id | Breadcrumb ID | Required |
| operation | Operation | Required |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CounterCraft.Breadcrumb.Message | string | Result message |
| CounterCraft.Breadcrumb.ID | number | Breadcrumb ID |


##### Command Example
```!countercraft-manage-campaign breadcrumb_id=5 operation=activate```

##### Human Readable Output

| | |
| --- | --- |
| Id | 5 |
| Message | Breadcrumb is currently in state: PAUSED. Action activate discarded |


## Additional Information
---

Please check the Deception Director user manual for more guidance on how to use and deploy campaigns.



