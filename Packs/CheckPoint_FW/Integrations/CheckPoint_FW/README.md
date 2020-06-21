Product Name: CheckPoint Firewall
Product Type: Network Security 
Product Version: R80.30
________________________________________
Integration Overview
Manage CheckPoint Firewall. 
Read information and to send commands to the Check Point Firewall server.
This integration was integrated and tested with version R80.30 of CheckPoint SmartConsole.

________________________________________
Use Cases
-	Manage hosts
-	Manage Groups
-	Manage roles
-	Manage Address range
-	Manage threat indicators
-	Manage Application site
-	Publish changes
-	Install policy
-	Verify policy
________________________________________

Playbooks
-	Block IP Playbook
-	UnBlock IP Playbook
-	Install Policy Playbook
-	Create policy backup and get status Playbook




How to configure the integration:
1. In the Smart Console, enable the web api:
Management & Setting → Blades → Management API, Advanced Setting → All IP address

2. Enable sftp on your server
CheckPoint guide to walk you through:
https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk82281

## Configure CheckPoint on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CheckPoint.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL \(e.g. example.net or 8.8.8.8\) | True |
| port | Server Port \(e.g. 4434\) | True |
| username | username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### checkpoint-host-list
***
Show all host objects


#### Base Command

`checkpoint-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.name | String | object name | 
| CheckPoint.host.uid | String | object uid | 
| CheckPoint.host.type | String | object type | 


#### Command Example
!checkpoint-host-list

#### Human Readable Output



### checkpoint-host-get
***
get all data of a given host


#### Base Command

`checkpoint-host-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object unique identifier (uid) or name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.name | Unknown | host name | 
| CheckPoint.host.uid | String | object uid | 
| CheckPoint.host.type | Unknown | object type | 
| CheckPoint.host.domain-name | String | domain name | 
| CheckPoint.host.domain-uid | String | domain uid | 
| CheckPoint.host.ipv4-address | String | IP address | 
| CheckPoint.host.ipv6-address | String | IP address | 
| CheckPoint.host.read-only | Boolean | indicates if the object is read only | 
| CheckPoint.host.creator | String | indicates the creator of the object | 
| CheckPoint.host.last-modifier | Unknown | indicates the last user modified the object | 


#### Command Example
!checkpoint-host-get identifier='test_host'


#### Human Readable Output



### checkpoint-host-add
***
Add new host


#### Base Command

`checkpoint-host-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | name of the new host | Required | 
| ip_address | ip address | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.name | String | object name | 
| CheckPoint.host.uid | String | object uid | 
| CheckPoint.host.type | String | object type | 
| CheckPoint.host.domain-name | String | domain name | 
| CheckPoint.host.domain-uid | String | domain uid | 
| CheckPoint.host.domain-type | String | domain type | 
| CheckPoint.host.creator | String | indicates the creator of the object | 
| CheckPoint.host.last-modifier | String | indicates the last user modifies the object | 
| CheckPoint.host.ipv4-address | String | ip address | 
| CheckPoint.host.ipv6-address | String | IP address | 
| CheckPoint.host.read-only | String | indicates if the object is read only | 


#### Command Example
!checkpoint-host-add identifier='test_host' ip_address='8.8.8.8'

#### Human Readable Output



### checkpoint-host-update
***
update host changes


#### Base Command

`checkpoint-host-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | Object unique identifier or name | Required | 
| ip | IPv4 or IPv6 address. | Optional | 
| new_name | New name of the object. | Optional | 
| comments | Comments string. | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors. You won't be able to publish such a changes.<br/>If ignore-warnings flag was omitted - warnings will also be ignored. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.name | String | object name | 
| CheckPoint.host.uid | String | object uid | 
| CheckPoint.host.type | String | object type | 
| CheckPoint.host.domain-name | String | domain name | 
| CheckPoint.host.domain-uid | String | domain uid | 
| CheckPoint.host.domain-type | String | domain type | 
| CheckPoint.host.creator | String | indicates the creator of the object | 
| CheckPoint.host.last-modifier | String | indicates the last user modified the object | 
| CheckPoint.host.ipv4-address | String | IP address | 
| CheckPoint.host.read-only | Boolean | IP address | 


#### Command Example
!checkpoint-host-update identifier='test_host'

#### Human Readable Output



### checkpoint-host-delete
***
delete host


#### Base Command

`checkpoint-host-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.host.message | String | operation status | 


#### Command Example
!checkpoint-host-delete identifier='test_host'

#### Human Readable Output



### checkpoint-group-list
***
Show a list of all groups


#### Base Command

`checkpoint-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.name | String | object's name | 
| CheckPoint.group.uid | String | object's uid | 
| CheckPoint.group.type | String | Type of the object | 


#### Command Example
!checkpoint-group-list

#### Human Readable Output



### checkpoint-group-get
***
Get all data of a given group


#### Base Command

`checkpoint-group-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object uid or name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.name | String | object name | 
| CheckPoint.group.uid | String | object uid | 
| CheckPoint.group.type | String | object type | 
| CheckPoint.group.domain-name | String | domain name | 
| CheckPoint.group.domain-uid | String | domain uid | 
| CheckPoint.group.domain-type | String | domain type | 
| CheckPoint.group.creator | String | indicates the creator of the object | 
| CheckPoint.group.last-modifier | String | indicates the last user modified the object | 
| CheckPoint.group.read-only | Boolean | indicates if the object is read only | 


#### Command Example
!checkpoint-group-get identifier='test_group'

#### Human Readable Output



### checkpoint-group-add
***
add a group


#### Base Command

`checkpoint-group-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Object name. Must be unique in the domain. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.name | String | object's name | 
| CheckPoint.group.uid | String | object uid | 
| CheckPoint.group.type | Unknown | object type | 
| CheckPoint.group.domain-name | String | domain name | 
| CheckPoint.group.domain-uid | String | domain uid | 
| CheckPoint.group.domain-type | String | domain type | 
| CheckPoint.group.creator | String | Indicates the object creator | 
| CheckPoint.group.last-modifier | String | Indicates the last user modified the object | 
| CheckPoint.group.read-only | Boolean | Indicates whether the object is read\-only | 
| CheckPoint.group.groups-name | Unknown | groups name | 


#### Command Example
!checkpoint-group-add identifier='test_group'

#### Human Readable Output



### checkpoint-group-update
***
update group object


#### Base Command

`checkpoint-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 
| new_name | New name of the group object | Optional | 
| comments | Comments string. | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.name | String | object name | 
| CheckPoint.group.uid | String | object uid | 
| CheckPoint.group.type | String | object type | 
| CheckPoint.group.domain-name | String | domain name | 
| CheckPoint.group.domain-uid | String | domain uid | 
| CheckPoint.group.domain-type | String | domain type | 
| CheckPoint.group.creator | String | Indicates the creator of the object | 
| CheckPoint.group.last-modifier | String | Indicates the lasr user modified the object | 
| CheckPoint.group.read-only | Boolean | Indicates if the object is read only | 


#### Command Example
!checkpoint-group-update identifier='test_group'

#### Human Readable Output



### checkpoint-group-delete
***
delete a group object


#### Base Command

`checkpoint-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.group.message | String | Operation massege | 


#### Command Example
!checkpoint-group-delete identifier='test_group'

#### Human Readable Output



### checkpoint-address-range-list
***
List all address range objects


#### Base Command

`checkpoint-address-range-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.name | String | object's name | 
| CheckPoint.address-range.uid | String | object's uid | 
| CheckPoint.address-range.type | String | Type of the object. | 


#### Command Example
!checkpoint-address-range-list 

#### Human Readable Output



### checkpoint-address-range-add
***
Add address range object


#### Base Command

`checkpoint-address-range-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | object name | Required | 
| ip_address_first | First IP address in the range. | Required | 
| ip_address_last | Last IP address in the range. | Required | 
| set_if_exists | If another object with the same identifier already exists, it will be updated. | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.name | String | object name | 
| CheckPoint.address-range.uid | String | object uid | 
| CheckPoint.address-range.type | String | object type | 
| CheckPoint.address-range.domain-name | String | domain name | 
| CheckPoint.address-range.domain-uid | String | domain uid | 
| CheckPoint.address-range.domain-type | String | domain type | 
| CheckPoint.address-range.ipv4-address-first | String | First IPv4 address in the range | 
| CheckPoint.address-range.ipv4-address-last | String | Last IPv4 address in the range | 
| CheckPoint.address-range.ipv6-address-first | String | First IPv4 address in the range | 
| CheckPoint.address-range.ipv6-address-last | String | Last IPv6 address in the range | 
| CheckPoint.address-range.read-only | Boolean | Indicates whether the object is read\-only. | 
| CheckPoint.address-range.creator | String | Indicates the creator of the object | 
| CheckPoint.address-range.last-modifier | String | Indicates the last user modified the object | 


#### Command Example
!checkpoint-address-range-add identifier='test_address_range' ip_address_first='8.8.8.8' ip_address_last='9.9.9.9'

#### Human Readable Output



### checkpoint-address-range-update
***
Update an address range object


#### Base Command

`checkpoint-address-range-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 
| ip_address_first | First IP address in the range. IPv4 or IPv6 address. | Optional | 
| ip_address_last | Last IP address in the range. IPv4 or IPv6 address. | Optional | 
| new_name | New name of the object. | Optional | 
| comments | Comments string. | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.name | String | object name | 
| CheckPoint.address-range.uid | String | object uid | 
| CheckPoint.address-range.type | String | object type | 
| CheckPoint.address-range.domain-name | String | domain name | 
| CheckPoint.address-range.domain-uid | String | domain uid | 
| CheckPoint.address-range.domain-type | String | domain type | 
| CheckPoint.address-range.ipv4-address-first | String | First IPv4 address in the range | 
| CheckPoint.address-range.ipv4-address-last | String | Last IPv4 address in the range | 
| CheckPoint.address-range.ipv6-address-first | String | First IPv4 address in the range | 
| CheckPoint.address-range.ipv6-address-last | String | Last IPv6 address in the range | 
| CheckPoint.address-range.read-only | Boolean | Indicates whether the object is read\-only. | 


#### Command Example
!checkpoint-address-range-update identifier='test_address_range'

#### Human Readable Output



### checkpoint-address-range-delete
***
Delete a given address range


#### Base Command

`checkpoint-address-range-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.message | String | Operation status | 


#### Command Example
!checkpoint-address-range-delete identifier='test_address_range'

#### Human Readable Output



### checkpoint-threat-indicator-list
***
List all threat indicators


#### Base Command

`checkpoint-threat-indicator-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Skip that many results before beginning to return them. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.name | String | object name | 
| CheckPoint.threat-indicator.uid | String | object uid | 
| CheckPoint.threat-indicator.type | String | object type | 


#### Command Example
!checkpoint-threat-indicator-list

#### Human Readable Output



### checkpoint-threat-indicator-get
***
Get data for a given list indicator


#### Base Command

`checkpoint-threat-indicator-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object uid or name | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.name | String | object name | 
| CheckPoint.threat-indicator.uid | String | object uid | 
| CheckPoint.threat-indicator.type | String | object type | 
| CheckPoint.threat-indicator.domain-name | String | Domain name | 
| CheckPoint.threat-indicator.domain-uid | String | object uid | 
| CheckPoint.threat-indicator.domain-type | Unknown | domain type | 
| CheckPoint.threat-indicator.creator | String | creator | 
| CheckPoint.threat-indicator.last-modifier | String | Indicates the last user modified the object | 
| CheckPoint.threat-indicator.read-only | Boolean | Indicates whether the object is read\-only. | 


#### Command Example
!checkpoint-threat-indicator-get name='test_threat_indicators'

#### Human Readable Output



### checkpoint-threat-indicator-add
***
Add a threat indicator


#### Base Command

`checkpoint-threat-indicator-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | threat indicator name | Required | 
| observables | The indicators observable or the contents of a file containing the indicators observables. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.task-id | String | Asynchronous task unique identifier. | 


#### Command Example
!checkpoint-threat-indicator-add name='test_threat_indicators' observables = [{"name": "My_Observable", "mail-to": "someone@somewhere.com"}]

#### Human Readable Output



### checkpoint-threat-indicator-update
***
Update a given indicator


#### Base Command

`checkpoint-threat-indicator-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name. | Required | 
| action | the action to set. | Optional | 
| new_name | New name of the object. | Optional | 
| comments | Comments string. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.name | String | object name | 
| CheckPoint.threat-indicator.uid | String | object uid | 
| CheckPoint.threat-indicator.type | String | object type | 
| CheckPoint.threat-indicator.action | String | The indicator's action. | 
| CheckPoint.threat-indicator.domain-name | String | domain name | 
| CheckPoint.threat-indicator.domain-uid | String | domain uid | 
| CheckPoint.threat-indicator.domain-type | String | domain type | 
| CheckPoint.threat-indicator.creator | String | Indicates the creator of the object | 
| CheckPoint.threat-indicator.last-modifier | String | Indicates the last user modified the object | 
| CheckPoint.threat-indicator.read-only | Boolean | Indicates whether the object is read\-only. | 


#### Command Example
!checkpoint-threat-indicator-update name='test_threat_indicators'

#### Human Readable Output



### checkpoint-address-range-get
***
Get all date of a given address range object


#### Base Command

`checkpoint-address-range-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name object | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.address-range.name | String | object name | 
| CheckPoint.address-range.uid | String | object uid | 
| CheckPoint.address-range.type | String | object type | 
| CheckPoint.address-range.domain-name | String | domain name | 
| CheckPoint.address-range.domain-uid | String | domain uid | 
| CheckPoint.address-range.domain-type | String | domain type | 


#### Command Example
!checkpoint-address-range-get identifier='test_address_range'

#### Human Readable Output



### checkpoint-threat-indicator-delete
***
delete threat indicator


#### Base Command

`checkpoint-threat-indicator-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.threat-indicator.message | String | Operation status | 


#### Command Example
!checkpoint-threat-indicator-delete name='test_threat_indicators'

#### Human Readable Output



### checkpoint-access-rule-list
***
Shows the entire Access Rules layer


#### Base Command

`checkpoint-access-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid | Required | 
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.access-rule.name | String | object name | 
| CheckPoint.access-rule.uid | String | object uid | 


#### Command Example
!checkpoint-access-rule-list identifier='test_access_rule'

#### Human Readable Output



### checkpoint-access-rule-add
***
Create new access rule


#### Base Command

`checkpoint-access-rule-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| layer | Layer that the rule belongs to identified by the name or UID. | Required | 
| position | Position in the rulebase. | Required | 
| name | Rule name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.access-rule.name | String | object name | 
| CheckPoint.access-rule.uid | String | object uid | 
| CheckPoint.access-rule.type | String | object type | 
| CheckPoint.access-rule.domain-name | String | domain name | 
| CheckPoint.access-rule.domain-uid | String | domain uid | 
| CheckPoint.access-rule.domain-type | String | domain type | 
| CheckPoint.access-rule.enabled | Boolean | Enable/Disable the rule. | 
| CheckPoint.access-rule.layer | String | Layer that the rule belongs to identified by the name or UID. | 
| CheckPoint.access-rule.creator | String | Indicated the object creator | 
| CheckPoint.access-rule.last-modifier | String | Indicates the last user modofied the object | 


#### Command Example
!checkpoint-access-rule-add layer='Network' position='top' name='test_access_rule'

#### Human Readable Output



### checkpoint-access-rule-update
***
Edit existing access rule using object name or uid.


#### Base Command

`checkpoint-access-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid, OR rule number | Required | 
| layer | Layer that the rule belongs to identified by the name or UID. | Required | 
| action | action to be taken on the rule | Optional | 
| enabled | Enable/Disable the rule. | Optional | 
| new_name | New name of the object. | Optional | 
| new_position | New position in the rulebase. value can be int to set specific position, ot str- 'top' or 'bottom' | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.access-rule.name | String | object name | 
| CheckPoint.access-rule.uid | String | object uid | 
| CheckPoint.access-rule.type | String | object type | 
| CheckPoint.access-rule.action-name | String | action name | 
| CheckPoint.access-rule.action-uid | String | action uid | 
| CheckPoint.access-rule.action-type | Unknown | action type | 
| CheckPoint.access-rule.action-domain-name | String | action domain name | 
| CheckPoint.access-rule.content-direction | String | On which direction the file types processing is applied. | 
| CheckPoint.access-rule.domain-name | String | domain name | 
| CheckPoint.access-rule.domain-uid | String | domain uid | 
| CheckPoint.access-rule.domain-type | String | domain type | 
| CheckPoint.access-rule.enabled | Boolean | Enable/Disable the rule. | 
| CheckPoint.access-rule.layer | String | Layer that the rule belongs to identified by the name or UID. | 
| CheckPoint.access-rule.creator | String | Indicates the creator of the object | 
| CheckPoint.access-rule.last-modifier | String | Indicates the last user modified the object | 


#### Command Example
!checkpoint-access-rule-update identifier='test_access_rule' layer='Network'

#### Human Readable Output



### checkpoint-access-rule-delete
***
Delete access rule


#### Base Command

`checkpoint-access-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid, name or rule-number. | Required | 
| layer | Layer that the rule belongs to identified by the name or UID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.access-rule.message | String | Operation status | 


#### Command Example
!checkpoint-access-rule-delete identifier='test_access_rule'

#### Human Readable Output



### checkpoint-application-site-list
***
Retrieve all objects.


#### Base Command

`checkpoint-application-site-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.application-site.name | String | objects name | 
| CheckPoint.application-site.uid | String | objects uid | 
| CheckPoint.application-site.type | String | objects type | 


#### Command Example
!checkpoint-application-site-list 

#### Human Readable Output



### checkpoint-application-site-add
***
Add application site


#### Base Command

`checkpoint-application-site-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Object name. Must be unique in the domain | Required | 
| primary_category | Each application is assigned to one primary category based on its most defining aspect | Required | 
| identifier | can be:<br/>  url-list(str): URLs that determine this particular application.<br/>  application-signature(str): Application signature generated by Signature Tool. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.application-site.name | String | object name | 
| CheckPoint.application-site.uid | String | object uid | 
| CheckPoint.application-site.type | String | object type | 
| CheckPoint.application-site.application-id | Number | application ID | 
| CheckPoint.application-site.description | String | A description for the application. | 
| CheckPoint.application-site.domain-name | String | domain name | 
| CheckPoint.application-site.domain-uid | String | domain uid | 
| CheckPoint.application-site.domain-type | String | domain name | 
| CheckPoint.application-site.url-list | String | URLs that determine this particular application. | 
| CheckPoint.application-site.creator | String | Indicates the creator of the object | 
| CheckPoint.application-site.last-modifier | String | Indicates the last user modified this object | 


#### Command Example
!checkpoint-application-site-add name='test_application_site' primary_category='Test Category'

#### Human Readable Output



### checkpoint-application-site-update
***
Edit existing application using object name or uid. It's impossible to set 'application-signature' when the application was initialized with 'url-list' and vice-verse.


#### Base Command

`checkpoint-application-site-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name | Required | 
| description | A description for the application | Optional | 
| primary_category | Each application is assigned to one primary category based on its most defining aspect | Optional | 
| application_signature | Application signature generated by Signature Tool | Optional | 
| new_name | New name of the object. | Optional | 
| urls_defined_as_regular_expression | States whether the URL is defined as a Regular Expression or not. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.application-site.name | String | object name | 
| CheckPoint.application-site.uid | String | object uid | 
| CheckPoint.application-site.type | String | object ty\[e | 
| CheckPoint.application-site.application-id | Number | application ID | 
| CheckPoint.application-site.description | String | A description for the application. | 
| CheckPoint.application-site.domain-name | String | domain name | 
| CheckPoint.application-site.domain-uid | String | domain uid | 
| CheckPoint.application-site.domain-type | String | domain type | 
| CheckPoint.application-site.url-list | String | URLs that determine this particular application. | 


#### Command Example
!checkpoint-application-site-update identifier='test_application_site'

#### Human Readable Output



### checkpoint-application-site-delete
***
Delete existing application site object using object name or uid.


#### Base Command

`checkpoint-application-site-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | uid or name object | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.application-site.message | String | Operation status. | 


#### Command Example
!checkpoint-application-site-delete name='test_application_site' primary_category='Test Category' identifier='www.cnet.com'

#### Human Readable Output



### checkpoint-publish
***
publish changes


#### Base Command

`checkpoint-publish`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
!checkpoint-publish

#### Human Readable Output



### checkpoint-install-policy
***
Intsalling policy


#### Base Command

`checkpoint-install-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_package | The name of the Policy Package to be installed. | Required | 
| targets | On what targets to execute this command. Targets may be identified by their name, or object unique identifier. | Required | 
| access | Set to be true in order to install the Access Control policy. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CheckPoint.instal-policy.task-id | String | operation task ID | 


#### Command Example
!checkpoint-install-policy policy_package='standard' targets='LAN-TEST'

#### Human Readable Output


