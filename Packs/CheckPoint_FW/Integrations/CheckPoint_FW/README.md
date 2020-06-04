Read information and to send commands to the Check Point Firewall server.
This integration was integrated and tested with version xx of CheckPoint
## Configure CheckPoint on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CheckPoint.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| server | Server URL \(e.g. https://example.net or 8.8.8.8\) | True |
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
| checkpoint.host.name | String | object name | 
| checkpoint.host.uid | String | object uid | 
| checkpoint.host.type | String | object type | 


#### Command Example
``` ```

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
| checkpoint.host.name | Unknown | host name | 
| checkpoint.host.uid | String | object uid | 
| checkpoint.host.type | Unknown | object type | 
| checkpoint.host.domain-name | String | domain name | 
| checkpoint.host.domain-uid | String | domain uid | 
| checkpoint.host.ipv4-address | String | IP address | 
| checkpoint.host.ipv6-address | String | IP address | 
| checkpoint.host.read-only | Boolean | indicates if the object is read only | 
| checkpoint.host.meta-info-creator | String | indicates the creator of the object | 
| checkpoint.host.meta-info-last-modifier | Unknown | indicates the last user modified the object | 


#### Command Example
``` ```

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
| checkpoint.host.name | String | object name | 
| checkpoint.host.uid | String | object uid | 
| checkpoint.host.type | String | object type | 
| checkpoint.host.domain-name | String | domain name | 
| checkpoint.host.domain-uid | String | domain uid | 
| checkpoint.host.domain-type | String | domain type | 
| checkpoint.host.meta-info-creator | String | indicates the creator of the object | 
| checkpoint.host.meta-info-last-modifier | String | indicates the last user modifies the object | 
| checkpoint.host.ipv4-address | String | ip address | 
| checkpoint.host.ipv6-address | String | IP address | 
| checkpoint.host.read-only | String | indicates if the object is read only | 


#### Command Example
``` ```

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
| ip | IPv4 or IPv6 address.  | Optional | 
| new_name | New name of the object. | Optional | 
| comments | Comments string. | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors. You won't be able to publish such a changes.<br/>If ignore-warnings flag was omitted - warnings will also be ignored. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| checkpoint.host.name | String | object name | 
| checkpoint.host.uid | String | object uid | 
| checkpoint.host.type | String | object type | 
| checkpoint.host.domain-name | String | domain name | 
| checkpoint.host.domain-uid | String | domain uid | 
| checkpoint.host.domain-type | String | domain type | 
| checkpoint.host.meta-info-creator | String | indicates the creator of the object | 
| checkpoint.host.meta-info-last-modifier | String | indicates the last user modified the object | 
| checkpoint.host.ipv4-address | String | IP address | 
| checkpoint.host.read-only | Boolean | IP address | 


#### Command Example
``` ```

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
| checkpoint.host.message | String | operation status | 


#### Command Example
``` ```

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
| checkpoint.group.name | String | object's name | 
| checkpoint.group.uid | String | object's uid | 
| checkpoint.group.type | String | Type of the object | 


#### Command Example
``` ```

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
| checkpoint.group.name | String | object name | 
| checkpoint.group.uid | String | object uid | 
| checkpoint.group.type | String | object type | 
| checkpoint.group.domain-name | String | domain name | 
| checkpoint.group.domain-uid | String | domain uid | 
| checkpoint.group.domain-type | String | domain type | 
| checkpoint.group.meta-info-creator | String | indicates the creator of the object | 
| checkpoint.group.meta-info-last-modifier | String | indicates the last user modified the object | 
| checkpoint.group.read-only | Boolean | indicates if the object is read only | 


#### Command Example
``` ```

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
| checkpoint.group.name | String | object's name | 
| checkpoint.group.uid | String | object uid | 
| checkpoint.group.type | Unknown | object type | 
| checkpoint.group.domain-name | String | domain name | 
| checkpoint.group.domain-uid | String | domain uid | 
| checkpoint.group.domain-type | String | domain type | 
| checkpoint.group.meta-info-creator | String | Indicates the object creator | 
| checkpoint.group.meta-info-last-modifier | String | Indicates the last user modified the object | 
| checkpoint.group.read-only | Boolean | Indicates whether the object is read\-only | 
| checkpoint.group.groups-name | Unknown | groups name | 


#### Command Example
``` ```

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
| checkpoint.group.name | String | object name | 
| checkpoint.group.uid | String | object uid | 
| checkpoint.group.type | String | object type | 
| checkpoint.group.domain-name | String | domain name | 
| checkpoint.group.domain-uid | String | domain uid | 
| checkpoint.group.domain-type | String | domain type | 
| checkpoint.group.meta-info-creator | String | Indicates the creator of the object | 
| checkpoint.group.meta-info-last-modifier | String | Indicates the lasr user modified the object | 
| checkpoint.group.read-only | Boolean | Indicates if the object is read only | 


#### Command Example
``` ```

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
| checkpoint.group.message | String | Operation massege | 


#### Command Example
``` ```

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
| checkpoint.address-range.name | String | object's name | 
| checkpoint.address-range.uid | String | object's uid | 
| checkpoint.address-range.type | String | Type of the object. | 


#### Command Example
``` ```

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
| set_if_exists | If another object with the same identifier already exists, it will be updated.  | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| checkpoint.address-range.name | String | object name | 
| checkpoint.address-range.uid | String | object uid | 
| checkpoint.address-range.type | String | object type | 
| checkpoint.address-range.domain-name | String | domain name | 
| checkpoint.address-range.domain-uid | String | domain uid | 
| checkpoint.address-range.domain-type | String | domain type | 
| checkpoint.address-range.ipv4-address-first | String | First IPv4 address in the range | 
| checkpoint.address-range.ipv4-address-last | String | Last IPv4 address in the range | 
| checkpoint.address-range.ipv6-address-first | String | First IPv4 address in the range | 
| checkpoint.address-range.ipv6-address-last | String | Last IPv6 address in the range | 
| checkpoint.address-range.read-only | Boolean | Indicates whether the object is read\-only. | 
| checkpoint.address-range.meta-info-creator | String | Indicates the creator of the object | 
| checkpoint.address-range.meta-info-last-modifier | String | Indicates the last user modified the object | 


#### Command Example
``` ```

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
| new_name |  New name of the object. | Optional | 
| comments |  Comments string. | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors | Apply changes ignoring errors. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| checkpoint.address-range.name | String | object name | 
| checkpoint.address-range.uid | String | object uid | 
| checkpoint.address-range.type | String | object type | 
| checkpoint.address-range.domain-name | String | domain name | 
| checkpoint.address-range.domain-uid | String | domain uid | 
| checkpoint.address-range.domain-type | String | domain type | 
| checkpoint.address-range.ipv4-address-first | String | First IPv4 address in the range | 
| checkpoint.address-range.ipv4-address-last | String | Last IPv4 address in the range | 
| checkpoint.address-range.ipv6-address-first | String | First IPv4 address in the range | 
| checkpoint.address-range.ipv6-address-last | String | Last IPv6 address in the range | 
| checkpoint.address-range.read-only | Boolean | Indicates whether the object is read\-only. | 


#### Command Example
``` ```

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
| checkpoint.address-range.message | String | Operation status | 


#### Command Example
``` ```

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
| checkpoint.threat-indicator.name | String | object name | 
| checkpoint.threat-indicator.uid | String | object uid | 
| checkpoint.threat-indicator.type | String | object type | 


#### Command Example
``` ```

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
| checkpoint.threat-indicator.name | String | object name | 
| checkpoint.threat-indicator.uid | String | object uid | 
| checkpoint.threat-indicator.type | String | object type | 
| checkpoint.threat-indicator.domain-name | String | Domain name | 
| checkpoint.threat-indicator.domain-uid | String | object uid | 
| checkpoint.threat-indicator.domain-type | Unknown | domain type | 
| checkpoint.threat-indicator.meta-info-creator | String | creator | 
| checkpoint.threat-indicator.meta-info-last-modifier | String | Indicates the last user modified the object | 
| checkpoint.threat-indicator.read-only | Boolean | Indicates whether the object is read\-only. | 


#### Command Example
``` ```

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
| observables | The indicator's observable or the contents of a file containing the indicator's observables.  | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| checkpoint.threat-indicator.task-id | String | Asynchronous task unique identifier. | 


#### Command Example
``` ```

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
| checkpoint.threat-indicator.name | String | object name | 
| checkpoint.threat-indicator.uid | String | object uid | 
| checkpoint.threat-indicator.type | String | object type | 
| checkpoint.threat-indicator.action | String | The indicator's action. | 
| checkpoint.threat-indicator.domain-name | String | domain name | 
| checkpoint.threat-indicator.domain-uid | String | domain uid | 
| checkpoint.threat-indicator.domain-type | String | domain type | 
| checkpoint.threat-indicator.meta-info-creator | String | Indicates the creator of the object | 
| checkpoint.threat-indicator.meta-info-last-modifier | String | Indicates the last user modified the object | 
| checkpoint.threat-indicator.read-only | Boolean | Indicates whether the object is read\-only. | 


#### Command Example
``` ```

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
| checkpoint.address-range.name | String | object name | 
| checkpoint.address-range.uid | String | object uid | 
| checkpoint.address-range.type | String | object type | 
| checkpoint.address-range.domain-name | String | domain name | 
| checkpoint.address-range.domain-uid | String | domain uid | 
| checkpoint.address-range.domain-type | String | domain type | 


#### Command Example
``` ```

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
| checkpoint.threat-indicator.message | String | Operation status | 


#### Command Example
``` ```

#### Human Readable Output



### checkpoint-access-rule-list
***
Shows the entire Access Rules layer


#### Base Command

`checkpoint-access-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier |  | Required | 
| limit | The maximal number of returned results. | Optional | 
| offset | Number of the results to initially skip. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| checkpoint.access-rule.name | String | object name | 
| checkpoint.access-rule.uid | String | object uid | 


#### Command Example
``` ```

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
| checkpoint.access-rule.name | String | object name | 
| checkpoint.access-rule.uid | String | object uid | 
| checkpoint.access-rule.type | String | object type | 
| checkpoint.access-rule.domain-name | String | domain name | 
| checkpoint.access-rule.domain-uid | String | domain uid | 
| checkpoint.access-rule.domain-type | String | domain type | 
| checkpoint.access-rule.enabled | Boolean | Enable/Disable the rule. | 
| checkpoint.access-rule.layer | String | Layer that the rule belongs to identified by the name or UID. | 
| checkpoint.access-rule.meta-info-creator | String | Indicated the object creator | 
| checkpoint.access-rule.meta-info-last-modifier | String | Indicates the last user modofied the object | 


#### Command Example
``` ```

#### Human Readable Output



### checkpoint-access-rule-update
***
Edit existing access rule using object name or uid.


#### Base Command

`checkpoint-access-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| identifier | object name or uid, OR  rule number | Required | 
| layer | Layer that the rule belongs to identified by the name or UID. | Required | 
| action | action to be taken on the rule | Optional | 
| enabled | Enable/Disable the rule. | Optional | 
| new_name | New name of the object. | Optional | 
| new_position | New position in the rulebase.  value can be int to set specific position, ot str- 'top' or 'bottom' | Optional | 
| ignore_warnings | Apply changes ignoring warnings. | Optional | 
| ignore_errors |  Apply changes ignoring errors | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| checkpoint.access-rule.name | String | object name | 
| checkpoint.access-rule.uid | String | object uid | 
| checkpoint.access-rule.type | String | object type | 
| checkpoint.access-rule.action-name | String | action name | 
| checkpoint.access-rule.action-uid | String | action uid | 
| checkpoint.access-rule.action-type | Unknown | action type | 
| checkpoint.access-rule.action-domain-name | String | action domain name | 
| checkpoint.access-rule.content-direction | String | On which direction the file types processing is applied. | 
| checkpoint.access-rule.domain-name | String | domain name | 
| checkpoint.access-rule.domain-uid | String | domain uid | 
| checkpoint.access-rule.domain-type | String | domain type | 
| checkpoint.access-rule.enabled | Boolean | Enable/Disable the rule. | 
| checkpoint.access-rule.layer | String | Layer that the rule belongs to identified by the name or UID. | 
| checkpoint.access-rule.meta-info-creator | String | Indicates the creator of the object | 
| checkpoint.access-rule.meta-info-last-modifier | String | Indicates the last user modified the object | 


#### Command Example
``` ```

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
| checkpoint.access-rule.message | String | Operation status | 


#### Command Example
``` ```

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
| checkpoint.application-site.name | String | objects name | 
| checkpoint.application-site.uid | String | objects uid | 
| checkpoint.application-site.type | String | objects type | 


#### Command Example
``` ```

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
| checkpoint.application-site.name | String | object name | 
| checkpoint.application-site.uid | String | object uid | 
| checkpoint.application-site.type | String | object ty\[e | 
| checkpoint.application-site.application-id | Number | application ID | 
| checkpoint.application-site.description | String | A description for the application. | 
| checkpoint.application-site.domain-name | String | domain name | 
| checkpoint.application-site.domain-uid | String | domain uid | 
| checkpoint.application-site.domain-type | String | domain name | 
| checkpoint.application-site.url-list | String | URLs that determine this particular application. | 
| checkpoint.application-site.meta-info-creator | String | Indicates the creator of the object | 
| checkpoint.application-site.meta-info-last-modifier | String | Indicates the last user modified this object | 


#### Command Example
``` ```

#### Human Readable Output



### checkpoint-application-site-update
***
Edit existing application using object name or uid. 
It's impossible to set 'application-signature' when the application was initialized with 'url-list' and vice-verse.


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
| urls_defined_as_regular_expression | States whether the URL is defined as a Regular Expression or not.  | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| checkpoint.application-site.name | String | object name | 
| checkpoint.application-site.uid | String | object uid | 
| checkpoint.application-site.type | String | object ty\[e | 
| checkpoint.application-site.application-id | Number | application ID | 
| checkpoint.application-site.description | String | A description for the application. | 
| checkpoint.application-site.domain-name | String | domain name | 
| checkpoint.application-site.domain-uid | String | domain uid | 
| checkpoint.application-site.domain-type | String | domain type | 
| checkpoint.application-site.url-list | String | URLs that determine this particular application. | 


#### Command Example
``` ```

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
| checkpoint.application-site.message | String | Operation status. | 


#### Command Example
``` ```

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
``` ```

#### Human Readable Output



### checkpoint-install-policy
***
intsalling policy


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
| checkpoint.instal-policy.task-id | String | operation task ID | 


#### Command Example
``` ```

#### Human Readable Output


