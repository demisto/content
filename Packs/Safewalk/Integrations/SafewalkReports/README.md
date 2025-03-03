Safewalk server integration
This integration was integrated and tested with version 3 of SafewalkReports

## Configure SafewalkReports in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL (e.g. https://soar.monstersofhack.com) |  | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Incidents Fetch Interval |  | False |
|  |  | False |
|  |  | False |
|  |  | False |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation | False |
| Source Reliability | Reliability of the source providing the intelligence data | True |
|  |  | False |
|  |  | False |
| Feed Fetch Interval |  | False |
| Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
| Tags | Supports CSV values. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### safewalk-get-associated-users
***
safewalk-get-associated-users


#### Base Command

`safewalk-get-associated-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| devicetype | devicetype. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.associated_users.data.id | String | users data id | 
| Safewalk.reports.associated_users.data.label | String | users data label | 



#### Human Readable Output



### safewalk-get-authentication-methods-distribution
***
safewalk-get-authentication-methods-distribution


#### Base Command

`safewalk-get-authentication-methods-distribution`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.device_auth_distribution.data.id | String | device_auth_distribution.data.id | 
| Safewalk.reports.device_auth_distribution.data.label | String | device_auth_distribution.data.label | 
| Safewalk.reports.device_auth_distribution.data.type | String | device_auth_distribution.data.type | 
| Safewalk.reports.device_auth_distribution.data | Number | device_auth_distribution.data | 



#### Human Readable Output



### safewalk-get-authentication-rate-per-device
***
safewalk-get-authentication-rate-per-device


#### Base Command

`safewalk-get-authentication-rate-per-device`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.device_auth_rate.data.id | String | device_auth_rate.data.id | 
| Safewalk.reports.device_auth_rate.data.label | String | device_auth_rate.data.label | 
| Safewalk.reports.device_auth_rate.data.type | String | device_auth_rate.data.type | 
| Safewalk.reports.device_auth_rate.data | Number | device_auth_rate.data | 



#### Human Readable Output



### safewalk-get-least-active-users
***
safewalk-get-least-active-users


#### Base Command

`safewalk-get-least-active-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sincedate | sincedate. | Optional | 
| userinformation | userinformation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.inactive_users.data.id | String | inactive_users.data.id | 
| Safewalk.reports.inactive_users.data.label | String | inactive_users.data.label | 



#### Human Readable Output



### safewalk-get-licenses-inventory
***
safewalk-get-licenses-inventory


#### Base Command

`safewalk-get-licenses-inventory`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.licensesinventory.total | Number | licenses inventory total | 
| Safewalk.reports.licensesinventory.data.id | String | icenses inventory data id | 
| Safewalk.reports.licensesinventory.data.label | String | licenses inventory data label | 
| Safewalk.reports.licensesinventory.data.type | String | licenses inventory data type | 
| Safewalk.reports.licensesinventory.data | Number | licenses inventory data | 



#### Human Readable Output



### safewalk-get-licenses-usage
***
safewalk-get-licenses-usage


#### Base Command

`safewalk-get-licenses-usage`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| begindate | begindate. | Optional | 
| enddate | enddate. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.licensesusage.total | Number | licenses usage total | 
| Safewalk.reports.licensesusage.data.id | String | licenses usage data id | 
| Safewalk.reports.licensesusage.data.label | String | licenses usage data label | 
| Safewalk.reports.licensesusage.data.type | String | licenses usage data type | 
| Safewalk.reports.licensesusage.data | Number | licenses usage data | 



#### Human Readable Output



### safewalk-get-most-active-users
***
safewalk-get-most-active-users


#### Base Command

`safewalk-get-most-active-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| days | days. | Optional | 
| limit | limit. | Optional | 
| userinformation | userinformation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.mostactiveusers.data.id | String | mostactiveusers.data.id | 
| Safewalk.reports.mostactiveusers.data.label | String | mostactiveusers.data.label | 
| Safewalk.reports.mostactiveusers.data.type | String | mostactiveusers.data.type | 
| Safewalk.reports.mostactiveusers.data | String | mostactiveusers.data | 



#### Human Readable Output



### safewalk-get-physical-tokens-inventory
***
safewalk-get-physical-tokens-inventory


#### Base Command

`safewalk-get-physical-tokens-inventory`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.physicaltokeninventory.total | Number | physicaltokeninventory.total | 
| Safewalk.reports.physicaltokeninventory.data.id | String | physicaltokeninventory.data.id | 
| Safewalk.reports.physicaltokeninventory.data.label | String | physicaltokeninventory.data.label | 
| Safewalk.reports.physicaltokeninventory.data.type | String | physicaltokeninventory.data.type | 
| Safewalk.reports.physicaltokeninventory.data | Number | physicaltokeninventory.data | 



#### Human Readable Output



### safewalk-get-registered-devices-distribution
***
safewalk-get-registered-devices-distribution


#### Base Command

`safewalk-get-registered-devices-distribution`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.registereddevices.total | Number | registereddevices.total | 
| Safewalk.reports.registereddevices.data.id | String | registereddevices.data.id | 
| Safewalk.reports.registereddevices.data.label | String | registereddevices.data.label | 
| Safewalk.reports.registereddevices.data.type | String | registereddevices.data.type | 
| Safewalk.reports.registereddevices.data | Number | registereddevices.data | 



#### Human Readable Output



### safewalk-get-registration
***
safewalk-get-registration


#### Base Command

`safewalk-get-registration`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| begindate | begindate. | Optional | 
| enddate | enddate. | Optional | 
| userinformation | userinformation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.registration.total | Number | registration.total | 
| Safewalk.reports.registration.data.id | String | registration.data.id | 
| Safewalk.reports.registration.data.label | String | registration.data.label | 
| Safewalk.reports.registration.data.type | String | registration.data.type | 



#### Human Readable Output



### safewalk-get-users-associations-indicators
***
safewalk-get-users-associations-indicators


#### Base Command

`safewalk-get-users-associations-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.reports.usersassociations.total | Number | usersassociations.total | 
| Safewalk.reports.usersassociations.data.id | String | usersassociations.data.id | 
| Safewalk.reports.usersassociations.data.label | String | usersassociations.data.label | 
| Safewalk.reports.usersassociations.data.type | String | usersassociations.data.type | 
| Safewalk.reports.usersassociations.data | Number | usersassociations.data | 



#### Human Readable Output

