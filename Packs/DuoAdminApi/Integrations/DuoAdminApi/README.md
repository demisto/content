DUO for admins.
Must have access to the admin api in order to use this.
This integration was integrated and tested with version 4.4.0 of DUO Admin

## Configure DUO Admin in Cortex


| **Parameter** | **Required** |
| --- | --- |
| API Hostname | True |
| Integration Key | True |
| Secret Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### duoadmin-get-authentication-logs-by-user
***
Returns authentication logs associated with a user. Limited to 30 at a time


#### Base Command

`duoadmin-get-authentication-logs-by-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The user associated with the logs. | Required | 
| from | Fetch logs from this time until now. Possible values are: 10_seconds_ago, 1_minute_ago, 10_minutes_ago, 1_hour_ago, 10_hours_ago, 1_day_ago, 1_week_ago, 1_month_ago, 1_year_ago, 5_years_ago, 10_years_ago. | Required | 
| limit | The maximum number of authentication logs to return. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DuoAdmin.UserDetails.auth_logs.result | string | Result of the authentication attempt | 
| DuoAdmin.UserDetails.auth_logs.event_type | string | Type of activity logged | 
| DuoAdmin.UserDetails.auth_logs.reason | string | Reason for the authentication attempt result | 
| DuoAdmin.UserDetails.auth_logs.access_device.ip | string | The GeoIP location of the access device. IP field | 
| DuoAdmin.UserDetails.auth_logs.access_device.hostname | string | The GeoIP location of the access device. Hostname field | 
| DuoAdmin.UserDetails.auth_logs.access_device.location.city | string | The GeoIP location of the access device. City field | 
| DuoAdmin.UserDetails.auth_logs.access_device.location.state | string | The GeoIP location of the access device. State field | 
| DuoAdmin.UserDetails.auth_logs.access_device.location.country | string | The GeoIP location of the access device. Country field | 
| DuoAdmin.UserDetails.auth_logs.auth_device.ip | string | The GeoIP location of the authentication device. IP field | 
| DuoAdmin.UserDetails.auth_logs.auth_device.hostname | string | The GeoIP location of the authentication device. Hostname field | 
| DuoAdmin.UserDetails.auth_logs.auth_device.location.city | string | The GeoIP location of the authentication device. City field | 
| DuoAdmin.UserDetails.auth_logs.auth_device.location.state | string | The GeoIP location of the authentication device. State field | 
| DuoAdmin.UserDetails.auth_logs.auth_device.location.country | string | The GeoIP location of the authentication device. Country field | 
| DuoAdmin.UserDetails.auth_logs.timestamp | date | Timestamp of the event | 
| DuoAdmin.UserDetails.auth_logs.application.name | string | Name of the application accessed | 
| DuoAdmin.UserDetails.auth_logs.factor | string | The authentication factor | 

### duoadmin-dissociate-device-from-user
***
Dissociates a device from a user


#### Base Command

`duoadmin-dissociate-device-from-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | user to dissociate a device from. | Required | 
| device_id | the device id to dissociate. | Required | 


#### Context Output

There is no context output for this command.
### duoadmin-delete-u2f-token
***
Delete a u2f token


#### Base Command

`duoadmin-delete-u2f-token`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token_id | the id of the token to delete. | Required | 


#### Context Output

There is no context output for this command.
### duoadmin-get-users
***
Return usernames and their user id


#### Base Command

`duoadmin-get-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DuoAdmin.UserDetails.username | string | Username | 
| DuoAdmin.UserDetails.user_id | string | User Id  | 
| DuoAdmin.UserDetails.status | string | Status | 
| DuoAdmin.UserDetails.is_enrolled | boolean | is_enrolled | 
| DuoAdmin.UserDetails.last_login | date | Last_login | 
| DuoAdmin.UserDetails.realname | string | Real Name | 
| DuoAdmin.UserDetails.email | string | Email | 
| DuoAdmin.UserDetails.phones | unknown | Phone numbers | 

### duoadmin-get-devices-by-user
***
Return devices associated with a user


#### Base Command

`duoadmin-get-devices-by-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DuoAdmin.UserDetails.phones.phone_id | string | Device Id | 
| DuoAdmin.UserDetails.phones.number | string | Device number | 
| DuoAdmin.UserDetails.phones.platform | string | Device platform | 
| DuoAdmin.UserDetails.phones.last_seen | date | Last time the device was used | 

### duoadmin-get-u2f-tokens-by-user
***
Returns a list of U2F tokens associated with the given username


#### Base Command

`duoadmin-get-u2f-tokens-by-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | username. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DuoAdmin.UserDetails.u2ftokens | Unknown | The list of  tokens | 

### duoadmin-get-devices
***
Returns all existing devices


#### Base Command

`duoadmin-get-devices`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DuoAdmin.Phones.phone_id | Unknown | Device Id | 
| DuoAdmin.Phones.number | Unknown | Device number | 
| DuoAdmin.Phones.platform | Unknown | Device platform | 
| DuoAdmin.Phones.last_seen | Unknown | Last time the device was used | 
| DuoAdmin.Phones.users | Unknown | Users associated with this device | 

### duoadmin-associate-device-to-user
***
Associates a device to a user


#### Base Command

`duoadmin-associate-device-to-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Required | 
| device_id | Device Id. | Required | 


#### Context Output

There is no context output for this command.
### duoadmin-get-admins
***
Returns administrator accounts


#### Base Command

`duoadmin-get-admins`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DuoAdmin.UserDetails.admin_id | string | Admin_id | 
| DuoAdmin.UserDetails.admin_units | unknown | Admin Units | 
| DuoAdmin.UserDetails.created | date | Created | 
| DuoAdmin.UserDetails.email | string | Email | 
| DuoAdmin.UserDetails.last_login | date | Last Login | 
| DuoAdmin.UserDetails.name | string | Name | 
| DuoAdmin.UserDetails.phone | unknown | Phone | 
| DuoAdmin.UserDetails.role | string | Admin Role | 
| DuoAdmin.UserDetails.status | string | Admin Status | 

### duoadmin-get-bypass-codes
***
Retrieves the information from the bypass code table


#### Base Command

`duoadmin-get-bypass-codes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DuoAdmin.UserDetails.bypass_code_id | unknown | Bypass Code Id | 
| DuoAdmin.UserDetails.admin_email | string | Admin Email | 
| DuoAdmin.UserDetails.created | date | Bypass Created | 
| DuoAdmin.UserDetails.expiration | unknown | Bypass Expiration | 
| DuoAdmin.UserDetails.reuse_count | unknown | Bypass Reuse Count | 
| DuoAdmin.UserDetails.user.username | unknown | Username | 
| DuoAdmin.UserDetails.user.created | unknown | Created | 
| DuoAdmin.UserDetails.user.email | unknown | Email | 
| DuoAdmin.UserDetails.user.last_login | unknown | Last Login | 
| DuoAdmin.UserDetails.user.status | unknown | Status | 
| DuoAdmin.UserDetails.user.user_id | unknown | User Id | 

### duoadmin-modify-admin
***
Modify the administrator user.


#### Base Command

`duoadmin-modify-admin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| admin_id | The id of the admin. | Required | 
| name | The name of the admin. | Optional | 
| phone | The phone number of the admin. | Optional | 
| password | the password of the admin. | Optional | 
| password_change_required | a flag to determine if the password should change. Possible values are: false, true. Default is false. | Optional | 


#### Context Output

There is no context output for this command.
### duoadmin-modify-user
***
Modify the user account.


#### Base Command

`duoadmin-modify-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user id of the user. | Required | 
| user_name | The user name of the user. | Optional | 
| realname | The real name of the user. | Optional | 
| status | The status of the user. Possible values are: active, disabled. | Optional | 
| notes | Notes for the user. | Optional | 
| email | The email of the user. | Optional | 
| first_name | The first name of the user. | Optional | 
| last_name | The last name of the user. | Optional | 
| alias1 | The first alias of the user. | Optional | 
| alias2 | The second alias of the user. | Optional | 
| alias3 | The third alias of the user. | Optional | 
| alias4 | The fourth alias of the user. | Optional | 
| aliases | The aliases list of the user. | Optional | 


#### Context Output

There is no context output for this command.