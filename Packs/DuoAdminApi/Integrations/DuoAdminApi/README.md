DUO for admins.
Must have access to the admin api in order to use this.

## Configure DUO Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DUO Admin.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Hostname | True |
    | Integration Key | True |
    | Secret Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DuoAdmin.UserDetails.username | Unknown | Username | 
| DuoAdmin.UserDetails.user_id | Unknown | User Id  | 

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

There are no input arguments for this command.

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