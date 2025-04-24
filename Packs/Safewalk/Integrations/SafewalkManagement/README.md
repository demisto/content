Safewalk server integration
This integration was integrated and tested with version 3 of SafewalkManagement

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure SafewalkManagement in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) |  | False |
| Max fetch |  | False |
| Server URL (e.g. https://soar.monstersofhack.com) |  | True |
| Fetch incidents |  | False |
| Incident type |  | False |
| API Key |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch indicators |  | False |
| Incidents Fetch Interval |  | False |
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
### safewalk-get-transactionlog
***
Display transaction log.


#### Base Command

`safewalk-get-transactionlog`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Pages to be displayed. | Optional | 
| search | User to search. | Optional | 
| locked | locked. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.management.transactionlist.count | Number | Number of transactions | 
| Safewalk.management.transactionlist.next | String | Next page | 
| Safewalk.management.transactionlist.previous | Unknown | Previous page | 
| Safewalk.management.transactionlist.results.reason_detail | Unknown | Reason | 
| Safewalk.management.transactionlist.results.is_locked | Boolean | Is locked | 
| Safewalk.management.transactionlist.results.id | Number | Result ID | 
| Safewalk.management.transactionlist.results.type | String | Result type | 
| Safewalk.management.transactionlist.results.timestamp | Date | Results timestamp | 
| Safewalk.management.transactionlist.results.user | String | Results user | 
| Safewalk.management.transactionlist.results.username | String | Results username | 
| Safewalk.management.transactionlist.results.serial_number | Unknown | Serial Number | 
| Safewalk.management.transactionlist.results.code | String | Code | 
| Safewalk.management.transactionlist.results.transaction_id | String | Transaction ID | 
| Safewalk.management.transactionlist.results.result | String | Result | 
| Safewalk.management.transactionlist.results.reason | Unknown | Reason | 
| Safewalk.management.transactionlist.results.caller | String | Caller | 



#### Human Readable Output



### safewalk-get-users
***
Search local users.


#### Base Command

`safewalk-get-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. | Optional | 
| search | search. | Optional | 
| locked | locked. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.management.userlist.count | Number | Count | 
| Safewalk.management.userlist.next | Unknown | Next | 
| Safewalk.management.userlist.previous | Unknown | Previous | 
| Safewalk.management.userlist.results.username | String | username | 
| Safewalk.management.userlist.results.first_name | String | First Name | 
| Safewalk.management.userlist.results.last_name | String | Last Name | 
| Safewalk.management.userlist.results.mobile | String | Mobile number | 
| Safewalk.management.userlist.results.email | String | Email | 
| Safewalk.management.userlist.results.is_locked | Boolean | Is Locked | 



#### Human Readable Output



### safewalk-get-ldap-users
***
Search LDAP users


#### Base Command

`safewalk-get-ldap-users`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | page. | Optional | 
| search | search. | Optional | 
| locked | locked. | Optional | 
| ldap | ldap. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.management.ldapusers.count | Number | Count | 
| Safewalk.management.ldapusers.next | Unknown | Next | 
| Safewalk.management.ldapusers.previous | Unknown | Previous | 
| Safewalk.management.ldapusers.results.username | String | username | 
| Safewalk.management.ldapusers.results.first_name | String | First Name | 
| Safewalk.management.ldapusers.results.last_name | String | Last Name | 
| Safewalk.management.ldapusers.results.mobile | String | Mobile number | 
| Safewalk.management.ldapusers.results.email | String | Email | 
| Safewalk.management.ldapusers.results.is_locked | Boolean | Is locked | 



#### Human Readable Output



### safewalk-get-ldaps
***
Get LDAP configuration.


#### Base Command

`safewalk-get-ldaps`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.management.ldaps.id | Number | ID | 
| Safewalk.management.ldaps.is_active | Boolean | Is active | 
| Safewalk.management.ldaps.ldap_type | String | Type | 
| Safewalk.management.ldaps.name | String | Name | 
| Safewalk.management.ldaps.domain | String | Domain | 
| Safewalk.management.ldaps.server | String | LDAP Server | 
| Safewalk.management.ldaps.port | Number | LDAP port | 
| Safewalk.management.ldaps.secondary_server | String | Secondary Server | 
| Safewalk.management.ldaps.secondary_port | Unknown | Secondary server port | 
| Safewalk.management.ldaps.bind_dn | String | Bind DN | 
| Safewalk.management.ldaps.bind_password | String | Bind password | 
| Safewalk.management.ldaps.root_dn | String | Root DN | 
| Safewalk.management.ldaps.user_search | String | User search | 
| Safewalk.management.ldaps.search_filter | String | Search filter | 
| Safewalk.management.ldaps.map_uid_attr | String | uid attribute | 
| Safewalk.management.ldaps.map_secondary_uid_attr | String | Secondary uid attribute | 
| Safewalk.management.ldaps.map_first_name_attr | String | Name attr | 
| Safewalk.management.ldaps.map_last_name_attr | String | Last Name attr | 
| Safewalk.management.ldaps.map_email_attr | String | Email attr | 
| Safewalk.management.ldaps.map_mobile_attr | String | Mobile attr | 
| Safewalk.management.ldaps.map_user_status_attr | String | User status attr | 
| Safewalk.management.ldaps.map_pwd_last_set_attr | String | map_pwd_last_set_attr | 
| Safewalk.management.ldaps.map_maximum_password_age | String | map_maximum_password_age | 
| Safewalk.management.ldaps.map_swisscom_mobile_id_sn_attr | String | map_swisscom_mobile_id_sn_attr | 
| Safewalk.management.ldaps.map_immutableid_attr | String | map_immutableid_attr | 
| Safewalk.management.ldaps.priority | Number | ldaps.priority | 



#### Human Readable Output



### safewalk-get-user-personalinformation
***
Get users personal information.


#### Base Command

`safewalk-get-user-personalinformation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.management.userpersonalinformation.username | String | Username | 
| Safewalk.management.userpersonalinformation.first_name | String | First name | 
| Safewalk.management.userpersonalinformation.last_name | String | Last name | 
| Safewalk.management.userpersonalinformation.dn | Unknown | DN | 
| Safewalk.management.userpersonalinformation.db_mobile_phone | String | Mobile phone | 
| Safewalk.management.userpersonalinformation.db_email | String | Email | 
| Safewalk.management.userpersonalinformation.ldap_mobile_phone | Unknown | LDAP mobile phone | 
| Safewalk.management.userpersonalinformation.ldap_email | Unknown | LDAP email | 
| Safewalk.management.userpersonalinformation.user_storage | String | User storage | 
| Safewalk.management.userpersonalinformation.is_locked | Boolean | Is locked | 
| Safewalk.management.userpersonalinformation.has_password_expired | Unknown | Password expired | 
| Safewalk.management.userpersonalinformation.is_required_to_change_password | Unknown | Is required to change password | 
| Safewalk.management.userpersonalinformation.user_disabled | Unknown | User disabled | 
| Safewalk.management.userpersonalinformation.user_lockout | Unknown | User lockout | 
| Safewalk.management.userpersonalinformation.password_expiration_date | Unknown | Password expiration date | 
| Safewalk.management.userpersonalinformation.last_authentication_attempt | Date | Last authentication attempt | 



#### Human Readable Output



### safewalk-set-user-personalinformation
***
Set user personal information.


#### Base Command

`safewalk-set-user-personalinformation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| email | email. | Optional | 
| mobile_phone | mobile_phone. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-get-user-accessattempts
***
Get user access attempts


#### Base Command

`safewalk-get-user-accessattempts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.management.accessattempts.failures_since_start | Number | Since start | 
| Safewalk.management.accessattempts.attempt_time | Date | Attempt time | 
| Safewalk.management.accessattempts.is_locked | Boolean | Is locked | 



#### Human Readable Output



### safewalk-delete-user-accessattempts
***
Delete user access attempts


#### Base Command

`safewalk-delete-user-accessattempts`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-get-user-tokens
***
Get user tokens


#### Base Command

`safewalk-get-user-tokens`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.management.usertokens.serial_number | Date | Usertokens serial number | 
| Safewalk.management.usertokens.type | String | User tokens type | 
| Safewalk.management.usertokens.confirmed | Boolean | User tokens confirmed | 
| Safewalk.management.usertokens.password_required | Unknown | User tokens password required | 
| Safewalk.management.usertokens.physical_token | Unknown | User tokens physical token | 
| Safewalk.management.usertokens.status | String | User tokens status | 
| Safewalk.management.usertokens.status_change_date | Unknown | User tokens status change date | 



#### Human Readable Output



### safewalk-delete-user-token
***
Delete user token.


#### Base Command

`safewalk-delete-user-token`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| devicetype | devicetype. | Optional | 
| serialnumber | serialnumber. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-send-user-virtualtoken
***
Send user virtual token.


#### Base Command

`safewalk-send-user-virtualtoken`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| token_devicetype | token_devicetype. | Optional | 
| token_serialnumber | token_serialnumber. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-get-user-settings
***
Get user settings.


#### Base Command

`safewalk-get-user-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.management.usersettings.backuptoken_attempts | Number | Backup token attempts | 
| Safewalk.management.usersettings.backuptoken_timeout | Number | Backup token timeout | 
| Safewalk.management.usersettings.backuptoken_gateways | Unknown | Backup token gateways | 
| Safewalk.management.usersettings.backup_password_required | Boolean | Backup password requiered | 
| Safewalk.management.usersettings.inherited_backuptoken_attempts.value | Number | Backup token attempts value | 
| Safewalk.management.usersettings.inherited_backuptoken_attempts.level | String | Backup token attempts level | 
| Safewalk.management.usersettings.inherited_backuptoken_timeout.value | Number | Backup token timeout value | 
| Safewalk.management.usersettings.inherited_backuptoken_timeout.level | String | Backup token timeout level | 
| Safewalk.management.usersettings.inherited_backuptoken_gateways.level | String | Backup token gateways level | 
| Safewalk.management.usersettings.inherited_backup_password_required.value | Boolean | Backup password required value | 
| Safewalk.management.usersettings.inherited_backup_password_required.level | String | Backup password required level | 
| Safewalk.management.usersettings.registration_token_attempts | Unknown | Registration token attempts | 
| Safewalk.management.usersettings.registration_token_timeout | Unknown | Registration token timeout | 
| Safewalk.management.usersettings.registration_token_gateways | Unknown | Registration token gateways | 
| Safewalk.management.usersettings.inherited_registration_token_attempts.value | Number | Registration token attempts value | 
| Safewalk.management.usersettings.inherited_registration_token_attempts.level | String | Registration token attempts level | 
| Safewalk.management.usersettings.inherited_registration_token_timeout.value | Number | Registration token timeout value | 
| Safewalk.management.usersettings.inherited_registration_token_timeout.level | String | Registration token timeout level | 
| Safewalk.management.usersettings.inherited_registration_token_gateways.level | String | Registration token gateways level | 
| Safewalk.management.usersettings.gaia_ttw_level | Unknown | gaia ttw level | 
| Safewalk.management.usersettings.inherited_gaia_ttw_level.value | String | gaia ttw level value | 
| Safewalk.management.usersettings.inherited_gaia_ttw_level.level | String | gaia ttw level level | 
| Safewalk.management.usersettings.sesami_mobile_password_required | Unknown | sesami mobile password required | 
| Safewalk.management.usersettings.sesami_slim_password_required | Unknown | sesami slim password required | 
| Safewalk.management.usersettings.hotp_password_required | Unknown | hotp password required | 
| Safewalk.management.usersettings.hotp_flex_password_required | Unknown | hotp flex password required | 
| Safewalk.management.usersettings.hotp_flex_pin_password_required | Unknown | hotp flex pin password required | 
| Safewalk.management.usersettings.totp_password_required | Unknown | totp password required | 
| Safewalk.management.usersettings.totp_flex_password_required | Unknown | totp flex password required | 
| Safewalk.management.usersettings.totp_flex_pin_password_required | Unknown | totp flex pin password required | 
| Safewalk.management.usersettings.totp_mobile_password_required | Unknown | totp mobile password required | 
| Safewalk.management.usersettings.inherited_sesami_mobile_password_required.value | Boolean | sesami mobile password required value | 
| Safewalk.management.usersettings.inherited_sesami_mobile_password_required.level | String | sesami mobile password required level | 
| Safewalk.management.usersettings.inherited_sesami_slim_password_required.value | Boolean | sesami slim password required value | 
| Safewalk.management.usersettings.inherited_sesami_slim_password_required.level | String | sesami slim password required level | 
| Safewalk.management.usersettings.inherited_hotp_password_required.value | Boolean | hotp password required value | 
| Safewalk.management.usersettings.inherited_hotp_password_required.level | String | hotp password required level | 
| Safewalk.management.usersettings.inherited_hotp_flex_password_required.value | Boolean | hotp flex password required value | 
| Safewalk.management.usersettings.inherited_hotp_flex_password_required.level | String | hotp flex password required level | 
| Safewalk.management.usersettings.inherited_hotp_flex_pin_password_required.value | Boolean | hotp flex pin password required value | 
| Safewalk.management.usersettings.inherited_hotp_flex_pin_password_required.level | String | hotp flex pin password required level | 
| Safewalk.management.usersettings.inherited_totp_password_required.value | Boolean | totp password required value | 
| Safewalk.management.usersettings.inherited_totp_password_required.level | String | totp password required level | 
| Safewalk.management.usersettings.inherited_totp_flex_password_required.value | Boolean | totp flex password required value | 
| Safewalk.management.usersettings.inherited_totp_flex_password_required.level | String | totp flex password required level | 
| Safewalk.management.usersettings.inherited_totp_flex_pin_password_required.value | Boolean | totp flex pin password required value | 
| Safewalk.management.usersettings.inherited_totp_flex_pin_password_required.level | String | totp flex pin password required level | 
| Safewalk.management.usersettings.inherited_totp_mobile_password_required.value | Boolean | totp mobile password required value | 
| Safewalk.management.usersettings.inherited_totp_mobile_password_required.level | String | totp mobile password required level | 
| Safewalk.management.usersettings.allow_password | Boolean | allow password | 
| Safewalk.management.usersettings.allow_password_for_registration | Boolean | allow password for registration | 
| Safewalk.management.usersettings.allow_access_when_pwd_expired | Boolean | allow access when pwd expired | 
| Safewalk.management.usersettings.allow_password_reset_when_forgot_pwd | Unknown | allow password reset when forgot pwd | 
| Safewalk.management.usersettings.min_otp_length | Unknown | min otp length | 
| Safewalk.management.usersettings.max_otp_length | Unknown | max otp length | 
| Safewalk.management.usersettings.inherited_allow_password.value | Boolean | allow password value | 
| Safewalk.management.usersettings.inherited_allow_password.level | String | allow password level | 
| Safewalk.management.usersettings.inherited_allow_password_for_registration.value | Boolean | allow password for registration value | 
| Safewalk.management.usersettings.inherited_allow_password_for_registration.level | String | allow password for registration level | 
| Safewalk.management.usersettings.inherited_allow_access_when_pwd_expired.value | Boolean | allow access when pwd expired value | 
| Safewalk.management.usersettings.inherited_allow_access_when_pwd_expired.level | String | allow access when pwd expired level | 
| Safewalk.management.usersettings.inherited_allow_password_reset_when_forgot_pwd.value | Boolean | allow password reset when forgot pwd value | 
| Safewalk.management.usersettings.inherited_allow_password_reset_when_forgot_pwd.level | String | allow password reset when forgot pwd level | 
| Safewalk.management.usersettings.inherited_min_otp_length.value | Number | min otp length value | 
| Safewalk.management.usersettings.inherited_min_otp_length.level | String | min otp length level | 
| Safewalk.management.usersettings.inherited_max_otp_length.value | Number | max otp length value | 
| Safewalk.management.usersettings.inherited_max_otp_length.level | String | max otp length level | 
| Safewalk.management.usersettings.max_allowed_failures | Unknown | max allowed failures | 
| Safewalk.management.usersettings.inherited_max_allowed_failures.value | Number | max allowed failures value | 
| Safewalk.management.usersettings.inherited_max_allowed_failures.level | String | max allowed failures level | 
| Safewalk.management.usersettings.totp_accept_tolerance | Unknown | totp accept tolerance | 
| Safewalk.management.usersettings.totp_resend_tolerance | Unknown | totp resend tolerance | 
| Safewalk.management.usersettings.totp_resend_timeout | Unknown | totp resend timeout | 
| Safewalk.management.usersettings.inherited_totp_accept_tolerance.value | Number | totp accept tolerance value | 
| Safewalk.management.usersettings.inherited_totp_accept_tolerance.level | String | totp accept tolerance level | 
| Safewalk.management.usersettings.inherited_totp_resend_tolerance.value | Number | totp resend tolerance value | 
| Safewalk.management.usersettings.inherited_totp_resend_tolerance.level | String | totp resend tolerance level | 
| Safewalk.management.usersettings.inherited_totp_resend_timeout.value | Number | totp resend timeout value | 
| Safewalk.management.usersettings.inherited_totp_resend_timeout.level | String | totp resend timeout level | 
| Safewalk.management.usersettings.hotp_accept_tolerance | Unknown | hotp accept tolerance | 
| Safewalk.management.usersettings.hotp_resend_tolerance | Unknown | hotp resend tolerance | 
| Safewalk.management.usersettings.hotp_resend_timeout | Unknown | hotp resend timeout | 
| Safewalk.management.usersettings.inherited_hotp_accept_tolerance.value | Number | hotp accept tolerance value | 
| Safewalk.management.usersettings.inherited_hotp_accept_tolerance.level | String | hotp accept tolerance level | 
| Safewalk.management.usersettings.inherited_hotp_resend_tolerance.value | Number | hotp resend tolerance value | 
| Safewalk.management.usersettings.inherited_hotp_resend_tolerance.level | String | inherited hotp resend tolerance level | 
| Safewalk.management.usersettings.inherited_hotp_resend_timeout.value | Number | hotp resend timeout value | 
| Safewalk.management.usersettings.inherited_hotp_resend_timeout.level | String | hotp resend timeout level | 
| Safewalk.management.usersettings.virtual_device_gateways | Unknown | virtual device gateways | 
| Safewalk.management.usersettings.virtual_device_accept_tolerance | Number | virtual device accept tolerance | 
| Safewalk.management.usersettings.inherited_virtual_device_gateways.level | String | virtual device gateways level | 
| Safewalk.management.usersettings.inherited_virtual_device_accept_tolerance.value | Number | virtual device accept tolerance value | 
| Safewalk.management.usersettings.inherited_virtual_device_accept_tolerance.level | String | virtual device accept tolerance level | 
| Safewalk.management.usersettings.dos_tmp_lockdown_max_fail_authentications | Unknown | dos_tmp_lockdown_max_fail_authentications | 
| Safewalk.management.usersettings.dos_tmp_lockdown_time_interval_in_seconds | Unknown | dos_tmp_lockdown_time_interval_in_seconds | 
| Safewalk.management.usersettings.dos_tmp_lockdown_time_in_seconds | Unknown | dos_tmp_lockdown_time_in_seconds | 
| Safewalk.management.usersettings.inherited_dos_tmp_lockdown_max_fail_authentications.value | Number | dos_tmp_lockdown_max_fail_authentications.value | 
| Safewalk.management.usersettings.inherited_dos_tmp_lockdown_max_fail_authentications.level | String | dos_tmp_lockdown_max_fail_authentications.level | 
| Safewalk.management.usersettings.inherited_dos_tmp_lockdown_time_interval_in_seconds.value | Number | dos_tmp_lockdown_time_interval_in_seconds.value | 
| Safewalk.management.usersettings.inherited_dos_tmp_lockdown_time_interval_in_seconds.level | String | dos_tmp_lockdown_time_interval_in_seconds.level | 
| Safewalk.management.usersettings.inherited_dos_tmp_lockdown_time_in_seconds.value | Number | dos_tmp_lockdown_time_in_seconds.value | 
| Safewalk.management.usersettings.inherited_dos_tmp_lockdown_time_in_seconds.level | String | dos_tmp_lockdown_time_in_seconds.level | 
| Safewalk.management.usersettings.user_storage | Unknown | User storage | 
| Safewalk.management.usersettings.multiple_step_auth_timeout | Unknown | multiple step auth timeout | 
| Safewalk.management.usersettings.inherited_user_storage.value | String | user storage value | 
| Safewalk.management.usersettings.inherited_user_storage.level | String | user storage level | 
| Safewalk.management.usersettings.inherited_multiple_step_auth_timeout.value | Number | multiple step auth timeout value | 
| Safewalk.management.usersettings.inherited_multiple_step_auth_timeout.level | String | usersettings_inherited_multiple_step_auth_timeout.level | 



#### Human Readable Output



### safewalk-get-user-group
***
Get user group.


#### Base Command

`safewalk-get-user-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.management.usergroup.default_group.name | String | default group name | 
| Safewalk.management.usergroup.default_group.is_member | Boolean | default group is member | 
| Safewalk.management.usergroup.default_group.dn | Unknown | default group dn | 
| Safewalk.management.usergroup.default_group.priority | Number | default group priority | 
| Safewalk.management.usergroup.groups.name | String | groups name | 
| Safewalk.management.usergroup.groups.is_member | Boolean | groups is member | 
| Safewalk.management.usergroup.groups.dn | String | groups dn | 
| Safewalk.management.usergroup.groups.priority | Number | groups priority | 



#### Human Readable Output



### safewalk-add-user-group
***
Add user group.


#### Base Command

`safewalk-add-user-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| new-group-name | new-group-name. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-remove-user-group
***
Remove user group.


#### Base Command

`safewalk-remove-user-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| old-group-name | old-group-name. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-get-user-registrationcode
***
Get user registration code


#### Base Command

`safewalk-get-user-registrationcode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Safewalk.management.registrationcode.expiration | Date | registration code expiration | 
| Safewalk.management.registrationcode.attempts_left | Number | registration code attempts left | 
| Safewalk.management.registrationcode.sent_by | Unknown | registration code sent by | 
| Safewalk.management.registrationcode.sent_on | Unknown | registration code sent on | 
| Safewalk.management.registrationcode.token | String | registration code token | 
| Safewalk.management.registrationcode.purpose | String | registration code purpose | 



#### Human Readable Output



### safewalk-set-user-registrationcode
***
Set user registration code


#### Base Command

`safewalk-set-user-registrationcode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| expiration | Expiration. | Optional | 
| attempts-left | attempts-left. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-send-user-registrationcode
***
Send user registration code


#### Base Command

`safewalk-send-user-registrationcode`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-create-user-token-virtual
***
Create user virtual token


#### Base Command

`safewalk-create-user-token-virtual`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-create-user-token-fastauth
***
Create user FastAuth Token


#### Base Command

`safewalk-create-user-token-fastauth`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| serial-number | Serial number. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-create-user-token-totpmobile
***
Create user TopMobile Token


#### Base Command

`safewalk-create-user-token-totpmobile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| serial-number | Serail number. | Optional | 
| password-required | Password required. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-create-user-token-totmobilehybrid
***
Create user TotMobileHybrid


#### Base Command

`safewalk-create-user-token-totmobilehybrid`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| serial-number | Serial number. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-create-user-token-physical
***
Create user Physical Token


#### Base Command

`safewalk-create-user-token-physical`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| serial-number | serial-number. | Optional | 
| password-required | password-required. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-create-user-token-backup
***
Create user Backup Token


#### Base Command

`safewalk-create-user-token-backup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| password-required | password-required. | Optional | 
| backuptoken-timeout | backuptoken-timeout. | Optional | 
| backuptoken_attempts | backuptoken_attempts. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-set-user-backuptoken-settings
***
Set user backup token


#### Base Command

`safewalk-set-user-backuptoken-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| backup-password-required | backup-password-required. | Optional | 
| backuptoken-attempts | backuptoken-attempts. | Optional | 
| backuptoken-timeout | backuptoken-timeout. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-set-user-general-settings
***
Set user general settings


#### Base Command

`safewalk-set-user-general-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| user-storage | User storage. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-set-user-hotpauthentication-settings
***
Set user hotpauthentication settings


#### Base Command

`safewalk-set-user-hotpauthentication-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| hotp-accept-tolerance | hotp-accept-tolerance. | Optional | 
| hotp-resend-tolerance | hotp-resend-tolerance. | Optional | 
| hotp-resend-timeout | hotp-resend-timeout. | Optional | 
| hotp-password_required | hotp-password_required. | Optional | 
| hotp-flex-password-required | hotp-flex-password-required. | Optional | 
| hotp-flex-pin-password-required | hotp-flex-pin-password-required. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-set-user-sesamiauthentication-settings
***
Set user sesamiauthentication setttings


#### Base Command

`safewalk-set-user-sesamiauthentication-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| sesami_mobile_password_required | sesami_mobile_password_required. | Optional | 
| sesami_slim_password_required | sesami_slim_password_required. | Optional | 
| gaia_ttw_level | gaia_ttw_level. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-set-user-totpauthentication-settings
***
Set user  totpauthentication settings


#### Base Command

`safewalk-set-user-totpauthentication-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| totp-accept-tolerance | totp-accept-tolerance. | Optional | 
| totp-resend-tolerance | totp-resend-tolerance. | Optional | 
| totp-resend-timeout | totp-resend-timeout. | Optional | 
| totp-password-required | totp-password-required. | Optional | 
| totp-flex-password-required | totp-flex-password-required. | Optional | 
| totp-flex-pin-password-required | totp-flex-pin-password-required. | Optional | 
| totp-mobile-password-required | totp-mobile-password-required. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-set-user-userauthentication-settings
***
Set user userauthentication settings


#### Base Command

`safewalk-set-user-userauthentication-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| multiple-step-auth-timeout | multiple-step-auth-timeout. | Optional | 
| allow-password | allow-password. | Optional | 
| allow-password-for-registration | allow-password-for-registration. | Optional | 
| max-allowed-failures | max-allowed-failures. | Optional | 
| allow-access-when-pwd-expired | allow-access-when-pwd-expired. | Optional | 
| allow-password-reset-when-forgot-pwd | allow-password-reset-when-forgot-pwd. | Optional | 
| min-otp-length | min-otp-length. | Optional | 
| max-otp-length | max-otp-length. | Optional | 
| dos-tmp-lockdown-max-fail-authentications | dos-tmp-lockdown-max-fail-authentications. | Optional | 
| dos-tmp-lockdown-time-interval-in-seconds | dos-tmp-lockdown-time-interval-in-seconds. | Optional | 
| dos-tmp-lockdown-time-in-seconds | dos-tmp-lockdown-time-in-seconds. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-set-user-virtualauthentication-settings
***
Set user virtualauthentication settings


#### Base Command

`safewalk-set-user-virtualauthentication-settings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| virtual-device-accept-tolerance | Virtual device accept tolerance. | Optional | 
| virtual-device-gateways | Virtual device gateways. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-create-user
***
Create user


#### Base Command

`safewalk-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Required | 
| password | Password. | Required | 
| firstname | First Name. | Required | 
| lastname | Last Name. | Required | 
| mobilephone | Mobile Phone. | Required | 
| email | email. | Required | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-delete-user
***
Delete user


#### Base Command

`safewalk-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output



### safewalk-update-user-group
***
Update user group


#### Base Command

`safewalk-update-user-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| new-group-name | New user group. | Optional | 


#### Context Output

There is no context output for this command.


#### Human Readable Output

