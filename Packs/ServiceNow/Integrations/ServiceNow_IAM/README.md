> <i>Note:</i> This integration should be used along with our IAM premium pack. For further details, visit our IAM pack documentation.

Integrate with ServiceNow's services to perform Identity Lifecycle Management operations.
This integration was integrated and tested with London version of ServiceNow.
For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

## Configure ServiceNow IAM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | ServiceNow URL \(https://domain.service-now.com\) | True |
| api_version | ServiceNow API Version \(e.g. 'v1'\). Specify this value to use an endpoint version other than the latest. | False |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| create_user_enabled | Allow creating users | False |
| update_user_enabled | Allow updating users | False |
| enable_user_enabled | Allow enabling users | False |
| disable_user_enabled | Allow disabling users | False |
| create_if_not_exists | Automatically create user if not found in update and enable commands | False |
| mapper_in | Incoming Mapper | True |
| mapper_out | Outgoing Mapper | True |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### iam-create-user
***
Creates a user.


#### Base Command

`iam-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | User Profile indicator details. | Required | 
| allow-enable | Enable the user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | If true, the employee's status is active, otherwise false. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | If true, the command was executed successfully, otherwise false. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
``` !iam-create-user user-profile=`{"email":"testdemisto2@paloaltonetworks.com", "givenname":"Test","surname":"Demisto"}` ```

#### Human Readable Output
### Create User Results (ServiceNow IAM)
|brand|instanceName|success|active|id|email|details|
|---|---|---|---|---|---|---|
| ServiceNow IAM | ServiceNow IAM_instance_1 | true | true | edab746f1b142410042611b4bd4bcb23 | testdemisto2@paloaltonetworks.com | calendar_integration: 1<br/>country: <br/>user_password: <br/>last_login_time: <br/>source: <br/>sys_updated_on: 2020-11-11 14:55:48<br/>building: <br/>web_service_access_only: false<br/>notification: 2<br/>enable_multifactor_authn: false<br/>sys_updated_by: admin<br/>sys_created_on: 2020-11-11 14:55:48<br/>sys_domain: {"link": "https://ven03941.service-now.com/api/now/table/sys_user_group/global", "value": "global"}<br/>state: <br/>vip: false<br/>sys_created_by: admin<br/>zip: <br/>home_phone: <br/>time_format: <br/>last_login: <br/>default_perspective: <br/>active: true<br/>sys_domain_path: /<br/>cost_center: <br/>phone: <br/>name: Test Demisto<br/>employee_number: <br/>password_needs_reset: false<br/>gender: <br/>city: <br/>failed_attempts: <br/>user_name: <br/>roles: <br/>title: <br/>sys_class_name: sys_user<br/>sys_id: edab746f1b142410042611b4bd4bcb23<br/>internal_integration_user: false<br/>ldap_server: <br/>mobile_phone: <br/>street: <br/>company: <br/>department: <br/>first_name: Test<br/>email: testdemisto2@paloaltonetworks.com<br/>introduction: <br/>preferred_language: <br/>manager: <br/>locked_out: false<br/>sys_mod_count: 0<br/>last_name: Demisto<br/>photo: <br/>avatar: <br/>middle_name: <br/>sys_tags: <br/>time_zone: <br/>schedule: <br/>date_format: <br/>location:  |



### iam-update-user
***
Updates an existing user with the data passed in the user-profile argument.


#### Base Command

`iam-update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 
| allow-enable | Enable the user. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | If true, the employee's status is active, otherwise false. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | If true, the command was executed successfully, otherwise false. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
``` !iam-update-user user-profile=`{"email":"testdemisto2@paloaltonetworks.com", "givenname":"Test","surname":"Demisto_updated"}` ```

#### Human Readable Output
### Update User Results (ServiceNow IAM)
|brand|instanceName|success|active|id|email|details|
|---|---|---|---|---|---|---|
| ServiceNow IAM | ServiceNow IAM_instance_1 | true | true | edab746f1b142410042611b4bd4bcb23 | testdemisto2@paloaltonetworks.com | calendar_integration: 1<br/>country: <br/>user_password: <br/>last_login_time: <br/>source: <br/>sys_updated_on: 2020-11-11 14:55:48<br/>building: <br/>web_service_access_only: false<br/>notification: 2<br/>enable_multifactor_authn: false<br/>sys_updated_by: admin<br/>sys_created_on: 2020-11-11 14:55:48<br/>sys_domain: {"link": "https://ven03941.service-now.com/api/now/table/sys_user_group/global", "value": "global"}<br/>state: <br/>vip: false<br/>sys_created_by: admin<br/>zip: <br/>home_phone: <br/>time_format: <br/>last_login: <br/>default_perspective: <br/>active: true<br/>sys_domain_path: /<br/>cost_center: <br/>phone: <br/>name: Test Demisto_updated<br/>employee_number: <br/>password_needs_reset: false<br/>gender: <br/>city: <br/>failed_attempts: <br/>user_name: <br/>roles: <br/>title: <br/>sys_class_name: sys_user<br/>sys_id: edab746f1b142410042611b4bd4bcb23<br/>internal_integration_user: false<br/>ldap_server: <br/>mobile_phone: <br/>street: <br/>company: <br/>department: <br/>first_name: Test<br/>email: testdemisto2@paloaltonetworks.com<br/>introduction: <br/>preferred_language: <br/>manager: <br/>locked_out: false<br/>sys_mod_count: 0<br/>last_name: Demisto_updated<br/>photo: <br/>avatar: <br/>middle_name: <br/>sys_tags: <br/>time_zone: <br/>schedule: <br/>date_format: <br/>location:  |



### iam-get-user
***
Retrieves a single user resource.


#### Base Command

`iam-get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | If true, the employee's status is active, otherwise false. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | If true, the command was executed successfully, otherwise false. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
``` !iam-get-user user-profile=`{"email":"testdemisto2@paloaltonetworks.com"}` ```

#### Human Readable Output
### Get User Results (ServiceNow IAM)
|brand|instanceName|success|active|id|email|details|
|---|---|---|---|---|---|---|
| ServiceNow IAM | ServiceNow IAM_instance_1 | true | true | edab746f1b142410042611b4bd4bcb23 | testdemisto2@paloaltonetworks.com | calendar_integration: 1<br/>country: <br/>user_password: <br/>last_login_time: <br/>source: <br/>sys_updated_on: 2020-11-11 14:55:48<br/>building: <br/>web_service_access_only: false<br/>notification: 2<br/>enable_multifactor_authn: false<br/>sys_updated_by: admin<br/>sys_created_on: 2020-11-11 14:55:48<br/>sys_domain: {"link": "https://ven03941.service-now.com/api/now/table/sys_user_group/global", "value": "global"}<br/>state: <br/>vip: false<br/>sys_created_by: admin<br/>zip: <br/>home_phone: <br/>time_format: <br/>last_login: <br/>default_perspective: <br/>active: true<br/>sys_domain_path: /<br/>cost_center: <br/>phone: <br/>name: Test Demisto_updated<br/>employee_number: <br/>password_needs_reset: false<br/>gender: <br/>city: <br/>failed_attempts: <br/>user_name: <br/>roles: <br/>title: <br/>sys_class_name: sys_user<br/>sys_id: edab746f1b142410042611b4bd4bcb23<br/>internal_integration_user: false<br/>ldap_server: <br/>mobile_phone: <br/>street: <br/>company: <br/>department: <br/>first_name: Test<br/>email: testdemisto2@paloaltonetworks.com<br/>introduction: <br/>preferred_language: <br/>manager: <br/>locked_out: false<br/>sys_mod_count: 0<br/>last_name: Demisto_updated<br/>photo: <br/>avatar: <br/>middle_name: <br/>sys_tags: <br/>time_zone: <br/>schedule: <br/>date_format: <br/>location:  |



### iam-disable-user
***
Disable an active user.


#### Base Command

`iam-disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | If true, the employee's status is active, otherwise false. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Indicates if the API was successful or provides error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | If true, the command was executed successfully, otherwise false. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
``` !iam-disable-user user-profile=`{"email":"testdemisto2@paloaltonetworks.com"}` ```

#### Human Readable Output
### Disable User Results (ServiceNow IAM)
|brand|instanceName|success|active|id|email|details|
|---|---|---|---|---|---|---|
| ServiceNow IAM | ServiceNow IAM_instance_1 | true | false | edab746f1b142410042611b4bd4bcb23 | testdemisto2@paloaltonetworks.com | calendar_integration: 1<br/>country: <br/>user_password: <br/>last_login_time: <br/>source: <br/>sys_updated_on: 2020-11-11 14:55:48<br/>building: <br/>web_service_access_only: false<br/>notification: 2<br/>enable_multifactor_authn: false<br/>sys_updated_by: admin<br/>sys_created_on: 2020-11-11 14:55:48<br/>sys_domain: {"link": "https://ven03941.service-now.com/api/now/table/sys_user_group/global", "value": "global"}<br/>state: <br/>vip: false<br/>sys_created_by: admin<br/>zip: <br/>home_phone: <br/>time_format: <br/>last_login: <br/>default_perspective: <br/>active: false<br/>sys_domain_path: /<br/>cost_center: <br/>phone: <br/>name: Test Demisto_updated<br/>employee_number: <br/>password_needs_reset: false<br/>gender: <br/>city: <br/>failed_attempts: <br/>user_name: <br/>roles: <br/>title: <br/>sys_class_name: sys_user<br/>sys_id: edab746f1b142410042611b4bd4bcb23<br/>internal_integration_user: false<br/>ldap_server: <br/>mobile_phone: <br/>street: <br/>company: <br/>department: <br/>first_name: Test<br/>email: testdemisto2@paloaltonetworks.com<br/>introduction: <br/>preferred_language: <br/>manager: <br/>locked_out: false<br/>sys_mod_count: 0<br/>last_name: Demisto_updated<br/>photo: <br/>avatar: <br/>middle_name: <br/>sys_tags: <br/>time_zone: <br/>schedule: <br/>date_format: <br/>location:  |
