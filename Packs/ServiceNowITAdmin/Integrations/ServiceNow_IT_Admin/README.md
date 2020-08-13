IAM Integration for ServiceNow. This handles user account auto-provisioning to ServiceNow
This integration was integrated and tested with version v2 of ServiceNow IT Admin
## Configure ServiceNow IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ServiceNow IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | ServiceNow URL, in the format https://company.service\-now.com/ | True |
| credentials | Username | True |
| proxy | Use system proxy settings | False |
| insecure | Trust any certificate \(not secure\) | False |
| api_version | ServiceNow API Version \(e.g. 'v1' or 'v2'\). Only specify this value to use an endpoint version other than the latest. | False |
| customMappingCreateUser | Custom Mapping for Create User | False |
| customMappingUpdateUser | Custom Mapping used for Update User | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-user
***
Retrieves details of a specific user


#### Base Command

`get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetUser.instanceName | string | Name of the instance used for testing | 
| GetUser.details | string | Gives the user Profile information if the API is success else error message | 
| GetUser.success | boolean | Status of the result. Can be true or false. | 
| GetUser.active | boolean | Gives the active status of user. Can be true or false | 
| GetUser.brand | string | Name of the Integration | 
| GetUser.errorCode | number | HTTP error response code | 
| GetUser.username | string | Value of username passed as argument | 
| GetUser.id | string | Value of id passed as argument | 
| GetUser.email | string | Value of email ID passed as argument | 
| GetUser.errorMessage | string | Reason why the API is failed | 
| GetUser | unknown | Command context path | 


#### Command Example
```!get-user scim={"id":"ade744de1b6e5010e9e2a9722a4bcbe0"} using=ServiceNowITAdmin```

#### Context Example
```
{
    "GetUser": {
        "active": false,
        "brand": "ServiceNow IT Admin",
        "details": {
            "active": "false",
            "agent_status": "",
            "avatar": "",
            "average_daily_fte": "",
            "building": "",
            "business_criticality": "3",
            "calendar_integration": "1",
            "city": "",
            "company": "",
            "correlation_id": "",
            "cost_center": "",
            "country": "",
            "date_format": "",
            "default_perspective": "",
            "department": "",
            "email": "testdemistouser99@paloaltonetworks.com",
            "employee_number": "",
            "enable_multifactor_authn": "false",
            "failed_attempts": "",
            "first_name": "demistouser",
            "gender": "",
            "geolocation_tracked": "false",
            "home_phone": "",
            "hr_integration_source": "",
            "internal_integration_user": "false",
            "introduction": "",
            "last_login": "",
            "last_login_time": "",
            "last_name": "test",
            "last_position_update": "",
            "latitude": "",
            "ldap_server": "",
            "location": "",
            "locked_out": "true",
            "longitude": "",
            "manager": "",
            "middle_name": "",
            "mobile_phone": "",
            "name": "demistouser test",
            "notification": "2",
            "on_schedule": "",
            "password_needs_reset": "false",
            "phone": "",
            "photo": "",
            "preferred_language": "",
            "roles": "",
            "schedule": "",
            "source": "",
            "sso_source": "",
            "state": "",
            "street": "",
            "sys_class_name": "sys_user",
            "sys_created_by": "okta.servicenow",
            "sys_created_on": "2020-08-12 14:07:25",
            "sys_domain": {
                "link": "https://panstage.service-now.com/api/now//table/sys_user_group/global",
                "value": "global"
            },
            "sys_id": "ade744de1b6e5010e9e2a9722a4bcbe0",
            "sys_mod_count": "12",
            "sys_tags": "",
            "sys_updated_by": "okta.servicenow",
            "sys_updated_on": "2020-08-13 15:37:52",
            "time_format": "",
            "time_sheet_policy": "",
            "time_zone": "",
            "title": "",
            "transaction_log": "",
            "u_badge": "false",
            "u_bomgar_name": "",
            "u_cost_center": "",
            "u_country": "",
            "u_device_token_android": "",
            "u_device_token_ios": "",
            "u_employee_type": "",
            "u_end_date": "",
            "u_exclude_from_round_robin": "false",
            "u_extensionattribute10": "",
            "u_extensionattribute11": "",
            "u_extensionattribute12": "",
            "u_extensionattribute13": "",
            "u_fired_events": "",
            "u_flag": "",
            "u_job_family": "",
            "u_job_function": "",
            "u_laptop_selection": "",
            "u_last_rep": "",
            "u_local": "false",
            "u_objectguid": "",
            "u_okta_startdate": "",
            "u_panwdirector": "",
            "u_panwea": "",
            "u_panwvp": "",
            "u_people_manager": "false",
            "u_profile_image": "",
            "u_region": "",
            "u_start_date": "",
            "u_workday_location": "",
            "user_name": "Xoar.test000000@paloaltonetworks.com",
            "user_password": "",
            "vip": "false",
            "x_nuvo_eam_out_of_office": "false",
            "x_nuvo_eam_primary_location": "",
            "x_nuvo_eam_primary_space": "",
            "x_nuvo_eam_user": {
                "link": "https://panstage.service-now.com/api/now//table/x_nuvo_eam_user/25e744de1b6e5010e9e2a9722a4bcbe2",
                "value": "25e744de1b6e5010e9e2a9722a4bcbe2"
            },
            "x_pd_integration_pagerduty_id": "",
            "zip": ""
        },
        "email": "testdemistouser99@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "ade744de1b6e5010e9e2a9722a4bcbe0",
        "instanceName": "ServiceNowITAdmin",
        "success": true,
        "username": "Xoar.test000000@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Get ServiceNow User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| ServiceNow IT Admin | ServiceNowITAdmin | true | false | ade744de1b6e5010e9e2a9722a4bcbe0 | Xoar.test000000@paloaltonetworks.com | testdemistouser99@paloaltonetworks.com | u_last_rep: <br/>calendar_integration: 1<br/>last_position_update: <br/>user_password: <br/>sys_updated_on: 2020-08-13 15:37:52<br/>building: <br/>sso_source: <br/>state: <br/>vip: false<br/>sys_created_by: okta.servicenow<br/>zip: <br/>u_country: <br/>u_job_function: <br/>time_format: <br/>last_login: <br/>active: false<br/>u_laptop_selection: <br/>u_okta_startdate: <br/>transaction_log: <br/>u_extensionattribute13: <br/>u_extensionattribute12: <br/>cost_center: <br/>phone: <br/>u_start_date: <br/>employee_number: <br/>u_cost_center: <br/>u_extensionattribute11: <br/>u_people_manager: false<br/>u_extensionattribute10: <br/>gender: <br/>city: <br/>user_name: Xoar.test000000@paloaltonetworks.com<br/>latitude: <br/>sys_class_name: sys_user<br/>x_nuvo_eam_primary_space: <br/>u_employee_type: <br/>u_local: false<br/>email: testdemistouser99@paloaltonetworks.com<br/>u_region: <br/>manager: <br/>business_criticality: 3<br/>locked_out: true<br/>last_name: test<br/>photo: <br/>avatar: <br/>u_job_family: <br/>on_schedule: <br/>u_device_token_ios: <br/>correlation_id: <br/>date_format: <br/>country: <br/>last_login_time: <br/>x_pd_integration_pagerduty_id: <br/>source: <br/>notification: 2<br/>enable_multifactor_authn: false<br/>sys_updated_by: okta.servicenow<br/>u_device_token_android: <br/>sys_created_on: 2020-08-12 14:07:25<br/>u_profile_image: <br/>agent_status: <br/>sys_domain: {"link": "https://panstage.service-now.com/api/now//table/sys_user_group/global", "value": "global"}<br/>u_exclude_from_round_robin: false<br/>longitude: <br/>home_phone: <br/>u_panwea: <br/>default_perspective: <br/>geolocation_tracked: false<br/>u_fired_events: <br/>average_daily_fte: <br/>time_sheet_policy: <br/>u_bomgar_name: <br/>u_badge: false<br/>u_workday_location: <br/>name: demistouser test<br/>x_nuvo_eam_primary_location: <br/>u_panwvp: <br/>password_needs_reset: false<br/>x_nuvo_eam_user: {"link": "https://panstage.service-now.com/api/now//table/x_nuvo_eam_user/25e744de1b6e5010e9e2a9722a4bcbe2", "value": "25e744de1b6e5010e9e2a9722a4bcbe2"}<br/>hr_integration_source: <br/>failed_attempts: <br/>roles: <br/>title: <br/>sys_id: ade744de1b6e5010e9e2a9722a4bcbe0<br/>internal_integration_user: false<br/>ldap_server: <br/>u_end_date: <br/>mobile_phone: <br/>street: <br/>company: <br/>department: <br/>first_name: demistouser<br/>introduction: <br/>preferred_language: <br/>x_nuvo_eam_out_of_office: false<br/>u_flag: <br/>sys_mod_count: 12<br/>middle_name: <br/>sys_tags: <br/>time_zone: <br/>schedule: <br/>u_panwdirector: <br/>location: <br/>u_objectguid:  |


### create-user
***
Creates a user


#### Base Command

`create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CreateUser | unknown | Command context path | 
| CreateUser.instanceName | string | Name of the instance used for testing | 
| CreateUser.active | boolean | Gives the active status of user. Can be true of false. | 
| CreateUser.brand | string | Name of the Integration | 
| CreateUser.details | string | Gives the raw response from API | 
| CreateUser.email | string | Value of email ID passed as argument | 
| CreateUser.errorCode | number | HTTP error response code | 
| CreateUser.errorMessage | string | Reason why the API is failed | 
| CreateUser.id | string | Value of id passed as argument | 
| CreateUser.instanceName | string | Name of the instance used for testing | 
| CreateUser.success | boolean | Status of the result. Can be true or false. | 
| CreateUser.username | string | Value of username passed as argument | 


#### Command Example
```!create-user scim={"name":{"familyName":"test","givenName":"demisto"},"emails":[{"type":"work","primary":true,"value":"testdemistouser13Aug@paloaltonetworks.com"}],"userName":"testXoar13Aug@paloaltonetworks.com"} using=ServiceNowITAdmin```

#### Context Example
```
{
    "CreateUser": {
        "active": true,
        "brand": "ServiceNow IT Admin",
        "details": {
            "active": "true",
            "agent_status": "",
            "avatar": "",
            "average_daily_fte": "",
            "building": "",
            "business_criticality": "3",
            "calendar_integration": "1",
            "city": "",
            "company": "",
            "correlation_id": "",
            "cost_center": "",
            "country": "",
            "date_format": "",
            "default_perspective": "",
            "department": "",
            "email": "testdemistouser13Aug@paloaltonetworks.com",
            "employee_number": "",
            "enable_multifactor_authn": "false",
            "failed_attempts": "",
            "first_name": "demisto",
            "gender": "",
            "geolocation_tracked": "false",
            "home_phone": "",
            "hr_integration_source": "",
            "internal_integration_user": "false",
            "introduction": "",
            "last_login": "",
            "last_login_time": "",
            "last_name": "test",
            "last_position_update": "",
            "latitude": "",
            "ldap_server": "",
            "location": "",
            "locked_out": "false",
            "longitude": "",
            "manager": "",
            "middle_name": "",
            "mobile_phone": "",
            "name": "demisto test",
            "notification": "2",
            "on_schedule": "",
            "password_needs_reset": "false",
            "phone": "",
            "photo": "",
            "preferred_language": "",
            "roles": "",
            "schedule": "",
            "source": "",
            "sso_source": "",
            "state": "",
            "street": "",
            "sys_class_name": "sys_user",
            "sys_created_by": "okta.servicenow",
            "sys_created_on": "2020-08-13 16:29:14",
            "sys_domain": {
                "link": "https://panstage.service-now.com/api/now//table/sys_user_group/global",
                "value": "global"
            },
            "sys_id": "ecf1bdea1b6e5850e11c7bff034bcb28",
            "sys_mod_count": "0",
            "sys_tags": "",
            "sys_updated_by": "okta.servicenow",
            "sys_updated_on": "2020-08-13 16:29:14",
            "time_format": "",
            "time_sheet_policy": "",
            "time_zone": "",
            "title": "",
            "transaction_log": "",
            "u_badge": "false",
            "u_bomgar_name": "",
            "u_cost_center": "",
            "u_country": "",
            "u_device_token_android": "",
            "u_device_token_ios": "",
            "u_employee_type": "",
            "u_end_date": "",
            "u_exclude_from_round_robin": "false",
            "u_extensionattribute10": "",
            "u_extensionattribute11": "",
            "u_extensionattribute12": "",
            "u_extensionattribute13": "",
            "u_fired_events": "",
            "u_flag": "",
            "u_job_family": "",
            "u_job_function": "",
            "u_laptop_selection": "",
            "u_last_rep": "",
            "u_local": "false",
            "u_objectguid": "",
            "u_okta_startdate": "",
            "u_panwdirector": "",
            "u_panwea": "",
            "u_panwvp": "",
            "u_people_manager": "false",
            "u_profile_image": "",
            "u_region": "",
            "u_start_date": "",
            "u_workday_location": "",
            "user_name": "testXoar13Aug@paloaltonetworks.com",
            "user_password": "",
            "vip": "false",
            "x_nuvo_eam_out_of_office": "false",
            "x_nuvo_eam_primary_location": "",
            "x_nuvo_eam_primary_space": "",
            "x_nuvo_eam_user": {
                "link": "https://panstage.service-now.com/api/now//table/x_nuvo_eam_user/e0f1bdea1b6e5850e11c7bff034bcb2a",
                "value": "e0f1bdea1b6e5850e11c7bff034bcb2a"
            },
            "x_pd_integration_pagerduty_id": "",
            "zip": ""
        },
        "email": "testdemistouser13Aug@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "ecf1bdea1b6e5850e11c7bff034bcb28",
        "instanceName": "ServiceNowITAdmin",
        "success": true,
        "username": "testXoar13Aug@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Create ServiceNow User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| ServiceNow IT Admin | ServiceNowITAdmin | true | true | ecf1bdea1b6e5850e11c7bff034bcb28 | testXoar13Aug@paloaltonetworks.com | testdemistouser13Aug@paloaltonetworks.com | u_last_rep: <br/>calendar_integration: 1<br/>last_position_update: <br/>user_password: <br/>sys_updated_on: 2020-08-13 16:29:14<br/>building: <br/>sso_source: <br/>state: <br/>vip: false<br/>sys_created_by: okta.servicenow<br/>zip: <br/>u_country: <br/>u_job_function: <br/>time_format: <br/>last_login: <br/>active: true<br/>u_laptop_selection: <br/>u_okta_startdate: <br/>transaction_log: <br/>u_extensionattribute13: <br/>u_extensionattribute12: <br/>cost_center: <br/>phone: <br/>u_start_date: <br/>employee_number: <br/>u_cost_center: <br/>u_extensionattribute11: <br/>u_people_manager: false<br/>u_extensionattribute10: <br/>gender: <br/>city: <br/>user_name: testXoar13Aug@paloaltonetworks.com<br/>latitude: <br/>sys_class_name: sys_user<br/>x_nuvo_eam_primary_space: <br/>u_employee_type: <br/>u_local: false<br/>email: testdemistouser13Aug@paloaltonetworks.com<br/>u_region: <br/>manager: <br/>business_criticality: 3<br/>locked_out: false<br/>last_name: test<br/>photo: <br/>avatar: <br/>u_job_family: <br/>on_schedule: <br/>u_device_token_ios: <br/>correlation_id: <br/>date_format: <br/>country: <br/>last_login_time: <br/>x_pd_integration_pagerduty_id: <br/>source: <br/>notification: 2<br/>enable_multifactor_authn: false<br/>sys_updated_by: okta.servicenow<br/>u_device_token_android: <br/>sys_created_on: 2020-08-13 16:29:14<br/>u_profile_image: <br/>agent_status: <br/>sys_domain: {"link": "https://panstage.service-now.com/api/now//table/sys_user_group/global", "value": "global"}<br/>u_exclude_from_round_robin: false<br/>longitude: <br/>home_phone: <br/>u_panwea: <br/>default_perspective: <br/>geolocation_tracked: false<br/>u_fired_events: <br/>average_daily_fte: <br/>time_sheet_policy: <br/>u_bomgar_name: <br/>u_badge: false<br/>u_workday_location: <br/>name: demisto test<br/>x_nuvo_eam_primary_location: <br/>u_panwvp: <br/>password_needs_reset: false<br/>x_nuvo_eam_user: {"link": "https://panstage.service-now.com/api/now//table/x_nuvo_eam_user/e0f1bdea1b6e5850e11c7bff034bcb2a", "value": "e0f1bdea1b6e5850e11c7bff034bcb2a"}<br/>hr_integration_source: <br/>failed_attempts: <br/>roles: <br/>title: <br/>sys_id: ecf1bdea1b6e5850e11c7bff034bcb28<br/>internal_integration_user: false<br/>ldap_server: <br/>u_end_date: <br/>mobile_phone: <br/>street: <br/>company: <br/>department: <br/>first_name: demisto<br/>introduction: <br/>preferred_language: <br/>x_nuvo_eam_out_of_office: false<br/>u_flag: <br/>sys_mod_count: 0<br/>middle_name: <br/>sys_tags: <br/>time_zone: <br/>schedule: <br/>u_panwdirector: <br/>location: <br/>u_objectguid:  |


### update-user
***
 


#### Base Command

`update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oldScim | Old SCIM content in JSON format | Required | 
| newScim | New SCIM content in JSON format | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UpdateUser | Unknown | Command context path | 
| UpdateUser.active | boolean | Gives the active status of user. Can be true of false. | 
| UpdateUser.brand | string | Name of the Integration | 
| UpdateUser.details | Unknown | Gives the raw response from API | 
| UpdateUser.email | string | Value of email ID passed as argument | 
| UpdateUser.errorCode | number | HTTP error response code | 
| UpdateUser.errorMessage | string | Reason why the API is failed | 
| UpdateUser.id | string | Value of id passed as argument | 
| UpdateUser.instanceName | string | Name of the instance used for testing | 
| UpdateUser.success | boolean | Status of the result. Can be true or false. | 
| UpdateUser.username | string | Value of username passed as argument | 


#### Command Example
```!update-user oldScim={"id":"ade744de1b6e5010e9e2a9722a4bcbe0"} newScim={"name":{"familyName":"test","givenName":"demistouser"},"emails":[{"type":"work","primary":true,"value":"testdemistouser99@paloaltonetworks.com"}]} using=ServiceNowITAdmin```

#### Context Example
```
{
    "UpdateUser": {
        "active": false,
        "brand": "ServiceNow IT Admin",
        "details": {
            "active": "false",
            "agent_status": "",
            "avatar": "",
            "average_daily_fte": "",
            "building": "",
            "business_criticality": "3",
            "calendar_integration": "1",
            "city": "",
            "company": "",
            "correlation_id": "",
            "cost_center": "",
            "country": "",
            "date_format": "",
            "default_perspective": "",
            "department": "",
            "email": "testdemistouser99@paloaltonetworks.com",
            "employee_number": "",
            "enable_multifactor_authn": "false",
            "failed_attempts": "",
            "first_name": "demistouser",
            "gender": "",
            "geolocation_tracked": "false",
            "home_phone": "",
            "hr_integration_source": "",
            "internal_integration_user": "false",
            "introduction": "",
            "last_login": "",
            "last_login_time": "",
            "last_name": "test",
            "last_position_update": "",
            "latitude": "",
            "ldap_server": "",
            "location": "",
            "locked_out": "true",
            "longitude": "",
            "manager": "",
            "middle_name": "",
            "mobile_phone": "",
            "name": "demistouser test",
            "notification": "2",
            "on_schedule": "",
            "password_needs_reset": "false",
            "phone": "",
            "photo": "",
            "preferred_language": "",
            "roles": "",
            "schedule": "",
            "source": "",
            "sso_source": "",
            "state": "",
            "street": "",
            "sys_class_name": "sys_user",
            "sys_created_by": "okta.servicenow",
            "sys_created_on": "2020-08-12 14:07:25",
            "sys_domain": {
                "link": "https://panstage.service-now.com/api/now//table/sys_user_group/global",
                "value": "global"
            },
            "sys_id": "ade744de1b6e5010e9e2a9722a4bcbe0",
            "sys_mod_count": "14",
            "sys_tags": "",
            "sys_updated_by": "okta.servicenow",
            "sys_updated_on": "2020-08-13 16:29:21",
            "time_format": "",
            "time_sheet_policy": "",
            "time_zone": "",
            "title": "",
            "transaction_log": "",
            "u_badge": "false",
            "u_bomgar_name": "",
            "u_cost_center": "",
            "u_country": "",
            "u_device_token_android": "",
            "u_device_token_ios": "",
            "u_employee_type": "",
            "u_end_date": "",
            "u_exclude_from_round_robin": "false",
            "u_extensionattribute10": "",
            "u_extensionattribute11": "",
            "u_extensionattribute12": "",
            "u_extensionattribute13": "",
            "u_fired_events": "",
            "u_flag": "",
            "u_job_family": "",
            "u_job_function": "",
            "u_laptop_selection": "",
            "u_last_rep": "",
            "u_local": "false",
            "u_objectguid": "",
            "u_okta_startdate": "",
            "u_panwdirector": "",
            "u_panwea": "",
            "u_panwvp": "",
            "u_people_manager": "false",
            "u_profile_image": "",
            "u_region": "",
            "u_start_date": "",
            "u_workday_location": "",
            "user_name": "Xoar.test000000@paloaltonetworks.com",
            "user_password": "",
            "vip": "false",
            "x_nuvo_eam_out_of_office": "false",
            "x_nuvo_eam_primary_location": "",
            "x_nuvo_eam_primary_space": "",
            "x_nuvo_eam_user": {
                "link": "https://panstage.service-now.com/api/now//table/x_nuvo_eam_user/25e744de1b6e5010e9e2a9722a4bcbe2",
                "value": "25e744de1b6e5010e9e2a9722a4bcbe2"
            },
            "x_pd_integration_pagerduty_id": "",
            "zip": ""
        },
        "email": "testdemistouser99@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "ade744de1b6e5010e9e2a9722a4bcbe0",
        "instanceName": "ServiceNowITAdmin",
        "success": true,
        "username": "Xoar.test000000@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Update ServiceNow User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| ServiceNow IT Admin | ServiceNowITAdmin | true | false | ade744de1b6e5010e9e2a9722a4bcbe0 | Xoar.test000000@paloaltonetworks.com | testdemistouser99@paloaltonetworks.com | u_last_rep: <br/>calendar_integration: 1<br/>last_position_update: <br/>user_password: <br/>sys_updated_on: 2020-08-13 16:29:21<br/>building: <br/>sso_source: <br/>state: <br/>vip: false<br/>sys_created_by: okta.servicenow<br/>zip: <br/>u_country: <br/>u_job_function: <br/>time_format: <br/>last_login: <br/>active: false<br/>u_laptop_selection: <br/>u_okta_startdate: <br/>transaction_log: <br/>u_extensionattribute13: <br/>u_extensionattribute12: <br/>cost_center: <br/>phone: <br/>u_start_date: <br/>employee_number: <br/>u_cost_center: <br/>u_extensionattribute11: <br/>u_people_manager: false<br/>u_extensionattribute10: <br/>gender: <br/>city: <br/>user_name: Xoar.test000000@paloaltonetworks.com<br/>latitude: <br/>sys_class_name: sys_user<br/>x_nuvo_eam_primary_space: <br/>u_employee_type: <br/>u_local: false<br/>email: testdemistouser99@paloaltonetworks.com<br/>u_region: <br/>manager: <br/>business_criticality: 3<br/>locked_out: true<br/>last_name: test<br/>photo: <br/>avatar: <br/>u_job_family: <br/>on_schedule: <br/>u_device_token_ios: <br/>correlation_id: <br/>date_format: <br/>country: <br/>last_login_time: <br/>x_pd_integration_pagerduty_id: <br/>source: <br/>notification: 2<br/>enable_multifactor_authn: false<br/>sys_updated_by: okta.servicenow<br/>u_device_token_android: <br/>sys_created_on: 2020-08-12 14:07:25<br/>u_profile_image: <br/>agent_status: <br/>sys_domain: {"link": "https://panstage.service-now.com/api/now//table/sys_user_group/global", "value": "global"}<br/>u_exclude_from_round_robin: false<br/>longitude: <br/>home_phone: <br/>u_panwea: <br/>default_perspective: <br/>geolocation_tracked: false<br/>u_fired_events: <br/>average_daily_fte: <br/>time_sheet_policy: <br/>u_bomgar_name: <br/>u_badge: false<br/>u_workday_location: <br/>name: demistouser test<br/>x_nuvo_eam_primary_location: <br/>u_panwvp: <br/>password_needs_reset: false<br/>x_nuvo_eam_user: {"link": "https://panstage.service-now.com/api/now//table/x_nuvo_eam_user/25e744de1b6e5010e9e2a9722a4bcbe2", "value": "25e744de1b6e5010e9e2a9722a4bcbe2"}<br/>hr_integration_source: <br/>failed_attempts: <br/>roles: <br/>title: <br/>sys_id: ade744de1b6e5010e9e2a9722a4bcbe0<br/>internal_integration_user: false<br/>ldap_server: <br/>u_end_date: <br/>mobile_phone: <br/>street: <br/>company: <br/>department: <br/>first_name: demistouser<br/>introduction: <br/>preferred_language: <br/>x_nuvo_eam_out_of_office: false<br/>u_flag: <br/>sys_mod_count: 14<br/>middle_name: <br/>sys_tags: <br/>time_zone: <br/>schedule: <br/>u_panwdirector: <br/>location: <br/>u_objectguid:  |


### enable-user
***
Enable a user


#### Base Command

`enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EnableUser | Unknown | Command context path | 
| EnableUser.active | boolean | Gives the active status of user. Can be true or false | 
| EnableUser.brand | string | Name of the Integration | 
| EnableUser.details | Unknown | Gives the response from API | 
| EnableUser.email | string | Value of email ID passed as argument | 
| EnableUser.errorCode | number | HTTP error response code | 
| EnableUser.errorMessage | string | Reason why the API is failed | 
| EnableUser.id | string | Value of id passed as argument | 
| EnableUser.instanceName | string | Name the instance used for testing | 
| EnableUser.success | boolean | Status of the result. Can be true or false | 
| EnableUser.username | string | Value of username passed as argument | 


#### Command Example
```!enable-user scim={"id":"ade744de1b6e5010e9e2a9722a4bcbe0"} using=ServiceNowITAdmin```

#### Context Example
```
{
    "EnableUser": {
        "active": true,
        "brand": "ServiceNow IT Admin",
        "details": {
            "active": "true",
            "agent_status": "",
            "avatar": "",
            "average_daily_fte": "",
            "building": "",
            "business_criticality": "3",
            "calendar_integration": "1",
            "city": "",
            "company": "",
            "correlation_id": "",
            "cost_center": "",
            "country": "",
            "date_format": "",
            "default_perspective": "",
            "department": "",
            "email": "testdemistouser99@paloaltonetworks.com",
            "employee_number": "",
            "enable_multifactor_authn": "false",
            "failed_attempts": "",
            "first_name": "demistouser",
            "gender": "",
            "geolocation_tracked": "false",
            "home_phone": "",
            "hr_integration_source": "",
            "internal_integration_user": "false",
            "introduction": "",
            "last_login": "",
            "last_login_time": "",
            "last_name": "test",
            "last_position_update": "",
            "latitude": "",
            "ldap_server": "",
            "location": "",
            "locked_out": "false",
            "longitude": "",
            "manager": "",
            "middle_name": "",
            "mobile_phone": "",
            "name": "demistouser test",
            "notification": "2",
            "on_schedule": "",
            "password_needs_reset": "false",
            "phone": "",
            "photo": "",
            "preferred_language": "",
            "roles": "",
            "schedule": "",
            "source": "",
            "sso_source": "",
            "state": "",
            "street": "",
            "sys_class_name": "sys_user",
            "sys_created_by": "okta.servicenow",
            "sys_created_on": "2020-08-12 14:07:25",
            "sys_domain": {
                "link": "https://panstage.service-now.com/api/now//table/sys_user_group/global",
                "value": "global"
            },
            "sys_id": "ade744de1b6e5010e9e2a9722a4bcbe0",
            "sys_mod_count": "13",
            "sys_tags": "",
            "sys_updated_by": "okta.servicenow",
            "sys_updated_on": "2020-08-13 16:29:18",
            "time_format": "",
            "time_sheet_policy": "",
            "time_zone": "",
            "title": "",
            "transaction_log": "",
            "u_badge": "false",
            "u_bomgar_name": "",
            "u_cost_center": "",
            "u_country": "",
            "u_device_token_android": "",
            "u_device_token_ios": "",
            "u_employee_type": "",
            "u_end_date": "",
            "u_exclude_from_round_robin": "false",
            "u_extensionattribute10": "",
            "u_extensionattribute11": "",
            "u_extensionattribute12": "",
            "u_extensionattribute13": "",
            "u_fired_events": "",
            "u_flag": "",
            "u_job_family": "",
            "u_job_function": "",
            "u_laptop_selection": "",
            "u_last_rep": "",
            "u_local": "false",
            "u_objectguid": "",
            "u_okta_startdate": "",
            "u_panwdirector": "",
            "u_panwea": "",
            "u_panwvp": "",
            "u_people_manager": "false",
            "u_profile_image": "",
            "u_region": "",
            "u_start_date": "",
            "u_workday_location": "",
            "user_name": "Xoar.test000000@paloaltonetworks.com",
            "user_password": "",
            "vip": "false",
            "x_nuvo_eam_out_of_office": "false",
            "x_nuvo_eam_primary_location": "",
            "x_nuvo_eam_primary_space": "",
            "x_nuvo_eam_user": {
                "link": "https://panstage.service-now.com/api/now//table/x_nuvo_eam_user/25e744de1b6e5010e9e2a9722a4bcbe2",
                "value": "25e744de1b6e5010e9e2a9722a4bcbe2"
            },
            "x_pd_integration_pagerduty_id": "",
            "zip": ""
        },
        "email": "testdemistouser99@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "ade744de1b6e5010e9e2a9722a4bcbe0",
        "instanceName": "ServiceNowITAdmin",
        "success": true,
        "username": "Xoar.test000000@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Enable ServiceNow User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| ServiceNow IT Admin | ServiceNowITAdmin | true | true | ade744de1b6e5010e9e2a9722a4bcbe0 | Xoar.test000000@paloaltonetworks.com | testdemistouser99@paloaltonetworks.com | u_last_rep: <br/>calendar_integration: 1<br/>last_position_update: <br/>user_password: <br/>sys_updated_on: 2020-08-13 16:29:18<br/>building: <br/>sso_source: <br/>state: <br/>vip: false<br/>sys_created_by: okta.servicenow<br/>zip: <br/>u_country: <br/>u_job_function: <br/>time_format: <br/>last_login: <br/>active: true<br/>u_laptop_selection: <br/>u_okta_startdate: <br/>transaction_log: <br/>u_extensionattribute13: <br/>u_extensionattribute12: <br/>cost_center: <br/>phone: <br/>u_start_date: <br/>employee_number: <br/>u_cost_center: <br/>u_extensionattribute11: <br/>u_people_manager: false<br/>u_extensionattribute10: <br/>gender: <br/>city: <br/>user_name: Xoar.test000000@paloaltonetworks.com<br/>latitude: <br/>sys_class_name: sys_user<br/>x_nuvo_eam_primary_space: <br/>u_employee_type: <br/>u_local: false<br/>email: testdemistouser99@paloaltonetworks.com<br/>u_region: <br/>manager: <br/>business_criticality: 3<br/>locked_out: false<br/>last_name: test<br/>photo: <br/>avatar: <br/>u_job_family: <br/>on_schedule: <br/>u_device_token_ios: <br/>correlation_id: <br/>date_format: <br/>country: <br/>last_login_time: <br/>x_pd_integration_pagerduty_id: <br/>source: <br/>notification: 2<br/>enable_multifactor_authn: false<br/>sys_updated_by: okta.servicenow<br/>u_device_token_android: <br/>sys_created_on: 2020-08-12 14:07:25<br/>u_profile_image: <br/>agent_status: <br/>sys_domain: {"link": "https://panstage.service-now.com/api/now//table/sys_user_group/global", "value": "global"}<br/>u_exclude_from_round_robin: false<br/>longitude: <br/>home_phone: <br/>u_panwea: <br/>default_perspective: <br/>geolocation_tracked: false<br/>u_fired_events: <br/>average_daily_fte: <br/>time_sheet_policy: <br/>u_bomgar_name: <br/>u_badge: false<br/>u_workday_location: <br/>name: demistouser test<br/>x_nuvo_eam_primary_location: <br/>u_panwvp: <br/>password_needs_reset: false<br/>x_nuvo_eam_user: {"link": "https://panstage.service-now.com/api/now//table/x_nuvo_eam_user/25e744de1b6e5010e9e2a9722a4bcbe2", "value": "25e744de1b6e5010e9e2a9722a4bcbe2"}<br/>hr_integration_source: <br/>failed_attempts: <br/>roles: <br/>title: <br/>sys_id: ade744de1b6e5010e9e2a9722a4bcbe0<br/>internal_integration_user: false<br/>ldap_server: <br/>u_end_date: <br/>mobile_phone: <br/>street: <br/>company: <br/>department: <br/>first_name: demistouser<br/>introduction: <br/>preferred_language: <br/>x_nuvo_eam_out_of_office: false<br/>u_flag: <br/>sys_mod_count: 13<br/>middle_name: <br/>sys_tags: <br/>time_zone: <br/>schedule: <br/>u_panwdirector: <br/>location: <br/>u_objectguid:  |


### disable-user
***
Disable a user


#### Base Command

`disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DisableUser | Unknown | Command context path | 
| DisableUser.active | boolean | Gives the active status of user. Can be true of false. | 
| DisableUser.brand | string | Name of the Integration | 
| DisableUser.details | string | Gives the raw response from API in case of error | 
| DisableUser.email | string | Value of email ID passed as argument | 
| DisableUser.errorCode | number | HTTP error response code | 
| DisableUser.errorMessage | string | Reason why the API is failed | 
| DisableUser.id | string | Value of id passed as argument | 
| DisableUser.instanceName | string | Name the instance used for testing | 
| DisableUser.success | boolean | Status of the result. Can be true or false. | 
| DisableUser.username | string | Value of username passed as argument | 


#### Command Example
```!disable-user scim={"id":"ade744de1b6e5010e9e2a9722a4bcbe0"} using=ServiceNowITAdmin```

#### Context Example
```
{
    "DisableUser": {
        "active": false,
        "brand": "ServiceNow IT Admin",
        "details": {
            "active": "false",
            "agent_status": "",
            "avatar": "",
            "average_daily_fte": "",
            "building": "",
            "business_criticality": "3",
            "calendar_integration": "1",
            "city": "",
            "company": "",
            "correlation_id": "",
            "cost_center": "",
            "country": "",
            "date_format": "",
            "default_perspective": "",
            "department": "",
            "email": "testdemistouser99@paloaltonetworks.com",
            "employee_number": "",
            "enable_multifactor_authn": "false",
            "failed_attempts": "",
            "first_name": "demistouser",
            "gender": "",
            "geolocation_tracked": "false",
            "home_phone": "",
            "hr_integration_source": "",
            "internal_integration_user": "false",
            "introduction": "",
            "last_login": "",
            "last_login_time": "",
            "last_name": "test",
            "last_position_update": "",
            "latitude": "",
            "ldap_server": "",
            "location": "",
            "locked_out": "true",
            "longitude": "",
            "manager": "",
            "middle_name": "",
            "mobile_phone": "",
            "name": "demistouser test",
            "notification": "2",
            "on_schedule": "",
            "password_needs_reset": "false",
            "phone": "",
            "photo": "",
            "preferred_language": "",
            "roles": "",
            "schedule": "",
            "source": "",
            "sso_source": "",
            "state": "",
            "street": "",
            "sys_class_name": "sys_user",
            "sys_created_by": "okta.servicenow",
            "sys_created_on": "2020-08-12 14:07:25",
            "sys_domain": {
                "link": "https://panstage.service-now.com/api/now//table/sys_user_group/global",
                "value": "global"
            },
            "sys_id": "ade744de1b6e5010e9e2a9722a4bcbe0",
            "sys_mod_count": "14",
            "sys_tags": "",
            "sys_updated_by": "okta.servicenow",
            "sys_updated_on": "2020-08-13 16:29:21",
            "time_format": "",
            "time_sheet_policy": "",
            "time_zone": "",
            "title": "",
            "transaction_log": "",
            "u_badge": "false",
            "u_bomgar_name": "",
            "u_cost_center": "",
            "u_country": "",
            "u_device_token_android": "",
            "u_device_token_ios": "",
            "u_employee_type": "",
            "u_end_date": "",
            "u_exclude_from_round_robin": "false",
            "u_extensionattribute10": "",
            "u_extensionattribute11": "",
            "u_extensionattribute12": "",
            "u_extensionattribute13": "",
            "u_fired_events": "",
            "u_flag": "",
            "u_job_family": "",
            "u_job_function": "",
            "u_laptop_selection": "",
            "u_last_rep": "",
            "u_local": "false",
            "u_objectguid": "",
            "u_okta_startdate": "",
            "u_panwdirector": "",
            "u_panwea": "",
            "u_panwvp": "",
            "u_people_manager": "false",
            "u_profile_image": "",
            "u_region": "",
            "u_start_date": "",
            "u_workday_location": "",
            "user_name": "Xoar.test000000@paloaltonetworks.com",
            "user_password": "",
            "vip": "false",
            "x_nuvo_eam_out_of_office": "false",
            "x_nuvo_eam_primary_location": "",
            "x_nuvo_eam_primary_space": "",
            "x_nuvo_eam_user": {
                "link": "https://panstage.service-now.com/api/now//table/x_nuvo_eam_user/25e744de1b6e5010e9e2a9722a4bcbe2",
                "value": "25e744de1b6e5010e9e2a9722a4bcbe2"
            },
            "x_pd_integration_pagerduty_id": "",
            "zip": ""
        },
        "email": "testdemistouser99@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "ade744de1b6e5010e9e2a9722a4bcbe0",
        "instanceName": "ServiceNowITAdmin",
        "success": true,
        "username": "Xoar.test000000@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Disable ServiceNow User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| ServiceNow IT Admin | ServiceNowITAdmin | true | false | ade744de1b6e5010e9e2a9722a4bcbe0 | Xoar.test000000@paloaltonetworks.com | testdemistouser99@paloaltonetworks.com | u_last_rep: <br/>calendar_integration: 1<br/>last_position_update: <br/>user_password: <br/>sys_updated_on: 2020-08-13 16:29:21<br/>building: <br/>sso_source: <br/>state: <br/>vip: false<br/>sys_created_by: okta.servicenow<br/>zip: <br/>u_country: <br/>u_job_function: <br/>time_format: <br/>last_login: <br/>active: false<br/>u_laptop_selection: <br/>u_okta_startdate: <br/>transaction_log: <br/>u_extensionattribute13: <br/>u_extensionattribute12: <br/>cost_center: <br/>phone: <br/>u_start_date: <br/>employee_number: <br/>u_cost_center: <br/>u_extensionattribute11: <br/>u_people_manager: false<br/>u_extensionattribute10: <br/>gender: <br/>city: <br/>user_name: Xoar.test000000@paloaltonetworks.com<br/>latitude: <br/>sys_class_name: sys_user<br/>x_nuvo_eam_primary_space: <br/>u_employee_type: <br/>u_local: false<br/>email: testdemistouser99@paloaltonetworks.com<br/>u_region: <br/>manager: <br/>business_criticality: 3<br/>locked_out: true<br/>last_name: test<br/>photo: <br/>avatar: <br/>u_job_family: <br/>on_schedule: <br/>u_device_token_ios: <br/>correlation_id: <br/>date_format: <br/>country: <br/>last_login_time: <br/>x_pd_integration_pagerduty_id: <br/>source: <br/>notification: 2<br/>enable_multifactor_authn: false<br/>sys_updated_by: okta.servicenow<br/>u_device_token_android: <br/>sys_created_on: 2020-08-12 14:07:25<br/>u_profile_image: <br/>agent_status: <br/>sys_domain: {"link": "https://panstage.service-now.com/api/now//table/sys_user_group/global", "value": "global"}<br/>u_exclude_from_round_robin: false<br/>longitude: <br/>home_phone: <br/>u_panwea: <br/>default_perspective: <br/>geolocation_tracked: false<br/>u_fired_events: <br/>average_daily_fte: <br/>time_sheet_policy: <br/>u_bomgar_name: <br/>u_badge: false<br/>u_workday_location: <br/>name: demistouser test<br/>x_nuvo_eam_primary_location: <br/>u_panwvp: <br/>password_needs_reset: false<br/>x_nuvo_eam_user: {"link": "https://panstage.service-now.com/api/now//table/x_nuvo_eam_user/25e744de1b6e5010e9e2a9722a4bcbe2", "value": "25e744de1b6e5010e9e2a9722a4bcbe2"}<br/>hr_integration_source: <br/>failed_attempts: <br/>roles: <br/>title: <br/>sys_id: ade744de1b6e5010e9e2a9722a4bcbe0<br/>internal_integration_user: false<br/>ldap_server: <br/>u_end_date: <br/>mobile_phone: <br/>street: <br/>company: <br/>department: <br/>first_name: demistouser<br/>introduction: <br/>preferred_language: <br/>x_nuvo_eam_out_of_office: false<br/>u_flag: <br/>sys_mod_count: 14<br/>middle_name: <br/>sys_tags: <br/>time_zone: <br/>schedule: <br/>u_panwdirector: <br/>location: <br/>u_objectguid:  |

