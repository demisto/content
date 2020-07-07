Exceed LMS Integration consists of a set of API endpoints that allow customers to perform CRUD operation on their user profiles. 
This integration was integrated and tested with version xx of Exceed LMS IT Admin
## Configure Exceed LMS IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Exceed LMS IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Exceed LMS url https://&lt;domain&gt;.exceedlms\-staging.com/ | True |
| api_key | api\_key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| customMappingCreateUser | Custom Mapping for Create User | False |
| customMappingUpdateUser | Custom Mapping for UpdateUser | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-user
***
Get a user detail


#### Base Command

`get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetUser | unknown | Command context path | 
| GetUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| GetUser.brand | string | Name of the Integration | 
| GetUser.details | string | Gives the user Profile information if the API is success else error message | 
| GetUser.email | string | Value of email ID passed as argument | 
| GetUser.errorCode | number |  HTTP error response code  | 
| GetUser.errorMessage | string | Reason why the API is failed | 
| GetUser.id | string | Value of id passed as argument | 
| GetUser.instanceName | string | Name of the instance used for testing | 
| GetUser.success | boolean | Status of the result. Can be true or false. | 
| GetUser.userName | string | Value of username passed as argument | 


#### Command Example
```!get-user scim={"id":"4917005"} using=ExceedLMSITAdmin```

#### Context Example
```
{
    "GetUser": {
        "active": true,
        "brand": "Exceed LMS IT Admin",
        "details": {
            "account_id": 1193,
            "address_one": null,
            "address_two": null,
            "authority": "student",
            "city": null,
            "code": "i-4917005",
            "country": null,
            "created_on": "2020-07-07T11:24:43+00:00",
            "custom_a": null,
            "custom_b": null,
            "custom_c": null,
            "custom_d": null,
            "custom_e": null,
            "custom_f": null,
            "custom_g": null,
            "custom_h": null,
            "custom_i": null,
            "custom_j": null,
            "custom_k": null,
            "custom_l": null,
            "custom_m": null,
            "custom_n": null,
            "custom_o": null,
            "custom_p": null,
            "custom_q": null,
            "custom_r": null,
            "custom_s": null,
            "custom_t": null,
            "custom_u": null,
            "email": "testdemistouser@paloaltonetworks.com",
            "external_avatar_url": null,
            "facebook_as_id": null,
            "facebook_id": null,
            "first_name": "testMydesmisto7",
            "full_name": "testmydesmisto7 test",
            "google_auth": null,
            "hide_welcome_page": false,
            "hired_on": null,
            "id": 4917005,
            "integration_id": null,
            "is_account_owner": false,
            "is_active": true,
            "is_pass_reset_required": false,
            "last_login_at": null,
            "last_name": "test",
            "locale": "en",
            "login": "testxoar7july@paloaltonetworks.com",
            "manager_id": null,
            "organization_id": 2702,
            "phone_fax": null,
            "phone_home": null,
            "phone_mobile": null,
            "phone_work": null,
            "picture_id": null,
            "position_id": null,
            "position_name": null,
            "provider": null,
            "registered_at": null,
            "registration_code": null,
            "registration_id": null,
            "rehired_on": null,
            "state": null,
            "tzid": null,
            "uid": null,
            "updated_by": null,
            "updated_on": "2020-07-07T11:24:43+00:00",
            "verified_at": null,
            "zip": null
        },
        "email": "testdemistouser@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": 4917005,
        "instanceName": "ExceedLMSITAdmin",
        "success": true,
        "username": "testxoar7july@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Get EXCEED LMS User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Exceed LMS IT Admin | account_id: 1193<br/>address_one: null<br/>address_two: null<br/>authority: student<br/>city: null<br/>code: i-4917005<br/>country: null<br/>created_on: 2020-07-07T11:24:43+00:00<br/>custom_a: null<br/>custom_b: null<br/>custom_c: null<br/>custom_d: null<br/>custom_e: null<br/>custom_f: null<br/>custom_g: null<br/>custom_h: null<br/>custom_i: null<br/>custom_j: null<br/>custom_k: null<br/>custom_l: null<br/>custom_m: null<br/>custom_n: null<br/>custom_o: null<br/>custom_p: null<br/>custom_q: null<br/>custom_r: null<br/>custom_s: null<br/>custom_t: null<br/>custom_u: null<br/>email: testdemistouser@paloaltonetworks.com<br/>external_avatar_url: null<br/>facebook_id: null<br/>first_name: testMydesmisto7<br/>full_name: testmydesmisto7 test<br/>google_auth: null<br/>hide_welcome_page: false<br/>hired_on: null<br/>rehired_on: null<br/>id: 4917005<br/>integration_id: null<br/>is_account_owner: false<br/>is_active: true<br/>is_pass_reset_required: false<br/>last_login_at: null<br/>last_name: test<br/>locale: en<br/>login: testxoar7july@paloaltonetworks.com<br/>manager_id: null<br/>organization_id: 2702<br/>phone_fax: null<br/>phone_home: null<br/>phone_mobile: null<br/>phone_work: null<br/>picture_id: null<br/>position_id: null<br/>position_name: null<br/>provider: null<br/>registration_code: null<br/>registration_id: null<br/>state: null<br/>tzid: null<br/>uid: null<br/>updated_by: null<br/>updated_on: 2020-07-07T11:24:43+00:00<br/>zip: null<br/>registered_at: null<br/>verified_at: null<br/>facebook_as_id: null | testdemistouser@paloaltonetworks.com |  |  | 4917005 | ExceedLMSITAdmin | true | testxoar7july@paloaltonetworks.com |


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
| CreateUser.brand | string | Name of the Integration | 
| CreateUser.instanceName | string | Name of the instance used for testing | 
| CreateUser.success | boolean | Status of the result. Can be true or false. | 
| CreateUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| CreateUser.id | string | Value of id passed as argument | 
| CreateUser.username | string | Value of username passed as argument | 
| CreateUser.email | string | Value of email ID passed as argument | 
| CreateUser.errorCode | number | HTTP error response code  | 
| CreateUser.errorMessage | string | Reason why the API is failed | 
| CreateUser.details | string | Gives the raw response from API | 


#### Command Example
```!create-user scim={"name":{"familyName":"test","givenName":"demisto"},"emails":[{"type":"work","primary":true,"value":"testdemistouser9@paloaltonetworks.com"}],"userName":"testXoar9July@paloaltonetworks.com","urn:scim:schemas:extension:custom:1.0:user":{"firstname":"testMydesmisto9"}} using=ExceedLMSITAdmin```

#### Context Example
```
{
    "CreateUser": {
        "active": true,
        "brand": "Exceed LMS IT Admin",
        "details": {
            "accepted_catcat_terms_of_service": null,
            "account_id": 1193,
            "address_one": null,
            "address_three": null,
            "address_two": null,
            "authority": "student",
            "city": null,
            "code": "i-4917123",
            "company_name": null,
            "country": null,
            "created_on": "2020-07-07T13:06:32+00:00",
            "custom_a": null,
            "custom_b": null,
            "custom_c": null,
            "custom_d": null,
            "custom_e": null,
            "custom_f": null,
            "custom_g": null,
            "custom_h": null,
            "custom_i": null,
            "custom_j": null,
            "custom_k": null,
            "custom_l": null,
            "custom_m": null,
            "custom_n": null,
            "custom_o": null,
            "custom_p": null,
            "custom_q": null,
            "custom_r": null,
            "custom_s": null,
            "custom_t": null,
            "custom_u": null,
            "deletion_requested_at": null,
            "description": null,
            "dismissed_in_app_callouts": [],
            "email": "testdemistouser9@paloaltonetworks.com",
            "external_avatar_url": null,
            "facebook_as_id": null,
            "facebook_id": null,
            "first_name": "testMydesmisto9",
            "full_name": "testmydesmisto9 test",
            "google_auth": null,
            "hero_picture_id": null,
            "hide_welcome_page": false,
            "hired_on": null,
            "id": 4917123,
            "integration_id": null,
            "is_account_owner": false,
            "is_active": true,
            "is_onboarded": false,
            "is_pass_reset_required": false,
            "is_topic_onboarded": null,
            "job_title": null,
            "last_login_at": null,
            "last_name": "test",
            "latitude": null,
            "linkedin_url": null,
            "locale": "en",
            "login": "testxoar9july@paloaltonetworks.com",
            "login_disabled_at": null,
            "longitude": null,
            "manager_id": null,
            "onet_occupation_id": null,
            "organization_id": 2702,
            "password_hash": null,
            "password_salt": null,
            "phone_fax": null,
            "phone_home": null,
            "phone_mobile": null,
            "phone_work": null,
            "picture_id": null,
            "position_id": null,
            "profile_url": "testmydesmisto9testb6dcb9ef",
            "provider": null,
            "public_profile": false,
            "recovery_email": null,
            "recovery_token": null,
            "registered_at": null,
            "registration_code": null,
            "registration_id": null,
            "rehired_on": null,
            "remember_me_token": "dRhvKG8MNgHRvzYk46un2fo8",
            "state": null,
            "twitter_handle": null,
            "tzid": null,
            "uid": null,
            "unread_notifications_count": 0,
            "unsubscribe_mentor_digest_email": null,
            "unsubscribed_from_letters": null,
            "updated_by": "API",
            "updated_on": "2020-07-07T13:06:32+00:00",
            "verified_at": null,
            "website_url": null,
            "zip": null
        },
        "email": "testdemistouser9@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": 4917123,
        "instanceName": "ExceedLMSITAdmin",
        "success": true,
        "username": "testXoar9July@paloaltonetworks.com"
    }
}
```

#### Human Readable Output

>### Create Exceed LMS User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Exceed LMS IT Admin | id: 4917123<br/>account_id: 1193<br/>position_id: null<br/>picture_id: null<br/>is_active: true<br/>authority: student<br/>full_name: testmydesmisto9 test<br/>first_name: testMydesmisto9<br/>last_name: test<br/>login: testxoar9july@paloaltonetworks.com<br/>code: i-4917123<br/>tzid: null<br/>hired_on: null<br/>manager_id: null<br/>custom_a: null<br/>custom_b: null<br/>custom_c: null<br/>custom_d: null<br/>custom_e: null<br/>custom_f: null<br/>custom_g: null<br/>custom_h: null<br/>custom_i: null<br/>custom_j: null<br/>email: testdemistouser9@paloaltonetworks.com<br/>phone_work: null<br/>phone_mobile: null<br/>phone_fax: null<br/>phone_home: null<br/>address_one: null<br/>address_two: null<br/>city: null<br/>state: null<br/>zip: null<br/>updated_by: API<br/>updated_on: 2020-07-07T13:06:32+00:00<br/>is_pass_reset_required: false<br/>registration_id: null<br/>hide_welcome_page: false<br/>country: null<br/>is_account_owner: false<br/>integration_id: null<br/>last_login_at: null<br/>locale: en<br/>remember_me_token: dRhvKG8MNgHRvzYk46un2fo8<br/>registration_code: null<br/>password_hash: null<br/>password_salt: null<br/>organization_id: 2702<br/>google_auth: null<br/>created_on: 2020-07-07T13:06:32+00:00<br/>custom_k: null<br/>custom_l: null<br/>custom_m: null<br/>custom_n: null<br/>custom_o: null<br/>custom_p: null<br/>custom_q: null<br/>custom_r: null<br/>custom_s: null<br/>custom_t: null<br/>custom_u: null<br/>facebook_id: null<br/>provider: null<br/>uid: null<br/>external_avatar_url: null<br/>unread_notifications_count: 0<br/>recovery_email: null<br/>recovery_token: null<br/>is_onboarded: false<br/>hero_picture_id: null<br/>latitude: null<br/>longitude: null<br/>registered_at: null<br/>public_profile: false<br/>company_name: null<br/>description: null<br/>profile_url: testmydesmisto9testb6dcb9ef<br/>deletion_requested_at: null<br/>accepted_catcat_terms_of_service: null<br/>is_topic_onboarded: null<br/>onet_occupation_id: null<br/>unsubscribed_from_letters: null<br/>rehired_on: null<br/>unsubscribe_mentor_digest_email: null<br/>login_disabled_at: null<br/>twitter_handle: null<br/>website_url: null<br/>linkedin_url: null<br/>verified_at: null<br/>facebook_as_id: null<br/>dismissed_in_app_callouts: <br/>address_three: null<br/>job_title: null | testdemistouser9@paloaltonetworks.com |  |  | 4917123 | ExceedLMSITAdmin | true | testXoar9July@paloaltonetworks.com |


### update-user
***
Update a user


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
| UpdateUser | unknown | Command context path | 
| UpdateUser.brand | string | Name of the Integration | 
| UpdateUser.instanceName | string | Name of the instance used for testing | 
| UpdateUser.success | boolean | Status of the result. Can be true or false. | 
| UpdateUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| UpdateUser.id | string | Value of id passed as argument | 
| UpdateUser.username | string | Value of username passed as argument | 
| UpdateUser.email | string | Value of email ID passed as argument | 
| UpdateUser.errorCode | number | HTTP error response code | 
| UpdateUser.errorMessage | string |  Reason why the API is failed | 
| UpdateUser.details | string | Gives the raw response from API | 


#### Command Example
```!update-user oldScim={"id":"4917005"} newScim={"name":{"familyName":"test","givenName":"demistouser"},"emails":[{"type":"work","primary":true,"value":"testdemistouser@paloaltonetworks.com"}],"urn:scim:schemas:extension:custom:1.0:user":{"userName":"testxsoar1239@paloaltonetworks.com"}} using=ExceedLMSITAdmin```

#### Context Example
```
{
    "UpdateUser": {
        "active": true,
        "brand": "Exceed LMS IT Admin",
        "details": "200 OK",
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "4917005",
        "instanceName": "ExceedLMSITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Updated ExceedLMS User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Exceed LMS IT Admin | 200 OK |  |  |  | 4917005 | ExceedLMSITAdmin | true |  |


### enable-user
***
Enable a disabled user


#### Base Command

`enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EnableUser | unknown | Command context path | 
| EnableUser.brand | string | Name of the Integration | 
| EnableUser.instanceName | string | Name the instance used for testing | 
| EnableUser.success | boolean | Status of the result. Can be true or false. | 
| EnableUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| EnableUser.id | string | Value of id passed as argument | 
| EnableUser.username | string | Value of username passed as argument | 
| EnableUser.email | string | Value of email ID passed as argument | 
| EnableUser.errorCode | number | HTTP error response code | 
| EnableUser.errorMessage | string | Reason why the API is failed | 
| EnableUser.details | string | Gives the raw response from API in case of error | 


#### Command Example
```!enable-user scim={"id":"4917005"} using=ExceedLMSITAdmin```

#### Context Example
```
{
    "EnableUser": {
        "active": true,
        "brand": "Exceed LMS IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "4917005",
        "instanceName": "ExceedLMSITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Enable ExceedLMS User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| true | Exceed LMS IT Admin |  |  |  |  | 4917005 | ExceedLMSITAdmin | true |  |


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
| DisableUser | unknown | Command context path | 
| DisableUser.instanceName | string | Name the instance used for testing | 
| DisableUser.success | boolean | Status of the result. Can be true or false. | 
| DisableUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| DisableUser.id | string | Value of id passed as argument | 
| DisableUser.username | string | Value of username passed as argument | 
| DisableUser.email | string | Value of email ID passed as argument | 
| DisableUser.errorCode | number | HTTP error response code  | 
| DisableUser.errorMessage | string | Reason why the API is failed | 
| DisableUser.details | string | Gives the raw response from API in case of error | 
| DisableUser.brand | string | Name of the Integration | 


#### Command Example
```!disable-user scim={"id":"4917005"} using=ExceedLMSITAdmin```

#### Context Example
```
{
    "DisableUser": {
        "active": false,
        "brand": "Exceed LMS IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "4917005",
        "instanceName": "ExceedLMSITAdmin",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Disable ExceedLMS User:
>|active|brand|details|email|errorCode|errorMessage|id|instanceName|success|username|
>|---|---|---|---|---|---|---|---|---|---|
>| false | Exceed LMS IT Admin |  |  |  |  | 4917005 | ExceedLMSITAdmin | true |  |

