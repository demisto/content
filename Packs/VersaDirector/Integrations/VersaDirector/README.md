Versa Director is a virtualization and service creation platform that simplifies the design, automation, and delivery of SASE services. Versa Director provides the essential management, monitoring and orchestration capabilities needed to deliver all of the networking and security capabilities within Versa SASE.
This integration was integrated and tested with version 1.0.0 of VersaDirector

## Configure Versa Director on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Versa Director.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | Organization Name | Used by any command that requires organization argument. should be passed as parameter in configuration or as command argument. | False |
    | Username |  | False |
    | Password |  | False |
    | Use Auth Token | Check if Auth Token authentication method is used. | False |
    | Client ID | The Client ID parameter is used for Auth authentication. | False |
    | Client Secret | The Client Secret parameter is used for Auth authentication. | False |
    | Auth Token | The Auth Token parameter is used for Auth authentication.<br/>An Auth Token saved in the integration context take priority over an Auth Token passed as a parameter by default.<br/>If a Refresh Token is given, a new Auth Token is generated when an existing Auth Token expires, and it is then saved in the integration context. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### vd-auth-start
***
Obtain Access token from api client. If Client ID and Client Secret were not passed as parameters or arguments, a new Auth Client will be created.


#### Base Command

`vd-auth-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token_name | Name of access token. If an excising token name will be given as argument, an error might occur. | Optional | 
| description | Description of access token. | Optional | 
| client_id | Client ID for Token Authentication. If already passed as a parameter it will be prioritized by default. | Optional | 
| client_secret | Client Secret for Token Authentication. If already passed as a parameter it will be prioritized by default. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.AuthClient | String | Auth Client Credentials. | 

#### Command example
```!vd-auth-start token_name=example_token description="example token"```
#### Context Example
```json
{
    "VersaDirector": {
        "AuthClient": {
            "client_id": "example_client_id",
            "client_name": "example_token"
        }
    }
}
```

#### Human Readable Output

>Auth Client Created Successfully.
>Client ID: example_client_id, Auth Client Name: example_token.
>
>Authentication request was successful, Auth Token was created and saved in the Integration Context.
>Please check the 'Use Auth Token' in the configuration screen.
>To ensure the authentication is valid, run the 'vd-auth-test' command.

### vd-auth-test
***
Run a connectivity test to verify that the oauth process worked.


#### Base Command

`vd-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
#### Command example
```!vd-auth-test```
#### Human Readable Output

>Auth Token Authentication method connectivity verified.

### vd-predefined-application-list
***
List all user predefined application objects.


#### Base Command

`vd-predefined-application-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| family | Group type of application. Possible values are: business-system, collaboration, general-internet, media, networking. | Optional | 
| risks | Risks threshold - equals and higher than the input. | Optional | 
| tags | List of tags. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page., therefore default value is 0. | Optional | 
| limit | Limit number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.PredefinedApplication.name | string | The Predefined Application's name. | 
| VersaDirector.PredefinedApplication.family | string | Predefined application family type. | 
| VersaDirector.PredefinedApplication.subfamily | string | Predefined Sub-Group family application type. | 
| VersaDirector.PredefinedApplication.description | string | Predefined Application description. | 
| VersaDirector.PredefinedApplication.risk | string | Predefined application risks threshold, equals or higher than the input. | 
| VersaDirector.PredefinedApplication.productivity | string | Predefined application productivity. | 
| VersaDirector.PredefinedApplication.tag | string | Predefined application tag. | 

#### Command example
```!vd-predefined-application-list limit=1```
#### Context Example
```json
{
    "File": {
        "Comment": "Return result too large, uploaded as a file",
        "EntryID": "EXAMPLE_HASH",
        "Info": "text/plain",
        "MD5": "EXAMPLE_HASH",
        "Name": "Result file",
        "SHA1": "b1becec47a497da5b4b61970fe6ae83660adb703",
        "SHA256": "EXAMPLE_HASH",
        "SHA512": "EXAMPLE_HASH",
        "SSDeep": "EXAMPLE_HASH",
        "Size": 733757,
        "Type": "ASCII text, with very long lines (499)"
    },
    "VersaDirector": {
        "PredefinedApplication": [
            {
                "bandwidth": "1000",
                "bundle-version": "1.70",
                "deprecated": "0",
                "description": "01net website, a French high-tech news site.",
                "family": "general-internet",
                "flexvnf": "N/A",
                "ips": "0",
                "jitter": "80",
                "latency": "700",
                "name": "01NET",
                "path_mtu": "1400",
                "pkt_loss": "5",
                "productivity": "2",
                "risk": "2",
                "spack-version": "1210",
                "subfamily": "web",
                "tag": [
                    "web",
                    "v_non_business"
                ],
                "tcp_timeout": "300",
                "throughput": "800",
                "v-proto-id": "1549"
            },
        ]
    }
}
```

#### Human Readable Output

>Return result too large, uploaded as a file

### vd-appliance-user-modified-application-list
***
List all user modified predefined application objects associated with a specific organization and appliance (device).


#### Base Command

`vd-appliance-user-modified-application-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | Limit number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceUserModifiedApplication.app-specific-option-list.app-name | string | Appliance user modified application name. | 
| VersaDirector.ApplianceUserModifiedApplication.app-specific-option-list.app-risk | string | Appliance user modified application risk threshold. | 
| VersaDirector.ApplianceUserModifiedApplication.app-specific-option-list.app-productivity | string | Appliance user modified application productivity. | 
| VersaDirector.ApplianceUserModifiedApplication.app-specific-option-list.app-timeout | string | Appliance user modified application timeout. | 
| VersaDirector.ApplianceUserModifiedApplication.app-specific-option-list.app-final-with-endpoint | string | Appliance user modified application final endpoint. | 

#### Command example
```!vd-appliance-user-modified-application-list appliance_name=EXAMPLE_BRANCH limit=3```
#### Human Readable Output

>Empty response has returned from vd-appliance-user-modified-application-list command.
>Message:
>Error in API call [204] - 


### vd-template-user-modified-application-list
***
List all user modified predefined application objects associated with a specific organization and template.


#### Base Command

`vd-template-user-modified-application-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | Limit number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateUserModifiedApplication.app-specific-option-list.app-name | string | Template user modified application name. | 
| VersaDirector.TemplateUserModifiedApplication.app-specific-option-list.app-risk | string | Template user modified application risk threshold. | 
| VersaDirector.TemplateUserModifiedApplication.app-specific-option-list.app-productivity | string | Template user modified application productivity. | 
| VersaDirector.TemplateUserModifiedApplication.app-specific-option-list.app-timeout | string | Template user modified application timeout. | 
| VersaDirector.TemplateUserModifiedApplication.app-specific-option-list.app-final-with-endpoint | string | Template user modified application final endpoint. | 

#### Command example
```!vd-template-user-mod-Default-Application limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "TemplateUserModifiedApplication": {
            "app-final-with-endpoint": "false",
            "app-name": "TESTWISE",
            "app-productivity": "3",
            "app-risk": "3",
            "app-timeout": "300"
        }
    }
}
```

#### Human Readable Output

>### User modified predefined application objects associated with EXAMPLE_CLIENT
>|App - Name|App - Risk|App - Productivity|App - Timeout|App - Final - With - Endpoint|
>|---|---|---|---|---|
>| TESTWISE | 3 | 3 | 300 | false |


### vd-appliance-user-defined-application-list
***
List all user defined application objects associated with a specific organization and appliance (device).


#### Base Command

`vd-appliance-user-defined-application-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | Limit number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceUserDefinedApplication.user-defined-application.app-name | string | Appliance user defined application name. | 
| VersaDirector.ApplianceUserDefinedApplication.user-defined-application.description | string | Appliance user defined application description. | 
| VersaDirector.ApplianceUserDefinedApplication.user-defined-application.precedence | string | Appliance user defined application precedence. | 
| VersaDirector.ApplianceUserDefinedApplication.user-defined-application.tag | string | Appliance user defined application tag. | 
| VersaDirector.ApplianceUserDefinedApplication.user-defined-application.risk | string | Appliance user defined application risk threshold. | 
| VersaDirector.ApplianceUserDefinedApplication.user-defined-application.family | string | Appliance user defined application family. | 

#### Command example
```!vd-appliance-user-defined-application-list appliance_name=EXAMPLE_BRANCH limit=3```
#### Human Readable Output

>Empty response has returned from vd-appliance-user-defined-application-list command.
>Message:
>Error in API call [204] - 


### vd-template-user-defined-application-list
***
List all user defined application objects associated with a specific organization and template.


#### Base Command

`vd-template-user-defined-application-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | Limit number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateUserDefinedApplication.user-defined-application.app-name | string | Template user defined application name. | 
| VersaDirector.TemplateUserDefinedApplication.user-defined-application.description | string | Template user defined application description. | 
| VersaDirector.TemplateUserDefinedApplication.user-defined-application.precedence | string | Template user defined application precedence. | 
| VersaDirector.TemplateUserDefinedApplication.user-defined-application.tag | string | Template user defined application tag. | 
| VersaDirector.TemplateUserDefinedApplication.user-defined-application.risk | string | Template user defined application risk threshold. | 
| VersaDirector.TemplateUserDefinedApplication.user-defined-application.family | string | Template user defined application family. | 

#### Command example
```!vd-template-user-defined-application-list template_name=EXAMPLE_CLIENT-Default-Application limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "TemplateUserDefinedApplication": [
            {
                "app-match-ips": "false",
                "app-name": "TestApplication",
                "description": "This is a test from UI",
                "family": "collaboration",
                "precedence": "65",
                "productivity": "3",
                "risk": "3",
                "subfamily": "custom",
                "tag": [
                    "aaa",
                    "v_cloud",
                    "vs_evasive"
                ]
            },
            {
                "app-match-ips": "false",
                "app-match-rules": {
                    "rule-name": null
                },
                "app-name": "TestCustomApp",
                "app-timeout": "300",
                "description": "Test custom app creation from API",
                "family": null,
                "precedence": "95",
                "productivity": "5",
                "risk": "5",
                "subfamily": null,
                "tag": "aaa"
            }
        ]
    }
}
```

#### Human Readable Output

>### User defined application objects associated with EXAMPLE_CLIENT
>|App - Name|Description|Precedence|Tag|Risk|Family|
>|---|---|---|---|---|---|
>| TestApplication | This is a test from UI | 65 | ***values***: aaa, v_cloud, vs_evasive | 3 | collaboration |
>| TestCustomApp | Test custom app creation from API | 95 | aaa | 5 |  |


### vd-appliance-address-object-delete
***
Delete an address object associated with a specific organization and appliance (device).


#### Base Command

`vd-appliance-address-object-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| object_name | Address object name. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-appliance-address-object-delete object_name=Bad-Address appliance_name=EXAMPLE_BRANCH```
#### Human Readable Output

>Command run successfully.

### vd-appliance-address-object-edit
***
Edit an address object associated with a specific organization and appliance (device).


#### Base Command

`vd-appliance-address-object-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| object_name | Address object name. | Required | 
| description | Address object description. | Optional | 
| tags | List of tags. | Optional | 
| address_object_type | Address object type. Possible values are: ipv4-prefix, ipv4-range, ipv4-wildcard-mask, ipv6-prefix, fqdn, dynamic-address. | Required | 
| object_value | Object value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateAddressObject.name | string | Template Address object name. | 
| VersaDirector.TemplateAddressObject.tag | string | Template Address object tag. | 
| VersaDirector.TemplateAddressObject.description | string | Template address object description. | 
| VersaDirector.TemplateAddressObject.ipv4-prefix | string | Template address object ipv4-prefix. | 
| VersaDirector.TemplateAddressObject.ipv4-range | string | Template address object ipv4-range. | 
| VersaDirector.TemplateAddressObject.ipv4-wildcard-mask | string | Template address object ipv4-wildcard-mask. | 
| VersaDirector.TemplateAddressObject.ipv6-prefix | string | Template address object ipv6-prefix. | 
| VersaDirector.TemplateAddressObject.fqdn | string | Template address object fqdn. | 
| VersaDirector.TemplateAddressObject.dynamic-address | string | Template address object dynamic-address. | 

#### Command example
```!vd-appliance-address-object-edit appliance_name=EXAMPLE_BRANCH address_object_type=fqdn object_value=test1.com,test2.com object_name=Bad-Address description="changed"```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'address': {'name': 'Bad-Address', 'description': 'changed', 'tag': [], 'fqdn': 'test1.com,test2.com'}}

### vd-appliance-address-object-create
***
Create an address object associated with a specific organization and appliance (device).


#### Base Command

`vd-appliance-address-object-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| object_name | Address object name. | Required | 
| description | Address object description. | Required | 
| tags | List of tags. | Optional | 
| address_object_type | Address object type. Possible values are: ipv4-prefix, ipv4-range, ipv4-wildcard-mask, ipv6-prefix, fqdn, dynamic-address. | Required | 
| object_value | Object value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateAddressObject.name | string | Template Address object name. | 
| VersaDirector.TemplateAddressObject.tag | string | Template Address object tag. | 
| VersaDirector.TemplateAddressObject.description | string | Template address object description. | 
| VersaDirector.TemplateAddressObject.ipv4-prefix | string | Template address object ipv4-prefix. | 
| VersaDirector.TemplateAddressObject.ipv4-range | string | Template address object ipv4-range. | 
| VersaDirector.TemplateAddressObject.ipv4-wildcard-mask | string | Template address object ipv4-wildcard-mask. | 
| VersaDirector.TemplateAddressObject.ipv6-prefix | string | Template address object ipv6-prefix. | 
| VersaDirector.TemplateAddressObject.fqdn | string | Template address object fqdn. | 
| VersaDirector.TemplateAddressObject.dynamic-address | string | Template address object dynamic-address. | 

#### Command example
```!vd-appliance-address-object-create appliance_name=EXAMPLE_BRANCH address_object_type=fqdn object_value=test1.com,test2.com object_name=Bad-Address description="test"```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'address': {'name': 'Bad-Address', 'description': 'test', 'tag': [], 'fqdn': 'test1.com,test2.com'}}

### vd-appliance-address-object-list
***
List all address objects associated with a specific organization and appliance (device).


#### Base Command

`vd-appliance-address-object-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceAddressObject.name | string | Appliance address object name | 
| VersaDirector.ApplianceAddressObject.description | string | Appliance address object description | 
| VersaDirector.ApplianceAddressObject.tag | string | Appliance address object tag | 
| VersaDirector.ApplianceAddressObject.ipv4-prefix | string | Appliance address object ipv4-prefix | 
| VersaDirector.ApplianceAddressObject.fqdn | string | Appliance address object fqdn | 

#### Command example
```!vd-appliance-address-object-list appliance_name=EXAMPLE_BRANCH limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "ApplianceAddressObject": [
            {
                "ipv4-prefix": "EXAMPLE_URL/32",
                "name": "Bad-Address-1",
                "tag": "test"
            },
            {
                "fqdn": "test1.com",
                "name": "Bad-Address-2"
            },
            {
                "ipv4-prefix": "EXAMPLE_URL/32",
                "name": "Bad-Address-4"
            }
        ]
    }
}
```

#### Human Readable Output

>### Address objects associated with EXAMPLE_CLIENT
>|Name|Tag|Ipv 4- Prefix|Fqdn|
>|---|---|---|---|
>| Bad-Address-1 | test | EXAMPLE_URL/32 |  |
>| Bad-Address-2 |  |  | test1.com |
>| Bad-Address-4 |  | EXAMPLE_URL/32 |  |


### vd-template-address-object-delete
***
Delete an address object associated with a specific organization and template.


#### Base Command

`vd-template-address-object-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| object_name | Address object name. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-template-address-object-delete template_name=EXAMPLE_CLIENT-Default-Application object_name=Bad-Address```
#### Human Readable Output

>Command run successfully.

### vd-template-address-object-edit
***
Create an address object associated with a specific organization and template.


#### Base Command

`vd-template-address-object-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| object_name | Address object name. | Required | 
| description | Address object description. | Optional | 
| tags | List of tags. | Optional | 
| address_object_type | Address object type. Possible values are: ipv4-prefix, ipv4-range, ipv4-wildcard-mask, ipv6-prefix, fqdn, dynamic-address. | Required | 
| object_value | Object value. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateAddressObject.name | string | Template Address object name. | 
| VersaDirector.TemplateAddressObject.tag | string | Template Address object tag. | 
| VersaDirector.TemplateAddressObject.description | string | Template address object description. | 
| VersaDirector.TemplateAddressObject.ipv4-prefix | string | Template address object ipv4-prefix. | 
| VersaDirector.TemplateAddressObject.ipv4-range | string | Template address object ipv4-range. | 
| VersaDirector.TemplateAddressObject.ipv4-wildcard-mask | string | Template address object ipv4-wildcard-mask. | 
| VersaDirector.TemplateAddressObject.ipv6-prefix | string | Template address object ipv6-prefix. | 
| VersaDirector.TemplateAddressObject.fqdn | string | Template address object fqdn. | 
| VersaDirector.TemplateAddressObject.dynamic-address | string | Template address object dynamic-address. | 

#### Command example
```!vd-template-address-object-edit template_name=EXAMPLE_CLIENT-Default-Application address_object_type=fqdn object_value=test.com object_name=Bad-Address description="changed"```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'address': {'name': 'Bad-Address', 'description': 'changed', 'tag': [], 'fqdn': 'test.com'}}

### vd-template-address-object-create
***
Create an address object associated with a specific organization and template.


#### Base Command

`vd-template-address-object-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| object_name | Address object name. | Required | 
| description | Address object description. | Optional | 
| tags | List of tags. | Optional | 
| address_object_type | Address object type. Possible values are: ipv4-prefix, ipv4-range, ipv4-wildcard-mask, ipv6-prefix, fqdn, dynamic-address. | Required | 
| object_value | Object value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateAddressObject.name | string | Template Address object name. | 
| VersaDirector.TemplateAddressObject.tag | string | Template Address object tag. | 
| VersaDirector.TemplateAddressObject.description | string | Template address object description. | 
| VersaDirector.TemplateAddressObject.ipv4-prefix | string | Template address object ipv4-prefix. | 
| VersaDirector.TemplateAddressObject.ipv4-range | string | Template address object ipv4-range. | 
| VersaDirector.TemplateAddressObject.ipv4-wildcard-mask | string | Template address object ipv4-wildcard-mask. | 
| VersaDirector.TemplateAddressObject.ipv6-prefix | string | Template address object ipv6-prefix. | 
| VersaDirector.TemplateAddressObject.fqdn | string | Template address object fqdn. | 
| VersaDirector.TemplateAddressObject.dynamic-address | string | Template address object dynamic-address. | 

#### Command example
```!vd-template-address-object-create template_name=EXAMPLE_CLIENT-Default-Application address_object_type=fqdn object_value=test.com object_name=Bad-Address description="test"```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'address': {'name': 'Bad-Address', 'description': 'test', 'tag': [], 'fqdn': 'test.com'}}

### vd-template-address-object-list
***
List all address objects associated with a specific organization and template.


#### Base Command

`vd-template-address-object-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateAddressObject.name | string | Template Address object name. | 
| VersaDirector.TemplateAddressObject.description | string | Template address object description. | 
| VersaDirector.TemplateAddressObject.tag | string | Template Address object tag. | 
| VersaDirector.TemplateAddressObject.ipv4-prefix | string | Template address object ipv4-prefix. | 
| VersaDirector.TemplateAddressObject.fqdn | string | Template address object fqdn. | 

#### Command example
```!vd-template-address-object-list template_name=EXAMPLE_CLIENT-Default-Application limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "TemplateAddressObject": [
            {
                "description": "None",
                "ipv4-wildcard-mask": "MASK",
                "name": "Bad-Address-2",
                "tag": "['badAddress,veryBadAddress']"
            },
            {
                "description": "None",
                "ipv4-prefix": "1.1.1.1",
                "name": "Bad-Address-1",
                "tag": "[]"
            },
            {
                "description": "test bad addrees 4",
                "fqdn": "test4.com",
                "name": "Bad-Address-4",
                "tag": "[]"
            }
        ]
    }
}
```

#### Human Readable Output

>### Address objects associated with EXAMPLE_CLIENT
>|Name|Description|Tag|Ipv 4- Prefix|Fqdn|Ipv 4- Wildcard - Mask|
>|---|---|---|---|---|---|
>| Bad-Address-2 | None | ['badAddress,veryBadAddress'] |  |  | MASK |
>| Bad-Address-1 | None | [] | 1.1.1.1 |  |  |
>| Bad-Address-4 | test bad addrees 4 | [] |  | test4.com |  |


### vd-appliance-sdwan-policy-rule-delete
***
Delete an SD-WAN policy rule associated with a specific appliance (device).


#### Base Command

`vd-appliance-sdwan-policy-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| sdwan_policy_name | Name of the SDWAN policy. | Required | 
| rule_name | Name of the rule. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-appliance-sdwan-policy-rule-delete appliance_name=EXAMPLE_BRANCH rule_name=test_rule sdwan_policy_name=Default-Policy```
#### Human Readable Output

>Command run successfully.

### vd-appliance-sdwan-policy-rule-edit
***
Edit an SD-WAN policy rule associated with a specific appliance (device).


#### Base Command

`vd-appliance-sdwan-policy-rule-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| sdwan_policy_name | Name of the SDWAN policy. | Required | 
| custom_rule_json | Allows the use of the Custom SD-WAN Rule JSON template. All of the arguments listed below will be overridden. For an example, please see the integration documentation: LINK. | Optional | 
| rule_name | Name of the rule. | Required | 
| description | SDWAN policy description. | Optional | 
| tags | List of tags. | Optional | 
| source_address_objects | Source address objects. | Optional | 
| destination_address_objects | Destination address objects. | Optional | 
| url_reputation | Url reputation. | Optional | 
| custom_url_categories | Custom URL categories. | Optional | 
| forwarding_action | Forwarding action. Possible values are: allow, deny. | Required | 
| nexthop_ip | Nexthop IP. | Optional | 
| routing_instance | Routing instance. | Optional | 
| forwarding_profile | Forwarding profile. | Optional | 
| predefined_application | Predefined application. | Optional | 
| user_defined_application | User defined appliaction. | Optional | 


#### Context Output

There is no context output for this command.
### vd-appliance-sdwan-policy-rule-create
***
Create an SD-WAN policy rule associated with a specific appliance (device).


#### Base Command

`vd-appliance-sdwan-policy-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| sdwan_policy_name | Name of the SDWAN policy. | Required | 
| custom_rule_json | Allows the use of the Custom SD-WAN Rule JSON template. All of the arguments listed below will be overridden. For an example, please see the integration documentation: LINK. | Optional | 
| rule_name | Name of the rule. | Required | 
| description | SDWAN policy description. | Optional | 
| tags | List of tags. | Optional | 
| source_address_objects | Source address objects. | Optional | 
| destination_address_objects | Destination address objects. | Optional | 
| url_reputation | Url reputation. | Optional | 
| custom_url_categories | Custom URL categories. | Optional | 
| forwarding_action | Forwarding action. Possible values are: allow, deny. | Required | 
| nexthop_ip | Nexthop IP. | Optional | 
| routing_instance | Routing instance. | Optional | 
| forwarding_profile | Forwarding profile. | Optional | 
| predefined_application | Predefined appliaction. | Optional | 
| user_defined_application | User defined appliaction. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-appliance-sdwan-policy-rule-create appliance_name=EXAMPLE_BRANCH sdwan_policy_name=Default-Policy rule_name=test_rule forwarding_action=deny description="test"```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'rule': {'name': 'test_rule', 'description': 'test', 'tag': [], 'rule-disable': 'false', 'match': {'source': {'zone': {}, 'address': {'address-list': []}, 'user': {'user-type': 'any', 'local-database': {'status': 'disabled'}, 'external-database': {'status': 'disabled'}}}, 'destination': {'zone': {}, 'address': {'address-list': []}}, 'application': {'predefined-application-list': [], 'user-defined-application-list': []}, 'url-category': {'user-defined': []}, 'url-reputation': {'predefined': []}, 'ttl': {}}, 'set': {'lef': {'event': 'never', 'profile-default': 'true', 'rate-limit': '10'}, 'action': 'deny', 'tcp-optimization': {}}, 'monitor': {}}}

### vd-appliance-sdwan-policy-rule-list
***
List all SD-WAN policy rules associated with a specific appliance (device).


#### Base Command

`vd-appliance-sdwan-policy-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| sdwan_policy_name | Name of the SDWAN policy. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of objects to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceSdwanPolicyRule.name | string | Policy rule name | 
| VersaDirector.ApplianceSdwanPolicyRule.description | string | Policy rule description | 
| VersaDirector.ApplianceSdwanPolicyRule.rule-disable | string | Rule is disabled | 
| VersaDirector.ApplianceSdwanPolicyRule.set.action | string | Rule action | 

#### Command example
```!vd-appliance-sdwan-policy-rule-list appliance_name=EXAMPLE_BRANCH sdwan_policy_name=Default-Policy limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "ApplianceSdwanPolicyRule": [
            {
                "match": {
                    "source": {
                        "user": {
                            "external-database": {
                                "status": "disabled"
                            },
                            "local-database": {
                                "status": "disabled"
                            },
                            "user-type": "any"
                        }
                    },
                    "url-category": {
                        "user-defined": "Test_Cat"
                    }
                },
                "name": "Tesrt",
                "rule-disable": "false",
                "set": {
                    "action": "deny",
                    "lef": {
                        "event": "never",
                        "rate-limit": "10"
                    }
                }
            },
            {
                "match": {
                    "source": {
                        "user": {
                            "external-database": {
                                "status": "disabled"
                            },
                            "local-database": {
                                "status": "disabled"
                            },
                            "user-type": "any"
                        }
                    },
                    "url-category": {
                        "user-defined": "Test_Cat"
                    }
                },
                "name": "Block-custom-URL-category-rule",
                "rule-disable": "false",
                "set": {
                    "action": "deny",
                    "lef": {
                        "event": "never",
                        "rate-limit": "10"
                    }
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### SD-WAN policy rules associated with EXAMPLE_CLIENT
>|Name|Rule - Disable|
>|---|---|
>| Tesrt | false |
>| Block-custom-URL-category-rule | false |


### vd-appliance-sdwan-policy-list
***
List all SD-WAN policies associated with a specific organization and appliance (device).


#### Base Command

`vd-appliance-sdwan-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceSdwanPolicy.address | string | Appliance SDWAN Policy address | 
| VersaDirector.ApplianceSdwanPolicy.rule-disable | string | Appliance Sdwan Policy Rule disabled | 
| VersaDirector.ApplianceSdwanPolicy.match | string | Appliance SDWAN policy set Matching objects | 
| VersaDirector.ApplianceSdwanPolicy.set | string | Appliance SDWAN policy set | 

#### Command example
```!vd-appliance-sdwan-policy-list appliance_name=EXAMPLE_BRANCH limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "ApplianceSdwanPolicy": {
            "name": "Default-Policy",
            "rules": {
                "rule": [
                    {
                        "name": "Tesrt"
                    },
                    {
                        "name": "Block-custom-URL-category-rule"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### SD-WAN policies associated with EXAMPLE_CLIENT
>|Name|Rules|
>|---|---|
>| Default-Policy | **rule**:<br/>	**-**	***name***: Tesrt<br/>	**-**	***name***: Block-custom-URL-category-rule |


### vd-template-sdwan-policy-rule-delete
***
Delete an SD-WAN policy rule associated with a specific template.


#### Base Command

`vd-template-sdwan-policy-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| sdwan_policy_name | Name of the SDWAN policy. | Required | 
| rule_name | Name of the rule. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-template-sdwan-policy-rule-delete template_name=EXAMPLE_CLIENT-Default-Application sdwan_policy_name=Default-Policy rule_name=test_rule```
#### Human Readable Output

>Command run successfully.

### vd-template-sdwan-policy-rule-edit
***
Edit an SD-WAN policy rule associated with a specific appliance (device).


#### Base Command

`vd-template-sdwan-policy-rule-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| sdwan_policy_name | Name of the SDWAN policy. | Required | 
| custom_rule_json | Allows the use of the Custom SD-WAN Rule JSON template. All of the arguments listed below will be overridden. For an example, please see the integration documentation: LINK. | Optional | 
| rule_name | Name of the rule. | Required | 
| description | SDWAN policy description. | Optional | 
| tags | List of tags. | Optional | 
| source_address_objects | Source address objects. | Optional | 
| destination_address_objects | Destination address objects. | Optional | 
| url_reputation | Url reputation. | Optional | 
| custom_url_categories | Custom URL categories. | Optional | 
| forwarding_action | Forwarding action. Possible values are: allow, deny. | Required | 
| nexthop_ip | Nexthop IP. | Optional | 
| routing_instance | Routing instance. | Optional | 
| forwarding_profile | Forwarding profile. | Optional | 
| predefined_application | Predefined application. | Optional | 
| user_defined_application | User defined application. | Optional | 


#### Context Output

There is no context output for this command.
### vd-template-sdwan-policy-rule-create
***
Create an SD-WAN policy rule associated with a specific template.


#### Base Command

`vd-template-sdwan-policy-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| sdwan_policy_name | Name of the SDWAN policy. | Required | 
| custom_rule_json | Allows the use of the Custom SD-WAN Rule JSON template. All of the arguments listed below will be overridden. For an example, please see the integration documentation: LINK. | Optional | 
| rule_name | Name of the rule. | Required | 
| description | SDWAN policy description. | Optional | 
| tags | List of tags. | Optional | 
| source_address_objects | Source address objects. | Optional | 
| destination_address_objects | Destination address objects. | Optional | 
| url_reputation | Url reputation. | Optional | 
| custom_url_categories | Custom URL categories. | Optional | 
| forwarding_action | Forwarding action. Possible values are: allow, deny. | Required | 
| nexthop_ip | Nexthop IP. | Optional | 
| routing_instance | Routing instance. | Optional | 
| forwarding_profile | Forwarding profile. | Optional | 
| predefined_application | Predefined application. | Optional | 
| user_defined_application | User defined application. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-template-sdwan-policy-rule-create template_name=EXAMPLE_CLIENT-Default-Application sdwan_policy_name=Default-Policy rule_name=test_rule forwarding_action=deny```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'rule': {'name': 'test_rule', 'description': '', 'tag': [], 'rule-disable': 'false', 'match': {'source': {'zone': {}, 'address': {'address-list': []}, 'user': {'user-type': 'any', 'local-database': {'status': 'disabled'}, 'external-database': {'status': 'disabled'}}}, 'destination': {'zone': {}, 'address': {'address-list': []}}, 'application': {'predefined-application-list': [], 'user-defined-application-list': []}, 'url-category': {'user-defined': []}, 'url-reputation': {'predefined': []}, 'ttl': {}}, 'set': {'lef': {'event': 'never', 'profile-default': 'true', 'rate-limit': '10'}, 'action': 'deny', 'tcp-optimization': {}}, 'monitor': {}}}

#### Command example
```!vd-template-sdwan-policy-rule-create template_name=EXAMPLE_CLIENT-Default-Application sdwan_policy_name=Default-Policy rule_name=test_rule forwarding_action=deny```
#### Human Readable Output

>Object already exists.
>Request Body:
>
>(None, 'Not available.')

### vd-template-sdwan-policy-rule-list
***
List all SD-WAN policy rules associated with a specific template.


#### Base Command

`vd-template-sdwan-policy-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| sdwan_policy_name | Name of the SDWAN policy. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | Limit number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateSdwanPolicy.sdwan-policy-group.name | string | Template SDWAN policy group name | 
| VersaDirector.TemplateSdwanPolicy.sdwan-policy-group.rules | string | Template SDWAN policy group rules | 

#### Command example
```!vd-template-sdwan-policy-rule-list template_name=EXAMPLE_CLIENT-Default-Application sdwan_policy_name=Default-Policy limit=3 ```
#### Context Example
```json
{
    "VersaDirector": {
        "TemplateSdwanPolicyRule": [
            {
                "match": {
                    "application": {
                        "predefined-filter-list": "VOIP"
                    }
                },
                "name": "Voice",
                "set": {
                    "action": "allow",
                    "forwarding-profile": "Rule-Voice-FP"
                }
            },
            {
                "match": {
                    "application": {
                        "predefined-filter-list": "Audio-Video-Streaming"
                    }
                },
                "name": "Audio-Video-Streaming",
                "set": {
                    "action": "allow",
                    "forwarding-profile": "Rule-Audio-Video-Streaming-FP"
                }
            },
            {
                "match": {
                    "application": {
                        "predefined-group-list": "ADP-Apps"
                    }
                },
                "name": "ADP-Apps",
                "set": {
                    "action": "allow",
                    "forwarding-profile": "Rule-ADP-Apps-FP"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### SD-WAN policy rules associated with EXAMPLE_CLIENT
>|Name|Match|Set|
>|---|---|---|
>| Voice | **application**:<br/>	***predefined-filter-list***: VOIP | ***action***: allow<br/>***forwarding-profile***: Rule-Voice-FP |
>| Audio-Video-Streaming | **application**:<br/>	***predefined-filter-list***: Audio-Video-Streaming | ***action***: allow<br/>***forwarding-profile***: Rule-Audio-Video-Streaming-FP |
>| ADP-Apps | **application**:<br/>	***predefined-group-list***: ADP-Apps | ***action***: allow<br/>***forwarding-profile***: Rule-ADP-Apps-FP |


### vd-template-sdwan-policy-list
***
List all SD-WAN policies associated with a specific organization and template.


#### Base Command

`vd-template-sdwan-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | Limit number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateSdwanPolicy.sdwan-policy-group.name | string | Template SDWAN policy group name | 
| VersaDirector.TemplateSdwanPolicy.sdwan-policy-group.rules | string | Template SDWAN policy group rules | 

#### Command example
```!vd-template-sdwan-policy-list template_name=EXAMPLE_CLIENT-Default-Application limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "TemplateSdwanPolicy": {
            "collection": {
                "sdwan-policy-group": {
                    "name": "Default-Policy",
                    "rules": {
                        "rule": [
                            {
                                "name": "Voice"
                            },
                            {
                                "name": "Audio-Video-Streaming"
                            },
                            {
                                "name": "ADP-Apps"
                            },
                            {
                                "name": "Amazon-Apps"
                            },
                            {
                                "name": "Box-Apps"
                            },
                            {
                                "name": "Citrix-Apps"
                            },
                            {
                                "name": "Concur-Apps"
                            },
                            {
                                "name": "Docusign-Apps"
                            },
                            {
                                "name": "Dropbox-Apps"
                            },
                            {
                                "name": "IBM-Apps"
                            },
                            {
                                "name": "Intuit-Apps"
                            },
                            {
                                "name": "Jira-Apps"
                            },
                            {
                                "name": "Office365-Apps"
                            },
                            {
                                "name": "Oracle-Apps"
                            },
                            {
                                "name": "SAP-Apps"
                            },
                            {
                                "name": "Salesforce-Apps"
                            },
                            {
                                "name": "Zendesk-Apps"
                            },
                            {
                                "name": "Zoho-Apps"
                            },
                            {
                                "name": "SaaS-Applications"
                            },
                            {
                                "name": "Database"
                            },
                            {
                                "name": "Business-Traffic"
                            },
                            {
                                "name": "Google-Apps"
                            },
                            {
                                "name": "Conferencing-Apps"
                            },
                            {
                                "name": "SoftwareUpdates"
                            },
                            {
                                "name": "File-Transfer"
                            },
                            {
                                "name": "Adobe-Apps"
                            },
                            {
                                "name": "Advertising"
                            },
                            {
                                "name": "Gaming"
                            },
                            {
                                "name": "P2P"
                            },
                            {
                                "name": "Social-Media"
                            },
                            {
                                "name": "Block-custom-URL-category-rule"
                            },
                            {
                                "name": "bla"
                            }
                        ]
                    }
                }
            }
        }
    }
}
```

#### Human Readable Output

>### SD-WAN policies associated with EXAMPLE_CLIENT
>|Name|Rules|
>|---|---|
>| Default-Policy | **rule**:<br/>	**-**	***name***: Voice<br/>	**-**	***name***: Audio-Video-Streaming<br/>	**-**	***name***: ADP-Apps<br/>	**-**	***name***: Amazon-Apps<br/>	**-**	***name***: Box-Apps<br/>	**-**	***name***: Citrix-Apps<br/>	**-**	***name***: Concur-Apps<br/>	**-**	***name***: Docusign-Apps<br/>	**-**	***name***: Dropbox-Apps<br/>	**-**	***name***: IBM-Apps<br/>	**-**	***name***: Intuit-Apps<br/>	**-**	***name***: Jira-Apps<br/>	**-**	***name***: Office365-Apps<br/>	**-**	***name***: Oracle-Apps<br/>	**-**	***name***: SAP-Apps<br/>	**-**	***name***: Salesforce-Apps<br/>	**-**	***name***: Zendesk-Apps<br/>	**-**	***name***: Zoho-Apps<br/>	**-**	***name***: SaaS-Applications<br/>	**-**	***name***: Database<br/>	**-**	***name***: Business-Traffic<br/>	**-**	***name***: Google-Apps<br/>	**-**	***name***: Conferencing-Apps<br/>	**-**	***name***: SoftwareUpdates<br/>	**-**	***name***: File-Transfer<br/>	**-**	***name***: Adobe-Apps<br/>	**-**	***name***: Advertising<br/>	**-**	***name***: Gaming<br/>	**-**	***name***: P2P<br/>	**-**	***name***: Social-Media<br/>	**-**	***name***: Block-custom-URL-category-rule<br/>	**-**	***name***: bla |


### vd-appliance-access-policy-rule-delete
***
Delete an access policy configuration (NGFW) rule associated with a specific appliance (device).


#### Base Command

`vd-appliance-access-policy-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| access_policy_name | Access policy name. | Required | 
| rule_name | Name of the rule. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-appliance-access-policy-rule-delete rule_name=test_rule_new1 appliance_name=EXAMPLE_BRANCH access_policy_name=Test_Policy```
#### Human Readable Output

>Command run successfully.

### vd-appliance-access-policy-rule-edit
***
Edit access policy configuration (NGFW) rule associated with a specific appliance (device). Important note - the data provided in the request overwrites the existing rule settings.


#### Base Command

`vd-appliance-access-policy-rule-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| access_policy_name | Access policy name. | Required | 
| custom_rule_json | Allows the use of the Custom Access policy rule JSON template. All of the arguments listed below will be overridden. For an example, please see the integration documentation: LINK. | Optional | 
| rule_name | Name of the rule. | Required | 
| description | SDWAN policy description. | Optional | 
| tags | List of tags. | Optional | 
| source_address_objects | Source address objects. | Optional | 
| destination_address_objects | Destination address objects. | Optional | 
| url_reputation | Url reputation. | Optional | 
| predefined_application | Predefined appliaction. | Optional | 
| user_defined_application | User defined appliaction. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-appliance-access-policy-rule-edit rule_name=test_rule_new1 appliance_name=EXAMPLE_BRANCH access_policy_name=Test_Policy description="test rule changed" source_address_objects="Bad-Address-1" destination_address_objects="Bad-Address-2"```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'access-policy': {'name': 'test_rule_new1', 'description': 'test rule changed', 'rule-disable': 'false', 'tag': [], 'match': {'source': {'zone': {}, 'address': {'address-list': ['Bad-Address-1'], 'negate': ''}, 'site-name': [], 'user': {'user-type': 'any', 'local-database': {'status': 'disabled'}, 'external-database': {'status': 'disabled'}}}, 'destination': {'zone': {}, 'address': {'address-list': ['Bad-Address-2'], 'negate': ''}, 'site-name': []}, 'application': {'predefined-application-list': [], 'user-defined-application-list': []}, 'url-category': {'user-defined': []}, 'url-reputation': {'predefined': []}, 'ttl': {}}, 'set': {'lef': {'event': 'never', 'options': {'send-pcap-data': {'enable': False}}}, 'action': 'deny', 'tcp-session-keepalive': 'disabled'}}}

### vd-appliance-access-policy-rule-create
***
Create an access policy configuration (NGFW) rule associated with a specific appliance (device).


#### Base Command

`vd-appliance-access-policy-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| access_policy_name | Access policy name. | Required | 
| custom_rule_json | Allows the use of the Custom Access policy rule JSON template. All of the arguments listed below will be overridden. For an example, please see the integration documentation: LINK. | Optional | 
| rule_name | Name of the rule. | Required | 
| description | SDWAN policy description. | Required | 
| tags | List of tags. | Optional | 
| source_address_objects | Source address objects. | Required | 
| destination_address_objects | Destination address objects. | Required | 
| url_reputation | Url reputation. | Optional | 
| predefined_application | Predefined appliaction. | Optional | 
| user_defined_application | User defined appliaction. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-appliance-access-policy-rule-create rule_name=test_rule_new1 appliance_name=EXAMPLE_BRANCH access_policy_name=Test_Policy description="test rule" source_address_objects="Bad-Address-1" destination_address_objects="Bad-Address-2"```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'access-policy': {'name': 'test_rule_new1', 'description': 'test rule', 'rule-disable': 'false', 'tag': [], 'match': {'source': {'zone': {}, 'address': {'address-list': ['Bad-Address-1'], 'negate': ''}, 'site-name': [], 'user': {'user-type': 'any', 'local-database': {'status': 'disabled'}, 'external-database': {'status': 'disabled'}}}, 'destination': {'zone': {}, 'address': {'address-list': ['Bad-Address-2'], 'negate': ''}, 'site-name': []}, 'application': {'predefined-application-list': [], 'user-defined-application-list': []}, 'url-category': {'user-defined': []}, 'url-reputation': {'predefined': []}, 'ttl': {}}, 'set': {'lef': {'event': 'never', 'options': {'send-pcap-data': {'enable': False}}}, 'action': 'deny', 'tcp-session-keepalive': 'disabled'}}}

### vd-appliance-access-policy-rule-list
***
List all access policy configuration (NGFW) rules associated with a specific Appliance.


#### Base Command

`vd-appliance-access-policy-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| access_policy_name | Access policy name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceAccessPolicyRule.name | string | Appliance access policy rule name | 
| VersaDirector.ApplianceAccessPolicyRule.description | string | Appliance access policy rule description | 
| VersaDirector.ApplianceAccessPolicyRule.tag | string | Appliance access policy rule tag | 
| VersaDirector.ApplianceAccessPolicyRule.rule-disable | string | Appliance access policy rule disabled | 

#### Command example
```!vd-appliance-access-policy-rule-list appliance_name=EXAMPLE_BRANCH access_policy_name=Test_Policy limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "ApplianceAccessPolicyRule": {
            "collection": {
                "access-policy": [
                    {
                        "description": "test rule",
                        "match": {
                            "destination": {
                                "address": {
                                    "address-list": "Bad-Address-2",
                                    "negate": null
                                }
                            },
                            "source": {
                                "address": {
                                    "address-list": "Bad-Address-1",
                                    "negate": null
                                },
                                "user": {
                                    "external-database": {
                                        "status": "disabled"
                                    },
                                    "local-database": {
                                        "status": "disabled"
                                    },
                                    "user-type": "any"
                                }
                            }
                        },
                        "name": "Test_Rule",
                        "rule-disable": "false",
                        "set": {
                            "action": "deny",
                            "lef": {
                                "event": "never",
                                "options": {
                                    "send-pcap-data": {
                                        "enable": "false"
                                    }
                                }
                            },
                            "tcp-session-keepalive": "disabled"
                        }
                    },
                    {
                        "match": {
                            "destination": {
                                "address": {
                                    "address-list": "Bad-Address-2",
                                    "negate": null
                                }
                            },
                            "source": {
                                "address": {
                                    "address-list": [
                                        "Bad-Address-1",
                                        "Bad-Address-2"
                                    ],
                                    "negate": null
                                },
                                "user": {
                                    "external-database": {
                                        "status": "disabled"
                                    },
                                    "local-database": {
                                        "status": "disabled"
                                    },
                                    "user-type": "any"
                                }
                            },
                            "url-category": {
                                "user-defined": "Test_Cat"
                            },
                            "url-reputation": {
                                "predefined": "high_risk"
                            }
                        },
                        "name": "Block-custom-URL-category-rulethree",
                        "rule-disable": "false",
                        "set": {
                            "action": "deny",
                            "lef": {
                                "event": "never",
                                "options": {
                                    "send-pcap-data": {
                                        "enable": "false"
                                    }
                                }
                            },
                            "tcp-session-keepalive": "disabled"
                        },
                        "tag": [
                            "API",
                            "test"
                        ]
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Access policies associated with EXAMPLE_CLIENT
>|Name|Description|Tag|Rule - Disable|
>|---|---|---|---|
>| Test_Rule | test rule |  | false |
>| Block-custom-URL-category-rulethree |  | ***values***: API, test | false |


### vd-appliance-access-policy-list
***
List all access policies associated with a specific organization and appliance (device).


#### Base Command

`vd-appliance-access-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceAccessPolicy.name | string | Access policy name. | 
| VersaDirector.ApplianceAccessPolicy.rules | string | Access policy rules | 

#### Command example
```!vd-appliance-access-policy-list appliance_name=EXAMPLE_BRANCH limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "ApplianceAccessPolicy": {
            "collection": {
                "access-policy-group": {
                    "description": "This is a test",
                    "name": "Test_Policy",
                    "rules": {
                        "access-policy": [
                            {
                                "name": "Test_Rule"
                            },
                            {
                                "name": "Block-custom-URL-category-rulethree"
                            }
                        ]
                    }
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Access policies associated with EXAMPLE_CLIENT
>|Name|Rules|
>|---|---|
>| Test_Policy | **access-policy**:<br/>	**-**	***name***: Test_Rule<br/>	**-**	***name***: Block-custom-URL-category-rulethree |


### vd-template-access-policy-rule-delete
***
Delete an access policy configuration (NGFW) rule associated with a specific template.


#### Base Command

`vd-template-access-policy-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| access_policy_name | Access policy name. | Required | 
| rule_name | Name of the rule. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-template-access-policy-rule-delete rule_name=test_rule template_name=EXAMPLE_CLIENT-Test-NGFW access_policy_name=Default-Policy```
#### Human Readable Output

>Command run successfully.

### vd-template-access-policy-rule-edit
***
Edit access policy configuration (NGFW) rule associated with a specific template. Important note - the data provided in the request overwrites the existing rule settings.


#### Base Command

`vd-template-access-policy-rule-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| access_policy_name | Access policy name. | Required | 
| custom_rule_json | Allows the use of the Custom Access policy rule JSON template. All of the arguments listed below will be overridden. For an example, please see the integration documentation: LINK. | Optional | 
| rule_name | Name of the rule. | Required | 
| description | SDWAN policy description. | Optional | 
| tags | List of tags. | Optional | 
| source_address_objects | Source address objects. | Optional | 
| destination_address_objects | Destination address objects. | Optional | 
| url_reputation | Url reputation. | Optional | 
| predefined_application | Predefined appliaction. | Optional | 
| user_defined_application | User defined appliaction. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-template-access-policy-rule-edit template_name=EXAMPLE_CLIENT-Test-NGFW rule_name=test_rule access_policy_name=Default-Policy```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'access-policy': {'name': 'test_rule', 'description': '', 'rule-disable': 'false', 'tag': [], 'match': {'source': {'zone': {}, 'address': {'address-list': [], 'negate': ''}, 'site-name': [], 'user': {'user-type': 'any', 'local-database': {'status': 'disabled'}, 'external-database': {'status': 'disabled'}}}, 'destination': {'zone': {}, 'address': {'address-list': [], 'negate': ''}, 'site-name': []}, 'application': {'predefined-application-list': [], 'user-defined-application-list': []}, 'url-category': {'user-defined': []}, 'url-reputation': {'predefined': []}, 'ttl': {}}, 'set': {'lef': {'event': 'never', 'options': {'send-pcap-data': {'enable': False}}}, 'action': 'deny', 'tcp-session-keepalive': 'disabled'}}}

### vd-template-access-policy-rule-create
***
Create an access policy configuration (NGFW) rule associated with a specific template.


#### Base Command

`vd-template-access-policy-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| access_policy_name | Access policy name. | Required | 
| custom_rule_json | Allows the use of the Custom Access policy rule JSON template. All of the arguments listed below will be overridden. For an example, please see the integration documentation: LINK. | Optional | 
| rule_name | Name of the rule. | Required | 
| description | Access policy description. | Optional | 
| tags | List of tags. | Optional | 
| source_address_objects | Source address objects. | Optional | 
| destination_address_objects | Destination address objects. | Optional | 
| url_reputation | Url reputation. | Optional | 
| predefined_application | Predefined appliaction. | Optional | 
| user_defined_application | User defined appliaction. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!vd-template-access-policy-rule-create template_name=EXAMPLE_CLIENT-Test-NGFW rule_name=test_rule access_policy_name=Default-Policy```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'access-policy': {'name': 'test_rule', 'description': '', 'rule-disable': 'false', 'tag': [], 'match': {'source': {'zone': {}, 'address': {'address-list': [], 'negate': ''}, 'site-name': [], 'user': {'user-type': 'any', 'local-database': {'status': 'disabled'}, 'external-database': {'status': 'disabled'}}}, 'destination': {'zone': {}, 'address': {'address-list': [], 'negate': ''}, 'site-name': []}, 'application': {'predefined-application-list': [], 'user-defined-application-list': []}, 'url-category': {'user-defined': []}, 'url-reputation': {'predefined': []}, 'ttl': {}}, 'set': {'lef': {'event': 'never', 'options': {'send-pcap-data': {'enable': False}}}, 'action': 'deny', 'tcp-session-keepalive': 'disabled'}}}

### vd-template-access-policy-rule-list
***
List all access policy configuration (NGFW) rules associated with a specific template.


#### Base Command

`vd-template-access-policy-rule-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| access_policy_name | Access policy name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateAccessPolicy.name | string | Template access policy name | 
| VersaDirector.TemplateAccessPolicy.description | string | Template access policy description | 
| VersaDirector.TemplateAccessPolicy.tag | string | Template access policy tag | 
| VersaDirector.TemplateAccessPolicy.rule-disable | string | Template access policy disabled | 

#### Command example
```!vd-template-access-policy-rule-list template_name=EXAMPLE_CLIENT-Test-NGFW access_policy_name=Default-Policy limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "TemplateAccessPolicyRule": {
            "collection": {
                "access-policy": [
                    {
                        "match": {
                            "source": {
                                "user": {
                                    "external-database": {
                                        "status": "disabled"
                                    },
                                    "local-database": {
                                        "status": "disabled"
                                    },
                                    "user-type": "any"
                                }
                            },
                            "url-category": {
                                "user-defined": [
                                    "Danil_Test_API_again",
                                    "Danil_Test_Three"
                                ]
                            }
                        },
                        "name": "Block-custom-URL-category-rule two",
                        "rule-disable": "false",
                        "set": {
                            "action": "deny",
                            "lef": {
                                "event": "never",
                                "options": {
                                    "send-pcap-data": {
                                        "enable": "false"
                                    }
                                }
                            },
                            "tcp-session-keepalive": "disabled"
                        }
                    },
                    {
                        "description": "Some description",
                        "match": {
                            "application": {
                                "predefined-group-list": "Box-Apps"
                            },
                            "destination": {
                                "address": {
                                    "negate": null
                                }
                            },
                            "source": {
                                "address": {
                                    "address-list": [
                                        "Bad-Address-1",
                                        "Bad-Address-2"
                                    ],
                                    "negate": null
                                },
                                "user": {
                                    "external-database": {
                                        "status": "disabled"
                                    },
                                    "local-database": {
                                        "status": "disabled"
                                    },
                                    "user-type": "any"
                                }
                            },
                            "url-category": {
                                "user-defined": "Danil_Test_API_again"
                            },
                            "url-reputation": {
                                "predefined": "high_risk"
                            }
                        },
                        "name": "test_rule_UI",
                        "rule-disable": "false",
                        "set": {
                            "action": "allow",
                            "lef": {
                                "event": "never",
                                "options": {
                                    "send-pcap-data": {
                                        "enable": "false"
                                    }
                                }
                            },
                            "tcp-session-keepalive": "disabled"
                        },
                        "tag": "test"
                    },
                    {
                        "description": null,
                        "match": {
                            "application": {
                                "predefined-application-list": "[]",
                                "user-defined-application-list": "[]"
                            },
                            "destination": {
                                "address": {
                                    "address-list": "[]",
                                    "negate": null
                                }
                            },
                            "source": {
                                "address": {
                                    "address-list": "[]",
                                    "negate": null
                                },
                                "user": {
                                    "external-database": {
                                        "status": "disabled"
                                    },
                                    "local-database": {
                                        "status": "disabled"
                                    },
                                    "user-type": "any"
                                }
                            },
                            "url-category": {
                                "user-defined": "[]"
                            },
                            "url-reputation": {
                                "predefined": "[]"
                            }
                        },
                        "name": "rule",
                        "rule-disable": "false",
                        "set": {
                            "action": "deny",
                            "lef": {
                                "event": "never",
                                "options": {
                                    "send-pcap-data": {
                                        "enable": "false"
                                    }
                                }
                            },
                            "tcp-session-keepalive": "disabled"
                        },
                        "tag": "[]"
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Access policies associated with EXAMPLE_CLIENT
>|Name|Description|Tag|Rule - Disable|
>|---|---|---|---|
>| Block-custom-URL-category-rule two |  |  | false |
>| test_rule_UI | Some description | test | false |
>| rule |  | [] | false |


### vd-template-access-policy-list
***
List all access policies associated with a specific organization and template.


#### Base Command

`vd-template-access-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateAccessPolicy.name | string | Template access policy name | 
| VersaDirector.TemplateAccessPolicy.rules | string | Access policy rules | 

#### Command example
```!vd-template-access-policy-list template_name="EXAMPLE_CLIENT-Test-NGFW" limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "TemplateAccessPolicy": {
            "collection": {
                "access-policy-group": {
                    "name": "Default-Policy",
                    "rules": {
                        "access-policy": [
                            {
                                "name": "Block-custom-URL-category-rule two"
                            },
                            {
                                "name": "test_rule_UI"
                            },
                            {
                                "name": "rule"
                            },
                            {
                                "name": "Block-custom-URL-category-rule 555"
                            },
                            {
                                "name": "rule11111"
                            },
                            {
                                "name": "rule1233"
                            },
                            {
                                "name": "rule12333"
                            },
                            {
                                "name": "rule123331"
                            },
                            {
                                "name": "rule1233311"
                            },
                            {
                                "name": "rule12333111"
                            },
                            {
                                "name": "rule111111"
                            },
                            {
                                "name": "Block-custom-URL-category-rule three"
                            }
                        ]
                    }
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Access policies associated with EXAMPLE_CLIENT
>|Name|Rules|
>|---|---|
>| Default-Policy | **access-policy**:<br/>	**-**	***name***: Block-custom-URL-category-rule two<br/>	**-**	***name***: test_rule_UI<br/>	**-**	***name***: rule<br/>	**-**	***name***: Block-custom-URL-category-rule 555<br/>	**-**	***name***: rule11111<br/>	**-**	***name***: rule1233<br/>	**-**	***name***: rule12333<br/>	**-**	***name***: rule123331<br/>	**-**	***name***: rule1233311<br/>	**-**	***name***: rule12333111<br/>	**-**	***name***: rule111111<br/>	**-**	***name***: Block-custom-URL-category-rule three |


### vd-appliance-custom-url-category-delete
***
Delete a custom URL category associated with a specific appliance (device).


#### Base Command

`vd-appliance-custom-url-category-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| url_category_name | URL category name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceCustomUrlCategory.category-name | string | Appliance custom url category category name | 
| VersaDirector.ApplianceCustomUrlCategory.category-description | string | Appliance custom url category description | 
| VersaDirector.ApplianceCustomUrlCategory.content.confidence | number | Appliance custom url category confidence threshold | 
| VersaDirector.ApplianceCustomUrlCategory.content.urls | string | Appliance custom url category URLs | 

#### Command example
```!vd-appliance-custom-url-category-delete appliance_name=EXAMPLE_BRANCH url_category_name="category_example"```
#### Human Readable Output

>Command run successfully.

### vd-appliance-custom-url-category-edit
***
Edit a custom URL category associated with a specific appliance (device). Important note - the data provided in the request overwrites the existing object.


#### Base Command

`vd-appliance-custom-url-category-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| url_category_name | URL category name. | Required | 
| description | Custom url category description. | Required | 
| confidence | Confidence threshold. | Required | 
| urls | URLs. | Optional | 
| url_reputation | Url reputation. | Optional | 
| patterns | Patterns. | Optional | 
| pattern_reputation | Pattern reputation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceCustomUrlCategory.category-name | string | Appliance custom url category category name | 
| VersaDirector.ApplianceCustomUrlCategory.category-description | string | Appliance custom url category description | 
| VersaDirector.ApplianceCustomUrlCategory.content.confidence | number | Appliance custom url category confidence threshold | 
| VersaDirector.ApplianceCustomUrlCategory.content.urls | string | Appliance custom url category URLs | 

### vd-appliance-custom-url-category-create
***
Create a custom URL category associated with a specific appliance (device).


#### Base Command

`vd-appliance-custom-url-category-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| url_category_name | URL category name. | Required | 
| description | Custom url category description. | Required | 
| confidence | Confidence threshold. | Required | 
| urls | URLs. | Optional | 
| url_reputation | Url reputation. | Optional | 
| patterns | Patterns. | Optional | 
| pattern_reputation | Pattern reputation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceCustomUrlCategory.content.category-name | string | Appliance custom url category name. | 
| VersaDirector.ApplianceCustomUrlCategory.content.category-description | string | Appliance custom url category description. | 
| VersaDirector.ApplianceCustomUrlCategory.content.confidence | number | Appliance custom url category confidence threshold. | 
| VersaDirector.ApplianceCustomUrlCategory.content.urls | string | Appliance custom url category URLs. | 

#### Command example
```!vd-appliance-custom-url-category-create appliance_name=EXAMPLE_BRANCH description="description example" url_category_name="category_example" confidence=80```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'url-category': {'category-name': 'category_example', 'category-description': 'description example', 'confidence': '80', 'urls': {'strings': [], 'patterns': []}}}

#### Command example
```!vd-appliance-custom-url-category-create appliance_name=EXAMPLE_BRANCH description="description example" url_category_name="category_example" confidence=90```
#### Human Readable Output

>Object already exists.
>Request Body:
>
>(None, 'Not available.')

### vd-appliance-custom-url-category-list
***
List all custom URL categories associated with a specific appliance or get a specific custom URL category.


#### Base Command

`vd-appliance-custom-url-category-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| appliance_name | Appliance name. | Required | 
| url_category_name | URL category name. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplianceCustomUrlCategory.category-name | string | Appliance custom url category name. | 
| VersaDirector.ApplianceCustomUrlCategory.content.category-description | string | Appliance custom url category description. | 
| VersaDirector.ApplianceCustomUrlCategory.content.confidence | number | Appliance custom url category confidence threshold. | 
| VersaDirector.ApplianceCustomUrlCategory.content.urls | string | Appliance custom url category URLs. | 

#### Command example
```!vd-appliance-custom-url-category-list appliance_name=EXAMPLE_BRANCH limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "ApplianceCustomUrlCategory": {
            "collection": {
                "url-category": {
                    "category-description": "Test",
                    "category-name": "Test_Cat",
                    "confidence": "95",
                    "urls": {
                        "patterns": {
                            "pattern-value": "%.test2.ru"
                        },
                        "strings": {
                            "string-value": "hxxps://test1.ru"
                        }
                    }
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Application Service Appliances associated with EXAMPLE_CLIENT
>|Category - Name|Category - Description|Confidence|Urls|
>|---|---|---|---|
>| Test_Cat | Test | 95 | **strings**:<br/>	***string-value***: hxxps:<span>//</span>test1.ru<br/>**patterns**:<br/>	***pattern-value***: %.test2.ru |


### vd-template-custom-url-category-delete
***
Delete a custom URL category associated with a specific template.


#### Base Command

`vd-template-custom-url-category-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| url_category_name | URL category name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateCustomUrlCategory.category-name | string | Template custom url category name. | 
| VersaDirector.TemplateCustomUrlCategory.category-description | string | Template custom url category description. | 
| VersaDirector.TemplateCustomUrlCategory.content.confidence | number | Template custom url category confidence threshold. | 
| VersaDirector.TemplateCustomUrlCategory.content.urls | string | Template custom url category URLs. | 

#### Command example
```!vd-template-custom-url-category-delete template_name=EXAMPLE_CLIENT-Default-Application url_category_name="category_example"```
#### Human Readable Output

>Command run successfully.

### vd-template-custom-url-category-edit
***
Edit a custom URL category associated with a specific template. Important note - the data provided in the request overwrites the existing object.


#### Base Command

`vd-template-custom-url-category-edit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| url_category_name | URL category name. | Required | 
| description | Custom url category description. | Required | 
| confidence | Confidence threshold. | Required | 
| urls | URLs. | Optional | 
| url_reputation | Url reputation. | Optional | 
| patterns | Patterns. | Optional | 
| pattern_reputation | Pattern reputation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateCustomUrlCategory.category-name | string | Template custom url category name | 
| VersaDirector.ApplicationServiceTemplatecontent.category-description | string | Template custom url category description | 
| VersaDirector.ApplicationServiceTemplate.content.confidence | number | Template custom url category confidence threshold | 
| VersaDirector.ApplicationServiceTemplate.content.urls | string | Template custom url category URLs | 

#### Command example
```!vd-template-custom-url-category-edit template_name=EXAMPLE_CLIENT-Default-Application description="description example" url_category_name="category_example" confidence=90```
#### Human Readable Output

>Command run successfully.
>Request Body:
>
>{'url-category': {'category-name': 'category_example', 'category-description': 'description example', 'confidence': '90', 'urls': {'strings': [], 'patterns': []}}}

### vd-template-custom-url-category-create
***
Create a custom URL category associated with a specific template.


#### Base Command

`vd-template-custom-url-category-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| url_category_name | URL category name. | Required | 
| description | Custom url category description. | Required | 
| confidence | Confidence threshold. | Required | 
| urls | URLs. | Optional | 
| url_reputation | Url reputation. | Optional | 
| patterns | Patterns. | Optional | 
| pattern_reputation | Pattern reputation. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateCustomUrlCategory.category-name | string | Template custom url category name | 
| VersaDirector.ApplicationServiceTemplatecontent.category-description | string | Template custom url category category description | 
| VersaDirector.ApplicationServiceTemplate.content.confidence | number | Template custom url category confidence threshold | 
| VersaDirector.ApplicationServiceTemplate.content.urls | string | Template custom url category URLs | 

#### Command example
```!vd-template-custom-url-category-create template_name=EXAMPLE_CLIENT-Default-Application description="description example" url_category_name="category_example" confidence=80```
#### Human Readable Output

>Object created successfully.

### vd-template-custom-url-category-list
***
List all custom URL categories associated with a specific template or get a specific custom URL category.


#### Base Command

`vd-template-custom-url-category-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| template_name | Template name. | Required | 
| url_category_name | URL category name. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| url_category_name | URL category name. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.TemplateCustomUrlCategory.category-name | string | Template custom url category name | 
| VersaDirector.ApplicationServiceTemplatecontent.category-description | string | Template custom url category category description | 
| VersaDirector.ApplicationServiceTemplate.content.confidence | number | Template custom url category confidence threshold | 
| VersaDirector.ApplicationServiceTemplate.content.urls | string | Template custom url category URLs | 

#### Command example
```!vd-template-custom-url-category-list template_name=EXAMPLE_CLIENT-Default-Application limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "TemplateCustomUrlCategory": {
            "collection": {
                "url-category": [
                    {
                        "category-description": "Some description for testing, and now editing",
                        "category-name": "category example1",
                        "confidence": "90",
                        "urls": {
                            "patterns": {
                                "pattern-value": ".*.testurl.com"
                            },
                            "strings": {
                                "string-value": "hxxps://test.ru"
                            }
                        }
                    },
                    {
                        "category-description": "Some description for testing, and now editing",
                        "category-name": "category example2",
                        "confidence": "5",
                        "urls": {
                            "patterns": [
                                {
                                    "pattern-value": ".*.testurl.com"
                                },
                                {
                                    "pattern-value": ".*.testurl2.com"
                                }
                            ],
                            "strings": [
                                {
                                    "string-value": "hxxps://test1.ru"
                                },
                                {
                                    "string-value": "hxxps://test2.ru"
                                }
                            ]
                        }
                    },
                    {
                        "category-description": "description example",
                        "category-name": "category example9",
                        "confidence": "80",
                        "urls": {
                            "patterns": {
                                "pattern-value": "[]"
                            },
                            "strings": {
                                "string-value": "[]"
                            }
                        }
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Application Service Templates associated with EXAMPLE_CLIENT
>|Category - Name|Category - Description|Confidence|Urls|
>|---|---|---|---|
>| category example1 | Some description for testing, and now editing | 90 | **strings**:<br/>	***string-value***: hxxps:<span>//</span>test.ru<br/>**patterns**:<br/>	***pattern-value***: .*.testurl.com |
>| category example2 | Some description for testing, and now editing | 5 | **strings**:<br/>	**-**	***string-value***: hxxps:<span>//</span>test1.ru<br/>	**-**	***string-value***: hxxps:<span>//</span>test2.ru<br/>**patterns**:<br/>	**-**	***pattern-value***: .*.testurl.com<br/>	**-**	***pattern-value***: .*.testurl2.com |
>| category example9 | description example | 80 | **strings**:<br/>	***string-value***: []<br/>**patterns**:<br/>	***pattern-value***: [] |


### vd-template-change-commit
***
Commit a specific template change to an appliance/s (devices). This will trigger a task to make the commit, and then it will be polled to retrieve status until complete, and the status will be presented.


#### Base Command

`vd-template-change-commit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| template_name | New template name for the device. | Required | 
| appliances | List of devices the change will be committed to. | Required | 
| mode | Commit mode to specified devices. Possible values are: overwrite, merge, forced_merge. | Required | 
| task_id | Task ID hidden polling command. | Optional | 
| hide_polling_output | whether to hide the polling result (automatically filled by polling). | Optional | 
| reboot | Reboot devices after change is committed (true/false). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.Commit.versa-tasks.id | string | Task ID | 
| VersaDirector.Commit.versa-tasks.task-description | string | Task description | 
| VersaDirector.Commit.versa-tasks.user | string | Task user | 
| VersaDirector.Commit.task-status | string | Task status | 
| VersaDirector.Commit.versa-tasks.progressmessage | string | Task progress message | 

#### Command example
```!vd-template-change-commit template_name=EXAMPLE_CLIENT-Test-NGFW appliances=EXAMPLE_BRANCH mode=merge reboot=false```
#### Human Readable Output

>Fetching Results:

### vd-application-service-template-list
***
List all application service templates. Can be filtered by organization or a keyword search.


#### Base Command

`vd-application-service-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| keyword | Keyword. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.ApplicationServiceTemplate.createDate | string | Application service template create date | 
| VersaDirector.ApplicationServiceTemplate.createDate | string | Application service template modify date | 
| VersaDirector.ApplicationServiceTemplate.content.lastUpdatedBy | string | Application service template last updated by | 
| VersaDirector.ApplicationServiceTemplate.content.name | string | Application service template content name | 
| VersaDirector.ApplicationServiceTemplate.content.organization | string | Application service template associated organization | 
| VersaDirector.ApplicationServiceTemplate.content.status | string | Application service template status | 

#### Command example
```!vd-application-service-template-list limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "ApplicationServiceTemplate": {
            "content": [
                {
                    "createDate": "2021-08-26 18:02:44",
                    "lastUpdatedBy": "Sunil",
                    "modifyDate": "2021-08-26 18:02:48",
                    "name": "EXAMPLE_CLIENT-Default-Application",
                    "organization": "EXAMPLE_CLIENT",
                    "status": "DEPLOYED"
                }
            ],
            "empty": false,
            "first": true,
            "last": true,
            "number": 0,
            "numberOfElements": 1,
            "pageable": {
                "offset": 0,
                "pageNumber": 0,
                "pageSize": 3,
                "paged": true,
                "sort": {
                    "empty": false,
                    "sorted": true,
                    "unsorted": false
                },
                "unpaged": false
            },
            "size": 3,
            "sort": {
                "empty": false,
                "sorted": true,
                "unsorted": false
            },
            "totalElements": 1,
            "totalPages": 1
        }
    }
}
```

#### Human Readable Output

>### Application Service Templates associated with EXAMPLE_CLIENT
>|Create Date|Modify Date|Last Updated By|Name|Organization|Status|
>|---|---|---|---|---|---|
>| 2021-08-26 18:02:44 | 2021-08-26 18:02:48 | Sunil | EXAMPLE_CLIENT-Default-Application | EXAMPLE_CLIENT | DEPLOYED |


### vd-datastore-template-list
***
List all templates associated with a specific data-store.  As a best practice, it is not recommended to apply rules to datastore templates. Instead use devices/service/application templates.


#### Base Command

`vd-datastore-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.DataStoreTemplate.name | string | Template name. | 
| VersaDirector.DataStoreTemplate.appliance-owner | string | DataStore template appliacne owner | 
| VersaDirector.DataStoreTemplate.available-routing-instances | string | DataStore template available routing instances | 
| VersaDirector.DataStoreTemplate.owned-routing-instances | string | DataStore template owned routing instances | 
| VersaDirector.DataStoreTemplate.available-networks | string | DataStore template available networks | 

#### Command example
```!vd-datastore-template-list limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "DataStoreTemplate": {
            "collection": {
                "org": {
                    "appliance-owner": null,
                    "available-networks": [
                        "INET",
                        "INET-2",
                        "LTE",
                        "MPLS",
                        "MPLS-2"
                    ],
                    "available-routing-instances": "EXAMPLE_CLIENT-LAN-VR",
                    "name": "EXAMPLE_CLIENT",
                    "owned-routing-instances": "EXAMPLE_CLIENT-LAN-VR"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Templates associated with EXAMPLE_CLIENT Data-Store
>|Name|Available - Routing - Instances|Owned - Routing - Instances|Available - Networks|
>|---|---|---|---|
>| EXAMPLE_CLIENT | EXAMPLE_CLIENT-LAN-VR | EXAMPLE_CLIENT-LAN-VR | INET,<br/>INET-2,<br/>LTE,<br/>MPLS,<br/>MPLS-2 |


### vd-template-list
***
List all templates associated with a specific organization. Default type argument is 'MAIN'.


#### Base Command

`vd-template-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| type | Type of template. If not specified in request, all types will be fetched. Possible values are: SERVICE, MAIN. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | Limit number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.Template |  | Template name. | 

#### Command example
```!vd-template-list limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "Template": [
            {
                "analyticsEnabled": true,
                "compositeOrPrimary": "composite",
                "dynamicTenantConfig": false,
                "isAnalyticsEnabled": true,
                "isDynamicTenantConfig": false,
                "isPrimary": true,
                "isStaging": false,
                "lockDetails": {
                    "lockType": "NONE",
                    "user": "EXAMPLE_USER"
                },
                "name": "EXAMPLE_SITE",
                "organization": [
                    "EXAMPLE_CLIENT"
                ],
                "primary": true,
                "providerTenant": "EXAMPLE_CLIENT",
                "rbacResourceTags": [],
                "staging": false,
                "templateType": "sdwan-post-staging"
            }
        ]
    }
}
```

#### Human Readable Output

>### Templates associated with EXAMPLE_CLIENT
>|Name|Organization|Lock Details|Template Type|Is Primary|Is Staging|
>|---|---|---|---|---|---|
>| EXAMPLE_SITE | EXAMPLE_CLIENT | user: EXAMPLE_USER<br/>lockType: NONE | sdwan-post-staging | true | false |


### vd-appliance-group-template-appliance-list
***
List all appliances associated with a specific device-group and associated templates


#### Base Command

`vd-appliance-group-template-appliance-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_group | Device group name. | Required | 
| template_name | Template name. | Required | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.DeviceGroup.createDate | string | Device group create date. | 
| VersaDirector.DeviceGroup.modifyDate | string | Device group modify date. | 
| VersaDirector.DeviceGroup.lastUpdatedBy | string | Device group last updated by | 
| VersaDirector.DeviceGroup.name | string | Device group name. | 
| VersaDirector.DeviceGroup.poststagingTemplatePriority | string | Device group post staging template priority. | 
| VersaDirector.DeviceGroup.oneTimePassword | string | Device group one time password. | 
| VersaDirector.DeviceGroup.poststaging-template | string | Device group post staging template. | 
| VersaDirector.DeviceGroup.enable-2factor-auth | string | Device group enable two factor authentication. | 
| VersaDirector.DeviceGroup.enable-staging-url | string | Device group enable staging url. | 

#### Command example
```!vd-appliance-group-template-appliance-list device_group="EXAMPLE_BRANCH" template_name=EXAMPLE_CLIENT-Test-NGFW limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "DeviceGroup": {
            "ca-config-on-branch-notification": false,
            "enable-2factor-auth": false,
            "enable-staging-url": false,
            "inventory-name": [],
            "name": "EXAMPLE_BRANCH",
            "oneTimePassword": false,
            "poststaging-template": "EXAMPLE_CLIENT-Test-NGFW",
            "template-association": [
                {
                    "category": "DataStore",
                    "deviceTemplateStatus": null,
                    "name": "EXAMPLE_CLIENT-DataStore",
                    "organization": "EXAMPLE_CLIENT",
                    "templateAssociationType": "DEVICE_GROUP"
                },
                {
                    "category": "Main",
                    "deviceTemplateStatus": null,
                    "name": "EXAMPLE_CLIENT-Test-NGFW",
                    "organization": "EXAMPLE_CLIENT",
                    "templateAssociationType": "DEVICE_GROUP"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Appliances
>|Name|Poststaging - Template|Template - Association|
>|---|---|---|
>| EXAMPLE_BRANCH | EXAMPLE_CLIENT-Test-NGFW | **-**	***name***: EXAMPLE_CLIENT-DataStore<br/>**-**	***name***: EXAMPLE_CLIENT-Test-NGFW |


### vd-appliance-group-list
***
List all appliance (device) groups associated with an organization (tenant)


#### Base Command

`vd-appliance-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.DeviceGroup.createDate | string | Device group create date. | 
| VersaDirector.DeviceGroup.modifyDate | string | Device group modify date. | 
| VersaDirector.DeviceGroup.lastUpdatedBy | string | Last updated by | 
| VersaDirector.DeviceGroup.name | string | Device group name. | 
| VersaDirector.DeviceGroup.organization | string | Associated organization | 
| VersaDirector.DeviceGroup.poststagingTemplatePriority | number | Post staging template priority | 
| VersaDirector.DeviceGroup.oneTimePassword | string | One time password | 
| VersaDirector.DeviceGroup.poststaging-template | string | Post staging template | 
| VersaDirector.DeviceGroup.enable-2factor-auth | string | Enable two factor authentication | 
| VersaDirector.DeviceGroup.enable-staging-url | string | Enable staging url | 
| VersaDirector.DeviceGroup.inventory-name | String | Inventory name | 

#### Command example
```!vd-appliance-group-list limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "DeviceGroup": {
            "device-group": [
                {
                    "ca-config-on-branch-notification": false,
                    "createDate": "2022-10-05 10:44:26",
                    "enable-2factor-auth": false,
                    "enable-staging-url": false,
                    "inventory-name": [
                        "EXAMPLE_BRANCH"
                    ],
                    "lastUpdatedBy": "christian",
                    "modifyDate": "2022-10-05 10:44:26",
                    "name": "EXAMPLE_BRANCH-DG",
                    "oneTimePassword": false,
                    "organization": "EXAMPLE_CLIENT",
                    "poststaging-template": "EXAMPLE_SITE",
                    "poststagingTemplatePriority": 2
                }
            ],
            "totalCount": 1
        }
    }
}
```

#### Human Readable Output

>### Appliance groups associated with EXAMPLE_CLIENT
>|Name|Organization|Create Date|Inventory - Name|Poststaging - Template|
>|---|---|---|---|---|
>| EXAMPLE_BRANCH-DG | EXAMPLE_CLIENT | 2022-10-05 10:44:26 | EXAMPLE_BRANCH | EXAMPLE_SITE |


### vd-organization-appliance-list
***
List all devices associated with a specific organization


#### Base Command

`vd-organization-appliance-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization | Name of the associated organization. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. default value 0. | Optional | 
| limit | The maximum number of results to retrieve. default value 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.Appliance.name | string | Appliance name. | 
| VersaDirector.Appliance.uuid | string | Appliance UUID | 
| VersaDirector.Appliance.applianceLocation | string | Appliance location | 

#### Command example
```!vd-organization-appliance-list limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "Appliance": {
            "appliances": [
                {
                    "Hardware": {
                        "cpuCores": 0,
                        "cpuCount": 4,
                        "cpuLoad": 2,
                        "cpuModel": "pc-i440fx-2.12",
                        "diskSize": "75.44GiB",
                        "fanless": false,
                        "firmwareVersion": "21.2.3",
                        "freeDisk": "70.78GiB",
                        "freeMemory": "4.11GiB",
                        "hardWareSerialNo": "Not Specified",
                        "intelQuickAssistAcceleration": false,
                        "interfaceCount": 6,
                        "lpm": false,
                        "manufacturer": "QEMU",
                        "memory": "7.58GiB",
                        "model": "Standard PC (i440FX + PIIX, 1996)",
                        "name": "EXAMPLE_BRANCH",
                        "packageName": "EXAMPLE_PACKAGE",
                        "serialNo": "EXAMPLE_BRANCH-SN",
                        "sku": "Not Specified",
                        "ssd": false
                    },
                    "OssPack": {
                        "name": "EXAMPLE_BRANCH",
                        "osspackVersion": "unknown",
                        "updateType": "unknown"
                    },
                    "SPack": {
                        "apiVersion": "11",
                        "flavor": "sample",
                        "name": "EXAMPLE_BRANCH",
                        "releaseDate": "2022-07-22",
                        "spackVersion": "1975",
                        "updateType": "full"
                    },
                    "alarmSummary": {
                        "columnNames": [
                            "columnName 0"
                        ],
                        "monitorType": "Alarms",
                        "rows": [
                            {
                                "columnValues": [
                                    0
                                ],
                                "firstColumnValue": "critical"
                            },
                            {
                                "columnValues": [
                                    3
                                ],
                                "firstColumnValue": "major"
                            },
                            {
                                "columnValues": [
                                    0
                                ],
                                "firstColumnValue": "minor"
                            },
                            {
                                "columnValues": [
                                    0
                                ],
                                "firstColumnValue": "warning"
                            },
                            {
                                "columnValues": [
                                    0
                                ],
                                "firstColumnValue": "indeterminate"
                            },
                            {
                                "columnValues": [
                                    12
                                ],
                                "firstColumnValue": "cleared"
                            }
                        ],
                        "tableId": "Alarms",
                        "tableName": "Alarms"
                    },
                    "appIdDetails": {
                        "appIdAvailableBundleVersion": "EXAMPLE_VERSION ",
                        "appIdInstalledBundleVersion": "EXAMPLE_VERSION ",
                        "appIdInstalledEngineVersion": "EXAMPLE_VERSION "
                    },
                    "applianceCapabilities": {
                        "capabilities": [
                            "path-state-monitor",
                            "bw-in-interface-state",
                            "config-encryption:v3",
                            "route-filter-feature"
                        ]
                    },
                    "applianceLocation": {
                        "applianceName": "EXAMPLE_BRANCH",
                        "applianceUuid": "7aa83cdc-933a-4604-a5e4-06dfbf3c755f",
                        "latitude": "0.",
                        "locationId": "Madrid, Spain",
                        "longitude": "0.",
                        "type": "branch"
                    },
                    "branch-maintenance-mode": false,
                    "branchId": "103",
                    "branchInMaintenanceMode": false,
                    "connector": "local",
                    "connectorType": "local",
                    "controll-status": "Unavailable",
                    "controllers": [
                        "Controller-1"
                    ],
                    "cpeHealth": {
                        "columnNames": [
                            "Category",
                            "Up",
                            "Down",
                            "Disabled"
                        ],
                        "rows": [
                            {
                                "columnValues": [
                                    0,
                                    0,
                                    0
                                ],
                                "firstColumnValue": "Physical Ports"
                            },
                            {
                                "columnValues": [
                                    1,
                                    0,
                                    0
                                ],
                                "firstColumnValue": "Config Sync Status"
                            },
                            {
                                "columnValues": [
                                    1,
                                    0,
                                    0
                                ],
                                "firstColumnValue": "Reachability Status"
                            },
                            {
                                "columnValues": [
                                    1,
                                    0,
                                    0
                                ],
                                "firstColumnValue": "Service Status"
                            }
                        ]
                    },
                    "createdAt": "2022-10-05 11:10:07.561",
                    "deployment": "normal",
                    "inter-chassis-ha-status": {
                        "ha-configured": false
                    },
                    "intra-chassis-ha-status": {
                        "ha-configured": false
                    },
                    "ipAddress": "EXAMPLE_URL",
                    "last-updated-time": "2022-11-13 10:24:39.0",
                    "location": "Madrid, Spain",
                    "lockDetails": {
                        "lockType": "NONE",
                        "user": "EXAMPLE_USER"
                    },
                    "name": "EXAMPLE_BRANCH",
                    "nodes": {
                        "nodeStatusList": {
                            "cpu-load": 2,
                            "host-ip": "NOT-APPLICABLE",
                            "load-factor": 2,
                            "memory-load": 9,
                            "node-type": "VCSN",
                            "slot-id": 0,
                            "vm-name": "NOT-APPLICABLE",
                            "vm-status": "NOT-APPLICABLE"
                        }
                    },
                    "overall-status": "NOT-APPLICABLE",
                    "ownerOrg": "EXAMPLE_CLIENT",
                    "path-status": "Unavailable",
                    "ping-status": "REACHABLE",
                    "refreshCycleCount": 0,
                    "services": [
                        "sdwan",
                        "nextgen-firewall",
                        "cgnat"
                    ],
                    "services-status": "GOOD",
                    "sngCount": 0,
                    "softwareVersion": "21.2.3-GA 67ff6c7 20220730 NORMAL",
                    "startTime": "Mon Nov  7 05:11:42 2022",
                    "sync-status": "IN_SYNC",
                    "type": "branch",
                    "ucpe-nodes": {
                        "ucpeNodeStatusList": []
                    },
                    "unreachable": false,
                    "uuid": "7aa83cdc-933a-4604-a5e4-06dfbf3c755f",
                    "yang-compatibility-status": "Unavailable"
                }
            ],
            "totalCount": 1
        }
    }
}
```

#### Human Readable Output

>### Organization List
>|Name|Ip Address|Type|Software Version|Owner Org|
>|---|---|---|---|---|
>| EXAMPLE_BRANCH | EXAMPLE_URL | branch | 21.2.3-GA 67ff6c7 20220730 NORMAL | EXAMPLE_CLIENT |


### vd-organization-list
***
List all organizations/tenants


#### Base Command

`vd-organization-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.Organization.name | String | Organization name | 
| VersaDirector.Organization.uuid | String | Organization UUID | 
| VersaDirector.Organization.parent | String | Organization parent | 
| VersaDirector.Organization.subscriptionPlan | String | Organization subscription plan | 
| VersaDirector.Organization.id | String | Organization ID | 
| VersaDirector.Organization.authType | String | Organization auth type | 
| VersaDirector.Organization.cpeDeploymentType | String | Organization CPE deployment type | 
| VersaDirector.Organization.appliances | String | Organization appliances | 
| VersaDirector.Organization.vrfsGroups | String | Organization VRFS groups | 
| VersaDirector.Organization.wanNetworkGroups | String | Organization WAN network groups | 
| VersaDirector.Organization.analyticsClusters | String | Organization analytics clusters | 
| VersaDirector.Organization.sharedControlPlane | String | Organization shared control plane | 
| VersaDirector.Organization.blockInterRegionRouting | String | Organization blockInter region routing | 

#### Command example
```!vd-organization-list limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "Organization": [
            {
                "analyticsClusters": [
                    "Analytics-Cluster"
                ],
                "appliances": [
                    "0fe816fd-225b-47a3-b299-32079904520a",
                    "7aa83cdc-933a-4604-a5e4-06dfbf3c755f"
                ],
                "authType": "psk",
                "blockInterRegionRouting": false,
                "cpeDeploymentType": "SDWAN",
                "dynamicTenantConfig": {
                    "inactivityInterval": 48,
                    "uuid": "5b0dbe83-4195-4e44-ac5a-3af342d4932f"
                },
                "id": 168,
                "name": "EXAMPLE_CLIENT",
                "parent": "Versa",
                "sharedControlPlane": false,
                "subscriptionPlan": "EXAMPLE_PLAN",
                "uuid": "64ae7957-1fa0-4c11-a724-b4ebf8e47b45",
                "vrfsGroups": [
                    {
                        "description": null,
                        "enable_vpn": true,
                        "id": 334,
                        "name": "EXAMPLE_CLIENT-LAN-VR",
                        "vrfId": 152
                    }
                ],
                "wanNetworkGroups": [
                    {
                        "description": "",
                        "id": 1264,
                        "name": "INET",
                        "transport-domains": [
                            "Internet"
                        ]
                    },
                    {
                        "description": "",
                        "id": 1265,
                        "name": "INET-2",
                        "transport-domains": [
                            "Internet"
                        ]
                    },
                    {
                        "description": "",
                        "id": 1266,
                        "name": "LTE",
                        "transport-domains": [
                            "Internet"
                        ]
                    },
                    {
                        "description": "",
                        "id": 1267,
                        "name": "MPLS",
                        "transport-domains": [
                            "MPLS"
                        ]
                    },
                    {
                        "description": "",
                        "id": 1268,
                        "name": "MPLS-2",
                        "transport-domains": [
                            "MPLS-2"
                        ]
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Organization List
>|Name|Id|Parent|Appliances|Cpe Deployment Type|Uuid|
>|---|---|---|---|---|---|
>| EXAMPLE_CLIENT | 168 | Versa | 0fe816fd-225b-47a3-b299-32079904520a,<br/>7aa83cdc-933a-4604-a5e4-06dfbf3c755f | SDWAN | 64ae7957-1fa0-4c11-a724-b4ebf8e47b45 |


### vd-appliance-list
***
List all available appliances for all organizations/tenants, with a limit of max 25 appliances per organization


#### Base Command

`vd-appliance-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of objects to retrieve per page. | Optional | 
| limit | Limit number of results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VersaDirector.Appliance.name | String | Appliance name. | 
| VersaDirector.Appliance.uuid | String | Appliance UUID | 
| VersaDirector.Appliance.ipAddress | String | Appliance IP address | 
| VersaDirector.Appliance.appType | String | Appliance application type | 
| VersaDirector.Appliance.branchId | Number | Application branch ID | 

#### Command example
```!vd-appliance-list limit=3```
#### Context Example
```json
{
    "VersaDirector": {
        "Appliance": {
            "appliance-list": [
                {
                    "appType": "branch",
                    "branchId": 103,
                    "ipAddress": "EXAMPLE_URL",
                    "name": "EXAMPLE_BRANCH",
                    "uuid": "7aa83cdc-933a-4604-a5e4-06dfbf3c755f"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Appliances
>|Name|Uuid|Ip Address|App Type|Branch Id|
>|---|---|---|---|---|
>| EXAMPLE_BRANCH | 7aa83cdc-933a-4604-a5e4-06dfbf3c755f | EXAMPLE_URL | branch | 103 |


### vd-auth-start
***
Obtain Access token from api client.


#### Base Command

`vd-auth-start`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| token_name | Name of access token. If an excising token name will be given as argument, an error might occur. | Required | 
| description | Description of access token. | Optional | 


#### Context Output

There is no context output for this command.
### vd-auth-complete
***
Obtain Auth token from the auth client.


#### Base Command

`vd-auth-complete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| client_id | client id for Token Authentication. | Required | 
| client_secret | client secret for Token Authentication. | Required | 


#### Context Output

There is no context output for this command.