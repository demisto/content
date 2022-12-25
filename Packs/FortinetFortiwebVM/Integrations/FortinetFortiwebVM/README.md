Fortiweb VM integration allows to manage WAF policies and block cookies, URLs, and hostnames.
This integration was integrated and tested with version xx of fortiweb_vm

## Configure Fortiweb VM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Fortiweb VM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | The API Key. | True |
    | API Version | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fortiwebvm-protected-hostname-group-create
***
Create Protected Hostname Group.


#### Base Command

`fortiwebvm-protected-hostname-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Protected Hostname Group Name. | Required | 
| default_action | Select whether to accept or deny HTTP requests whose Host: field does not match any of the host definitions that you will add to this protected hosts group. Possible values are: Allow, Deny (no log), Deny. Default is Allow. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-protected-hostname-group-create name=example```
#### Human Readable Output

>### Hostname group successfully created!
>|Name|
>|---|
>| example |


### fortiwebvm-protected-hostname-group-update
***
Update Protected Hostname Group.


#### Base Command

`fortiwebvm-protected-hostname-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Protected Hostname Group Name. | Required | 
| default_action | Select whether to accept or deny HTTP requests whose Host: field does not match any of the host definitions that you will add to this protected hosts group. Possible values are: Allow, Deny (no log), Deny. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-protected-hostname-group-update name=example default_action=Deny```
#### Human Readable Output

>### Hostname group successfully updated!
>|Name|
>|---|
>| example |


### fortiwebvm-protected-hostname-group-list
***
List the Protected Hostname groups.


#### Base Command

`fortiwebvm-protected-hostname-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Protected Hostname Group Name. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ProtectedHostnameGroup.id | String | Protected Hostname Group ID. | 
| FortiwebVM.ProtectedHostnameGroup.default_action | Number | Protected Hostname Group Action. | 
| FortiwebVM.ProtectedHostnameGroup.protected_hostname_count | Number | Protected Hostname Group members number. | 
| FortiwebVM.ProtectedHostnameGroup.can_delete | Boolean | Can deleted flag. Supports API version 1 only. | 

#### Command example
```!fortiwebvm-protected-hostname-group-list name=example```
#### Context Example - API Version 1
```json
{
    "FortiwebVM": {
        "ProtectedHostnameGroup": {
            "can_delete": true,
            "default_action": "Allow",
            "id": "example",
            "protected_hostname_count": 0
        }
    }
}
```

#### Human Readable Output - API Version 1

>### Protected Hostnames Groups:
>Showing 1 rows out of 1.
>|Id|Default Action|Protected Hostname Count|Can Delete|
>|---|---|---|---|
>| example | Allow | 0 | true |

#### Context Example - API Version 2

```json
{
    "FortiwebVM": {
        "ProtectedHostnameGroup": {
            "default_action": "Allow",
            "id": "example",
            "protected_hostname_count": 0
        }
    }
}
```


#### Human Readable Output - API Version 2


>### Protected Hostnames Groups:
>Showing 1 rows out of 1.
>|Id|Default Action|Protected Hostname Count|
>|---|---|---|
>| example | Allow | 0 |


### fortiwebvm-protected-hostname-member-create
***
Create Protected Hostname Member (Protected Hostname Member is a sub-object of Protected Hostname Group).


#### Base Command

`fortiwebvm-protected-hostname-member-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Protected Hostname Group Name. | Required | 
| action | Select whether to accept or deny HTTP requests whose Host. Possible values are: Allow, Deny (no log), Deny. Default is Allow. | Optional | 
| host | Enter the IP address or FQDN of a virtual or real web host, as it appears in the Host: field of HTTP headers, such as www.example.com. The maximum length is 256 characters. | Required | 
| ignore_port | Enable ignore-port so that the host names with port number will be protected. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional | 
| include_subdomains | Enable include-subdomains so that the sub domains of the host will be protected. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ProtectedHostnameMember.id | String | Protected Hostname Member ID | 

#### Command example
```!fortiwebvm-protected-hostname-member-create group_name=example host=1.2.3.4 action=Deny```
#### Context Example
```json
{
    "FortiwebVM": {
        "ProtectedHostnameMember": {
            "id": "1"
        }
    }
}
```

#### Human Readable Output

>### Hostname member successfully created!
>|Id|
>|---|
>| 1 |


### fortiwebvm-protected-hostname-member-update
***
Update protected Hostname Member (Protected Hostname Member is a member of Protected Hostname).


#### Base Command

`fortiwebvm-protected-hostname-member-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Protected Hostname Group Name. | Required | 
| member_id | Protected hostname member ID. | Required | 
| action | Select whether to accept or deny HTTP requests whose Host.Requiered in V1. Possible values are: Allow, Deny (no log), Deny. | Optional | 
| host | Enter the IP address or FQDN of a virtual or real web host, as it appears in the Host: field of HTTP headers, such as www.example.com. The maximum length is 256 characters. | Optional | 
| ignore_port | Enable ignore-port so that the host names with port number will be protected. Supports API version 2 only. Possible values are: enable, disable. | Optional | 
| include_subdomains | Enable include-subdomains so that the sub domains of the host will be protected. Supports API version 2 only. Possible values are: enable, disable. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-protected-hostname-member-update group_name=example member_id=1 action=Allow```
#### Human Readable Output

>### Hostname member successfully updated!
>|Id|
>|---|
>| 1 |


### fortiwebvm-protected-hostname-member-list
***
List all the Protected Hostname Members (Protected Hostname Member is a member of Protected Hostname).


#### Base Command

`fortiwebvm-protected-hostname-member-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Protected Hostname Group Name. | Required | 
| member_id | Protected Hostname Member ID. | Optional | 
| page | The page number of the results to retrieve. Default is 25. | Optional | 
| page_size | A number of hostname members per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ProtectedHostnameMember.group_name | String | Protected Hostname Group Name. | 
| FortiwebVM.ProtectedHostnameMember.Members.id | String | Protected Hostname Member ID. | 
| FortiwebVM.ProtectedHostnameMember.Members.action | String | Protected Hostname Member Action. | 
| FortiwebVM.ProtectedHostnameMember.Members.host | String | Protected Hostname Member IP Address. | 
| FortiwebVM.ProtectedHostnameMember.Members.ignore_port | String | Protected Hostname Member Ignore Port. Supports API version 2 only. | 
| FortiwebVM.ProtectedHostnameMember.Members.include_subdomains | String | Protected Hostname Member Include Subdomains. Supports API version 2 only. | 

#### Command example
```!fortiwebvm-protected-hostname-member-list group_name=example member_id=1```
#### Context Example - API Version 1
```json
{
    "FortiwebVM": {
        "ProtectedHostnameMember": {
            "Members": [
                {
                    "action": "Deny",
                    "host": "1.2.3.4",
                    "id": "1"
                }
            ],
            "group_name": "example"
        }
    }
}
```

#### Human Readable Output - API Version 1

>### Protected Hostnames Members:
>Showing 1 rows out of 1.
>|Id|Action|Host|
>|---|---|---|
>| 1 | Deny | 1.2.3.4 |

#### Context Example - API Version 2
```json
{
    "FortiwebVM": {
        "ProtectedHostnameMember": {
            "Members": [
                {
                    "action": "Deny",
                    "host": "1.2.3.4",
                    "id": "1",
                    "ignore_port": "disable",
                    "include_subdomains": "disable"
                }
            ],
            "group_name": "example"
        }
    }
}
```

#### Human Readable Output - API Version 2

>### Protected Hostnames Members:
>Showing 1 rows out of 1.
>|Id|Action|Host|Ignore Port|Include Subdomains|
>|---|---|---|---|---|
>| 1 | Deny | 1.2.3.4 | disable | disable |

### fortiwebvm-protected-hostname-member-delete
***
Delete Protected Hostname Member (Protected Hostname Member is a member of Protected Hostname).


#### Base Command

`fortiwebvm-protected-hostname-member-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Protected Hostname Group Name. | Required | 
| member_id | Protected Hostname Member ID. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-protected-hostname-member-delete group_name=example member_id=1```
#### Human Readable Output

>### Hostname member successfully deleted!
>|Id|
>|---|
>| 1 |


### fortiwebvm-protected-hostname-group-delete
***
Delete Protected Hostname.


#### Base Command

`fortiwebvm-protected-hostname-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Protected Hostname Group Name. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-protected-hostname-group-delete name=example```
#### Human Readable Output

>### Hostname group successfully deleted!
>|Name|
>|---|
>| example |


There is no context output for this command.
### fortiwebvm-ip-list-group-create
***
Create IP List.


#### Base Command

`fortiwebvm-ip-list-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | IP List Group Name. | Required | 
| action | Select which action FortiWeb will take when it detects a violation of the rule. Supports API version 2 only. Possible values are: Alert deny, Block period, Deny (no log). Default is Alert deny. | Optional | 
| block_period | Enter the number of seconds that you want to block subsequent requests from a client after FortiWeb detects that the client has violated the rule. The valid range is 1–3,600 seconds. Supports API version 2 only. Default is 600. | Optional | 
| severity | Select which severity level the FortiWeb appliance will use when a blacklisted IP address attempts to connect to your web servers.Supports API version 2 only. Possible values are: Low, Medium, High, Info. Default is Low. | Optional | 
| ignore_x_forwarded_for | enable Ignore X-Forwarded-For so that the IP addresses will be scanned at the TCP layer instead of HTTP layer. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional | 
| trigger_policy | Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a blacklisted IP address’s attempt to connect to your web serversSupports API version 2 only. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-ip-list-group-create name=example```
#### Human Readable Output

>### IP List group successfully created!
>|Name|
>|---|
>| example |


### fortiwebvm-ip-list-group-update
***
Update IP List.


#### Base Command

`fortiwebvm-ip-list-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | IP list group name. | Required | 
| action | Select which action FortiWeb will take when it detects a violation of the rule. Supports API version 2 only. Possible values are: Alert deny, Block period, Deny (no log). | Optional | 
| block_period | Enter the number of seconds that you want to block subsequent requests from a client after FortiWeb detects that the client has violated the rule. The valid range is 1–3,600 seconds. Supports API version 2 only. | Optional | 
| severity | Select which severity level the FortiWeb appliance will use when a blacklisted IP address attempts to connect to your web servers. Supports API version 2 only. Possible values are: Low, Medium, High, Info. | Optional | 
| ignore_x_forwarded_for | enable Ignore X-Forwarded-For so that the IP addresses will be scanned at the TCP layer instead of HTTP layer. Supports API version 2 only. Possible values are: enable, disable. | Optional | 
| trigger_policy | Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a blacklisted IP address’s attempt to connect to your web serversSupports API version 2 only. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-ip-list-group-update name=example block_period=550```
#### Human Readable Output

>### IP List group successfully updated!
>|Name|
>|---|
>| example |


### fortiwebvm-ip-list-group-list
***
Supports API versions 1 & 2.


#### Base Command

`fortiwebvm-ip-list-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | IP List Name. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.IpListGroup.id | String | IP list id. | 
| FortiwebVM.IpListGroup.ip_list_count | Number | IP list members number. | 
| FortiwebVM.IpListGroup.can_delete | Boolean | Can delete flag. Supports API version 1 only. | 
| FortiwebVM.IpListGroup.q_ref | Number | The CMDB reference count. Supports API version 2 only. | 
| FortiwebVM.IpListGroup.q_type | Number | IP list group object type. Supports API version 2 only. | 
| FortiwebVM.IpListGroup.can_clone | Number | Can clone flag. Supports API version 2 only. | 
| FortiwebVM.IpListGroup.block_period | Number | IP list group Block Period. Supports API version 2 only. | 
| FortiwebVM.IpListGroup.can_view | Number | Can view flag. Supports API version 2 only. | 
| FortiwebVM.IpListGroup.action | String | IP list group Action. Supports API version 2 only. | 
| FortiwebVM.IpListGroup.trigger_policy | String | IP list group Trigger Policy Name. Supports API version 2 only. | 
| FortiwebVM.IpListGroup.severity | String | IP list group Severity. Supports API version 2 only. | 

#### Command example - API Version 1
```!fortiwebvm-ip-list-group-list name=example```
#### Context Example
```json
{
    "FortiwebVM": {
        "IpListGroup": {
            "can_delete": true,
            "id": "example",
            "ip_list_count": 0
        }
    }
}
```

#### Human Readable Output - API Version 1

>### IP Lists Groups:
>Showing 1 rows out of 1.
>|Id|Ip List Count|
>|---|---|
>| example | 0 |

#### Context Example - API Version 2
```json
{
    "FortiwebVM": {
        "IpListGroup": {
            "action": "alert_deny",
            "block_period": 550,
            "can_clone": 1,
            "can_view": 0,
            "id": "example",
            "ip_list_count": 0,
            "q_ref": 0,
            "q_type": 1,
            "severity": "Low",
            "trigger_policy": ""
        }
    }
}
```

#### Human Readable Output - API Version 2

>### IP Lists Groups:
>Showing 1 rows out of 1.
>|Id|Ip List Count|Action|Block Period|Severity|Trigger Policy|
>|---|---|---|---|---|---|
>| example | 0 | alert_deny | 550 | Low |  |


### fortiwebvm-ip-list-member-create
***
Supports API versions 1 & 2.


#### Base Command

`fortiwebvm-ip-list-member-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | IP List Group Name. | Required | 
| type | The type of the source IP address . Possible values are: Trust IP, Black IP, Allow Only Ip. | Required | 
| ip_address | IPv4/IPv6/IP Range. | Required | 
| severity | Select which severity level the FortiWeb appliance will use when a blacklisted IP address attempts to connect to your web servers:Supports API version 1 only.Required when type= "Black Ip". Possible values are: High, Medium, Low, Informative. Default is Medium. | Optional | 
| trigger_policy | Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a blacklisted IP address’s attempt to connect to your web serversSupports API version 1 only.Required when type= "Black Ip". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.IpListMember.id | Number | IP List Policy Member ID | 

#### Command example
```!fortiwebvm-ip-list-member-create group_name=example ip_address=1.2.3.4 type="Black IP"```
#### Context Example
```json
{
    "FortiwebVM": {
        "IpListMember": {
            "id": "1"
        }
    }
}
```

#### Human Readable Output

>### IP List member successfully created!
>|Id|
>|---|
>| 1 |


### fortiwebvm-ip-list-member-update
***
Update IP List Policy Member (IP List Policy Member is a member of IP List).


#### Base Command

`fortiwebvm-ip-list-member-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | IP List Group Name. | Required | 
| member_id | IP List Policy Member id. | Required | 
| type | The type of the source IP address . Possible values are: Trust IP, Black IP, Allow Only Ip. | Optional | 
| ip_address | IPv4/IPv6/IP Range. | Optional | 
| severity | Select which severity level the FortiWeb appliance will use when a blacklisted IP address attempts to connect to your web servers:Supports API version 1 only.Required when type= "Black Ip". Possible values are: High, Medium, Low, Informative. | Optional | 
| trigger_policy | Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a blacklisted IP address’s attempt to connect to your web serversSupports API version 1 only.Required when type= "Black Ip". | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-ip-list-member-update group_name=example member_id=1 ip_address=1.2.3.6```
#### Human Readable Output

>### IP List member successfully updated!
>|Id|
>|---|
>| 1 |


### fortiwebvm-ip-list-member-list
***
List the IP List Policy Member(IP List Policy Member is a member of IP List).


#### Base Command

`fortiwebvm-ip-list-member-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | IP List Group Name. | Required | 
| member_id | IP List Member ID. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.IpListMember.group_name | String | IP list Group Name. | 
| FortiwebVM.IpListMember.Members.id | String | IP list Member ID. | 
| FortiwebVM.IpListMember.Members.type | String | IP list Member Type. | 
| FortiwebVM.IpListMember.Members.severity | String | IP list Member Severity. Supports API version 1 only. | 
| FortiwebVM.IpListMember.Members.trigger_policy | String | IP list Member Trigger Policy. Supports API version 1 only. | 
| FortiwebVM.IpListMember.Members.ip | String | IP list Member IP Address. | 

#### Command example
```!fortiwebvm-ip-list-member-list group_name=example```
#### Context Example - API Version 1
```json
{
    "FortiwebVM": {
        "IpListMember": {
            "Members": [
                {
                    "id": "1",
                    "ip": "1.2.3.4",
                    "severity": "Medium",
                    "trigger_policy": "",
                    "type": "Black IP"
                }
            ],
            "group_name": "example"
        }
    }
}
```

#### Human Readable Output - API Version 1

>### IP Lists Members:
>Showing 1 rows out of 1.
>|Id|Type|Ip|Severity|Trigger Policy|
>|---|---|---|---|---|
>| 1 | Black IP | 1.2.3.4 | Medium |  |


#### Context Example - API Version 2
```json
{
    "FortiwebVM": {
        "IpListMember": {
            "Members": [
                {
                    "id": "1",
                    "ip": "1.2.3.4",
                    "type": "Black IP"
                }
            ],
            "group_name": "example"
        }
    }
}
```

#### Human Readable Output - API Version 2

>### IP Lists Members:
>Showing 1 rows out of 1.
>|Id|Type|Ip|
>|---|---|---|
>| 1 | Black IP | 1.2.3.4 |

### fortiwebvm-ip-list-member-delete
***
Delete IP List Policy Member (IP List Policy Member is a member of IP List).


#### Base Command

`fortiwebvm-ip-list-member-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | IP List Group Name. | Required | 
| member_id | IP List Policy Member ID. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-ip-list-member-delete group_name=example member_id=1```
#### Human Readable Output

>### IP List member successfully deleted!
>|Id|
>|---|
>| 1 |


### fortiwebvm-ip-list-group-delete
***
Supports API versions 1 & 2.


#### Base Command

`fortiwebvm-ip-list-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | IP list group name. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-ip-list-group-delete name=example```
#### Human Readable Output

>### IP List group successfully deleted!
>|Id|
>|---|
>| example |


### fortiwebvm-custom-predefined-whitelist-update
***
Update Custom Predefined Global Whitelist.


#### Base Command

`fortiwebvm-custom-predefined-whitelist-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Predefined Global White List ID. | Required | 
| status | Status. Possible values are: enable, disable. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-custom-predefined-whitelist-update id=10002 status=disable```
#### Human Readable Output

>### Custom predifined whitelist member successfully updated!
>|Id|
>|---|
>| 10002 |


### fortiwebvm-custom-predefined-whitelist-list
***
Get Custom Predefined Global Whitelist.


#### Base Command

`fortiwebvm-custom-predefined-whitelist-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom Predifined White List ID. | Optional | 
| type | Type. Possible values are: URL, Parameter, Cookie, Header Field. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomPredefinedGlobalWhitelist.id | Number | Predefined Global White List Member ID. | 
| FortiwebVM.CustomPredefinedGlobalWhitelist.name | String | Predefined Global White List Member Name. | 
| FortiwebVM.CustomPredefinedGlobalWhitelist.path | String | Predefined Global White List Member Path. | 
| FortiwebVM.CustomPredefinedGlobalWhitelist.domain | String | Predefined Global White List Member Domain. | 
| FortiwebVM.CustomPredefinedGlobalWhitelist.status | Boolean | Predefined Global White List Member Status. | 

#### Command example
```!fortiwebvm-custom-predefined-whitelist-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "CustomPredefinedGlobalWhitelist": {
            "domain": "",
            "id": 100002,
            "name": "",
            "path": "/browserconfig.xml",
            "status": true
        }
    }
}
```

#### Human Readable Output

>### Custom whitelist members:
>Showing 1 rows out of 36.
>|Id|Name|Path|Domain|Status|
>|---|---|---|---|---|
>| 100002 |  | /browserconfig.xml |  | true |


### fortiwebvm-custom-whitelist-url-create
***
Create Custom Global White List URL Object (Custom Global White List URL Object is an object of Custom Global White List).


#### Base Command

`fortiwebvm-custom-whitelist-url-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_type | Indicate whether the request-file "&lt;url_str&gt;" field contains a literal URL (plain), or a regular expression designed to match multiple URLs (regular). Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional | 
| request_url | Depending on your selection in the request-type {plain \| regular} field, enter either:The literal URL, such as /robots.txt, that the HTTP request must contain in order to match the rule. The URL must begin with a backslash ( / ).A regular expression, such as ^/*.html, matching all and only the URLs to which the rule should apply. The pattern does not require a slash ( / ); however, it must at match URLs that begin with a backslash, such as /index.html. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomGlobalWhitelist.id | Number | Custom Global Whitelist ID | 

#### Command example
```!fortiwebvm-custom-whitelist-url-create request_url=/123```
#### Context Example
```json
{
    "FortiwebVM": {
        "CustomGlobalWhitelist": {
            "id": 1
        }
    }
}
```

#### Human Readable Output

>### Custom whitelist URL member succesfuly created!
>|Id|
>|---|
>| 1 |


### fortiwebvm-custom-whitelist-parameter-create
***
Create Custom Global White List Parameter Object (Custom Global White List Parameter Object is an object of Custom Global White List).


#### Base Command

`fortiwebvm-custom-whitelist-parameter-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_type | Indicate whether the request-file "&lt;url_str&gt;" field contains a literal URL (plain), or a regular expression designed to match multiple URLs (regular). Supports API version 2 only.Required when request_url_status= True. Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional | 
| request_url | Depending on your selection in the request-type {plain \| regular} field, enter either:The literal URL, such as /robots.txt, that the HTTP request must contain in order to match the rule. The URL must begin with a backslash ( / ).A regular expression, such as ^/*.html, matching all and only the URLs to which the rule should apply. The pattern does not require a slash ( / ); however, it must at match URLs that begin with a backslash, such as /index.html. Supports API version 2 only.Required when request_url_status= True. | Optional | 
| name | Enter the name of the parameter as it appears in the HTTP URL or body, such as rememberme. | Required | 
| name_type | Indicate whether the name "&lt;name_str&gt;" field will contain a literal parameter name (Simple String), or a regular expression designed to match all parameter names (Regular Expression). Supports API version 2 only. Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional | 
| request_url_status | Enable to apply this rule only to HTTP requests for specific URLs. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional | 
| domain_status | Enable to apply this rule only to HTTP requests for specific domains. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional | 
| domain_type | Indicate whether the domain "&lt;cookie_str&gt;" field will contain a literal domain/IP address (Simple String), or a regular expression designed to match multiple domains/IP addresses (Regular Expression). Supports API version 2 only.Required when request_url_status= True. Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional | 
| domain | Enter the partial or complete domain name or IP address as it appears in the cookieSupports API version 2 only.Required when request_url_status= True. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomGlobalWhitelist.id | Number | Custom Global Whitelist ID | 

#### Command example
```!fortiwebvm-custom-whitelist-parameter-create name=example```
#### Context Example
```json
{
    "FortiwebVM": {
        "CustomGlobalWhitelist": {
            "id": 2
        }
    }
}
```

#### Human Readable Output

>### Custom whitelist Parameter member succesfuly created!
>|Id|
>|---|
>| 2 |


### fortiwebvm-custom-whitelist-cookie-create
***
Create Custom Global White List Cookie Object (Custom Global White List Cookie  Object is an object of Custom Global White List).


#### Base Command

`fortiwebvm-custom-whitelist-cookie-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Enter the name of the cookie as it appears in the HTTP request, such as NID. | Required | 
| domain | Enter the partial or complete domain name or IP address as it appears in the cookie. | Optional | 
| path | Enter the path as it appears in the cookie. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomGlobalWhitelist.id | Number | Custom Global Whitelist ID | 

#### Command example
```!fortiwebvm-custom-whitelist-cookie-create name=example domain=abc path=/abc```
#### Context Example
```json
{
    "FortiwebVM": {
        "CustomGlobalWhitelist": {
            "id": 2
        }
    }
}
```

#### Human Readable Output

>### Custom whitelist Cookie member succesfuly created!
>|Id|
>|---|
>| 2 |


### fortiwebvm-custom-whitelist-header-field-create
***
Create Custom Global White List Header Field Object (Custom Global White List Header Field Object is an object of Custom Global White List). Supports API version 2 only.


#### Base Command

`fortiwebvm-custom-whitelist-header-field-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Enter the name of the cookie as it appears in the HTTP header. | Required | 
| header_name_type | Indicate whether the type field will contain a literal name (plain), or a regular expression designed to match multiple names (regular). Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional | 
| value_status | Enable to also check the value of the HTTP header. Only the HTTP headers which match both the name and the value will be allowlisted. Possible values are: enable, disable. Default is disable. | Optional | 
| header_value_type | Indicate whether the header name will contain a literal name (plain), or a regular expression designed to match multiple names (regular). Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional | 
| value | The value of the HTTP header.Required when: value_status is enable. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomGlobalWhitelist.id | Number | Custom Global Whitelist ID | 

### fortiwebvm-custom-whitelist-url-update
***
Update Custom Global White List URL Object (Custom Global White List URL Object is an object of Custom Global White List).


#### Base Command

`fortiwebvm-custom-whitelist-url-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom Global Whitelist Object ID. | Required | 
| status | Status. Enable to exempt this object from all scans. Possible values are: enable, disable. Default is enable. | Optional | 
| request_type | Indicate whether the request-file "&lt;url_str&gt;" field contains a literal URL (plain), or a regular expression designed to match multiple URLs (regular). Possible values are: Simple String, Regular Expression. | Optional | 
| request_url | Depending on your selection in the request-type {plain \| regular} field, enter either:The literal URL, such as /robots.txt, that the HTTP request must contain in order to match the rule. The URL must begin with a backslash ( / ).A regular expression, such as ^/*.html, matching all and only the URLs to which the rule should apply. The pattern does not require a slash ( / ); however, it must at match URLs that begin with a backslash, such as /index.html. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-custom-whitelist-url-update id=1 status=disable```
#### Human Readable Output

>### Custom whitelist URL member succesfuly updated!
>|Id|
>|---|
>| 1 |


### fortiwebvm-custom-whitelist-parameter-update
***
Update Custom Global White List Parameter Object (Custom Global White List Parameter Object is an object of Custom Global White List).


#### Base Command

`fortiwebvm-custom-whitelist-parameter-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom Global Whitelist Object ID. | Required | 
| status | Status. Enable to exempt this object from all scans. Possible values are: enable, disable. Default is enable. | Optional | 
| request_type | Indicate whether the request-file "&lt;url_str&gt;" field contains a literal URL (plain), or a regular expression designed to match multiple URLs (regular). Supports API version 2 only.Required when request_url_status= True. Possible values are: Simple String, Regular Expression. Default is enable. | Optional | 
| request_url | Depending on your selection in the request-type {plain \| regular} field, enter either:The literal URL, such as /robots.txt, that the HTTP request must contain in order to match the rule. The URL must begin with a backslash ( / ).A regular expression, such as ^/*.html, matching all and only the URLs to which the rule should apply. The pattern does not require a slash ( / ); however, it must at match URLs that begin with a backslash, such as /index.html. Supports API version 2 only.Required when request_url_status= True. | Optional | 
| name | Name. | Optional | 
| name_type | Indicate whether the name "&lt;name_str&gt;" field will contain a literal parameter name (Simple String), or a regular expression designed to match all parameter names (Regular Expression). Supports API version 2 only. Possible values are: Simple String, Regular Expression. | Optional | 
| request_url_status | Enable to apply this rule only to HTTP requests for specific URLs. Supports. Possible values are: enable, disable. | Optional | 
| domain_status | Enable to apply this rule only to HTTP requests for specific domains. Supports. Possible values are: enable, disable. | Optional | 
| domain_type | Indicate whether the domain "&lt;cookie_str&gt;" field will contain a literal domain/IP address (Simple String), or a regular expression designed to match multiple domains/IP addresses (Regular Expression). Supports API version 2 only.Required when request_url_status= True. Possible values are: Simple String, Regular Expression. | Optional | 
| domain | Enter the partial or complete domain name or IP address as it appears in the cookieSupports API version 2 only.Required when request_url_status= True. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-custom-whitelist-parameter-update id=2 status=disable```
#### Human Readable Output

>### Custom whitelist Parameter member succesfuly updated!
>|Id|
>|---|
>| 2 |


### fortiwebvm-custom-whitelist-cookie-update
***
Update Custom Global White List Cookie Object (Custom Global White List Cookie  Object is an object of Custom Global White List).


#### Base Command

`fortiwebvm-custom-whitelist-cookie-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom Global Whitelist Object ID. | Required | 
| status | Status. Enable to exempt this object from all scans. Possible values are: enable, disable. Default is enable. | Optional | 
| name | Enter the name of the cookie as it appears in the HTTP request, such as NID. | Optional | 
| domain | Enter the partial or complete domain name or IP address as it appears in the cookie. | Optional | 
| path | Enter the path as it appears in the cookie. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-custom-whitelist-cookie-update id=3 status=disable```
#### Human Readable Output

>### Custom whitelist Cookie member succesfuly updated!
>|Id|
>|---|
>| 3 |


### fortiwebvm-custom-whitelist-header-field-update
***
Update Custom Global White List Header Field Object (Custom Global White List Header Field Object is an object of Custom Global White List). Supports API version 2 only.


#### Base Command

`fortiwebvm-custom-whitelist-header-field-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom Global Whitelist Object ID. | Required | 
| status | Status. Enable to exempt this object from all scans. Possible values are: enable, disable. Default is enable. | Optional | 
| header_name_type | Indicate whether the type field will contain a literal name (plain), or a regular expression designed to match multiple names (regular). Possible values are: Simple String, Regular Expression. | Optional | 
| name | Enter the name of the cookie as it appears in the HTTP header. | Optional | 
| header_value_type | Indicate whether the header name will contain a literal name (plain), or a regular expression designed to match multiple names (regular). Possible values are: Simple String, Regular Expression. | Optional | 
| value_status | Enable to also check the value of the HTTP header. Only the HTTP headers which match both the name and the value will be allowlisted. Possible values are: enable, disable. | Optional | 
| value | The value of the HTTP header.Required when value_status is enable. | Optional | 


#### Context Output

There is no context output for this command.
### fortiwebvm-custom-whitelist-delete
***
Delete Custom Global White List Object from Custom Global White List.


#### Base Command

`fortiwebvm-custom-whitelist-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Object id number. | Required | 


#### Context Output

There is no context output for this command.
### fortiwebvm-custom-whitelist-list
***
List the Custom Global Whitelist Objects.


#### Base Command

`fortiwebvm-custom-whitelist-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom Global Whitelist Object ID. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomGlobalWhitelist.id | Number | Custom Global Whitelist object ID. | 
| FortiwebVM.CustomGlobalWhitelist.name | Number | Custom Global Whitelist object Name. | 
| FortiwebVM.CustomGlobalWhitelist.type | Number | Custom Global Whitelist object Type. | 
| FortiwebVM.CustomGlobalWhitelist.status | Boolean | Custom Global Whitelist object status. | 
| FortiwebVM.CustomGlobalWhitelist.request_type | Number | Custom Global Whitelist object Request Type. | 
| FortiwebVM.CustomGlobalWhitelist.request_url | String | Custom Global Whitelist object Request URL. | 
| FortiwebVM.CustomGlobalWhitelist.header_name_type | String | Custom Global Whitelist object Header Type. Supports API version 2 only. | 
| FortiwebVM.CustomGlobalWhitelist.domain_type | String | Custom Global Whitelist object Domain Type. Supports API version 2 only. | 
| FortiwebVM.CustomGlobalWhitelist.name_type | String | Custom Global Whitelist object Name Type.  Supports API version 2 only. | 
| FortiwebVM.CustomGlobalWhitelist.request_url_status | String | Custom Global Whitelist object Request File Status. Supports API version 2 only. | 
| FortiwebVM.CustomGlobalWhitelist.domain_status | String | Custom Global Whitelist object Domain Status. Supports API version 2 only. | 
| FortiwebVM.CustomGlobalWhitelist.domain | String | Custom Global Whitelist object Domain. Supports API version 2 only. | 
| FortiwebVM.CustomGlobalWhitelist.path | String | Custom Global Whitelist object Path. Supports API version 2 only. | 
| FortiwebVM.CustomGlobalWhitelist.header_value_type | String | Custom Global Whitelist object Value Type. Supports API version 2 only. | 
| FortiwebVM.CustomGlobalWhitelist.value | String | Custom Global Whitelist object Value. Supports API version 2 only. | 
| FortiwebVM.CustomGlobalWhitelist.value_status | String | Custom Global Whitelist object Value Status. Supports API version 2 only. | 

#### Command example
```!fortiwebvm-custom-whitelist-list limit=1```
#### Context Example - API Version 1
```json
{
    "FortiwebVM": {
        "CustomGlobalWhitelist": {
            "domain": "",
            "id": 1,
            "name": "",
            "path": "",
            "request_type": "Simple String",
            "request_url": "/123",
            "status": false,
            "type": "URL"
        }
    }
}
```
#### Human Readable Output - API Version 1

>### Custom whitelist members:
>Showing 1 rows out of 3.
>|Id|Name|Request Url|Path|Domain|Status|
>|---|---|---|---|---|---|
>| 1 |  | /123 |  |  | false |

#### Context Example - API Version 2
```json
{
    "FortiwebVM": {
        "CustomGlobalWhitelist": {
            "domain": "",
            "domain_status": "disable",
            "domain_type": "",
            "header_name_type": "",
            "header_value_type": "",
            "id": "1",
            "name": "",
            "name_type": "",
            "path": "",
            "request_type": "",
            "request_url": "/123",
            "request_url_status": "disable",
            "status": "disable",
            "type": "URL",
            "value": "",
            "value_status": "disable"
        }
    }
}
```

#### Human Readable Output - API Version 2

>### Custom whitelist members:
>Showing 1 rows out of 3.
>|Id|Name|Request Url|Path|Domain|Status|
>|---|---|---|---|---|---|
>| 1 |  | /123 |  |  | disable |




### fortiwebvm-geo-ip-member-add
***
Create Geo IP Member (Geo IP Member is a member of Geo IP).


#### Base Command

`fortiwebvm-geo-ip-member-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Geo IP Group Name. | Required | 
| countries | Country name to add to the GEO IP List name.(Comma-separated value). Possible values are: Afghanistan, Aland Islands, Albania, Algeria, American Samoa, Andorra, Angola, Anguilla, Antarctica, Antigua And Barbuda, Argentina, Armenia, Aruba, Australia, Austria, Azerbaijan, Bahamas, Bahrain, Bangladesh, Barbados, Belarus, Belgium, Belize, Benin, Bermuda, Bhutan, Bolivia, Bonaire Saint Eustatius And Saba, Bosnia And Herzegovina, Botswana, Brazil, British Indian Ocean Territory, British Virgin Islands, Brunei Darussalam, Bulgaria, Burkina Faso, Burundi, Cambodia, Cameroon, Canada, Cape Verde, Cayman Islands, Central African Republic, Chad, Chile, China, Colombia, Comoros, Congo, Cook Islands, Costa Rica, Cote D Ivoire, Croatia, Cuba, Curacao, Cyprus, Czech Republic, Democratic People S Republic Of Korea, Democratic Republic Of The Congo, Denmark, Djibouti, Dominica, Dominican Republic, Ecuador, Egypt, El Salvador, Equatorial Guinea, Eritrea, Estonia, Ethiopia, Falkland Islands  Malvinas, Faroe Islands, Federated States Of Micronesia, Fiji, Finland, France, French Guiana, French Polynesia, Gabon, Gambia, Georgia, Germany, Ghana, Gibraltar, Greece, Greenland, Grenada, Guadeloupe, Guam, Guatemala, Guernsey, Guinea, Guinea-Bissau, Guyana, Haiti, Honduras, Hong Kong, Hungary, Iceland, India, Indonesia, Iran, Iraq, Ireland, Isle Of Man, Israel, Italy, Jamaica, Japan, Jersey, Jordan, Kazakhstan, Kenya, Kiribati, Kosovo, Kuwait, Kyrgyzstan, Lao People S Democratic Republic, Latvia, Lebanon, Lesotho, Liberia, Libya, Liechtenstein, Lithuania, Luxembourg, Macao, Macedonia, Madagascar, Malawi, Malaysia, Maldives, Mali, Malta, Marshall Islands, Martinique, Mauritania, Mauritius, Mayotte, Mexico, Moldova, Monaco, Mongolia, Montenegro, Montserrat, Morocco, Mozambique, Myanmar, Namibia, Nauru, Nepal, Netherlands, New Caledonia, New Zealand, Nicaragua, Niger, Nigeria, Niue, Norfolk Island, Northern Mariana Islands, Norway, Oman, Pakistan, Palau, Palestine, Panama, Papua New Guinea, Paraguay, Peru, Philippines, Poland, Portugal, Puerto Rico, Qatar, Republic Of Korea, Reunion, Romania, Russian Federation, Rwanda, Saint Bartelemey, Saint Kitts And Nevis, Saint Lucia, Saint Martin, Saint Pierre And Miquelon, Saint Vincent And The Grenadines, Samoa, San Marino, Sao Tome And Principe, Saudi Arabia, Senegal, Serbia, Seychelles, Sierra Leone, Singapore, Sint Maarten, Slovakia, Slovenia, Solomon Islands, Somalia, South Africa, South Georgia And The South Sandwich Islands, South Sudan, Spain, Sri Lanka, Sudan, Suriname, Swaziland, Sweden, Switzerland, Syria, Taiwan, Tajikistan, Tanzania, Thailand, Timor-Leste, Togo, Tokelau, Tonga, Trinidad And Tobago, Tunisia, Turkey, Turkmenistan, Turks And Caicos Islands, Tuvalu, Uganda, Ukraine, United Arab Emirates, United Kingdom, United States, Uruguay, U S  Virgin Islands, Uzbekistan, Vanuatu, Vatican, Venezuela, Vietnam, Wallis And Futuna, Yemen, Zambia, Zimbabwe. Default is Low. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-geo-ip-member-add group_name=example countries=Algeria```
#### Context Example
```json
{
    "FortiwebVM": {
        "GeoIpMember": {
            "country": "Algeria",
            "id": "1"
        }
    }
}
```

#### Human Readable Output

>### Geo IP member successfully added!
>|Id|Country|
>|---|---|
>| 1 | Algeria |


### fortiwebvm-geo-ip-member-delete
***
Delete Geo IP Member (Geo IP Member is a member of Geo IP).


#### Base Command

`fortiwebvm-geo-ip-member-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Geo IP Group Name. | Required | 
| member_id | Geo IP Member ID Number. (The ID of the Geo IP Member is the ID of the country in the Geo IP List). | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-geo-ip-member-delete group_name=example member_id=1```
#### Human Readable Output

>### Geo IP member succesfuly deleted!
>|Member Id|
>|---|
>| 1 |


### fortiwebvm-geo-ip-member-list
***
Get Geo IP Member (Geo IP Member is a member of Geo IP).


#### Base Command

`fortiwebvm-geo-ip-member-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Geo IP Name. | Required | 
| member_id | Geo IP Member ID Number. (The ID of the Geo IP Member is the ID of the country in the Geo IP List). | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.GeoIpMember.group_name | String | Geo IP Member Group Name. | 
| FortiwebVM.GeoIpMember.countries.id | String | Geo IP Member ID. | 
| FortiwebVM.GeoIpMember.countries.country | Number | Geo IP Member Country Name. | 

#### Command example
```!fortiwebvm-geo-ip-member-list group_name=example member_id=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "GeoIpMember": {
            "countries": [
                {
                    "country": "Algeria",
                    "id": "1"
                }
            ],
            "group_name": "example"
        }
    }
}
```

#### Human Readable Output

>### Geo IP member:
>Showing 1 rows out of 1.
>|Id|Country|
>|---|---|
>| 1 | Algeria |


### fortiwebvm-geo-ip-group-create
***
Create Geo IP.


#### Base Command

`fortiwebvm-geo-ip-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Geo IP Group Name. | Required | 
| trigger_policy | Enter the name of the trigger to apply when this rule is violated. | Optional | 
| severity | Select the severity level to use in logs and reports generated when a violation of the rule occurs. Possible values are: High, Medium, Low, Info. Default is Low. | Optional | 
| exception_rule | Geo IP Exception groups. | Optional | 
| action | Select which action FortiWeb will take when it detects a violation of the rule:alert_deny—Block the request (or reset the connection) and generate an alert and/or log message.deny_no_log—Block the request (or reset the connection).block-period—Block subsequent requests from the client for a number of seconds. Also configure block-period. Supports API version 2 only. Possible values are: Alert deny, Block period, Deny (no log). Default is Block period. | Optional | 
| block_period | Block Period.The number of seconds that you want to block subsequent requests.The valid range is 1–3,600 seconds.Relevant when action=Block period True. Supports API version 2 only. Default is 600. | Optional | 
| ignore_x_forwarded_for | enable Ignore X-Forwarded-For so that the IP addresses will be scanned at the TCP layer instead of HTTP layer. Supports API version 2 only. Possible values are: enable, disable. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-geo-ip-group-create name=example```
#### Human Readable Output

>### Geo IP group successfully created!
>|Name|
>|---|
>| example |


### fortiwebvm-geo-ip-group-update
***
Update Geo IP.


#### Base Command

`fortiwebvm-geo-ip-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Geo IP Group Name. | Required | 
| trigger_policy | Enter the name of the trigger to apply when this rule is violated. | Optional | 
| severity | Select the severity level to use in logs and reports generated when a violation of the rule occurs. Possible values are: High, Medium, Low, Info. | Optional | 
| exception_rule | Geo IP Exception groups. | Optional | 
| action | Select which action FortiWeb will take when it detects a violation of the rule:alert_deny—Block the request (or reset the connection) and generate an alert and/or log message.deny_no_log—Block the request (or reset the connection).block-period—Block subsequent requests from the client for a number of seconds. Also configure block-period. Supports API version 2 only. Possible values are: Alert deny, Block period, Deny (no log). | Optional | 
| block_period | Block Period.The number of seconds that you want to block subsequent requests.The valid range is 1–3,600 seconds. Supports API version 2 only. | Optional | 
| ignore_x_forwarded_for | enable Ignore X-Forwarded-For so that the IP addresses will be scanned at the TCP layer instead of HTTP layer. Supports API version 2 only. Possible values are: enable, disable. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-geo-ip-group-update name=example```
#### Human Readable Output

>### Geo IP group successfully updated!
>|Name|
>|---|
>| example |


### fortiwebvm-geo-ip-group-delete
***
Delete Geo IP.


#### Base Command

`fortiwebvm-geo-ip-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Geo IP Group Name. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-geo-ip-group-delete name=example```
#### Human Readable Output

>### Geo IP group successfully deleted!
>|Id|
>|---|
>| example |


### fortiwebvm-geo-ip-group-list
***
Get Geo IP list.


#### Base Command

`fortiwebvm-geo-ip-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Geo IP Group Name. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.GeoIpGroup.id | Number | Geo IP Group ID. | 
| FortiwebVM.GeoIpGroup.count | Number | Geo IP Group Members Count. | 
| FortiwebVM.GeoIpGroup.trigger_policy | String | Geo IP Group Trigger Policy Name. | 
| FortiwebVM.GeoIpGroup.severity | String | Geo IP Group Severity Number. | 
| FortiwebVM.GeoIpGroup.except | String | Geo IP Group Exception groups. | 
| FortiwebVM.GeoIpGroup.can_delete | Boolean | Geo IP Group Can delete flag. Supports API version 1 only. | 
| FortiwebVM.GeoIpGroup.action | String | Geo IP Group Action. Supports API version 2 only. | 
| FortiwebVM.GeoIpGroup.block_period | Number | Geo IP Group Block Period. Supports API version 2 only. | 
| FortiwebVM.GeoIpGroup.ignore_x_forwarded_for | String | Geo IP Group Ignore X-Forwarded-For flag. Supports API version 2 only. | 

#### Command example
```!fortiwebvm-geo-ip-group-list name=example```
#### Context Example
```json
{
    "FortiwebVM": {
        "GeoIpGroup": {
            "can_delete": true,
            "count": 0,
            "except": "",
            "id": "example",
            "severity": "Low",
            "trigger_policy": ""
        }
    }
}
```

#### Human Readable Output

>### Geo IP group:
>Showing 1 rows out of 1.
>|Id|Count|Trigger Policy|Severity|Except|
>|---|---|---|---|---|
>| example | 0 |  | Low |  |


### fortiwebvm-system-operation-status-get
***
Get Operation Status


#### Base Command

`fortiwebvm-system-operation-status-get`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-system-operation-status-get```
#### Context Example
```json
{
    "FortiwebVM": {
        "SystemOperation": [
            {
                "alias": "",
                "id": "port1",
                "ip_netmask": "192.168.30.137/24",
                "label": 1,
                "link": "Up",
                "name": "port1",
                "rx": 582306,
                "speed_duplex": "10000 Mbps/Full Duplex",
                "tx": 18115
            },
            {
                "alias": "",
                "id": "port2",
                "ip_netmask": "0.0.0.0/0",
                "label": 2,
                "link": "Up",
                "name": "port2",
                "rx": 571254,
                "speed_duplex": "10000 Mbps/Full Duplex",
                "tx": 141
            },
            {
                "alias": "",
                "id": "port3",
                "ip_netmask": "0.0.0.0/0",
                "label": 3,
                "link": "Up",
                "name": "port3",
                "rx": 571338,
                "speed_duplex": "10000 Mbps/Full Duplex",
                "tx": 141
            },
            {
                "alias": "",
                "id": "port4",
                "ip_netmask": "0.0.0.0/0",
                "label": 4,
                "link": "Up",
                "name": "port4",
                "rx": 571252,
                "speed_duplex": "10000 Mbps/Full Duplex",
                "tx": 141
            },
            {
                "alias": "",
                "id": "port5",
                "ip_netmask": "0.0.0.0/0",
                "label": 5,
                "link": "Up",
                "name": "port5",
                "rx": 571246,
                "speed_duplex": "10000 Mbps/Full Duplex",
                "tx": 141
            },
            {
                "alias": "",
                "id": "port6",
                "ip_netmask": "0.0.0.0/0",
                "label": 6,
                "link": "Up",
                "name": "port6",
                "rx": 571245,
                "speed_duplex": "10000 Mbps/Full Duplex",
                "tx": 141
            },
            {
                "alias": "",
                "id": "port7",
                "ip_netmask": "0.0.0.0/0",
                "label": 7,
                "link": "Up",
                "name": "port7",
                "rx": 571239,
                "speed_duplex": "10000 Mbps/Full Duplex",
                "tx": 141
            },
            {
                "alias": "",
                "id": "port8",
                "ip_netmask": "0.0.0.0/0",
                "label": 8,
                "link": "Up",
                "name": "port8",
                "rx": 571283,
                "speed_duplex": "10000 Mbps/Full Duplex",
                "tx": 141
            },
            {
                "alias": "",
                "id": "port9",
                "ip_netmask": "0.0.0.0/0",
                "label": 9,
                "link": "Up",
                "name": "port9",
                "rx": 572431,
                "speed_duplex": "10000 Mbps/Full Duplex",
                "tx": 141
            },
            {
                "alias": "",
                "id": "port10",
                "ip_netmask": "0.0.0.0/0",
                "label": 10,
                "link": "Up",
                "name": "port10",
                "rx": 572083,
                "speed_duplex": "10000 Mbps/Full Duplex",
                "tx": 141
            }
        ]
    }
}
```

#### Human Readable Output

>### Operation networks:
>|Id|Name|Label|Alias|Ip Netmask|Speed Duplex|Tx|Rx|Link|
>|---|---|---|---|---|---|---|---|---|
>| port1 | port1 | 1 |  | 192.168.30.137/24 | 10000 Mbps/Full Duplex | 18115 | 582306 | Up |
>| port2 | port2 | 2 |  | 0.0.0.0/0 | 10000 Mbps/Full Duplex | 141 | 571254 | Up |
>| port3 | port3 | 3 |  | 0.0.0.0/0 | 10000 Mbps/Full Duplex | 141 | 571338 | Up |
>| port4 | port4 | 4 |  | 0.0.0.0/0 | 10000 Mbps/Full Duplex | 141 | 571252 | Up |
>| port5 | port5 | 5 |  | 0.0.0.0/0 | 10000 Mbps/Full Duplex | 141 | 571246 | Up |
>| port6 | port6 | 6 |  | 0.0.0.0/0 | 10000 Mbps/Full Duplex | 141 | 571245 | Up |
>| port7 | port7 | 7 |  | 0.0.0.0/0 | 10000 Mbps/Full Duplex | 141 | 571239 | Up |
>| port8 | port8 | 8 |  | 0.0.0.0/0 | 10000 Mbps/Full Duplex | 141 | 571283 | Up |
>| port9 | port9 | 9 |  | 0.0.0.0/0 | 10000 Mbps/Full Duplex | 141 | 572431 | Up |
>| port10 | port10 | 10 |  | 0.0.0.0/0 | 10000 Mbps/Full Duplex | 141 | 572083 | Up |


### fortiwebvm-system-policy-status-get
***
Get Policy Status.


#### Base Command

`fortiwebvm-system-policy-status-get`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-system-policy-status-get```
#### Human Readable Output

>### Policy status:
>**No entries.**


### fortiwebvm-system-status-get
***
Get System Status.


#### Base Command

`fortiwebvm-system-status-get`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-system-status-get```
#### Context Example
```json
{
    "FortiwebVM": {
        "SystemStatus": {
            "administrativeDomain": "Disabled",
            "antivirusService": {
                "anti_expired": "Expired (1969-12-31)",
                "anti_expired_text": "[Renew]",
                "anti_expired_url": "http://support.fortinet.com/",
                "anti_update_text": "[Update]",
                "anti_update_url": "#navigate/SignatureUpdate",
                "antivirusLastUpdateMethod": "Manual",
                "antivirusLastUpdateTime": "1969-12-31",
                "exVirusDatabaseVersion": "1.00000",
                "regularVirusDatabaseVersion": "1.00000"
            },
            "bufferSizeMax": 102400,
            "credentialStuffingDefense": {
                "databaseVersion": "0.00000",
                "expired": "Expired (1969-12-31)",
                "expired_text": "[Renew]",
                "expired_url": "http://support.fortinet.com/",
                "lastUpdateTime": "1969-12-31"
            },
            "fileUploadLimitMax": 102400,
            "fipcc": "Disabled",
            "firmwareVersion": "FortiWeb-VM 6.12,build0421(GA),191218",
            "firmware_partition": 2,
            "haStatus": "Standalone",
            "hostName": "FortiWeb",
            "logDisk": "Available",
            "operationMode": "Reverse Proxy",
            "readonly": false,
            "registration": {
                "label": "[Unregistered]",
                "text": "[Register]",
                "url": "https://support.fortinet.com"
            },
            "reputationService": {
                "reputationBuildNumber": "1.00020",
                "reputationLastUpdateMethod": "Manual",
                "reputationLastUpdateTime": "1969-12-31",
                "reputation_expired": "Expired (1969-12-31)",
                "reputation_expired_text": "[Renew]",
                "reputation_expired_url": "http://support.fortinet.com/",
                "reputation_update_text": "[Update]",
                "reputation_update_url": "#navigate/SignatureUpdate"
            },
            "securityService": {
                "buildNumber": "0.00240",
                "expired": "Expired (1969-12-31)",
                "expired_text": "[Renew]",
                "expired_url": "http://support.fortinet.com/",
                "lastUpdateMethod": "Manual",
                "lastUpdateTime": "1969-12-31",
                "update_text": "[Update]",
                "update_url": "#navigate/SignatureUpdate"
            },
            "serialNumber": "FVVM00UNLICENSED",
            "systemTime": "Sun Dec 25 01:01:32 2022\n",
            "systemUptime": "2 day(s) 20 hour(s) 7 min(s)",
            "vmLicense": "invalid"
        }
    }
}
```

#### Human Readable Output

>### System Status:
>|High Ability Status|Host Name|Serial Number|Operation Mode|System Time|Firmware Version|Administrative Domain|System Uptime|Fips And Cc Mode|Log Disk|
>|---|---|---|---|---|---|---|---|---|---|
>| Standalone | FortiWeb | FVVM00UNLICENSED | Reverse Proxy | Sun Dec 25 01:01:32 2022<br/> | FortiWeb-VM 6.12,build0421(GA),191218 | Disabled | 2 day(s) 20 hour(s) 7 min(s) | Disabled | Available |


### fortiwebvm-virtual-server-list
***
List the Virtual Servers.


#### Base Command

`fortiwebvm-virtual-server-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.VirtualServer.id | String | Virtual Server Name. | 

#### Command example
```!fortiwebvm-virtual-server-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "VirtualServer": {
            "id": "virtual1"
        }
    }
}
```

#### Human Readable Output

>### Virtual Servers:
>Showing 1 rows out of 1.
>|Id|
>|---|
>| virtual1 |


### fortiwebvm-geo-exception-list
***
List the Geo Exception Groups.


#### Base Command

`fortiwebvm-geo-exception-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.GeoExceptionGroup.id | String | Geo Exception Group Name. | 

#### Command example
```!fortiwebvm-geo-exception-list limit=1```
#### Human Readable Output

>### Geo exception:
>Showing 0 rows out of 0.
>**No entries.**


### fortiwebvm-trigger-policy-list
***
List the Trigger Policies Rules.


#### Base Command

`fortiwebvm-trigger-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.TriggerPolicy.id | String | Trigger Policy Name. | 

#### Command example
```!fortiwebvm-trigger-policy-list limit=1```
#### Human Readable Output

>### Content Routing Policy:
>Showing 0 rows out of 0.
>**No entries.**


### fortiwebvm-certificate-intermediate-group-list
***
List the Certificate intermediate groups.


#### Base Command

`fortiwebvm-certificate-intermediate-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CertificateIntermediateGroup.id | String | Certificate Intermediate Group Name. | 

#### Command example
```!fortiwebvm-certificate-intermediate-group-list limit=1```
#### Human Readable Output

>### Content Routing Policy:
>Showing 0 rows out of 0.
>**No entries.**


### fortiwebvm-server-pool-list
***
List the Server Pools.


#### Base Command

`fortiwebvm-server-pool-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPool.id | String | Server Pool Name. | 

#### Command example
```!fortiwebvm-server-pool-list limit=1```
#### Human Readable Output

>### Server pool:
>Showing 0 rows out of 0.
>**No entries.**


### fortiwebvm-http-service-list
***
List the  HTTP Services.


#### Base Command

`fortiwebvm-http-service-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.HttpServiceList.id | String | HTTP Service Name. | 

#### Command example
```!fortiwebvm-http-service-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "HttpServiceList": {
            "id": "HTTP"
        }
    }
}
```

#### Human Readable Output

>### HTTP services:
>Showing 1 rows out of 5.
>|Id|
>|---|
>| HTTP |


### fortiwebvm-inline-protection-profile-list
***
List the Inline Protection Profiles.


#### Base Command

`fortiwebvm-inline-protection-profile-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.InlineProtectionProfile.id | String | Inline protection profile name. | 

#### Command example
```!fortiwebvm-inline-protection-profile-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "InlineProtectionProfile": {
            "id": "Inline High Level Security"
        }
    }
}
```

#### Human Readable Output

>### Inline Protection Profile:
>Showing 1 rows out of 10.
>|Id|
>|---|
>| Inline High Level Security |


### fortiwebvm-server-policy-create
***
Create Server Policy.


#### Base Command

`fortiwebvm-server-policy-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Policy Name. | Required | 
| json_template_id | Allows the use of the server policy JSON template. All of the arguments listed below will be overridden. For an example, see the integration . | Optional | 
| deployment_mode | Deployment Mode. Specify the distribution method that FortiWeb uses when it forwards connections accepted by this policy. Possible values are: HTTP Content Routing, Single Server/Server Balance. | Optional | 
| virtual_server | Enter the name of a virtual server that provides the IP address and network interface of incoming traffic that FortiWeb routes and to which the policy applies a protection profile. The maximum length is 63 characters. | Optional | 
| mach_once | Match once enabled.Required when: deployment_mode = "HTTP Content Routing". Possible values are: enable, disable. Default is disable. | Optional | 
| server_pool | Enter the name of the server pool whose members receive the connections. Required when: deployment_mode = "Single Server/Server Balance". | Optional | 
| protected_hostnames | Protected hostnames group name. Enter the name of a protected hosts group to allow or reject connections based upon whether the Host. | Optional | 
| client_real_ip | Enable to configure FortiWeb to use the source IP address of the client that originated the request when it connects to a back-end server on behalf of that client. Possible values are: enable, disable. Default is disable. | Optional | 
| ip_range | Specify an IP address or address range to directly connect to the back-end server. Required when: client_real_ip = "enable". Supports API version 2 only. | Optional | 
| syn_cookie | Enable to detect TCP SYN flood attacks. Possible values are: enable, disable. Default is disable. | Optional | 
| half_open_thresh | The maximum number of TCP SYN packets, including retransmission, that FortiWeb allows to be sent per second to a destination address. If this threshold is exceeded, the FortiWeb appliance treats the traffic as a DoS attack and ignores additional traffic from that source address. The valid range is 10–10,000.. Default is 8192. | Optional | 
| http_service | HTTP service name. Custom or predefined service that defines the port number on which the virtual server receives HTTPS traffic. | Optional | 
| https_service | HTTPS service name. Custom or predefined service that defines the port number on which the virtual server receives HTTPS traffic. | Optional | 
| multi_certificate | Enable to allow FortiWeb to use multiple local certificates.. | Optional | 
| certificate_group | Select the multi-certificate file you have created.Required when:  multi-certificate is enable. | Optional | 
| proxy | Missing. | Optional | 
| redirect_to_https | Enable to automatically redirect all HTTP requests to the HTTPS service with the same URL and parameters. Possible values are: enable, disable. Default is disable. | Optional | 
| inline_protection_profile | Inline web protection profile name. | Optional | 
| monitor_mode | Enable to override deny and redirect actions defined in the server protection rules for the selected policy. This setting enables FortiWeb to log attacks without performing the deny or redirect action. Disable to allow FortiWeb to perform attack deny/redirect actions as defined by the server protection rules. Possible values are: enable, disable. Default is disable. | Optional | 
| url_case_sensitivity | Enable to differentiate uniform resource locators (URLs) according to upper case and lower case letters for features that act upon the URLs in the headers of HTTP requests, such as block list rules, and allow list rules. Possible values are: enable, disable. Default is disable. | Optional | 
| comments | Enter a description or other comment. If the comment is more than one word or contains special characters, surround the comment with double quotes ( " ). The maximum length is 999 characters. | Optional | 
| certificate_type | Enable allow FortiWeb to automatically retrieve CA certificates from Let's Encrypt. Supports API version 2 only. Possible values are: Local, Multi Certificate, Letsencrypt. Default is Local. | Optional | 
| lets_certificate | Select the Letsencrypt certificate you have created. Supports API version 2 only.Required when: certificate-type is enable. | Optional | 
| retry_on | Enable to configure whether to retry a failed TCP connection or HTTP request in Reverse Proxy mode. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional | 
| retry_on_cache_size | Enter a cache size limit for the HTTP request packet. Supports API version 2 only.Required when: retry_on is enable. Default is 512. | Optional | 
| retry_on_connect_failure | Enable to configure the retry times in case of any TCP connection failure. Supports API version 2 only. Required when: retry_on is enable. Possible values are: enable, disable. Default is disable. | Optional | 
| retry_times_on_connect_failure | Enter the retry times when FortiWeb reconnects the single server or switch to the other pserver. The valid range is 1-5. Supports API version 2 only.Required when: retry_on_connect_failure and retry_on are enable. Possible values are: 1, 2, 3, 4, 5. Default is 3. | Optional | 
| retry_on_http_layer | Enable to configure the retry times and failure response code in case of any HTTP connection failure. Supports API version 2 only.Required when: retry_on is enable. Possible values are: enable, disable. Default is disable. | Optional | 
| retry_times_on_http_layer | Enter the retry times when FortiWeb reconnects the single server or switch to the other pserver. The valid range is 1-5. Supports API version 2 only.Required when: retry_on and retry_on_http_layer are enable. Possible values are: 1, 2, 3, 4, 5. Default is 3. | Optional | 
| retry_on_http_response_codes | Select the failure return code when pserver can be connected to determine enabling HTTP failure retry. Supports API version 2 only. Required when: retry_on and retry_on_http_layer are enable. Possible values are: 404, 408, 500, 501, 502, 503, 504. | Optional | 
| scripting | Not documented. Supports API version 2 only. Possible values are: enable, disable. | Optional | 
| scripting_list | Not documented. Required when: scripting is enable. Supports API version 2 only. | Optional | 
| allow_list | Supports API version 2 only. | Optional | 
| replace_msg | Select the replacement message to apply to the policy. Supports API version 2 only. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-policy-create name=example virtual_server=virtual1 http_service=HTTP deployment_mode="HTTP Content Routing"```
#### Human Readable Output

>### Server Policy succesfuly created!
>|Name|
>|---|
>| example |


### fortiwebvm-server-policy-update
***
Update Server Policy.


#### Base Command

`fortiwebvm-server-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Policy Name. | Required | 
| deployment_mode | Deployment Mode. Possible values are: HTTP Content Routing, Single Server/Server Balance. | Optional | 
| virtual_server | Enter the name of a virtual server that provides the IP address and network interface of incoming traffic that FortiWeb routes and to which the policy applies a protection profile. The maximum length is 63 characters. | Optional | 
| mach_once | Match once enabled.Required when: deployment_mode = "HTTP Content Routing". Possible values are: enable, disable. Default is disable. | Optional | 
| server_pool | Enter the name of the server pool whose members receive the connections. Required when: deployment_mode = "Single Server/Server Balance". | Optional | 
| protected_hostnames | Protected hostnames group name. Enter the name of a protected hosts group to allow or reject connections based upon whether the Host. | Optional | 
| client_real_ip | Enable to configure FortiWeb to use the source IP address of the client that originated the request when it connects to a back-end server on behalf of that client. | Optional | 
| ip_range | Specify an IP address or address range to directly connect to the back-end server. Required when: client_real_ip = "enable". Supports API version 2 only. | Optional | 
| syn_cookie | Enable to detect TCP SYN flood attacks. Possible values are: enable, disable. Default is disable. | Optional | 
| half_open_thresh | The maximum number of TCP SYN packets, including retransmission, that FortiWeb allows to be sent per second to a destination address. If this threshold is exceeded, the FortiWeb appliance treats the traffic as a DoS attack and ignores additional traffic from that source address. The valid range is 10–10,000.. | Optional | 
| http_service | HTTP service name. Custom or predefined service that defines the port number on which the virtual server receives HTTPS traffic. | Optional | 
| https_service | HTTPS service name. Custom or predefined service that defines the port number on which the virtual server receives HTTPS traffic. | Optional | 
| http2 | Enable HTTP/2.Required when: HTTPSService is not null. Possible values are: enable, disable. Default is disable. | Optional | 
| multi_certificate | Enable to allow FortiWeb to use multiple local certificates. | Optional | 
| certificate_group | Required  when:  multi-certificate is enable.Select the multi-certificate file you have created. | Optional | 
| certificate | Required  when:  multi-certificate is disable. | Optional | 
| intergroup | Certificate intermediate group.Required  when: HTTPSService is not null. | Optional | 
| proxy | Missing in version 1. Possible values are: enable, disable. Default is disable. | Optional | 
| redirect_to_https | Enable to automatically redirect all HTTP requests to the HTTPS service with the same URL and parameters. | Optional | 
| inline_protection_profile | Inline web protection profile name. | Optional | 
| monitor_mode | Enable to override deny and redirect actions defined in the server protection rules for the selected policy. This setting enables FortiWeb to log attacks without performing the deny or redirect action. Disable to allow FortiWeb to perform attack deny/redirect actions as defined by the server protection rules. Possible values are: enable, disable. Default is disable. | Optional | 
| url_case_sensitivity | Enable to differentiate uniform resource locators (URLs) according to upper case and lower case letters for features that act upon the URLs in the headers of HTTP requests, such as block list rules, and allow list rules. | Optional | 
| comments | Enter a description or other comment. If the comment is more than one word or contains special characters, surround the comment with double quotes ( " ). The maximum length is 999 characters. | Optional | 
| certificate_type | Enable allow FortiWeb to automatically retrieve CA certificates from Let's Encrypt. Supports API version 2 only. Possible values are: Local, Multi Certificate, Letsencrypt. | Optional | 
| lets_certificate | Select the Letsencrypt certificate you have created. Supports API version 2 only.Required  when: certificate-type is enable. | Optional | 
| retry_on | Enable to configure whether to retry a failed TCP connection or HTTP request in Reverse Proxy mode. Supports API version 2 only. Possible values are: enable, disable. | Optional | 
| retry_on_cache_size | Enter a cache size limit for the HTTP request packet. Supports API version 2 only.Required when: retry_on is enable. | Optional | 
| retry_on_connect_failure | Enable to configure the retry times in case of any TCP connection failure. Supports API version 2 only. Required when: retry_on is enable. Possible values are: enable, disable. | Optional | 
| retry_times_on_connect_failure | Enter the retry times when FortiWeb reconnects the single server or switch to the other pserver. The valid range is 1-5. Supports API version 2 only.Required when: retry_on_connect_failure and retry_on are enable. Possible values are: 1, 2, 3, 4, 5. | Optional | 
| retry_on_http_layer | Enable to configure the retry times and failure response code in case of any HTTP connection failure. Supports API version 2 only.Required when: retry_on is enable. Possible values are: enable, disable. | Optional | 
| retry_times_on_http_layer | Enter the retry times when FortiWeb reconnects the single server or switch to the other pserver. The valid range is 1-5. Supports API version 2 only.Required when: retry_on and retry_on_http_layer are enable. Possible values are: 1, 2, 3, 4, 5. | Optional | 
| retry_on_http_response_codes | Select the failure return code when pserver can be connected to determine enabling HTTP failure retry. Supports API version 2 only. Required when: retry_on and retry_on_http_layer are enable. Possible values are: 404, 408, 500, 501, 502, 503, 504. | Optional | 
| scripting | Not documented. Supports API version 2 only. | Optional | 
| scripting_list | Not documented. Supports API version 2 only.Required  when: scripting-on is enable. | Optional | 
| allow_list | Not documented. Required when: scripting is enable. Supports API version 2 only. | Optional | 
| replacemsg | Select the replacement message to apply to the policy. Supports API version 2 only. | Optional | 
| json_template_id | Allows the use of the server policy JSON template. All of the arguments listed below will be overridden. For an example, see the integration . | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-policy-update name=example```
#### Human Readable Output

>### Server Policy succesfuly updated!
>|Name|
>|---|
>| example |


### fortiwebvm-server-policy-delete
***
Delete Server Policy.


#### Base Command

`fortiwebvm-server-policy-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Policy Name. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-policy-delete name=example```
#### Human Readable Output

>### Server Policy succesfuly deleted!
>|Id|
>|---|
>| example |


### fortiwebvm-server-policy-list
***
List the Server Policies.


#### Base Command

`fortiwebvm-server-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Server Policy Name. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPolicy.name | String | Server Policy Name. | 
| FortiwebVM.ServerPolicy.deployment_mode | String | Server Policy Deployment Mode. | 
| FortiwebVM.ServerPolicy.protocol | String | Server Policy protocol. | 
| FortiwebVM.ServerPolicy.web_protection_profile | String | Server Policy inherit web protection profile flag. | 
| FortiwebVM.ServerPolicy.monitor_mode | String | Enable to override deny and redirect actions defined in the server protection rules for the selected policy. This setting enables FortiWeb to log attacks without performing the deny or redirect action. Disable to allow FortiWeb to perform attack deny/redirect actions as defined by the server protection rules. | 
| FortiwebVM.ServerPolicy.http_service | String | HTTP service name. Custom or predefined service that defines the port number on which the virtual server receives HTTPS traffic. | 
| FortiwebVM.ServerPolicy.https_service | String | HTTPS service name. Custom or predefined service that defines the port number on which the virtual server receives HTTPS traffic. | 
| FortiwebVM.ServerPolicy.certificate | String | Server Polciy certificate. | 
| FortiwebVM.ServerPolicy.certificate_intermediate_group | String | Server Polciy certificate intermediate group. | 
| FortiwebVM.ServerPolicy.server_pool | String | Server Policy Server Pool name. | 
| FortiwebVM.ServerPolicy.protected_hostnames | String | Server Policy Protected Hostname name. | 
| FortiwebVM.ServerPolicy.client_real_ip | String | Enable to configure FortiWeb to use the source IP address of the client that originated the request when it connects to a back-end server on behalf of that client. | 
| FortiwebVM.ServerPolicy.syn_cookie | String | Enable to detect TCP SYN flood attacks. | 
| FortiwebVM.ServerPolicy.redirect_to_https | String | Enable to automatically redirect all HTTP requests to the HTTPS service with the same URL and parameters. | 
| FortiwebVM.ServerPolicy.http2 | String | Enable HTTP/2.Required when: HTTPSService is not null. | 
| FortiwebVM.ServerPolicy.url_case_sensitivity | String | Enable to differentiate uniform resource locators \(URLs\) according to upper case and lower case letters for features that act upon the URLs in the headers of HTTP requests, such as block list rules, and allow list rules. | 
| FortiwebVM.ServerPolicy.comments | String | Enter a description or other comment. If the comment is more than one word or contains special characters, surround the comment with double quotes \( " \). The maximum length is 999 characters. | 
| FortiwebVM.ServerPolicy.retry_on | String | Enable to configure whether to retry a failed TCP connection or HTTP request in Reverse Proxy mode. Supports API version 2 only. | 
| FortiwebVM.ServerPolicy.retry_on_cache_size | String | Enter a cache size limit for the HTTP request packet. Supports API version 2 only.Required when: retry_on is enable. | 
| FortiwebVM.ServerPolicy.retry_times_on_connect_failure | String | Enable to configure the retry times in case of any TCP connection failure. Supports API version 2 only. Required when: retry_on is enable. | 
| FortiwebVM.ServerPolicy.retry_on_http_layer | String | Enable to configure the retry times and failure response code in case of any HTTP connection failure. Supports API version 2 only.Required when: retry_on is enable. | 
| FortiwebVM.ServerPolicy.retry_times_on_http_layer | String | The retry times when FortiWeb reconnects the single server or switch to the other pserver. The valid range is 1-5. Supports API version 2 only.Required when: retry_on and retry_on_http_layer are enable. | 
| FortiwebVM.ServerPolicy.retry_on_http_response_codes | String | The failure return code when pserver can be connected to determine enabling HTTP failure retry. Supports API version 2 only. Required when: retry_on and retry_on_http_layer are enable. | 
| FortiwebVM.ServerPolicy.scripting | String | Not documented. Supports API version 2 only. | 
| FortiwebVM.ServerPolicy.scripting_list | String | Not documented. Required when: scripting is enable. Supports API version 2 only. | 
| FortiwebVM.ServerPolicy.allow_list | String | Server Policy Allow List. Supports API version 2 only. | 
| FortiwebVM.ServerPolicy.replace_msg | String | Server Policy replacement message. Supports API version 2 only. API version 2 only. | 

#### Command example
```!fortiwebvm-server-policy-list name=example```
#### Context Example
```json
{
    "FortiwebVM": {
        "ServerPolicy": {
            "certificate": "",
            "certificate_intermediate_group": "",
            "client_real_ip": false,
            "comments": "",
            "deployment_mode": "HTTP Content Routing",
            "half_open_thresh": 8192,
            "http2": false,
            "http_service": "HTTP",
            "https_service": "",
            "monitor_mode": false,
            "name": "example",
            "protected_hostnames": "",
            "protocol": "HTTP",
            "redirect_to_https": false,
            "server_pool": "",
            "syn_cookie": false,
            "url_case_sensitivity": false,
            "virtual_server": "virtual1",
            "web_protection_profile": ""
        }
    }
}
```

#### Human Readable Output

>### Server Policies:
>Showing 1 rows out of 1.
>|Name|Deployment Mode|Virtual Server|Protocol|Web Protection Profile|Monitor Mode|
>|---|---|---|---|---|---|
>| example | HTTP Content Routing | virtual1 | HTTP |  | false |


### fortiwebvm-content-routing-policy-list
***
List the HTTP Content Routing Policies.


#### Base Command

`fortiwebvm-content-routing-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.HttpContentRoutingPolicy.id | String | Policy Name. | 

#### Command example
```!fortiwebvm-content-routing-policy-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "HttpContentRoutingPolicy": {
            "id": "content1"
        }
    }
}
```

#### Human Readable Output

>### Content Routing Policy:
>Showing 1 rows out of 1.
>|Id|
>|---|
>| content1 |


### fortiwebvm-http-content-routing-member-add
***
Create Server Policy HTTP Content Routing Member (HTTP Content Routing Member is a member of HTTP Content Routing).


#### Base Command

`fortiwebvm-http-content-routing-member-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy Name. | Required | 
| is_default | Is FortiWeb applies the protection profile to any traffic that does not match conditions specified in the HTTP content routing policies?. Possible values are: yes, no. Default is no. | Optional | 
| http_content_routing_policy | HTTP content routing policy name. | Required | 
| inherit_web_protection_profile | Enable inherit web protection profile. Possible values are: enable, disable. Default is disable. | Optional | 
| profile | Web protection profile, it is required when inherit web protection profile is disabled. | Optional | 
| status | HTTP content routing member status. Supports API version 2 only. Possible values are: enable, disable. Default is enable. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.HttpContentRoutingMember.id | Number | Http Content Routing Member ID. | 

#### Command example
```!fortiwebvm-http-content-routing-member-add policy_name=example http_content_routing_policy=content1```
#### Context Example
```json
{
    "FortiwebVM": {
        "HttpContentRoutingMember": {
            "id": "1"
        }
    }
}
```

#### Human Readable Output

>### HTTP content routing member succesfuly created!
>|Id|
>|---|
>| 1 |


### fortiwebvm-http-content-routing-member-update
***
Update Server Policy HTTP Content Routing Member (HTTP Content Routing Member is a member of HTTP Content Routing).


#### Base Command

`fortiwebvm-http-content-routing-member-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy Name. | Required | 
| http_content_routing_policy | HTTP content routing policy name. | Optional | 
| id | Server Policy HTTP Content Routing Member ID. | Required | 
| is_default | Is FortiWeb applies the protection profile to any traffic that does not match conditions specified in the HTTP content routing policies?. Possible values are: yes, no. | Optional | 
| inherit_web_protection_profile | Enable inherit web protection profile. Possible values are: enable, disable. | Optional | 
| profile | Web protection profile, it is required when inherit web protection profile is disabled. Supports API version 1 only. | Optional | 
| status | Supports API version 2 only. Possible values are: enable, disable. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-http-content-routing-member-update policy_name=example id=1```
#### Human Readable Output

>### HTTP content routing member succesfuly updated!
>|Id|
>|---|
>| 1 |


### fortiwebvm-http-content-routing-member-delete
***
Delete Server Policy HTTP Content Routing Member (HTTP Content Routing Member is a member of HTTP Content Routing).


#### Base Command

`fortiwebvm-http-content-routing-member-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy Name. | Required | 
| id | Server Policy HTTP Content Routing Member ID. | Required | 


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-http-content-routing-member-delete policy_name=example id=1```
#### Human Readable Output

>### HTTP content routing member succesfuly deleted!
>|Id|
>|---|
>| 1 |


### fortiwebvm-http-content-routing-member-list
***
List the Server Policy HTTP Content Routing Members (HTTP Content Routing Member is a member of HTTP Content Routing).


#### Base Command

`fortiwebvm-http-content-routing-member-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy Name. | Required | 
| id | Server Policy HTTP Content Routing Member ID. | Optional | 
| page | The page number of the results to retrieve. | Optional | 
| page_size | The maximum number of records to retrieve per page. | Optional | 
| limit | The maximum number of records to retrieve. . Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.HttpContentRoutingMember.policy_name | String | HTTP Content Routing Policy Name. | 
| FortiwebVM.HttpContentRoutingMember.Members.id | String | HTTP Content Routing ID. | 
| FortiwebVM.HttpContentRoutingMember.Members.default | String | HTTP Content Routing Is Default. | 
| FortiwebVM.HttpContentRoutingMember.Members.http_content_routing_policy | String | HTTP content routing policy name. | 
| FortiwebVM.HttpContentRoutingMember.Members.inherit_web_protection_profile | Boolean | HTTP Content Routing inherit web protection profile flag. | 
| FortiwebVM.HttpContentRoutingMember.Members.profile | String | HTTP Content Routing Profile. | 
| FortiwebVM.HttpContentRoutingMember.Members.status | String | HTTP Content Routing Status. Supports API version 2 only. | 

#### Command example
```!fortiwebvm-http-content-routing-member-list policy_name=example```
#### Context Example
```json
{
    "FortiwebVM": {
        "HttpContentRoutingMember": {
            "Members": [
                {
                    "default": "No",
                    "http_content_routing_policy": "content1",
                    "id": "1",
                    "inherit_web_protection_profile": false,
                    "profile": ""
                }
            ],
            "policy_name": "example"
        }
    }
}
```

#### Human Readable Output

>### HTTP Content Routing Policy Members:
>Showing 1 rows out of 1.
>|Id|Default|Http Content Routing Policy|Inherit Web Protection Profile|Profile|
>|---|---|---|---|---|
>| 1 | No | content1 | false |  |

