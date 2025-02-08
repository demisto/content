Fortiweb VM integration allows to manage WAF policies and block cookies, URLs, and host names.
This integration was integrated and tested with version 1 & 2 of fortiweb_vm

## Configure Fortiweb VM in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Username. | True |
| Password. | True |
| API Version | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fortiwebvm-protected-hostname-group-create
***
Create protected host name group.


#### Base Command

`fortiwebvm-protected-hostname-group-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Protected host name group name. | Required |
| default_action | Whether to accept or deny HTTP requests whose Host field does not match any of the host definitions that you add to this protected hosts group. Possible values are: Allow, Deny (no log), Deny. Default is Allow. | Optional |


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
Update protected host name group.


#### Base Command

`fortiwebvm-protected-hostname-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Protected host name group name. | Required |
| default_action | Whether to accept or deny HTTP requests whose Host field does not match any of the host definitions that you will add to this protected hosts group. Possible values are: Allow, Deny (no log), Deny. | Optional |


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
List the Protected host name group.


#### Base Command

`fortiwebvm-protected-hostname-group-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Protected host name group name. | Optional |
| page | The page number of the results to retrieve. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ProtectedHostnameGroup.id | String | Protected host name group ID. |
| FortiwebVM.ProtectedHostnameGroup.default_action | Number | Protected host name group action. |
| FortiwebVM.ProtectedHostnameGroup.protected_hostname_count | Number | The number of protected host name group members. |
| FortiwebVM.ProtectedHostnameGroup.can_delete | Boolean | Whether the Geo IP group can be deleted. Supports API version 1 only. |

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
Create protected host name member.


#### Base Command

`fortiwebvm-protected-hostname-member-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Protected host name group name. | Required |
| action | Whether to accept or deny HTTP requests whose Host field does not match any of the host definitions that you add to this protected hosts group. Possible values are: Allow, Deny (no log), Deny. Default is Allow. | Optional |
| host | Enter the IP address or FQDN of a virtual or real web host, as it appears in the Host field of HTTP headers, such as www.example.com. The maximum length is 256 characters. | Required |
| ignore_port | Whether host names with a port number will be protected. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional |
| include_subdomains | Whether sub-domains of the host will be protected. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ProtectedHostnameMember.id | String | Protected host name member ID |

#### Human Readable Output

>### Hostname member successfully created!
>|Id|
>|---|
>| 1 |


### fortiwebvm-protected-hostname-member-update
***
Update a protected host name member.


#### Base Command

`fortiwebvm-protected-hostname-member-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Protected host name group name. | Required |
| member_id | Protected host name member ID. | Required |
| action | Whether to accept or deny HTTP requests whose Host field does not match any of the host definitions that you add to this protected hosts group. Required in V1. Possible values are: Allow, Deny (no log), Deny. | Optional |
| host | Enter the IP address or FQDN of a virtual or real web host, as it appears in the Host field of HTTP headers, such as www.example.com. The maximum length is 256 characters. | Optional |
| ignore_port | Whether host names with a port number will be protected. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| include_subdomains | Whether sub-domains of the host will be protected. Supports API version 2 only. Possible values are: enable, disable. | Optional |


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
List all the protected host name members.


#### Base Command

`fortiwebvm-protected-hostname-member-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Protected host name group name. | Required |
| member_id | Protected host name member ID. | Optional |
| page | The page number of the results to retrieve. Default is 25. | Optional |
| page_size | A number of hostname members per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ProtectedHostnameMember.group_name | String | Protected host name group name. |
| FortiwebVM.ProtectedHostnameMember.Members.id | String | Protected host name member ID. |
| FortiwebVM.ProtectedHostnameMember.Members.action | String | Protected hostname member action. |
| FortiwebVM.ProtectedHostnameMember.Members.host | String | Protected host name member IP address. |
| FortiwebVM.ProtectedHostnameMember.Members.ignore_port | String | Protected host name member ignore port. Supports API version 2 only. |
| FortiwebVM.ProtectedHostnameMember.Members.include_subdomains | String | Protected host name member include sub-domains. Supports API version 2 only. |

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
Delete protected host name member.


#### Base Command

`fortiwebvm-protected-hostname-member-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Protected host name group name. | Required |
| member_id | Protected host name member ID. | Required |


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
Delete a protected host name.


#### Base Command

`fortiwebvm-protected-hostname-group-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Protected host name group name. | Required |


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
| name | IP list group name. | Required |
| action | The action FortiWeb will take when it detects a violation of the rule. Supports API version 2 only. Possible values are: Alert deny, Block period, Deny (no log). Default is Alert deny. | Optional |
| block_period | Enter the number of seconds to block subsequent requests from a client after FortiWeb detects that the client has violated the rule. The valid range is 1–3,600 seconds. Supports API version 2 only. Default is 600. | Optional |
| severity | The severity level the FortiWeb appliance will use when a blacklisted IP address attempts to connect to your web servers. Supports API version 2 only. Possible values are: Low, Medium, High, Info. Default is Low. | Optional |
| ignore_x_forwarded_for | Whether IP addresses will be scanned at the TCP layer instead of the HTTP layer. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional |
| trigger_policy | The trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a blacklisted IP address's attempt to connect to your web servers. Supports API version 2 only. | Optional |


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
Update an IP list.


#### Base Command

`fortiwebvm-ip-list-group-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | IP list group name. | Required |
| action | The action FortiWeb will take when it detects a violation of the rule. Supports API version 2 only. Possible values are: Alert deny, Block period, Deny (no log). | Optional |
| block_period | The number of seconds to block subsequent requests from a client after FortiWeb detects that the client has violated the rule. The valid range is 1–3,600 seconds. Supports API version 2 only. | Optional |
| severity | The severity level the FortiWeb appliance will use when a blacklisted IP address attempts to connect to your web servers. Supports API version 2 only. Possible values are: Low, Medium, High, Info. | Optional |
| ignore_x_forwarded_for | Whether the IP addresses will be scanned at the TCP layer instead of the HTTP layer. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| trigger_policy | The trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a blacklisted IP address's attempt to connect to your web servers. Supports API version 2 only. | Optional |


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
| name | IP list name. | Optional |
| page | The page number of the results to retrieve. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.IpListGroup.id | String | IP list ID. |
| FortiwebVM.IpListGroup.ip_list_count | Number | The number of IP list members. |
| FortiwebVM.IpListGroup.can_delete | Boolean | Whether the Geo IP group can be deleted. Supports API version 1 only. |
| FortiwebVM.IpListGroup.q_ref | Number | The CMDB reference count. Supports API version 2 only. |
| FortiwebVM.IpListGroup.q_type | Number | IP list group object type. Supports API version 2 only. |
| FortiwebVM.IpListGroup.can_clone | Number | Whether the IP list group can be cloned. Supports API version 2 only. |
| FortiwebVM.IpListGroup.block_period | Number | IP list group block period. Supports API version 2 only. |
| FortiwebVM.IpListGroup.can_view | Number | Whether you can view the IP list group. Supports API version 2 only. |
| FortiwebVM.IpListGroup.action | String | IP list group action. Supports API version 2 only. |
| FortiwebVM.IpListGroup.trigger_policy | String | IP list group trigger policy name. Supports API version 2 only. |
| FortiwebVM.IpListGroup.severity | String | IP list group severity. Supports API version 2 only. |

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
Create an IP list member. Supports API versions 1 & 2.


#### Base Command

`fortiwebvm-ip-list-member-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | IP list group name. | Required |
| type | The type of the source IP address. Possible values are: Trust IP, Black IP, Allow Only Ip. | Required |
| ip_address | IPv4/IPv6 IP range. | Required |
| severity | The severity level the FortiWeb appliance will use when a blacklisted IP address attempts to connect to your web servers. Supports API version 1 only. Required when type= \"Black Ip\". Possible values are: High, Medium, Low, Informative. Default is Medium. | Optional |
| trigger_policy | The trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a blacklisted IP address's attempt to connect to your web servers. Supports API version 1 only. Required when type= \"Black Ip\". | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.IpListMember.id | Number | IP list policy member ID. |

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
Update IP list policy member.


#### Base Command

`fortiwebvm-ip-list-member-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | IP list group name. | Required |
| member_id | IP list policy member ID. | Required |
| type | The type of the source IP address. Possible values are: Trust IP, Black IP, Allow Only Ip. | Optional |
| ip_address | IPv4/IPv6 IP range. | Optional |
| severity | The severity level the FortiWeb appliance will use when a blacklisted IP address attempts to connect to your web servers. Supports API version 1 only. Required when type= \"Black Ip\". Possible values are: High, Medium, Low, Informative. | Optional |
| trigger_policy | The trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a blacklisted IP address's attempt to connect to your web servers. Supports API version 1 only. Required when type= \"Black Ip\". | Optional |


#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-ip-list-member-update group_name=example member_id=1 ip_address=1.2.3.4```
#### Human Readable Output

>### IP List member successfully updated!
>|Id|
>|---|
>| 1 |


### fortiwebvm-ip-list-member-list
***
List the IP list policy members.


#### Base Command

`fortiwebvm-ip-list-member-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | IP list group name. | Required |
| member_id | IP list member ID. | Optional |
| page | The page number of the results to retrieve. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.IpListMember.group_name | String | IP list group name. |
| FortiwebVM.IpListMember.Members.id | String | IP list member ID. |
| FortiwebVM.IpListMember.Members.type | String | IP list member type. |
| FortiwebVM.IpListMember.Members.severity | String | IP list member severity. Supports API version 1 only. |
| FortiwebVM.IpListMember.Members.trigger_policy | String | IP list member trigger policy. Supports API version 1 only. |
| FortiwebVM.IpListMember.Members.ip | String | IP list member IP address. |

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
Delete an IP list policy member.


#### Base Command

`fortiwebvm-ip-list-member-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | IP list group name. | Required |
| member_id | IP list policy member ID. | Required |


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
Update the custom predefined global whitelist.


#### Base Command

`fortiwebvm-custom-predefined-whitelist-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Predefined global whitelist ID. | Required |
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
Get custom predefined global whitelist.


#### Base Command

`fortiwebvm-custom-predefined-whitelist-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom predefined whitelist ID. | Optional |
| type | Type of the custom predefined whitelist. Possible values are: URL, Parameter, Cookie, Header Field. | Optional |
| page | The page number of the results to retrieve. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomPredefinedGlobalWhitelist.id | Number | Predefined global whitelist member ID. |
| FortiwebVM.CustomPredefinedGlobalWhitelist.name | String | Predefined global whitelist member name. |
| FortiwebVM.CustomPredefinedGlobalWhitelist.path | String | Predefined global whitelist member path. |
| FortiwebVM.CustomPredefinedGlobalWhitelist.domain | String | Predefined global whitelist member domain. |
| FortiwebVM.CustomPredefinedGlobalWhitelist.status | Boolean | Predefined global whitelist member status. |

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
            "path": "test",
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
>| 100002 |  | test |  | true |


### fortiwebvm-custom-whitelist-url-create
***
Create a custom global whitelist URL object.


#### Base Command

`fortiwebvm-custom-whitelist-url-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_type | Indicate whether the request-file \"&lt;url_str&gt;\" field contains a literal URL (Simple String), or a regular expression designed to match multiple URLs (Regular Expression). Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional |
| request_url | Depending on your selection in the request-type {plain \| regular} field, enter either:  - The literal URL, such as /robots.txt, that the HTTP request must contain in order to match the rule. The URL must begin with a backslash ( / ). - A regular expression, such as ^/*.html, matching all and only the URLs to which the rule should apply. The pattern does not require a slash ( / ); however, it must at least match URLs that begin with a backslash, such as /index.html. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomGlobalWhitelist.id | Number | Custom global whitelist ID |

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
Create a custom global whitelist parameter object.


#### Base Command

`fortiwebvm-custom-whitelist-parameter-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_type | Indicate whether the request-file \"&lt;url_str&gt;\" field contains a literal URL (plain), or a regular expression designed to match multiple URLs (regular). Supports API version 2 only. Required when request_url_status= True. Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional |
| request_url | Depending on your selection in the request-type {plain \| regular} field, enter either: - The literal URL, such as /robots.txt, that the HTTP request must contain in order to match the rule. The URL must begin with a backslash ( / ). - A regular expression, such as ^/*.html, matching all and only the URLs to which the rule should apply. The pattern does not require a slash ( / ); however, it must at least match URLs that begin with a backslash, such as /index.html. Supports API version 2 only. Required when request_url_status= True. | Optional |
| name | Enter the name of the parameter as it appears in the HTTP URL or body, such as rememberme. | Required |
| name_type | Indicate whether the name \"&lt;name_str&gt;\" field will contain a literal parameter name (Simple String), or a regular expression designed to match all parameter names (Regular Expression). Supports API version 2 only. Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional |
| request_url_status | Enable to apply this rule only to HTTP requests for specific URLs. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional |
| domain_status | Enable to apply this rule only to HTTP requests for specific domains. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional |
| domain_type | Indicate whether the domain \"&lt;cookie_str&gt;\" field will contain a literal domain/IP address (Simple String), or a regular expression designed to match multiple domains/IP addresses (Regular Expression). Supports API version 2 only. Required when request_url_status= True. Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional |
| domain | The partial or complete domain name or IP address as it appears in the cookie. Supports API version 2 only. Required when request_url_status= True. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomGlobalWhitelist.id | Number | Custom global whitelist ID. |

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
Create a custom global whitelist cookie object.


#### Base Command

`fortiwebvm-custom-whitelist-cookie-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the cookie as it appears in the HTTP request, such as NID. | Required |
| domain | The partial or complete domain name or IP address as it appears in the cookie. | Optional |
| path | The path as it appears in the cookie. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomGlobalWhitelist.id | Number | Custom global whitelist ID |

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
Create a custom global whitelist header field object. Supports API version 2 only.


#### Base Command

`fortiwebvm-custom-whitelist-header-field-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Enter the name of the cookie as it appears in the HTTP header. | Required |
| header_name_type | Indicate whether the type field will contain a literal name (Simple String), or a regular expression designed to match multiple names (Regular Expression). Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional |
| value_status | Enable to also check the value of the HTTP header. Only the HTTP headers that match both the name and the value will be allowlisted. Possible values are: enable, disable. Default is disable. | Optional |
| header_value_type | Indicate whether the header name will contain a literal name (plain), or a regular expression designed to match multiple names (regular). Possible values are: Simple String, Regular Expression. Default is Simple String. | Optional |
| value | The value of the HTTP header. Required when value_status is enabled. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomGlobalWhitelist.id | Number | Custom global whitelist ID. |

### fortiwebvm-custom-whitelist-url-update
***
Update a custom global whitelist URL object.


#### Base Command

`fortiwebvm-custom-whitelist-url-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom global whitelist object ID. | Required |
| status | Enable to exempt this object from all scans. Possible values are: enable, disable. Default is enable. | Optional |
| request_type | Indicate whether the request-file \"&lt;url_str&gt;\" field contains a literal URL (plain), or a regular expression designed to match multiple URLs (regular). Possible values are: Simple String, Regular Expression. | Optional |
| request_url | Depending on your selection in the request-type {plain \| regular} field, enter either - The literal URL, such as /robots.txt, that the HTTP request must contain in order to match the rule. The URL must begin with a backslash ( / ). - A regular expression, such as ^/*.html, matching all and only the URLs to which the rule should apply. The pattern does not require a slash ( / ); however, it must at least match URLs that begin with a backslash, such as /index.html. | Optional |


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
Update custom global whitelist parameter object.


#### Base Command

`fortiwebvm-custom-whitelist-parameter-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom global whitelist object ID. | Required |
| status | Enable to exempt this object from all scans. Possible values are: enable, disable. Default is enable. | Optional |
| request_type | Indicate whether the request-file \"&lt;url_str&gt;\" field contains a literal URL (plain), or a regular expression designed to match multiple URLs (regular). Supports API version 2 only. Required when request_url_status= True. Possible values are: Simple String, Regular Expression. Default is enable. | Optional |
| request_url | Depending on your selection in the request-type {plain \| regular} field, enter either: - The literal URL, such as /robots.txt, that the HTTP request must contain in order to match the rule. The URL must begin with a backslash ( / ). - A regular expression, such as ^/*.html, matching all and only the URLs to which the rule should apply. The pattern does not require a slash ( / ); however, it must at least match URLs that begin with a backslash, such as /index.html. Supports API version 2 only. Required when request_url_status= True. | Optional |
| name | Name. | Optional |
| name_type | Indicate whether the name \"&lt;name_str&gt;\" field will contain a literal parameter name (Simple String), or a regular expression designed to match all parameter names (Regular Expression). Supports API version 2 only. Possible values are: Simple String, Regular Expression. | Optional |
| request_url_status | Enable to apply this rule only to HTTP requests for specific URLs. Supports. Possible values are: enable, disable. | Optional |
| domain_status | Enable to apply this rule only to HTTP requests for specific domains. Supports. Possible values are: enable, disable. | Optional |
| domain_type | Indicate whether the domain \"&lt;cookie_str&gt;\" field will contain a literal domain/IP address (Simple String), or a regular expression designed to match multiple domains/IP addresses (Regular Expression). Supports API version 2 only. Required when request_url_status= True. Possible values are: Simple String, Regular Expression. | Optional |
| domain | Enter the partial or complete domain name or IP address as it appears in the cookie. Supports API version 2 only. Required when request_url_status= True. | Optional |


#### Context Output

There is no context output for this command.
### fortiwebvm-custom-whitelist-cookie-update
***
Update a custom global whitelist cookie object.


#### Base Command

`fortiwebvm-custom-whitelist-cookie-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom global whitelist object ID. | Required |
| status | Enable to exempt this object from all scans. Possible values are: enable, disable. Default is enable. | Optional |
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
Update a custom global whitelist header field object. Supports API version 2 only.


#### Base Command

`fortiwebvm-custom-whitelist-header-field-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom global whitelist object ID. | Required |
| status | Enable to exempt this object from all scans. Possible values are: enable, disable. Default is enable. | Optional |
| header_name_type | Indicate whether the type field will contain a literal name (Simple String), or a regular expression designed to match multiple names (Regular Expression). Possible values are: Simple String, Regular Expression. | Optional |
| name | The name of the cookie as it appears in the HTTP header. | Optional |
| header_value_type | Indicate whether the header name will contain a literal name (Simple String), or a regular expression designed to match multiple names (Regular Expression). Possible values are: Simple String, Regular Expression. | Optional |
| value_status | Enable to also check the value of the HTTP header. Only the HTTP headers that match both the name and the value will be allowlisted. Possible values are: enable, disable. | Optional |
| value | The value of the HTTP header. Required when value_status is enabled. | Optional |


#### Context Output

There is no context output for this command.
### fortiwebvm-custom-whitelist-delete
***
Delete a custom global whitelist object from the custom global whitelist.


#### Base Command

`fortiwebvm-custom-whitelist-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Object ID number. | Required |


#### Context Output

There is no context output for this command.
### fortiwebvm-custom-whitelist-list
***
List the custom global whitelist objects.


#### Base Command

`fortiwebvm-custom-whitelist-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Custom global whitelist object ID. | Optional |
| page | The page number of the results to retrieve. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.CustomGlobalWhitelist.id | Number | Custom global whitelist object ID. |
| FortiwebVM.CustomGlobalWhitelist.name | Number | Custom global whitelist object name. |
| FortiwebVM.CustomGlobalWhitelist.type | Number | Custom global whitelist object type. |
| FortiwebVM.CustomGlobalWhitelist.status | Boolean | Custom global whitelist object status. |
| FortiwebVM.CustomGlobalWhitelist.request_type | Number | Custom global whitelist object request type. |
| FortiwebVM.CustomGlobalWhitelist.request_url | String | Custom global whitelist object request URL. |
| FortiwebVM.CustomGlobalWhitelist.header_name_type | String | Custom global whitelist object header type. Supports API version 2 only. |
| FortiwebVM.CustomGlobalWhitelist.domain_type | String | Custom global whitelist object domain type. Supports API version 2 only. |
| FortiwebVM.CustomGlobalWhitelist.name_type | String | Custom global whitelist object name type. Supports API version 2 only. |
| FortiwebVM.CustomGlobalWhitelist.request_url_status | String | Custom global whitelist object request file status. Supports API version 2 only. |
| FortiwebVM.CustomGlobalWhitelist.domain_status | String | Custom global whitelist object domain status. Supports API version 2 only. |
| FortiwebVM.CustomGlobalWhitelist.domain | String | Custom global whitelist object domain. Supports API version 2 only. |
| FortiwebVM.CustomGlobalWhitelist.path | String | Custom global whitelist object path. Supports API version 2 only. |
| FortiwebVM.CustomGlobalWhitelist.header_value_type | String | Custom global whitelist object value type. Supports API version 2 only. |
| FortiwebVM.CustomGlobalWhitelist.value | String | Custom global whitelist object value. Supports API version 2 only. |
| FortiwebVM.CustomGlobalWhitelist.value_status | String | Custom global whitelist object value status. Supports API version 2 only. |

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
Create Geo IP member.


#### Base Command

`fortiwebvm-geo-ip-member-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Geo IP group name. | Required |
| countries | Comma-separated list of country names to add to the GEO IP list name. Possible values are: Afghanistan, Aland Islands, Albania, Algeria, American Samoa, Andorra, Angola, Anguilla, Antarctica, Antigua And Barbuda, Argentina, Armenia, Aruba, Australia, Austria, Azerbaijan, Bahamas, Bahrain, Bangladesh, Barbados, Belarus, Belgium, Belize, Benin, Bermuda, Bhutan, Bolivia, Bonaire Saint Eustatius And Saba, Bosnia And Herzegovina, Botswana, Brazil, British Indian Ocean Territory, British Virgin Islands, Brunei Darussalam, Bulgaria, Burkina Faso, Burundi, Cambodia, Cameroon, Canada, Cape Verde, Cayman Islands, Central African Republic, Chad, Chile, China, Colombia, Comoros, Congo, Cook Islands, Costa Rica, Cote D Ivoire, Croatia, Cuba, Curacao, Cyprus, Czech Republic, Democratic People S Republic Of Korea, Democratic Republic Of The Congo, Denmark, Djibouti, Dominica, Dominican Republic, Ecuador, Egypt, El Salvador, Equatorial Guinea, Eritrea, Estonia, Ethiopia, Falkland Islands  Malvinas, Faroe Islands, Federated States Of Micronesia, Fiji, Finland, France, French Guiana, French Polynesia, Gabon, Gambia, Georgia, Germany, Ghana, Gibraltar, Greece, Greenland, Grenada, Guadeloupe, Guam, Guatemala, Guernsey, Guinea, Guinea-Bissau, Guyana, Haiti, Honduras, Hong Kong, Hungary, Iceland, India, Indonesia, Iran, Iraq, Ireland, Isle Of Man, Israel, Italy, Jamaica, Japan, Jersey, Jordan, Kazakhstan, Kenya, Kiribati, Kosovo, Kuwait, Kyrgyzstan, Lao People S Democratic Republic, Latvia, Lebanon, Lesotho, Liberia, Libya, Liechtenstein, Lithuania, Luxembourg, Macao, Macedonia, Madagascar, Malawi, Malaysia, Maldives, Mali, Malta, Marshall Islands, Martinique, Mauritania, Mauritius, Mayotte, Mexico, Moldova, Monaco, Mongolia, Montenegro, Montserrat, Morocco, Mozambique, Myanmar, Namibia, Nauru, Nepal, Netherlands, New Caledonia, New Zealand, Nicaragua, Niger, Nigeria, Niue, Norfolk Island, Northern Mariana Islands, Norway, Oman, Pakistan, Palau, Palestine, Panama, Papua New Guinea, Paraguay, Peru, Philippines, Poland, Portugal, Puerto Rico, Qatar, Republic Of Korea, Reunion, Romania, Russian Federation, Rwanda, Saint Bartelemey, Saint Kitts And Nevis, Saint Lucia, Saint Martin, Saint Pierre And Miquelon, Saint Vincent And The Grenadines, Samoa, San Marino, Sao Tome And Principe, Saudi Arabia, Senegal, Serbia, Seychelles, Sierra Leone, Singapore, Sint Maarten, Slovakia, Slovenia, Solomon Islands, Somalia, South Africa, South Georgia And The South Sandwich Islands, South Sudan, Spain, Sri Lanka, Sudan, Suriname, Swaziland, Sweden, Switzerland, Syria, Taiwan, Tajikistan, Tanzania, Thailand, Timor-Leste, Togo, Tokelau, Tonga, Trinidad And Tobago, Tunisia, Turkey, Turkmenistan, Turks And Caicos Islands, Tuvalu, Uganda, Ukraine, United Arab Emirates, United Kingdom, United States, Uruguay, U S  Virgin Islands, Uzbekistan, Vanuatu, Vatican, Venezuela, Vietnam, Wallis And Futuna, Yemen, Zambia, Zimbabwe. Default is Low. | Required |


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
Delete Geo IP member .


#### Base Command

`fortiwebvm-geo-ip-member-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Geo IP group name. | Required |
| member_id | Geo IP member ID number. (The ID of the Geo IP member is the ID of the country in the Geo IP list.). | Required |


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
Get Geo IP member.


#### Base Command

`fortiwebvm-geo-ip-member-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Geo IP Name. | Required |
| member_id | Geo IP member ID number. (The ID of the Geo IP Member is the ID of the country in the Geo IP list.). | Optional |
| page | The page number of the results to retrieve. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.GeoIpMember.group_name | String | Geo IP member group name. |
| FortiwebVM.GeoIpMember.countries.id | String | Geo IP member ID. |
| FortiwebVM.GeoIpMember.countries.country | Number | Geo IP member country name. |

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
| name | Geo IP group name. | Required |
| trigger_policy | Enter the name of the trigger to apply when this rule is violated. | Optional |
| severity | The severity level to use in logs and reports generated when a violation of the rule occurs. Possible values are: High, Medium, Low, Info. Default is Low. | Optional |
| exception_rule | Geo IP exception groups. | Optional |
| action | Select which action FortiWeb will take when it detects a violation of the rule: alert_deny — Block the request (or reset the connection) and generate an alert and/or log message. deny_no_log — Block the request (or reset the connection). block-period — Block subsequent requests from the client for a number of seconds. Also configure block-period. Supports API version 2 only. Possible values are: Alert deny, Block period, Deny (no log). Default is Block period. | Optional |
| block_period | The number of seconds to block subsequent requests. The valid range is 1–3,600 seconds. Relevant when action=Block period True. Supports API version 2 only. Default is 600. | Optional |
| ignore_x_forwarded_for | Whether to enable so that IP addresses will be scanned at the TCP layer instead of the HTTP layer. Supports API version 2 only. Possible values are: enable, disable. | Optional |


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
| name | Geo IP group name. | Required |
| trigger_policy | Enter the name of the trigger to apply when this rule is violated. | Optional |
| severity | The severity level to use in logs and reports generated when a violation of the rule occurs. Possible values are: High, Medium, Low, Info. | Optional |
| exception_rule | Geo IP exception groups. | Optional |
| action | The action FortiWeb will take when it detects a violation of the rule: alert_deny — Block the request (or reset the connection) and generate an alert and/or log message.deny_no_log — Block the request (or reset the connection). block-period — Block subsequent requests from the client for a number of seconds. Also configure block-period. Supports API version 2 only. Possible values are: Alert deny, Block period, Deny (no log). | Optional |
| block_period | The number of seconds to block subsequent requests. The valid range is 1–3,600 seconds. Supports API version 2 only. | Optional |
| ignore_x_forwarded_for | Whether to enable so that the IP addresses will be scanned at the TCP layer instead of the HTTP layer. Supports API version 2 only. Possible values are: enable, disable. | Optional |


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
| name | Geo IP group name. | Required |


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
| name | Geo IP group name. | Optional |
| page | The page number of the results to retrieve. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.GeoIpGroup.id | Number | Geo IP group ID. |
| FortiwebVM.GeoIpGroup.count | Number | The number of Geo IP group members. |
| FortiwebVM.GeoIpGroup.trigger_policy | String | Geo IP group trigger policy name. |
| FortiwebVM.GeoIpGroup.severity | String | Geo IP group severity number. |
| FortiwebVM.GeoIpGroup.except | String | Geo IP group exception groups. |
| FortiwebVM.GeoIpGroup.can_delete | Boolean |Whether the Geo IP group can be deleted.  Supports API version 1 only. |
| FortiwebVM.GeoIpGroup.action | String | Geo IP group action. Supports API version 2 only. |
| FortiwebVM.GeoIpGroup.block_period | Number | Geo IP group block period. Supports API version 2 only. |
| FortiwebVM.GeoIpGroup.ignore_x_forwarded_for | String | Whether IP addresses will be scanned at the TCP layer instead of the HTTP layer. Supports API version 2 only. |

### fortiwebvm-system-operation-status-get
***
Get operation status.


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
                "ip_netmask": "1.2.3.4/24",
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
                "ip_netmask": "1.2.3.4/0",
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
                "ip_netmask": "1.2.3.4/0",
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
                "ip_netmask": "1.2.3.4/0",
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
                "ip_netmask": "1.2.3.4/0",
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
                "ip_netmask": "1.2.3.4/0",
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
                "ip_netmask": "1.2.3.4/0",
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
                "ip_netmask": "1.2.3.4/0",
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
                "ip_netmask": "1.2.3.4/0",
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
                "ip_netmask": "1.2.3.4/0",
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
>| port1 | port1 | 1 |  | 1.2.3.4/24 | 10000 Mbps/Full Duplex | 18115 | 582306 | Up |
>| port2 | port2 | 2 |  | 1.2.3.4/0 | 10000 Mbps/Full Duplex | 141 | 571254 | Up |
>| port3 | port3 | 3 |  | 1.2.3.4/0 | 10000 Mbps/Full Duplex | 141 | 571338 | Up |
>| port4 | port4 | 4 |  | 1.2.3.4/0 | 10000 Mbps/Full Duplex | 141 | 571252 | Up |
>| port5 | port5 | 5 |  | 1.2.3.4/0 | 10000 Mbps/Full Duplex | 141 | 571246 | Up |
>| port6 | port6 | 6 |  | 1.2.3.4/0 | 10000 Mbps/Full Duplex | 141 | 571245 | Up |
>| port7 | port7 | 7 |  | 1.2.3.4/0 | 10000 Mbps/Full Duplex | 141 | 571239 | Up |
>| port8 | port8 | 8 |  | 1.2.3.4/0 | 10000 Mbps/Full Duplex | 141 | 571283 | Up |
>| port9 | port9 | 9 |  | 1.2.3.4/0 | 10000 Mbps/Full Duplex | 141 | 572431 | Up |
>| port10 | port10 | 10 |  | 1.2.3.4/0 | 10000 Mbps/Full Duplex | 141 | 572083 | Up |


### fortiwebvm-system-policy-status-get
***
Get policy status.


#### Base Command

`fortiwebvm-system-policy-status-get`
#### Input

There are no input arguments for this command.

#### Command example
```!fortiwebvm-system-policy-status-get```
#### Context Example - API Version 1
```json
{
    "FortiwebVM": {
        "SystemPolicy": {
            "connction_per_second": 0,
            "http_port": 80,
            "https_port": null,
            "id": "example",
            "mode": "Single Server/Server Pool",
            "name": "example",
            "session_count": 0,
            "status": "enable",
            "vserver": "1.2.3.4/32/"
        }
    }
}
```

#### Human Readable Output - API Version 1

>### Policy status:
>|Id|Name|Status|Vserver|Http Port|Https Port|Mode|Session Count|Connction Per Second|
>|---|---|---|---|---|---|---|---|---|
>| example | example | enable | 1.2.3.4/32/ | 80 |  | Single Server/Server Pool | 0 | 0 |

#### Context Example - API Version 2
```json
{
    "FortiwebVM": {
        "SystemPolicy": {
            "app_response_time": 0,
            "client_rtt": 0,
            "connction_per_second": 0,
            "http_port": "80",
            "https_port": null,
            "id": "example",
            "mode": "Single Server/Server Pool",
            "name": "example",
            "policy": 1099,
            "protocol": "HTTP",
            "server_rtt": 0,
            "session_count": 0,
            "status": "enable",
            "vserver": ""
        }
    }
}
```

#### Human Readable Output - API Version 2

>### Policy status:
>|Id|Name|Status|Vserver|Http Port|Https Port|Mode|Session Count|Connction Per Second|Policy|Client Rtt|Server Rtt|App Response Time|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| example | example | enable |  | 80 |  | Single Server/Server Pool | 0 | 0 | 1099 | 0 | 0 | 0 |


### fortiwebvm-system-status-get
***
Get system status.


#### Base Command

`fortiwebvm-system-status-get`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-system-status-get```
#### Context Example - API Version 1
```json
{
    "FortiwebVM": {
        "SystemStatus": {
            "administrativeDomain": "Disabled",
            "antivirusService": {
                "anti_expired": "Expired (1969-12-31)",
                "anti_expired_text": "[Renew]",
                "anti_expired_url": "test/",
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
                "expired_url": "test/",
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
                "url": "test"
            },
            "reputationService": {
                "reputationBuildNumber": "1.00020",
                "reputationLastUpdateMethod": "Manual",
                "reputationLastUpdateTime": "1969-12-31",
                "reputation_expired": "Expired (1969-12-31)",
                "reputation_expired_text": "[Renew]",
                "reputation_expired_url": "test/",
                "reputation_update_text": "[Update]",
                "reputation_update_url": "#navigate/SignatureUpdate"
            },
            "securityService": {
                "buildNumber": "0.00240",
                "expired": "Expired (1969-12-31)",
                "expired_text": "[Renew]",
                "expired_url": "test/",
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

#### Human Readable Output - API Version 1

>### System Status:
>|High Ability Status|Host Name|Serial Number|Operation Mode|System Time|Firmware Version|Administrative Domain|System Uptime|Fips And Cc Mode|Log Disk|
>|---|---|---|---|---|---|---|---|---|---|
>| Standalone | FortiWeb | FVVM00UNLICENSED | Reverse Proxy | Sun Dec 25 01:01:32 2022<br/> | FortiWeb-VM 6.12,build0421(GA),191218 | Disabled | 2 day(s) 20 hour(s) 7 min(s) | Disabled | Available |

#### Context Example - API Version 2
```json
{
    "FortiwebVM": {
        "SystemStatus": {
            "administrativeDomain": "Disabled",
            "bufferSizeMax": 102400,
            "fileUploadLimitMax": 102400,
            "firmwareVersion": "test",
            "firmware_partition": 2,
            "haStatus": "Standalone",
            "hostName": "FortiWeb",
            "managerMode": "Standalone",
            "operationMode": "Reverse Proxy",
            "readonly": false,
            "registration": {
                "label": "*",
                "text": "[Login]",
                "url": "test"
            },
            "serialNumber": "FVBAWS0001be9eec",
            "systemTime": "Sun Dec 25 02:06:38 2022\n",
            "up_days": "34",
            "up_hrs": "20",
            "up_mins": "45",
            "vmLicense": "valid"
        }
    }
}
```

#### Human Readable Output - API Version 2

>### System Status:
>|High Ability Status|Host Name|Serial Number|Operation Mode|System Time|Firmware Version|Administrative Domain|Manager Status|Sysyem Up Days|Sysyem Up Hrs|Sysyem Up Mins|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Standalone | FortiWeb | FVBAWS0001be9eec | Reverse Proxy | Sun Dec 25 02:06:38 2022<br/> | test 7.03,build0111(GA),220912 | Disabled | Standalone | 34 | 20 | 45 |

### fortiwebvm-virtual-server-list
***
List the virtual servers.


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
| FortiwebVM.VirtualServer.id | String | Virtual Server name. |

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
List the Geo exception groups.


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
#### Context Example
```json
{
    "FortiwebVM": {
        "GeoExceptionGroup": {
            "id": "exception1"
        }
    }
}
```

#### Human Readable Output

>### Geo exception:
>Showing 1 rows out of 1.
>|Id|
>|---|
>| exception1 |


### fortiwebvm-trigger-policy-list
***
List the trigger policy rules.


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
| FortiwebVM.TriggerPolicy.id | String | Trigger policy name. |

#### Command example
```!fortiwebvm-trigger-policy-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "TriggerPolicy": {
            "id": "trigger1"
        }
    }
}
```

#### Human Readable Output

>### Content Routing Policy:
>Showing 1 rows out of 1.
>|Id|
>|---|
>| trigger1 |


### fortiwebvm-certificate-intermediate-group-list
***
List the certificate intermediate groups.


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
| FortiwebVM.CertificateIntermediateGroup.id | String | Certificate intermediate group name. |

#### Command example
```!fortiwebvm-certificate-intermediate-group-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "CertificateIntermediateGroup": {
            "id": "group"
        }
    }
}
```

#### Human Readable Output

>### Content Routing Policy:
>Showing 1 rows out of 3.
>|Id|
>|---|
>| group |


### fortiwebvm-server-pool-list
***
List the server pools.


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
| FortiwebVM.ServerPool.id | String | Server pool name. |

#### Command example
```!fortiwebvm-server-pool-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "ServerPool": {
            "id": "Strong Dev"
        }
    }
}
```

#### Human Readable Output

>### Server pool:
>Showing 1 rows out of 2.
>|Id|
>|---|
>| Strong Dev |


### fortiwebvm-http-service-list
***
List the  HTTP services.


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
| FortiwebVM.HttpServiceList.id | String | HTTP service name. |

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
List the inline protection profiles.


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
Create a server policy.


#### Base Command

`fortiwebvm-server-policy-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Policy Name. | Required |
| json_template_id | Allows the use of the server policy JSON template. All of the arguments listed below will be overridden. | Optional |
| deployment_mode | The distribution method that FortiWeb uses when it forwards connections accepted by this policy. Possible values are: HTTP Content Routing, Single Server/Server Balance. | Optional |
| virtual_server | The name of a virtual server that provides the IP address and network interface of incoming traffic that FortiWeb routes and to which the policy applies a protection profile. The maximum length is 63 characters. | Optional |
| match_once | Enable to forward subsequent requests from an identified client connection to the same server pool as the initial connection from the client. Required when: deployment_mode = "HTTP Content Routing". Possible values are: enable, disable. Default is disable. | Optional |
| server_pool | The name of the server pool whose members receive the connections. Required when: deployment_mode = "Single Server/Server Balance". | Optional |
| protected_hostnames | The name of a protected hosts group to allow or reject connections based upon their host. | Optional |
| client_real_ip | Enable to configure FortiWeb to use the source IP address of the client that originated the request when it connects to a back-end server on behalf of that client. Possible values are: enable, disable. Default is disable. | Optional |
| ip_range | An IP address or address range to directly connect to the back-end server. Required when: client_real_ip = "enable". Supports API version 2 only. | Optional |
| syn_cookie | Enable to detect TCP SYN flood attacks. Possible values are: enable, disable. Default is disable. | Optional |
| half_open_thresh | The maximum number of TCP SYN packets, including retransmissions, that FortiWeb allows to be sent per second to a destination address. If this threshold is exceeded, the FortiWeb appliance treats the traffic as a DoS attack and ignores additional traffic from that source address. The valid range is 10–10,000. Default is 8192. | Optional |
| http_service | Custom or predefined service that defines the port number on which the virtual server receives HTTP traffic. | Optional |
| https_service | Custom or predefined service that defines the port number on which the virtual server receives HTTPS traffic. | Optional |
| multi_certificate | Enable to allow FortiWeb to use multiple local certificates. | Optional |
| certificate_group | The multi-certificate file you created. Required when:  multi_certificate is enabled. | Optional |
| proxy | Certificate group name. | Optional |
| redirect_to_https | Enable to automatically redirect all HTTP requests to the HTTPS service with the same URL and parameters. Possible values are: enable, disable. Default is disable. | Optional |
| inline_protection_profile | Inline web protection profile name. | Optional |
| monitor_mode | Enable to override deny and redirect actions defined in the server protection rules for the selected policy. This setting enables FortiWeb to log attacks without performing the deny or redirect action. Disable to allow FortiWeb to perform attack deny/redirect actions as defined by the server protection rules. Possible values are: enable, disable. Default is disable. | Optional |
| url_case_sensitivity | Enable to differentiate uniform resource locators (URLs) according to upper case and lower case letters for features that act upon the URLs in the headers of HTTP requests, such as block list rules, and allow list rules. Possible values are: enable, disable. Default is disable. | Optional |
| comments | A description or other comment. If the comment is more than one word or contains special characters, surround the comment with double quotes ( " ). The maximum length is 999 characters. | Optional |
| certificate_type | Certificate type. Supports API version 2 only. Possible values are: Local, Multi Certificate, Letsencrypt. Default is Local. | Optional |
| lets_certificate | Select the Letsencrypt certificate you created. Supports API version 2 only. Required when: certificate_type is 'Letsencrypt'. | Optional |
| retry_on | Enable to configure whether to retry a failed TCP connection or HTTP request in Reverse Proxy mode. Supports API version 2 only. Possible values are: enable, disable. Default is disable. | Optional |
| retry_on_cache_size | A cache size limit for the HTTP request packet. Supports API version 2 only. Required when: retry_on is enabled. Default is 512. | Optional |
| retry_on_connect_failure | Enable to configure the retry times in case of any TCP connection failure. Supports API version 2 only. Required when: retry_on is enabled. Possible values are: enable, disable. Default is disable. | Optional |
| retry_times_on_connect_failure | The number of retry times when FortiWeb reconnects the single server or switch to the other pserver. The valid range is 1-5. Supports API version 2 only. Required when: retry_on_connect_failure and retry_on are enabled. Possible values are: 1, 2, 3, 4, 5. Default is 3. | Optional |
| retry_on_http_layer | Enable to configure the retry times and failure response code in case of any HTTP connection failure. Supports API version 2 only. Required when: retry_on is enabled. Possible values are: enable, disable. Default is disable. | Optional |
| retry_times_on_http_layer | The number of retry times when FortiWeb reconnects the single server or switch to the other pserver. The valid range is 1-5. Supports API version 2 only. Required when: retry_on and retry_on_http_layer are enabled. Possible values are: 1, 2, 3, 4, 5. Default is 3. | Optional |
| retry_on_http_response_codes | The failure return code when the pserver can be connected to determine enabling HTTP failure retry. Supports API version 2 only. Required when: retry_on and retry_on_http_layer are enabled. Possible values are: 404, 408, 500, 501, 502, 503, 504. | Optional |
| scripting | Enable to perform actions that are not currently supported by the built-in feature set. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| scripting_list | Scripting list to perform actions that are not currently supported by the built-in feature set. Required when: scripting is enabled. Supports API version 2 only. | Optional |
| allow_list | The Policy Based Allow list to use instead of the Global Allow List. Supports API version 2 only. | Optional |
| replace_msg | The replacement message to apply to the policy. Supports API version 2 only. | Optional |


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
Update the server policy.


#### Base Command

`fortiwebvm-server-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Policy name. | Required |
| deployment_mode | Deployment mode. Possible values are: HTTP Content Routing, Single Server/Server Balance. | Optional |
| virtual_server | The name of a virtual server that provides the IP address and network interface of incoming traffic that FortiWeb routes and to which the policy applies a protection profile. The maximum length is 63 characters. | Optional |
| match_once | Enable to forward subsequent requests from an identified client connection to the same server pool as the initial connection from the client. Required when: deployment_mode = "HTTP Content Routing". Possible values are: enable, disable. Default is disable. | Optional |
| server_pool | Enter the name of the server pool whose members receive the connections. Required when: deployment_mode = "Single Server/Server Balance". | Optional |
| protected_hostnames | Protected hostnames group name. Enter the name of a protected hosts group to allow or reject connections based upon their host. | Optional |
| client_real_ip | Enable to configure FortiWeb to use the source IP address of the client that originated the request when it connects to a back-end server on behalf of that client. | Optional |
| ip_range | Specify an IP address or address range to directly connect to the back-end server. Required when: client_real_ip = "enable". Supports API version 2 only. | Optional |
| syn_cookie | Enable to detect TCP SYN flood attacks. Possible values are: enable, disable. Default is disable. | Optional |
| half_open_thresh | The maximum number of TCP SYN packets, including retransmissions, that FortiWeb allows to be sent per second to a destination address. If this threshold is exceeded, the FortiWeb appliance treats the traffic as a DoS attack and ignores additional traffic from that source address. The valid range is 10–10,000. | Optional |
| http_service | Custom or predefined service that defines the port number on which the virtual server receives HTTP traffic. | Optional |
| https_service | HTTPS service name. Custom or predefined service that defines the port number on which the virtual server receives HTTPS traffic. | Optional |
| http2 | Enable HTTP/2. Required when: HTTPSService is not null. Possible values are: enable, disable. Default is disable. | Optional |
| multi_certificate | Enable to allow FortiWeb to use multiple local certificates. | Optional |
| certificate_group | Required  when:  multi-certificate is enabled. Select the multi-certificate file you created. | Optional |
| certificate | Certificate group name. Required when:  multi-certificate is disabled. | Optional |
| intergroup | Certificate intermediate group. Required when: HTTPSService is not null. | Optional |
| proxy | Enable this option when proxy servers or load balancers are installed before FortiWeb. Possible values are: enable, disable. Default is disable. | Optional |
| redirect_to_https | Enable to automatically redirect all HTTP requests to the HTTPS service with the same URL and parameters. | Optional |
| inline_protection_profile | Inline web protection profile name. | Optional |
| monitor_mode | Enable to override deny and redirect actions defined in the server protection rules for the selected policy. This setting enables FortiWeb to log attacks without performing the deny or redirect action. Disable to allow FortiWeb to perform attack deny/redirect actions as defined by the server protection rules. Possible values are: enable, disable. Default is disable. | Optional |
| url_case_sensitivity | Enable to differentiate uniform resource locators (URLs) according to upper case and lower case letters for features that act upon the URLs in the headers of HTTP requests, such as block list rules, and allow list rules. | Optional |
| comments | A description or other comment. If the comment is more than one word or contains special characters, surround the comment with double quotes ( " ). The maximum length is 999 characters. | Optional |
| certificate_type | Certificate type. Supports API version 2 only. Possible values are: Local, Multi Certificate, Letsencrypt. Default is Local. | Optional |
| lets_certificate | Select the Letsencrypt certificate you created. Supports API version 2 only. Required when: certificate-type is enabled. | Optional |
| retry_on | Enable to configure whether to retry a failed TCP connection or HTTP request in Reverse Proxy mode. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| retry_on_cache_size | The cache size limit for the HTTP request packet. Supports API version 2 only. Required when: retry_on is enabled. | Optional |
| retry_on_connect_failure | Enable to configure the retry times in case of any TCP connection failure. Supports API version 2 only. Required when: retry_on is enabled. Possible values are: enable, disable. | Optional |
| retry_times_on_connect_failure | The number of retry times when FortiWeb reconnects the single server or switch to the other pserver. The valid range is 1-5. Supports API version 2 only. Required when: retry_on_connect_failure and retry_on are enabled. Possible values are: 1, 2, 3, 4, 5. | Optional |
| retry_on_http_layer | Enable to configure the retry times and failure response code in case of any HTTP connection failure. Supports API version 2 only. Required when: retry_on is enabled. Possible values are: enable, disable. | Optional |
| retry_times_on_http_layer | The number of retry times when FortiWeb reconnects the single server or switch to the other pserver. The valid range is 1-5. Supports API version 2 only. Required when: retry_on and retry_on_http_layer are enabled. Possible values are: 1, 2, 3, 4, 5. | Optional |
| retry_on_http_response_codes | The failure return code when the pserver can be connected to determine enabling HTTP failure retry. Supports API version 2 only. Required when: retry_on and retry_on_http_layer are enabled. Possible values are: 404, 408, 500, 501, 502, 503, 504. | Optional |
| scripting | Enable to perform actions that are not currently supported by the built-in feature set. Supports API version 2 only. | Optional |
| scripting_list | Scripting list to perform actions that are not currently supported by the built-in feature set. Required when: scripting is enabled. Supports API version 2 only. | Optional |
| allow_list | The Policy Based Allow list to use instead of the Global Allow List. Supports API version 2 only. | Optional |
| replacemsg | The replacement message to apply to the policy. Supports API version 2 only. | Optional |
| json_template_id | Allows the use of the server policy JSON template. All of the arguments listed below will be overridden. For an example, see the integration. | Optional |


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
Delete the server policy.


#### Base Command

`fortiwebvm-server-policy-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Policy name. | Required |


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
List the server policies.


#### Base Command

`fortiwebvm-server-policy-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Server policy name. | Optional |
| page | The page number of the results to retrieve. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPolicy.name | String | Server policy name. |
| FortiwebVM.ServerPolicy.deployment_mode | String | Server policy deployment mode. |
| FortiwebVM.ServerPolicy.protocol | String | Server policy protocol. |
| FortiwebVM.ServerPolicy.web_protection_profile | String | Server policy inherit web protection profile flag. |
| FortiwebVM.ServerPolicy.monitor_mode | String | This setting enables FortiWeb to log attacks without performing the deny or redirect action. Disable to allow FortiWeb to perform attack deny/redirect actions as defined by the server protection rules. |
| FortiwebVM.ServerPolicy.http_service | String | Custom or predefined service that defines the port number on which the virtual server receives HTTPS traffic. |
| FortiwebVM.ServerPolicy.https_service | String | Custom or predefined service that defines the port number on which the virtual server receives HTTPS traffic. |
| FortiwebVM.ServerPolicy.certificate | String | Server policy certificate. |
| FortiwebVM.ServerPolicy.certificate_intermediate_group | String | Server policy certificate intermediate group. |
| FortiwebVM.ServerPolicy.server_pool | String | Server policy server pool name. |
| FortiwebVM.ServerPolicy.protected_hostnames | String | Server policy protected hostname name. |
| FortiwebVM.ServerPolicy.client_real_ip | String | Enable to configure FortiWeb to use the source IP address of the client that originated the request when it connects to a back-end server on behalf of that client. |
| FortiwebVM.ServerPolicy.syn_cookie | String | Whether to detect TCP SYN flood attacks. |
| FortiwebVM.ServerPolicy.redirect_to_https | String | Whether to automatically redirect all HTTP requests to the HTTPS service with the same URL and parameters. |
| FortiwebVM.ServerPolicy.http2 | String | Whether to enable HTTP/2. Required when: HTTPSService is not null. |
| FortiwebVM.ServerPolicy.url_case_sensitivity | String | Whether to differentiate uniform resource locators \(URLs\) according to upper case and lower case letters for features that act upon the URLs in the headers of HTTP requests, such as block list rules, and allow list rules. |
| FortiwebVM.ServerPolicy.comments | String | A description or other comment. If the comment is more than one word or contains special characters, surround the comment with double quotes \( " \). The maximum length is 999 characters. |
| FortiwebVM.ServerPolicy.retry_on | String | Whether to configure whether to retry a failed TCP connection or HTTP request in Reverse Proxy mode. Supports API version 2 only. |
| FortiwebVM.ServerPolicy.retry_on_cache_size | String | A cache size limit for the HTTP request packet. Supports API version 2 only. Required when: retry_on is enabled. |
| FortiwebVM.ServerPolicy.retry_times_on_connect_failure | String | The number of retry times in case of any TCP connection failure. Supports API version 2 only. Required when: retry_on is enabled. |
| FortiwebVM.ServerPolicy.retry_on_http_layer | String | The number of retry times and failure response code in case of any HTTP connection failure. Supports API version 2 only. Required when: retry_on is enabled. |
| FortiwebVM.ServerPolicy.retry_times_on_http_layer | String | The number of retry times when FortiWeb reconnects the single server or switch to the other pserver. The valid range is 1-5. Supports API version 2 only. Required when: retry_on and retry_on_http_layer are enabled. |
| FortiwebVM.ServerPolicy.retry_on_http_response_codes | String | The failure return code when the pserver can be connected to determine enabling HTTP failure retry. Supports API version 2 only. Required when: retry_on and retry_on_http_layer are enabled. |
| FortiwebVM.ServerPolicy.scripting | String | Whether to perform actions that are not currently supported by the built-in feature set. Supports API version 2 only. |
| FortiwebVM.ServerPolicy.scripting_list | String | Server policy scripting list. Required when: scripting is enabled. Supports API version 2 only. |
| FortiwebVM.ServerPolicy.allow_list | String | Server policy allow list. Supports API version 2 only. |
| FortiwebVM.ServerPolicy.replace_msg | String | Server policy replacement message. Supports API version 2 only. API version 2 only. |

#### Command example
```!fortiwebvm-server-policy-list name=example```
#### Context Example - API Version 1
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

#### Human Readable Output - API Version 1

>### Server Policies:
>Showing 1 rows out of 1.
>|Name|Deployment Mode|Virtual Server|Protocol|Web Protection Profile|Monitor Mode|
>|---|---|---|---|---|---|
>| example | HTTP Content Routing | virtual1 | HTTP |  | false |

#### Context Example - API Version 2
```json
{
    "FortiwebVM": {
        "ServerPolicy": {
            "allow_list": "",
            "certificate": "",
            "certificate_intermediate_group": "",
            "client_real_ip": "disable",
            "comments": "",
            "deployment_mode": "HTTP Content Routing",
            "half_open_thresh": 8192,
            "http2": "disable",
            "http_service": "HTTP",
            "https_service": "",
            "monitor_mode": "disable",
            "name": "example",
            "protected_hostnames": "",
            "protocol": "HTTP",
            "redirect_to_https": "disable",
            "replace_msg": "Predefined",
            "retry_on": "disable",
            "retry_on_cache_size": 512,
            "retry_on_connect_failure": "disable",
            "retry_on_http_layer": "disable",
            "retry_on_http_response_codes": "",
            "retry_times_on_connect_failure": 3,
            "retry_times_on_http_layer": 3,
            "scripting": "disable",
            "scripting_list": "",
            "server_pool": "",
            "syn_cookie": "disable",
            "url_case_sensitivity": "disable",
            "virtual_server": "virtual1",
            "web_protection_profile": ""
        }
    }
}
```

#### Human Readable Output - API Version 2

>### Server Policies:
>Showing 1 rows out of 1.
>|Name|Deployment Mode|Virtual Server|Protocol|Web Protection Profile|Monitor Mode|
>|---|---|---|---|---|---|
>| example | HTTP Content Routing | virtual1 | HTTP |  | disable |

### fortiwebvm-content-routing-policy-list
***
List the HTTP content routing policies.


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
| FortiwebVM.HttpContentRoutingPolicy.id | String | Policy name. |

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
Create the server policy HTTP content routing member.


#### Base Command

`fortiwebvm-http-content-routing-member-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name. | Required |
| is_default | Whether FortiWeb applies the protection profile to any traffic that does not match conditions specified in the HTTP content routing policies. Possible values are: yes, no. Default is no. | Optional |
| http_content_routing_policy | HTTP content routing policy name. | Required |
| inherit_web_protection_profile | Whether to enable the inherit web protection profile. Possible values are: enable, disable. Default is disable. | Optional |
| profile | Web protection profile. This is required when inherit web protection profile is disabled. | Optional |
| status | HTTP content routing member status. Supports API version 2 only. Possible values are: enable, disable. Default is enable. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.HttpContentRoutingMember.id | Number | HTTP content routing member ID. |

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
Update the server policy HTTP content routing member.


#### Base Command

`fortiwebvm-http-content-routing-member-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name. | Required |
| http_content_routing_policy | HTTP content routing policy name. | Optional |
| id | Server policy HTTP content routing member ID. | Required |
| is_default | Whether FortiWeb applies the protection profile to any traffic that does not match conditions specified in the HTTP content routing policies. Possible values are: yes, no. | Optional |
| inherit_web_protection_profile | Whether to enable inherit web protection profile. Possible values are: enable, disable. | Optional |
| profile | Web protection profile. This is required when inherit web protection profile is disabled. Supports API version 1 only. | Optional |
| status | HTTP content routing member status. Supports API version 2 only. Possible values are: enable, disable. | Optional |


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
Delete the server policy HTTP content routing member.


#### Base Command

`fortiwebvm-http-content-routing-member-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name. | Required |
| id | Server policy HTTP content routing member ID. | Required |


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
List the Server policy HTTP content routing members.


#### Base Command

`fortiwebvm-http-content-routing-member-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | Policy name. | Required |
| id | Server policy HTTP content routing member ID. | Optional |
| page | The page number of the results to retrieve. | Optional |
| page_size | The maximum number of records to retrieve per page. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.HttpContentRoutingMember.policy_name | String | HTTP content routing policy name. |
| FortiwebVM.HttpContentRoutingMember.Members.id | String | HTTP content routing ID. |
| FortiwebVM.HttpContentRoutingMember.Members.default | String | Whether the HTTP content routing is the default. |
| FortiwebVM.HttpContentRoutingMember.Members.http_content_routing_policy | String | HTTP content routing policy name. |
| FortiwebVM.HttpContentRoutingMember.Members.inherit_web_protection_profile | Boolean | HTTP content routing inherit web protection profile flag. |
| FortiwebVM.HttpContentRoutingMember.Members.profile | String | HTTP content routing profile. |
| FortiwebVM.HttpContentRoutingMember.Members.status | String | HTTP content routing status. Supports API version 2 only. |


### fortiwebvm-persistence-policy-list

***
List all the persistence policies. The persistence policy applies to all members of the server pool. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-persistence-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Return all objects that include the specified string. For example: search=test will return objects like 'test1', 'test2', '5test', and any other objects containing the test string. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.PersistencePolicy.id | String | Persistence policy name. |
| FortiwebVM.PersistencePolicy.type | String | The persistence policy type. |

#### Command example
```!fortiwebvm-persistence-policy-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "PersistencePolicy": {
            "id": "test",
            "type": "Source IP"
        }
    }
}
```

#### Human Readable Output

>### Persistence policy:
>Showing page 1.
> Current page size: 50
>|Id|Type|
>|---|---|
>| test | Source IP |


### fortiwebvm-server-health-check-list

***
List all the server health check policies. Tests for server responsiveness (called “server health checks” in the web UI) and polls web servers that are members of a server pool to determine their availability before forwarding traffic. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-health-check-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Return all objects that include the specified string. For example: search=test will return objects like 'test1', 'test2', '5test', and any other objects containing the test string. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerHealthCheck.id | String | Server health check name. |

#### Command example
```!fortiwebvm-server-health-check-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "ServerHealthCheck": {
            "id": "HLTHCK_ICMP"
        }
    }
}
```

#### Human Readable Output

>### Server health check:
>Showing page 1.
> Current page size: 50
>|Id|
>|---|
>| HLTHCK_ICMP |


### fortiwebvm-local-certificate-list

***
List the Server certificate that is stored locally on the FortiWeb appliance. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-local-certificate-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Return all objects that include the specified string. For example: search=test will return objects like 'test1', 'test2', '5test', and any other objects containing the test string. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.LocalCertificate.id | String | The local certificate name. |
| FortiwebVM.LocalCertificate.valid_to | String | The local certificate expiration date. |

#### Command example
```!fortiwebvm-local-certificate-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "LocalCertificate": {
            "_id": "certificate",
            "can_config": true,
            "can_delete": true,
            "can_download": false,
            "can_view": true,
            "comments": "",
            "extension": "Name: X509v3 Subject Key Identifier<br>\nCritical: no<br>\nContent: <br>\ntest:Btest<br>\nName: X509v3 Authority Key Identifier<br>\nCritical: no<br>\nContent: <br>\nkeyid:test:Btest\n<br>\nName: X509v3 Basic Constraints<br>\nCritical: yes<br>\nContent: <br>\nCA:TRUE<br>\n",
            "id": "certificate",
            "issuer": "C = us, ST = nnew york, O = Internet Widgits Pty Ltd",
            "name": "certificate",
            "serial_number": "test",
            "status": "OK",
            "subject": "C = us, ST = nnew york, O = Internet Widgits Pty Ltd",
            "valid_from": "2023-04-23 08:47:47  GMT",
            "valid_to": "2024-04-22 08:47:47  GMT",
            "version": 3
        }
    }
}
```

#### Human Readable Output

>### Local certificate:
>Showing page 1.
> Current page size: 50
>|Id|Valid To|Subject|Status|
>|---|---|---|---|
>| certificate | 2024-04-22 08:47:47  GMT | C = us, ST = nnew york, O = Internet Widgits Pty Ltd | OK |


### fortiwebvm-network-interface-list

***
List the network interfaces. A network interface is a connection point that enables communication between the FortiWeb device and the network, allowing traffic to flow through for inspection and protection. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-network-interface-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Return all objects that include the specified string. For example: search=test will return objects like 'test1', 'test2', '5test', and any other objects containing the test string. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.NetworkInterface.name | String | Network interface name. |
| FortiwebVM.NetworkInterface.ipv4_netmask | String | IPv4 network mask. |
| FortiwebVM.NetworkInterface.ipv4_access | String | IPv4 allowed access list. |
| FortiwebVM.NetworkInterface.ipv6_netmask | String | IPv6 network mask. |
| FortiwebVM.NetworkInterface.ipv6_access | String | IPv6 allowed access list. |
| FortiwebVM.NetworkInterface.status | String | The network interface status. |
| FortiwebVM.NetworkInterface.type | String | The network interface type. |

#### Command example
```!fortiwebvm-network-interface-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "NetworkInterface": {
            "_id": "port1",
            "addressing6_mode": "0",
            "addressing_mode": "0",
            "can_del": false,
            "can_edit": true,
            "column_name": "port1()",
            "de": "",
            "edit_name": "port1 (00:0C:29:71:BB:4E)",
            "id": "port1",
            "ipv4_access": "HTTPS,PING,SSH,HTTP,FortiWeb Manager",
            "ipv4_administrative_access": [
                "https",
                "ping",
                "ssh",
                "http",
                "FWB-manager"
            ],
            "ipv4_netmask": "1.2.3.4/24",
            "ipv6_access": "",
            "ipv6_administrative_access": [],
            "ipv6_netmask": "::/0",
            "link_status": "up",
            "name": "port1",
            "port_id": 0,
            "ref": 0,
            "status": "up",
            "type": "Physical"
        }
    }
}
```

#### Human Readable Output

>### Network interface:
>Showing page 1.
> Current page size: 50
>|Name|Ipv4 Netmask|Ipv4 Access|Ipv6 Netmask|Ipv6 Access|Status|Type|
>|---|---|---|---|---|---|---|
>| port1 | 1.2.3.4/24 | HTTPS,PING,SSH,HTTP,FortiWeb Manager | ::/0 |  | up | Physical |



### fortiwebvm-multi-certificate-list

***
List the multi certificates. Multi certificates configure RSA, DSA, and ECDSA certificates and reference them in server policy in Reverse Proxy mode and pserver in True Transparent Proxy mode. Supports API version 2 only.

#### Base Command

`fortiwebvm-multi-certificate-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Return all objects that include the specified string. For example: search=test will return objects like 'test1', 'test2', '5test', and any other objects containing the test string. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.MultiCertificate.id | String | The multi certificate name. |

#### Command example
```!fortiwebvm-multi-certificate-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "MultiCertificate": {
            "id": "test"
        }
    }
}
```

#### Human Readable Output

>### Multi certificate:
>Showing page 1.
> Current page size: 50
>|Id|
>|---|
>| test |


### fortiwebvm-sni-certificate-list

***
List the SNI certificates. Server Name Indication (SNI) configuration identifies the certificate to use by domain. Supports API version 2 only.

#### Base Command

`fortiwebvm-sni-certificate-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Return all objects that include the specified string. For example: search=test will return objects like 'test1', 'test2', '5test', and any other objects containing the test string. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.SNICertificate.id | String | SNI certificate name. |

#### Command example
```!fortiwebvm-sni-certificate-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "SNICertificate": {
            "id": "test"
        }
    }
}
```

#### Human Readable Output

>### SNI certificate:
>Showing page 1.
> Current page size: 50
>|Id|
>|---|
>| test |


### fortiwebvm-virtual-ip-list

***
List the system virtual IPs. The virtual IP addresses are the IP addresses that paired with the domain name of your application. When users visit your application, the destination of their requests are these IP addresses. Supports API version 2 only.

#### Base Command

`fortiwebvm-virtual-ip-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Return all objects that include the specified string. For example: search=test will return objects like 'test1', 'test2', '5test', and any other objects containing the test string. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.VirtualIP.id | String | Virtual IP name. |

#### Command example
```!fortiwebvm-virtual-ip-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "VirtualIP": {
            "id": "test"
        }
    }
}
```

#### Human Readable Output

>### Virtaul IP:
>Showing page 1.
> Current page size: 50
>|Id|
>|---|
>| test |


### fortiwebvm-letsencrypt-certificate-list

***
List the Letsencrypt certificates. Supports API version 2 only.

#### Base Command

`fortiwebvm-letsencrypt-certificate-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Return all objects that include the specified string. For example: search=test will return objects like 'test1', 'test2', '5test', and any other objects containing the test string. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.Letsencrypt.id | String | Letsencrypt certificate name. |

#### Command example
```!fortiwebvm-letsencrypt-certificate-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "Letsencrypt": {
            "id": "test"
        }
    }
}
```

#### Human Readable Output

>### Letsencrypt certificate:
>Showing page 1.
> Current page size: 50
>|Id|
>|---|
>| test |


### fortiwebvm-url-access-rule-group-create

***
Create a URL access rule group. URL access rule group is a container that contains URL access rules (use fortiwebvm-url-access-rule-create/update/delete/list to manage the URL access rules). Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-url-access-rule-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | URL access rule group name. | Required |
| action | The action the FortiWeb appliance will take when a request matches the URL access rule. Possible values are: Pass, Alert &amp; Deny, Continue, Deny (no log). Default is Pass. | Optional |
| trigger_policy | Trigger policy name (dependencies - use fortiwebvm-trigger-policy-list to get the trigger policies). Relevant when: action=Alert &amp; Deny or Deny (no log). | Optional |
| severity | Severity level that FortiWeb appliance will use when a blocklisted IP address attempts to connect to your web servers. Relevant when: action=Alert &amp; Deny or Deny (no log). The default value is Low. Possible values are: High, Medium, Low, Informative. | Optional |
| host_status | Whether to require a host name. Possible values are: enable, disable. Default is disable. | Optional |
| host | The name of the protected host that the HTTP request must be in order to match the rule (dependencies - use fortiwebvm-protected-hostname-member-list to get hosts). Required when: host_status=enable. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-url-access-rule-group-create name=test```
#### Human Readable Output

>URL access rule group test was successfully created!

### fortiwebvm-url-access-rule-group-update

***
Update a URL access rule group. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-url-access-rule-group-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | URL access rule group name (dependencies - use fortiwebvm-url-access-rule-group-list command to get all URL access rule groups). | Required |
| action | The action the FortiWeb appliance will take when a request matches the URL access rule. Possible values are: Pass, Alert &amp; Deny, Continue, Deny (no log). | Optional |
| trigger_policy | Trigger policy name (dependencies - use fortiwebvm-trigger-policy-list to get the trigger policies). Relevant when: action=Alert &amp; Deny or Deny (no log). | Optional |
| severity | Severity level. Required when: action=Alert &amp; Deny or Deny (no log). Possible values are: High, Medium, Low, Informative. | Optional |
| host_status | Whether to require a host name. Possible values are: enable, disable. | Optional |
| host | The name of the protected host that the HTTP request must be in order to match the rule (dependencies - use fortiwebvm-protected-hostname-member-list to get hosts). Required when: host_status=enable. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-url-access-rule-group-update name=test action="Alert & Deny"```
#### Human Readable Output

>URL access rule group test was successfully updated!

### fortiwebvm-url-access-rule-group-delete

***
Delete a URL access rule group. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-url-access-rule-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | URL access rule group name (dependencies - use fortiwebvm-url-access-rule-group-list command to get all URL access rule groups). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-url-access-rule-group-delete name=test```
#### Human Readable Output

>URL access rule group test was successfully deleted!

### fortiwebvm-url-access-rule-group-list

***
List URL access rule groups. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-url-access-rule-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | URL access rule group name. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.URLAccessRuleGroup.id | String | URL access rule group name. |
| FortiwebVM.URLAccessRuleGroup.action | String | The action of the URL access rule group. |
| FortiwebVM.URLAccessRuleGroup.host_status | String | Whether to enable the host. |
| FortiwebVM.URLAccessRuleGroup.host | String | The host of the URL access rule group. |
| FortiwebVM.URLAccessRuleGroup.severity | String | The severity of the URL access rule group. |
| FortiwebVM.URLAccessRuleGroup.trigger_policy | String | The trigger policy of the URL access rule group. |
| FortiwebVM.URLAccessRuleGroup.count | Number | The count of the conditions that are related to the current URL access rule group.  |

#### Command example
```!fortiwebvm-url-access-rule-group-list name=test```
#### Context Example
```json
{
    "FortiwebVM": {
        "URLAccessRuleGroup": {
            "action": "alert_deny",
            "count": 0,
            "host": "",
            "host_status": "disable",
            "id": "test",
            "severity": "Low",
            "trigger_policy": ""
        }
    }
}
```

#### Human Readable Output

>### URL access rule group
>Showing page 1.
> Current page size: 50
>|Id|Action|Host|Severity|Count|
>|---|---|---|---|---|
>| test | alert_deny |  | Low | 0 |


### fortiwebvm-url-access-rule-condition-create

***
Create a URL access rule condition (URL access rule condition is a member of URL access rule group). URL access rules define the HTTP requests that are allowed or denied based on their hostname and URL. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-url-access-rule-condition-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | URL access rule group name (dependencies - use fortiwebvm-url-access-rule-group-list command to get all URL access rule groups). | Required |
| url_type | URL type. Select how to use the text in url_pattern to determine whether or not a request URL meets the conditions for this rule. Possible values are: Simple String, Regular Expression. | Required |
| url_pattern | Depending on your selection in url_type and meet_this_condition_if, type a regular expression that defines either all matching or all non-matching URLs. Must start with '/' when url_type=Simple String. | Required |
| meet_this_condition_if | Indicate how to use url_pattern when determining whether or not this rule’s condition has been met. Possible values are: Object matches the URL Pattern, Object does not match the URL Pattern. Default is Object matches the URL Pattern. | Optional |
| source_address | Whether to enable source address. Possible values are: enable, disable. Default is disable. | Optional |
| source_address_type | The source address type. Relevant when source_address=enable. . Possible values are: IP, IP Resolved by Specified Domain, Source Domain. | Optional |
| ip_range | IPv4/IPv6 IP range. For exampe: 1.2.3.4-1.2.3.4 or 2001::1-2001::100. Relevant when source_address_type=IP. . | Optional |
| ip_type | IP type. Relevant when source_address_type=IP Resolved by Specified Domain. . Possible values are: IPv4, IPv6. | Optional |
| ip | IP resolved by specified domain. Relevant when source_address_type=IP Resolved by Specified Domain. . | Optional |
| source_domain_type | Source domain type. Relevant when source_address_type=Source Domain. . Possible values are: Simple String, Regular Expression. | Optional |
| source_domain | Source domain. For example: test.com. Relevant when source_address_type=Source Domain. . | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.URLAccessRuleGroup.Condition.id | String | The URL access rule condition ID. |

#### Command example
```!fortiwebvm-url-access-rule-condition-create group_name=test url_pattern=test url_type="Regular Expression"```
#### Context Example
```json
{
    "FortiwebVM": {
        "URLAccessRuleGroup": {
            "Condition": {
                "id": "1"
            },
            "id": "test"
        }
    }
}
```

#### Human Readable Output

>### URL access rule condition 1 was successfully added to URL access rule group test.
>|Id|
>|---|
>| 1 |


### fortiwebvm-url-access-rule-condition-update

***
Update a URL access rule condition (URL access rule condition is a member of URL access rule group). Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-url-access-rule-condition-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | URL access rule group name (dependencies - use fortiwebvm-url-access-rule-group-list command to get all URL access rule groups). | Required |
| condition_id | URL access rule condition ID (dependencies - use fortiwebvm-url-access-rule-condition-list command to get all URL access condition IDs). | Required |
| url_type | URL type. Select how to use the text in url_pattern to determine whether or not a request URL meets the conditions for this rule. Possible values are: Simple String, Regular Expression. | Optional |
| url_pattern | Depending on your selection in url_type and meet_this_condition_if, type a regular expression that defines either all matching or all non-matching URLs. Must start with '/' when url_type=Simple String. | Optional |
| meet_this_condition_if | Indicate how to use url_pattern when determining whether or not this rule’s condition has been met. Possible values are: Object matches the URL Pattern, Object does not match the URL Pattern. | Optional |
| source_address | Whether to enable source address. Possible values are: enable, disable. | Optional |
| source_address_type | The source address type. Possible values are: IP, IP Resolved by Specified Domain, Source Domain. | Optional |
| ip_range | IPv4/IPv6 IP range. For exampe: 1.2.3.4-1.2.3.4 or 2001::1-2001::100. Relevant when source_address_type=IP. . | Optional |
| ip_type | IP Type. Relevant when source_address_type=IP Resolved by Specified Domain. . Possible values are: IPv4, IPv6. | Optional |
| ip | IP resolved by specified domain. Relevant when source_address_type=IP Resolved by Specified Domain. . | Optional |
| source_domain_type | Source domain type. Relevant when source_address_type=Source Domain. . Possible values are: Simple String, Regular Expression. | Optional |
| source_domain | Source domain. For example: test.com. Relevant when source_address_type=Source Domain. . | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-url-access-rule-condition-update group_name=test condition_id=1 url_type="Regular Expression" url_pattern=test2```
#### Human Readable Output

>URL access rule condition 1 was successfully updated!

### fortiwebvm-url-access-rule-condition-delete

***
Delete a URL access rule condition (URL access rule condition is a member of URL access rule group). Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-url-access-rule-condition-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | URL access rule group name (dependencies - use fortiwebvm-url-access-rule-group-list command to get all URL access rule groups). | Required |
| condition_id | URL access rule condition member ID (dependencies - use fortiwebvm-url-access-rule-condition-list command to get all URL access rule condition IDs). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-url-access-rule-condition-delete group_name=test condition_id=1```
#### Human Readable Output

>URL access rule condition 1 was successfully deleted!

### fortiwebvm-url-access-rule-condition-list

***
List URL access rule conditions (URL access rule condition is a member of URL access rule group). Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-url-access-rule-condition-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | URL access rule group name (dependencies - use fortiwebvm-url-access-rule-group-list command to get all URL access rule groups). | Required |
| condition_id | URL access rule condition member ID (dependencies - use fortiwebvm-url-access-rule-condition-list command to get all URL access rule condition IDs). | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.URLAccessRuleGroup.Condition.id | String | URL access rule condition name. |
| FortiwebVM.URLAccessRuleGroup.Condition.url_type | String | URL access rule condition URL type. |
| FortiwebVM.URLAccessRuleGroup.Condition.url_pattern | String | URL access rule condition URL pattern. |
| FortiwebVM.URLAccessRuleGroup.Condition.meet_this_condition_if | String | Indicate how to use url_pattern when determining whether or not this rule’s condition has been met. |
| FortiwebVM.URLAccessRuleGroup.Condition.source_address | String | URL access rule condition source address. |
| FortiwebVM.URLAccessRuleGroup.Condition.source_address_type | String | URL access rule condition source address type. |
| FortiwebVM.URLAccessRuleGroup.Condition.ip_range | String | IPv4/IPv6 IP range. |
| FortiwebVM.URLAccessRuleGroup.Condition.domain | String | URL access rule condition domain. |
| FortiwebVM.URLAccessRuleGroup.Condition.source_domain_type | String | URL access rule condition source domain type. |
| FortiwebVM.URLAccessRuleGroup.Condition.source_domain | String | URL access rule condition domain type. |
| FortiwebVM.URLAccessRuleGroup.Condition.only_method_check | String | Whether use HTTP method check is enable or not. Supports API version 2 only. |
| FortiwebVM.URLAccessRuleGroup.Condition.only_protocol_check | String | Whether use HTTP protocol check is enable or not. Supports API version 2 only. |
| FortiwebVM.URLAccessRuleGroup.Condition.only_method | String | Methods that were checked. Supports API version 2 only. |
| FortiwebVM.URLAccessRuleGroup.Condition.only_protocol | String | Protocols that were checked. Supports API version 2 only. |

#### Command example
```!fortiwebvm-url-access-rule-condition-list group_name=test condition_id=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "URLAccessRuleGroup": {
            "Condition": [
                {
                    "domain": "",
                    "id": "1",
                    "ip_range": "",
                    "ip_type": "IPv4",
                    "meet_this_condition_if": "Object matches the URL Pattern",
                    "only_method": "",
                    "only_method_check": "disable",
                    "only_protocol": "",
                    "only_protocol_check": "disable",
                    "source_address": "disable",
                    "source_address_type": "IP",
                    "source_domain": "",
                    "source_domain_type": "Simple String",
                    "url_pattern": "test2",
                    "url_type": "Regular Expression"
                }
            ],
            "id": "test"
        }
    }
}
```

#### Human Readable Output

>### URL access rule condition
>Showing page 1.
> Current page size: 50
>|Id|Url Type|Url Pattern|Meet This Condition If|Source Address Type|Ip Range|Domian Type|Domain|Source Domain Type|Source Domain|
>|---|---|---|---|---|---|---|---|---|---|
>| 1 | Regular Expression | test2 | Object matches the URL Pattern | IP |  |  |  | Simple String |  |


### fortiwebvm-virtual-server-group-create

***
Create a virtual server group. In API version 1, virtual server group defines the network interface, bridge, and IP address on which traffic destined for an individual physical server or server farm will arrive. In API version 2, virtual server group is a container that contains the virtual server items (use fortiwebvm-virtual-server-item-create/update/delete/list to manage the virtual server group’s items). Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-virtual-server-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Virtual server group name. | Required |
| interface | The name of the network interface or bridge. (dependencies - use fortiwebvm-network-interface-list command to get all the network interfaces). For example: port1. Required in API version 1. Supports API version 1 only. | Optional |
| ipv4_address | The IPv4 address and subnet of the virtual server. For example: 1.2.3.4/254.0.0.0. At least one of ipv4_address and ipv6_address is required. Supports API version 1 only. | Optional |
| ipv6_address | The IPv6 address and subnet of the virtual server. At least one of ipv4_address and ipv6_address is required. Supports API version 1 only. Default is ::/0. | Optional |
| status | Whether to enable the virtual server group. Supports API version 1 only. Possible values are: enable, disable. Default is enable. | Optional |
| use_interface_ip | Whether to use interface IP. enable - use interface IP. disable - use ipv4_address and ipv6_address. Supports API version 1 only. Possible values are: enable, disable. Default is disable. | Optional |

#### Context Output

There is no context output for this command.
#### Command example - API Version 1
```!fortiwebvm-virtual-server-group-create name=test use_interface_ip=enable interface=port1```
#### Command example - API Version 2
```!fortiwebvm-virtual-server-group-create name=test```
#### Human Readable Output

>Virtual server group test was successfully created!

### fortiwebvm-virtual-server-group-update

***
Update a virtual server group. Supports API version 1 only.

#### Base Command

`fortiwebvm-virtual-server-group-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Virtual server group name (dependencies - use fortiwebvm-virtual-server-group-list command to get all virtual server groups). | Required |
| interface | The name of the network interface or bridge. (dependencies - use fortiwebvm-network-interface-list command to get all the network interfaces). For example: port1. Supports API version 1 only. | Optional |
| ipv4_address | The IPv4 address and subnet of the virtual server. For exampl: 1.2.3.4/254.0.0.0. At leaset one of ipv4_address and ipv6_address required. Supports API version 1 only. | Optional |
| ipv6_address | The IPv4 address and subnet of the virtual server. At least one of ipv4_address and ipv6_address is required. Supports API version 1 only. | Optional |
| status | Whether to enable the virtual server group. Supports API version 1 only. Possible values are: enable, disable. | Optional |
| use_interface_ip | Whether to use interface IP. enable - use interface IP. disable - use ipv4_address and ipv6_address. Possible values are: enable, disable. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-virtual-server-group-update name=test status=disable use_interface_ip=enable```
#### Human Readable Output

>Virtual server group test was successfully updated!

### fortiwebvm-virtual-server-group-delete

***
Delete virtual server group. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-virtual-server-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Virtual server group name (dependencies - use fortiwebvm-virtual-server-group-list command to get all virtual server groups). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-virtual-server-group-delete name=test```
#### Human Readable Output

>Virtual server group test was successfully deleted!

### fortiwebvm-virtual-server-group-list

***
List the virtual server groups. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-virtual-server-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The virtual server group name. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.VirtualServerGroup.id | String | The virtual server group name. |
| FortiwebVM.VirtualServerGroup.ipv4_address | String | IP V4 address. Supports API version 1 only. |
| FortiwebVM.VirtualServerGroup.ipv6_address | String | IP V6 address. Supports API version 1 only. |
| FortiwebVM.VirtualServerGroup.interface | String | The interface name. Supports API version 1 only. |
| FortiwebVM.VirtualServerGroup.use_interface_ip | String | Whether to use interface IP. Supports API version 1 only. |
| FortiwebVM.VirtualServerGroup.enable | String | Whether the Virtual Server is enabled. Supports API version 1 only. |
| FortiwebVM.VirtualServerGroup.items_count | String | The number of items related to the Virtual Server. Supports API version 2 only. |

#### Command example
```!fortiwebvm-virtual-server-group-list limit=1```
#### Context Example - API Version 1
```json
{
    "FortiwebVM": {
        "VirtualServerGroup": {
            "_id": "test",
            "can_delete": true,
            "enable": true,
            "id": "test",
            "interface": "port1",
            "ipv4_address": "1.2.3.4/1.2.3.4",
            "ipv6_address": "::/0",
            "name": "test",
            "use_interface_ip": true
        }
    }
}
```
#### Context Example - API Version 2
```json
{
    "FortiwebVM": {
        "VirtualServerGroup": {
            "can_clone": 1,
            "can_view": 0,
            "id": "test",
            "name": "test",
            "q_ref": 0,
            "q_type": 1,
            "sz_vip-list": 0
        }
    }
}
```
#### Human Readable Output

>### Virtual server group
>Showing page 1.
> Current page size: 50
>|Id|Items Count|
>|---|---|
>| test |  |


### fortiwebvm-virtual-server-item-create

***
Create a virtual server item (virtual server Item is a member of virtual server group in API version 2). A virtual server defines the network interface, bridge, and IP address on which traffic destined for an individual physical server or server farm will arrive in API version 2. Supports API version 2 only.

#### Base Command

`fortiwebvm-virtual-server-item-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Virtual server group name (dependencies - use fortiwebvm-virtual-server-group-list command to get all the virtual server groups). . | Required |
| interface | The name of the network interface or bridge. (dependencies - use fortiwebvm-network-interface-list command to get all the network interfaces). Required when use_interface_ip=enable. | Optional |
| use_interface_ip | Whether to use interface IP. enable - use interface IP. disable - use virtual IP. Possible values are: enable, disable. Default is disable. | Optional |
| status | Whether to enable the virtual server item. . Possible values are: enable, disable. Default is enable. | Optional |
| virtual_ip | The virtual IP name of the virtual server item (dependencies - use fortiwebvm-virtual-ip-list command to get all the virtual IP names). Required when use_interface_ip=disable. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.VirtualServerGroup.Item.id | String | The Virtual server item ID. |

#### Command example
```!fortiwebvm-virtual-server-item-create group_name=test use_interface_ip=enable interface=port1```
#### Context Example
```json
{
    "FortiwebVM": {
        "VirtualServerGroup": {
            "Item": {
                "id": "1"
            },
            "id": "test"
        }
    }
}
```

#### Human Readable Output

>### Virtual server item 1 was successfully added to virtual server group test.
>|Id|
>|---|
>| 1 |


### fortiwebvm-virtual-server-item-update

***
Update a virtual server item (virtual server Item is a member of virtual server group in API version 2). Supports API version 2 only.

#### Base Command

`fortiwebvm-virtual-server-item-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Virtual server group name (dependencies - use fortiwebvm-virtual-server-group-list command to get all the virtual server groups). . | Required |
| item_id | Virtual server item ID (dependencies - use fortiwebvm-virtual-server-item-list command to get all the virtual server items). . | Required |
| interface | The name of the network interface or bridge. (dependencies - use fortiwebvm-network-interface-list command to get all the network interfaces). Required when use_interface_ip=enable. | Optional |
| use_interface_ip | Whether to use interface IP. enable - use interface IP. disable - use virtual IP. Possible values are: enable, disable. | Optional |
| status | Whether to enable the virtual server item. . Possible values are: enable, disable. | Optional |
| virtual_ip | The virtual IP name of the virtual server item (dependencies - use fortiwebvm-virtual-ip-list command to get all the virtual IP names). Required when use_interface_ip=disable. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-virtual-server-item-update group_name=test item_id=1 status=disable```
#### Human Readable Output

>Virtual server item 1 was successfully updated!

### fortiwebvm-virtual-server-item-delete

***
Delete a virtual server item (virtual server Item is a member of virtual server group in API version 2). Supports API versions 2 only.

#### Base Command

`fortiwebvm-virtual-server-item-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Virtual server group name (dependencies - use fortiwebvm-virtual-server-group-list command to get all virtual server groups). | Required |
| item_id | Virtual server item ID. (dependencies - use fortiwebvm-virtual-server-item-list command to get all virtual server items). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-virtual-server-item-delete group_name=test item_id=1```
#### Human Readable Output

>Virtual server item 1 was successfully deleted!

### fortiwebvm-virtual-server-item-list

***
List virtual server items (virtual server item is a member of virtual server group in API version 2). Supports API version 2 only.

#### Base Command

`fortiwebvm-virtual-server-item-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Virtual server group name (dependencies - use fortiwebvm-virtual-server-group-list command to get all virtual server groups). | Required |
| item_id | Virtual server item ID. (dependencies - use fortiwebvm-virtual-server-item-list command to get all virtual server items). | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.VirtualServerGroup.Item.id | String | Virtual server item ID. |
| FortiwebVM.VirtualServerGroup.Item.interface | String | The name of the network interface or bridge. |
| FortiwebVM.VirtualServerGroup.Item.status | String | Wheter the item is enabled or disabled. |
| FortiwebVM.VirtualServerGroup.Item.use_interface_ip | String | Whether virtual server uses interface IP. |
| FortiwebVM.VirtualServerGroup.Item.virtual_ip | String | The virtual IP of the virtual server. |

#### Command example
```!fortiwebvm-virtual-server-item-list group_name=test limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "VirtualServerGroup": {
            "Item": [
                {
                    "id": "1",
                    "interface": "port1",
                    "status": "disable",
                    "use_interface_ip": "enable",
                    "virtual_ip": ""
                }
            ],
            "id": "test"
        }
    }
}
```

#### Human Readable Output

>### Virtual server item
>Showing page 1.
> Current page size: 50
>|Id|Interface|Status|Use Interface Ip|Virtual Ip|
>|---|---|---|---|---|
>| 1 | port1 | disable | enable |  |


### fortiwebvm-server-pool-group-create

***
Create a server pool group. Server pools define a group of one or more physical or domain servers (web servers) that FortiWeb distributes connections among, or where the connections pass through to, depending on the operation mode. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-pool-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Server pool group name. | Required |
| type | The operation mode of the appliance to display the corresponding pool options. Possible values are: Reverse Proxy, Offline Protection, True Transparent Proxy, Transparent Inspection, WCCP. Default is Reverse Proxy. | Optional |
| comments | Description or other comment. | Optional |
| server_balance | Specifies whether the pool contains a single server or multiple members. Relevant when type=Reverse Proxy. Possible values are: Single Server, Server Balance. Default is Single Server. | Optional |
| health_check | The name of the server health check FortiWeb uses to determine the responsiveness of server pool members (dependencies - use fortiwebvm-server-health-check-list command to get all health check policies). Relevant when server_balance=Server Balance. | Optional |
| lb_algo | The load-balancing algorithms that FortiWeb uses when it distributes new connections among server pool members. Relevant when server_balance=Server Balance. Possible values are: Round Robin, Weighted Round Robin, Least Connection, URI Hash, Full URI Hash, Host Hash, Host Domain Hash, Source IP Hash. Default is Round Robin. | Optional |
| persistence | The name of the persistence policy that specifies a session persistence method and timeout to apply to the pool (dependencies - use fortiwebvm-persistence-policy-list command to get all persistence policies). Relevant when server_balance=Server Balance. | Optional |
| http_reuse | Configure multiplexing so that FortiWeb uses a single connection to a server for requests from multiple clients. Enter one of these options: Aggressive - The first request from a client can use a cached server connection only when the cached server connection has been used by more than one client. Always - Client requests will use an available connection cached server connection. Never - Disable multiplexing. Safe - A client will establish a new connection for the first request, but will use an available cached server connection for subsequent requests. Relevant when protocol=HTTP. Supports API version 2 only. Possible values are: Aggressive, Always, Never, Safe. | Optional |
| protocol | The server pool protocol. HTTP - Specifies that the server pool governs HTTP traffic. Specific options for configuring an HTTP server pool become available. FTP - Specifies that the server pool governs FTP traffic. Specific options for configuring an FTP server pool become available. ADFSPIP - Specifies that the server pool governs ADFSPIP traffic. Specific options for configuring an ADFSPIP server pool become available. In case you use FTP/ADFSPIP make sure it enabled in the “Feature Visibility” (under system-&gt;config). Supports API version 2 only. Relevant when type=Reverse Proxy. Possible values are: HTTP, FTP, ADFSPIP. | Optional |
| reuse_conn_idle_time | Idle time limit for a cached server connection. If a cached server connection remains idle for the set duration, it will be closed. The valid range is 1–1000. Supports API version 2 only. Default is 10. | Optional |
| reuse_conn_max_count | The maximum number of allowed cached server connections. If FortiWeb meets the set number, no more cached server connections will be established. The valid range is 1–1000 for each server.  Supports API version 2 only. Default is 100. | Optional |
| reuse_conn_max_request | The maximum number of HTTP responses that the cached server connection may handle. If a cached server connection meets the set number, it will be closed. The valid range is 1–1000. Supports API version 2 only. Default is 100. | Optional |
| reuse_conn_total_time | The maximum time limit in which a cached server connection may be reused. If a cached server connection exists for longer than the set limit, it will be closed. The valid range is 1–1000. Supports API version 2 only. Default is 100. | Optional |
| server_pool_id | A 64-bit random integer assigned to each server policy. The policy-id is a unique identification number for each server policy. Supports API version 2 only. | Optional |
| proxy_protocol | If the back-end server enables proxy protocol, you need to enable the Proxy Protocol option on FortiWeb so that the TCP SSL and HTTP traffic can successfully go through. The real IP address of the client will be included in the proxy protocol header. Relevant when type=Reverse Proxy or True Transparent Proxy or Offline Protection or Transparent Inspection. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| proxy_protocol_version | The proxy protocol version for the back-end server. Relevant when type=Reverse Proxy or True Transparent Proxy. Supports API version 2 only. Possible values are: V1, V2. Default is V1. | Optional |
| adfs_server_name | Enter a name for the AD FS Server. It should be the federation service name. This option is mandatory if the AD FS Server needs to verify the server name in the SSL handshake. Relevant when protocol=ADFSPIP. Supports API version 2 only. | Optional |
| health_check_source_ip | Health check source IP. Supports API version 2 only. Required when the system operation type is True Transparent Proxy and health_check is not empty. | Optional |
| health_check_source_ip_v6 | Health check source v6 IP. Supports API version 2 only. Required when the system operation type is True Transparent Proxy and health_check is not empty. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-group-create name=test server_balance=ServerBalance```
#### Human Readable Output

>Server pool group test was successfully created!

### fortiwebvm-server-pool-group-update

***
Update a server pool group. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-pool-group-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| type | The operation mode of the appliance to display the corresponding pool options. Possible values are: Reverse Proxy, Offline Protection, True Transparent Proxy, Transparent Inspection, WCCP. | Optional |
| comments | Enter a description or other comment. If the comment is more than one word or contains special characters, surround the comment with double quotes ( " ). The maximum length is 199 characters. | Optional |
| server_balance | Specifies whether the pool contains a single server or multiple members. Possible values are: Single Server, Server Balance. | Optional |
| health_check | The name of the server health check FortiWeb uses to determine the responsiveness of server pool members (dependencies - use fortiwebvm-server-health-check-list command to get all health check policies). Relevant when server_balance=Server Balance. | Optional |
| lb_algo | The load-balancing algorithms that FortiWeb uses when it distributes new connections among server pool members. Relevant when server_balance=Server Balance. Possible values are: Round Robin, Weighted Round Robin, Least Connection, URI Hash, Full URI Hash, Host Hash, Host Domain Hash, Source IP Hash. | Optional |
| persistence | The name of the persistence policy that specifies a session persistence method and timeout to apply to the pool (dependencies - use fortiwebvm-persistence-policy-list command to get all persistence policies). Relevant when server_balance=Server Balance. | Optional |
| http_reuse | Configure multiplexing so that FortiWeb uses a single connection to a server for requests from multiple clients. Enter one of these options: Aggressive - The first request from a client can use a cached server connection only when the cached server connection has been used by more than one client. Always - Client requests will use an available connection cached server connection. Never - Disable multiplexing. Safe - A client will establish a new connection for the first request, but will use an available cached server connection for subsequent requests. Relevant when protocol=HTTP. Supports API version 2 only. Possible values are: Aggressive, Always, Never, Safe. | Optional |
| protocol | The server pool protocol. HTTP - Specifies that the server pool governs HTTP traffic. Specific options for configuring an HTTP server pool become available. FTP - Specifies that the server pool governs FTP traffic. Specific options for configuring an FTP server pool become available. ADFSPIP - Specifies that the server pool governs ADFSPIP traffic. Specific options for configuring an ADFSPIP server pool become available. In case you use FTP/ADFSPIP make sure it enabled in the “Feature Visibility” (under system-&gt;config). Supports API version 2 only. Relevant when type=Reverse Proxy. Possible values are: HTTP, FTP, ADFSPIP. | Optional |
| reuse_conn_idle_time | Idle time limit for a cached server connection. If a cached server connection remains idle for the set duration, it will be closed. The valid range is 1–1000. Supports API version 2 only. | Optional |
| reuse_conn_max_count | The maximum number of allowed cached server connections. If FortiWeb meets the set number, no more cached server connections will be established. The valid range is 1–1000 for each pserver. Supports API version 2 only. | Optional |
| reuse_conn_max_request | The maximum number of HTTP responses that the cached server connection may handle. If a cached server connection meets the set number, it will be closed. The valid range is 1–1000. Supports API version 2 only. | Optional |
| reuse_conn_total_time | The maximum time limit in which a cached server connection may be reused. If a cached server connection exists for longer than the set limit, it will be closed. The valid range is 1–1000. Supports API version 2 only. | Optional |
| server_pool_id | A 64-bit random integer assigned to each server policy. The policy-id is a unique identification number for each server policy. Supports API version 2 only. | Optional |
| proxy_protocol | If the back-end server enables proxy protocol, you need to enable the Proxy Protocol option on FortiWeb so that the TCP SSL and HTTP traffic can successfully go through. The real IP address of the client will be included in the proxy protocol header. Relevant when type=Reverse Proxy or True Transparent Proxy or Offline Protection or Transparent Inspection. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| proxy_protocol_version | The proxy protocol version for the back-end server. Relevant when type=Reverse Proxy or True Transparent Proxy. Supports API version 2 only. Possible values are: V1, V2. | Optional |
| adfs_server_name | Enter a name for the AD FS Server. It should be the federation service name. This option is mandatory if the AD FS Server needs to verify the server name in the SSL handshake. Relevant when protocol=ADFSPIP. Supports API version 2 only. | Optional |
| health_check_source_ip | Health check source IP. Supports API version 2 only. Required when the type="True Transparent Proxy" and health_check is not empty. | Optional |
| health_check_source_ip_v6 | Health check source v6 IP. Supports API version 2 only. Required when the type="True Transparent Proxy" and health_check is not empty. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-group-update name=test comments=test```
#### Human Readable Output

>Server pool group test was successfully updated!

### fortiwebvm-server-pool-group-delete

***
Delete a server pool group. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-pool-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-group-delete name=test```
#### Human Readable Output

>Server pool group test was successfully deleted!

### fortiwebvm-server-pool-group-list

***
List server pool groups. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-pool-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Server pool group name. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPoolGroup.id | String | Server pool group ID. |
| FortiwebVM.ServerPoolGroup.pool_count | String | The number of rule members. |
| FortiwebVM.ServerPoolGroup.server_balance | String | Whether the pool contains a single server or multiple members.  |
| FortiwebVM.ServerPoolGroup.type | String | Server pool type. |
| FortiwebVM.ServerPoolGroup.comments | String | Comments that are attached to the server pool. |
| FortiwebVM.ServerPoolGroup.lb_algorithm | String | Server pool load balancing algorithm. |
| FortiwebVM.ServerPoolGroup.health_check | String | The name of the server health check. |
| FortiwebVM.ServerPoolGroup.persistence | String | The name of the persistence policy that specifies a session persistence method and timeout to apply to the pool. |
| FortiwebVM.ServerPoolGroup.protocol | String | Server pool protocol. Supports API version 2 only. |
| FortiwebVM.ServerPoolGroup.http_reuse | String | Server pool HTTP reuse. Supports API version 2 only. |
| FortiwebVM.ServerPoolGroup.reuse_conn_total_time | Number | The maximum time limit in which a cached server connection may be reused. If a cached server connection exists for longer than the set limit, it will be closed. Supports API version 2 only. |
| FortiwebVM.ServerPoolGroup.reuse_conn_idle_time | Number | Idle time limit for a cached server connection. If a cached server connection remains idle for the set duration, it will be closed. Supports API version 2 only. |
| FortiwebVM.ServerPoolGroup.reuse_conn_max_request | Number | The maximum number of HTTP responses that the cached server connection may handle. If a cached server connection meets the set number, it will be closed. Supports API version 2 only. |
| FortiwebVM.ServerPoolGroup.reuse_conn_max_count | Number | The maximum number of allowed cached server connections. If FortiWeb meets the set number, no more cached server connections will be established. Supports API version 2 only. |
| FortiwebVM.ServerPoolGroup.adfs_server_name | String | The name for the AD FS Server. Supports API version 2 only. |
| FortiwebVM.ServerPoolGroup.server_pool_id | String | A 64-bit random integer assigned to each server policy. Supports API version 2 only. |

#### Command example
```!fortiwebvm-server-pool-group-list limit=1```
#### Context Example - API Version 1
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "comments": "",
            "health_check": "",
            "id": "rp",
            "lb_algorithm": "",
            "persistence": "",
            "pool_count": 0,
            "server_balance": "Single Server",
            "type": "Reverse Proxy"
        }
    }
}
```
#### Context Example - API Version 2
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "adfs_server_name": "",
            "comments": "",
            "health_check": "",
            "http_reuse": "never",
            "id": "test",
            "lb_algorithm": "round-robin",
            "persistence": "",
            "pool_count": 1,
            "protocol": "HTTP",
            "reuse_conn_idle_time": 10,
            "reuse_conn_max_count": 100,
            "reuse_conn_max_request": 100,
            "reuse_conn_total_time": 100,
            "server_balance": "disable",
            "server_pool_id": "16406048845216073408",
            "type": "Reverse Proxy"
        }
    }
}
```

#### Human Readable Output

>### Server pool group
>Showing page 1.
> Current page size: 50
>|Id|Type|Pool Count|Server Balance|Comments|Lb Algorithm|Health Check|Persistence|
>|---|---|---|---|---|---|---|---|
>| rp | Reverse Proxy | 0 | Single Server |  |  |  |  |


### fortiwebvm-server-pool-reverse-proxy-rule-create

***
Create a rule for a reverse proxy server pool group (server pool rule is a member of server pool group). Reverse proxy — Requests are destined for a virtual server’s network interface and IP address on the FortiWeb appliance. Supports API versions 1 & 2. Server pool rule advanced SSL settings are not supported in this command.

#### Base Command

`fortiwebvm-server-pool-reverse-proxy-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| status | Server pool rule status. Possible values are: enable, disable, maintenance. Default is enable. | Optional |
| server_type | Specify whether to specify the pool member by IP address, domain, or automatically pulled by SDN connector. The value “External connector”. Supports API version 2 only. Possible values are: IP, Domain, External connector. | Required |
| sdn_address_type | Select whether you want FortiWeb to get the public or private addresses of your application's VM instances, or select all to get both the public and the private addresses. Relevant when the server pool group server balance=Server Balance and server_type=External connector. Supports API version 2 only. Possible values are: Private, Public, All. | Optional |
| sdn_connector | Select the SDN connector you have created (dependencies - use fortiwebvm-sdn-connector-list command to get all the SDN connectors). Required when the server pool group server balance=Server Balance and server_type=External connector. Supports API version 2 only. Possible values are: aws, azure. | Optional |
| filter | Once you select the SDN collector that you have created, choose the filter for your VMs in your public cloud account. You should know the filter name (there is no helper command). For example (AWS filter) instance-id=i-12345678. Required when the server pool group server balance=Server Balance and server_type=External connector. Supports API version 2 only. | Optional |
| ip | The IP address of the web server to include in the pool. Required when: (server_type= ip). | Optional |
| domain | The fully-qualified domain name of the web server to include in the pool, such as www.example.com. Required when: (server_type=domain). | Optional |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . Default is  80. | Optional |
| connection_limit | Connection limit. The maximum number of concurrent connections to the backend server. 0 for no connection limit. Size range: 0-1048576. Default is 0. | Optional |
| http2 | Enable to allow HTTP/2 communication between the FortiWeb and this back-end web server for HTTP/2 security inspections. Possible values are: enable, disable. | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. | Optional |
| client_certificate_file | The client certificate that FortiWeb uses to connect to this server pool member (dependencies - use fortiwebvm-local-certificate-list command to get all the local certificates). Relevant when: ssl=enable. | Optional |
| recover | The number of seconds to postpone forwarding traffic after downtime when a health check indicates that this server has become available again. Size range: 0-86400. Default is 0. | Optional |
| warm_up | Warm up, if the server cannot initially handle full connection load when it begins to respond to health checks. Size range: 0-86400. Default is 0. | Optional |
| warm_rate | The maximum connection rate per second while the server is starting up. Size range: 1-86400.. Default is 10. | Optional |
| weight | The assigned relative preference among members. Higher values are more preferred and are assigned with connections more frequently. Relevant when the server pool group server balance=Server Balance. Size range: 1-9999. Default is 1. | Optional |
| health_check_inherit | Enable to use the health check specified by health in the server pool configuration. Disable to use the health check specified by health in this pool member configuration. Relevant when the server pool group server balance=Server Balance. Possible values are: enable, disable. | Optional |
| health_check_domain | The domain name of the server pool. Required when the server pool group server balance=Server Balance and health_check_inherit=enable. Supports API version 2 only. | Optional |
| backup_server | Enter enable to configure this pool member as a backup server. FortiWeb only routes connections for the pool to a backup server when all the other members of the server pool fail their server health check. Relevant when the server pool group server balance=Server Balance.. Possible values are: enable, disable. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPoolGroup.Rule.id | String | The server pool rule ID. |

#### Command example
```!fortiwebvm-server-pool-reverse-proxy-rule-create group_name=rp server_type=IP ip=1.2.3.4```
#### Context Example
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "Rule": {
                "id": "1"
            },
            "id": "rp"
        }
    }
}
```

#### Human Readable Output

>### Server pool rule 1 was successfully added to server pool group rp.
>|Id|
>|---|
>| 1 |


### fortiwebvm-server-pool-reverse-proxy-rule-update

***
Update a rule for a reverse proxy server pool group. Supports API versions 1 & 2. Server pool rule advanced SSL settings are not supported in this command.

#### Base Command

`fortiwebvm-server-pool-reverse-proxy-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| rule_id | Server pool rule ID (dependencies - use fortiwebvm-server-pool-rule-list command to get all server pool rules). | Required |
| status | Server pool rule status. Possible values are: enable, disable, maintenance. | Optional |
| server_type | Specify whether to specify the pool member by IP address, domain, or automatically pulled by SDN connector. The value “External connector”. Supports API version 2 only. Possible values are: IP, Domain, External connector. | Optional |
| sdn_address_type | Select whether you want FortiWeb to get the public or private addresses of your application's VM instances, or select all to get both the public and the private addresses. Relevant when the server pool group server balance=Server Balance and server_type=External connector. Supports API version 2 only. Possible values are: Private, Public, All. | Optional |
| sdn_connector | Select the SDN connector you have created (dependencies - use fortiwebvm-sdn-connector-list command to get all the SDN connectors). Required when the server pool group server balance=Server Balance and server_type=External connector. Supports API version 2 only. Possible values are: aws, azure. | Optional |
| filter | Once you select the SDN collector that you have created, choose the filter for your VMs in your public cloud account. You should know the filter name (there is no helper command). For example (AWS filter) instance-id=i-12345678. Required when the server pool group server balance=Server Balance and server_type=External connector. Supports API version 2 only. | Optional |
| ip | The IP address of the web server to include in the pool. Required when: (server_type= ip). | Optional |
| domain | The fully-qualified domain name of the web server to include in the pool, such as www.example.com. Required when: (server_type=domain). | Optional |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . | Optional |
| connection_limit | The maximum number of concurrent connections to the backend server. 0 for no connection limit. Size range: 0-1048576. | Optional |
| http2 | Enable to allow HTTP/2 communication between the FortiWeb and this back-end web server for HTTP/2 security inspections. Possible values are: enable, disable. | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. | Optional |
| client_certificate_file | The client certificate that FortiWeb uses to connect to this server pool member (dependencies - use fortiwebvm-local-certificate-list command to get all the local certificates). Relevant when: ssl=enable. | Optional |
| recover | The number of seconds to postpone forwarding traffic after downtime when a health check indicates that this server has become available again. Size range: 0-86400. | Optional |
| warm_up | Warm up, if the server cannot initially handle full connection load when it begins to respond to health checks. Size range: 0-86400. | Optional |
| warm_rate | The maximum connection rate per second while the server is starting up. Size range: 1-86400.. | Optional |
| weight | The assigned relative preference among members. Higher values are more preferred and are assigned with connections more frequently. Relevant when the server pool group server balance=Server Balance. Size range: 1-9999. | Optional |
| health_check_inherit | Enable to use the health check specified by health in the server pool configuration. Disable to use the health check specified by health in this pool member configuration. Relevant when the server pool group server balance=Server Balance. Possible values are: enable, disable. | Optional |
| health_check_domain | The domain name of the server pool. Required when the server pool group server balance=Server Balance and health_check_inherit=enable. Supports API version 2 only. | Optional |
| backup_server | Enter enable to configure this pool member as a backup server. FortiWeb only routes connections for the pool to a backup server when all the other members of the server pool fail their server health check. Relevant when the server pool group server balance=Server Balance.. Possible values are: enable, disable. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-reverse-proxy-rule-update group_name=rp rule_id=1 status=disable```
#### Human Readable Output

>Server pool rule 1 was successfully updated!

### fortiwebvm-server-pool-offline-protection-rule-create

***
Create a rule for an offline protection server pool group (server pool rule is a member of server pool group). Offline Protection - Requests are destined for a real web server instead of the FortiWeb appliance; traffic is duplicated to the FortiWeb through a span port. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-pool-offline-protection-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| status | Server pool rule status. Possible values are: enable, disable. Default is enable. | Optional |
| ip | The IP address of the web server to include in the pool. | Required |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. Default is 80. | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. Default is disable. | Optional |
| certificate_file | The name of the certificate that FortiWeb uses to decrypt SSL-secured connections. Required when ssl=enable. | Optional |
| enable_sni | Enable to use a Server Name Indication (SNI) certificate. Server Name Indication allows multiple HTTPS websites to be served by the same IP address without requiring all those sites to use the same certificate. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| sni_certificate | The name of the Server Name Indication (SNI) certificate that specifies which certificate FortiWeb uses when encrypting or decrypting SSL-secured connections for a specified domain. (dependencies - use fortiwebvm-sni-certificate-list command to get all SNI certificates). Required when enable_sni=enable. Supports API version 2 only. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPoolGroup.Rule.id | String | The server pool rule ID. |

#### Command example
```!fortiwebvm-server-pool-offline-protection-rule-create group_name=op ip=1.2.3.4```
#### Context Example
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "Rule": {
                "id": "1"
            },
            "id": "op"
        }
    }
}
```

#### Human Readable Output

>### Server pool rule 1 was successfully added to server pool group op.
>|Id|
>|---|
>| 1 |


### fortiwebvm-server-pool-offline-protection-rule-update

***
Update a rule for an offline protection server pool group (server pool rule is a member of server pool group). Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-pool-offline-protection-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| rule_id | Server pool rule ID (dependencies - use fortiwebvm-server-pool-rule-list command to get all server pool rules). | Required |
| status | Server pool rule status. Possible values are: enable, disable. | Optional |
| ip | The IP address of the web server to include in the pool. | Optional |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. | Optional |
| certificate_file | The name of the certificate that FortiWeb uses to decrypt SSL-secured connections. (dependencies - use fortiwebvm-local-certificate-list command to get all the local certificates). Required when ssl=enable. | Optional |
| enable_sni | Enable to use a Server Name Indication (SNI) certificate. Server Name Indication allows multiple HTTPS websites to be served by the same IP address without requiring all those sites to use the same certificate. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| sni_certificate | The name of the Server Name Indication (SNI) policy that specifies which certificate FortiWeb uses when encrypting or decrypting SSL-secured connections for a specified domain. (dependencies - use fortiwebvm-sni-certificate-list command to get all SNI certificates). Required when enable_sni=enable. Supports API version 2 only. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-offline-protection-rule-update group_name=op rule_id=1 port=81```
#### Human Readable Output

>Server pool rule 1 was successfully updated!

### fortiwebvm-server-pool-true-transparent-proxy-rule-create

***
Create a rule for a true transparent server pool group (server pool rule is a member of server pool group). True transparent proxy  -  Requests are destined for a real web server instead of the FortiWeb appliance. Supports API versions 1 & 2. Server pool rule advanced SSL settings are not supported in this command.

#### Base Command

`fortiwebvm-server-pool-true-transparent-proxy-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| status | The status of the server pool rule. enable - Specifies that this pool member can receive new sessions from FortiWeb. disable - Specifies that this pool member does not receive new sessions from FortiWeb and FortiWeb closes any current sessions as soon as possible. maintenance - Specifies that this pool member does not receive new sessions from FortiWeb but FortiWeb maintains any current connections. Possible values are: enable, disable. Default is enable. | Optional |
| ip | The IP address of the web server to include in the pool. . | Required |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . Default is 80. | Optional |
| http2 | Enable to allow HTTP/2 communication between the FortiWeb and this back-end web server for HTTP/2 security inspections. Possible values are: enable, disable. | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. | Optional |
| certificate_type | Enable this option to allow FortiWeb to use Local / Multi Certificate / Letsencrypt certificates. Supports API version 2 only. Possible values are: Local, Multi Certificate, Letsencrypt. Default is Local. | Optional |
| certificate_file | The name of the certificate that FortiWeb uses to decrypt SSL-secured connections. Relevant when enable_ssl=enable. In API version 2 - relevant when enable_ssl=enable and certificate_type=Local (dependencies - use fortiwebvm-local-certificate-list command to list all the local certificates). | Optional |
| multi_certificate | Multi certificate (dependencies use fortiwebvm-multi-certificate-list to get all the multi-certificates). Relevant when enable_ssl=enable and certificate_file=Multi Certificate. Supports API version 2 only. | Optional |
| letsencrypt | Relevant when enable_ssl=enable and certificate_file=Letsencrypt (dependencies - use fortiwebvm-letsencrypt-certificate-list command to list all the letsencrypt certificates). Supports API version 2 only. | Optional |
| certficate_intermediate_group | The name of a group of intermediate certificate authority (CA) certificates, if any, that FortiWeb presents to clients to complete the signing chain for them and validate the server certificate’s CA signature (dependencies - use fortiwebvm-certificate-intermediate-group-list command to get all the certificate intermediate groups). Relevant when ssl=enable. | Optional |
| client_certificate_file | The client certificate that FortiWeb uses to connect to this server pool member (dependencies - use fortiwebvm-local-certificate-list command to get all the local certificates). Relevant when: ssl=enable. | Optional |
| health_check_inherit | Enable to use the health check specified by health in the server pool configuration. Disable to use the health check specified by health in this pool member configuration. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| health_check_domain | The domain name of the server pool. Required when health_check_inherit=enable. Supports API version 2 only. | Optional |
| health_check | The name of a server health check FortiWeb uses to determine the responsiveness of server pool members (dependencies - use fortiwebvm-server-health-check-list command to get all health check policies). Supports API version 2 only. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPoolGroup.Rule.id | String | The server pool rule ID. |

#### Command example
```!fortiwebvm-server-pool-true-transparent-proxy-rule-create group_name=ttp server_type=IP ip=1.2.3.4```
#### Context Example
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "Rule": {
                "id": "1"
            },
            "id": "ttp"
        }
    }
}
```

#### Human Readable Output

>### Server pool rule 1 was successfully added to server pool group ttp.
>|Id|
>|---|
>| 1 |


### fortiwebvm-server-pool-true-transparent-proxy-rule-update

***
Update a rule for a true transparent server pool group (server pool rule is a member of server pool group). Supports API versions 1 & 2. Server pool rule advanced SSL settings are not supported in this command.

#### Base Command

`fortiwebvm-server-pool-true-transparent-proxy-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| rule_id | Server pool rule ID (dependencies - use fortiwebvm-server-pool-rule-list command to get all server pool rules). | Required |
| status | The status of the server pool rule. enable - Specifies that this pool member can receive new sessions from FortiWeb. disable - Specifies that this pool member does not receive new sessions from FortiWeb and FortiWeb closes any current sessions as soon as possible. maintenance - Specifies that this pool member does not receive new sessions from FortiWeb but FortiWeb maintains any current connections. Possible values are: enable, disable. | Optional |
| ip | The IP address of the web server to include in the pool. . | Optional |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . | Optional |
| http2 | Enable to allow HTTP/2 communication between the FortiWeb and this back-end web server for HTTP/2 security inspections. Possible values are: enable, disable. | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. | Optional |
| certificate_type | Enable this option to allow FortiWeb to use Local / Multi Certificate / Letsencrypt certificates. Supports API version 2 only. Possible values are: Local, Multi Certificate, Letsencrypt. | Optional |
| certificate_file | The name of the certificate that FortiWeb uses to decrypt SSL-secured connections. Relevant when enable_ssl=enable. In API version 2 - relevant when enable_ssl=enable and certificate_type=Local (dependencies - use fortiwebvm-local-certificate-list command to list all the local certificates). | Optional |
| multi_certificate | Multi certificate (dependencies use fortiwebvm-multi-certificate-list to get all the multi-certificates). Relevant when enable_ssl=enable and certificate_file=Multi Certificate. Supports API version 2 only. | Optional |
| letsencrypt | Relevant when enable_ssl=enable and certificate_file=Letsencrypt (dependencies - use fortiwebvm-letsencrypt-certificate-list command to list all the letsencrypt certificates). Supports API version 2 only. | Optional |
| certficate_intermediate_group | The name of a group of intermediate certificate authority (CA) certificates, if any, that FortiWeb presents to clients to complete the signing chain for them and validate the server certificate’s CA signature (dependencies - use fortiwebvm-certificate-intermediate-group-list command to get all the certificate intermediate groups). Relevant when ssl=enable. | Optional |
| client_certificate_file | The client certificate that FortiWeb uses to connect to this server pool member (dependencies - use fortiwebvm-local-certificate-list command to get all the local certificates). Relevant when: ssl=enable. | Optional |
| health_check_inherit | Enable to use the health check specified by health in the server pool configuration. Disable to use the health check specified by health in this pool member configuration. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| health_check_domain | The domain name of the server pool. Required when health_check_inherit=enable. Supports API version 2 only. | Optional |
| health_check | The name of a server health check FortiWeb uses to determine the responsiveness of server pool members (dependencies - use fortiwebvm-server-health-check-list command to get all health check policies). Supports API version 2 only. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-true-transparent-proxy-rule-update group_name=ttp rule_id=1 port=82```
#### Human Readable Output

>Server pool rule 1 was successfully updated!

### fortiwebvm-server-pool-transparent-inspection-rule-create

***
Create a rule for a transparent inspection server pool group (server pool rule is a member of server pool group). Transparent Inspection  -  Requests are destined for a real web server instead of the FortiWeb appliance. The FortiWeb appliance asynchronously inspects traffic arriving on a network port that belongs to a Layer 2 bridge, applies the first applicable policy, and lets permitted traffic pass through. Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-pool-transparent-inspection-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| status | Server pool rule status. Possible values are: enable, disable. | Optional |
| ip | The IP address of the web server to include in the pool. . | Required |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . Default is 80. | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. | Optional |
| certificate_file | The name of the certificate that FortiWeb uses to decrypt SSL-secured connections. (dependencies - use fortiwebvm-local-certificate-list command to get all the local certificates). Required when ssl=enable. | Optional |
| enable_sni | Enable to use a Server Name Indication (SNI) certificate. Server Name Indication allows multiple HTTPS websites to be served by the same IP address without requiring all those sites to use the same certificate. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| sni_certificate | The name of the Server Name Indication (SNI) policy that specifies which certificate FortiWeb uses when encrypting or decrypting SSL-secured connections for a specified domain. (dependencies - use fortiwebvm-sni-certificate-list command to get all SNI certificates). Required when enable_sni=enable. Supports API version 2 only. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPoolGroup.Rule.id | String | The server pool rule ID. |

#### Command example
```!fortiwebvm-server-pool-transparent-inspection-rule-create group_name=ti ip=1.2.3.4```
#### Context Example
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "Rule": {
                "id": "1"
            },
            "id": "ti"
        }
    }
}
```

#### Human Readable Output

>### Server pool rule 1 was successfully added to server pool group ti.
>|Id|
>|---|
>| 1 |


### fortiwebvm-server-pool-transparent-inspection-rule-update

***
Update a rule for a transparent inspection server pool group (server pool rule is a member of server pool group). Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-pool-transparent-inspection-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| rule_id | Server pool rule ID (dependencies - use fortiwebvm-server-pool-rule-list command to get all server pool rules). | Required |
| status | Server pool rule status. Possible values are: enable, disable. | Optional |
| ip | The IP address of the web server to include in the pool. . | Optional |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . Default is 80. | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. | Optional |
| certificate_file | The name of the certificate that FortiWeb uses to decrypt SSL-secured connections. (dependencies - use fortiwebvm-local-certificate-list command to get all the local certificates). Required when ssl=enable. | Optional |
| enable_sni | Enable to use a Server Name Indication (SNI) configuration. Server Name Indication allows multiple HTTPS websites to be served by the same IP address without requiring all those sites to use the same certificate. Supports API version 2 only. Possible values are: enable, disable. | Optional |
| sni_policy | The name of the Server Name Indication (SNI) configuration that specifies which certificate FortiWeb uses when encrypting or decrypting SSL-secured connections for a specified domain. Required when enable_sni=enable. Supports API version 2 only. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-transparent-inspection-rule-update group_name=ti rule_id=1 port=83```
#### Human Readable Output

>Server pool rule 1 was successfully updated!

### fortiwebvm-server-pool-wccp-rule-create

***
Create a rule for an WCCP server pool group (server pool rule is a member of server pool group). WCCP - The FortiWeb appliance allows traffic to pass through to the server pool when it receives traffic that is directed to the FortiWeb (configured as a WCCP client) by a FortiGate acting as a WCCP server. Supports API versions 1 & 2. Server pool rule advanced SSL settings are not supported in this command.

#### Base Command

`fortiwebvm-server-pool-wccp-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| status | Server pool rule status. Possible values are: enable, disable. Default is enable. | Optional |
| ip | The IP address of the web server to include in the pool. . | Required |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. Default is disable. | Optional |
| certificate_type | Enable this option to allow FortiWeb to use Local / Multi Certificate certificates. Supports API version 2 only. Possible values are: Local, Multi Certificate. Default is Local. | Optional |
| certificate_file | The name of the certificate that FortiWeb uses to decrypt SSL-secured connections. Relevant when enable_ssl=enable. Relevant when enable_ssl=enable and certificate_type=Local (dependencies - use fortiwebvm-local-certificate-list command to list all the local certificates). | Optional |
| multi_certificate | Multi certificate (dependencies use fortiwebvm-multi-certificate-list to get all the multi-certificates). Relevant when enable_ssl=enable and certificate_type=Multi Certificate. Supports API version 2 only. | Optional |
| certficate_intermediate_group | The name of a group of intermediate certificate authority (CA) certificates, if any, that FortiWeb presents to clients to complete the signing chain for them and validate the server certificate’s CA signature (dependencies - use fortiwebvm-certificate-intermediate-group-list command to get all the certificate intermediate groups). Relevant when ssl=enable. | Optional |
| client_certificate_file | The client certificate that FortiWeb uses to connect to this server pool member. Relevant when: enable_ssl=enable (dependencies - use fortiwebvm-local-certificate-list command to list all the local certificates). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPoolGroup.Rule.id | String | The server pool rule ID. |

#### Command example
```!fortiwebvm-server-pool-wccp-rule-create group_name=wccp ip=1.2.3.4 port=84```
#### Context Example
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "Rule": {
                "id": "1"
            },
            "id": "wccp"
        }
    }
}
```

#### Human Readable Output

>### Server pool rule 1 was successfully added to server pool group wccp.
>|Id|
>|---|
>| 1 |


### fortiwebvm-server-pool-wccp-rule-update

***
Update a rule for an WCCP server pool group (server pool rule is a member of server pool group). Supports API versions 1 & 2. Server pool rule advanced SSL settings are not supported in this command.

#### Base Command

`fortiwebvm-server-pool-wccp-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| rule_id | Server pool rule ID (dependencies - use fortiwebvm-server-pool-rule-list command to get all server pool rules). | Required |
| status | Server pool rule status. Possible values are: enable, disable. | Optional |
| ip | The IP address of the web server to include in the pool. . | Optional |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. | Optional |
| certificate_type | Enable this option to allow FortiWeb to use Local / Multi Certificate certificates. Supports API version 2 only. Possible values are: Local, Multi Certificate. | Optional |
| certificate_file | The name of the certificate that FortiWeb uses to decrypt SSL-secured connections. Relevant when enable_ssl=enable. Relevant when enable_ssl=enable and certificate_type=Local (dependencies - use fortiwebvm-local-certificate-list command to list all the local certificates). | Optional |
| multi_certificate | Multi certificate (dependencies use fortiwebvm-multi-certificate-list to get all the multi-certificates). Relevant when enable_ssl=enable and certificate_type=Multi Certificate. Supports API version 2 only. | Optional |
| certficate_intermediate_group | The name of a group of intermediate certificate authority (CA) certificates, if any, that FortiWeb presents to clients to complete the signing chain for them and validate the server certificate’s CA signature (dependencies - use fortiwebvm-certificate-intermediate-group-list command to get all the certificate intermediate groups). Relevant when ssl=enable. | Optional |
| client_certificate_file | The client certificate that FortiWeb uses to connect to this server pool member. Relevant when: enable_ssl=enable (dependencies - use fortiwebvm-local-certificate-list command to list all the local certificates). | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-wccp-rule-update group_name=wccp rule_id=1 port=84```
#### Human Readable Output

>Server pool rule 1 was successfully updated!

### fortiwebvm-server-pool-ftp-rule-create

***
Create a rule for an FTP server pool group (server pool rule is a member of server pool group). Supports API version 2 only. Server pool rule advanced SSL settings are not supported in this command.

#### Base Command

`fortiwebvm-server-pool-ftp-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| status | Server pool rule status. Possible values are: enable, disable, maintenance. Default is enable. | Optional |
| server_type | Specify whether to specify the pool member by IP address or domain. Possible values are: IP, Domain. | Optional |
| ip | The IP address of the web server to include in the pool. Required when: (server_type=IP). | Optional |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . Default is 21. | Optional |
| connection_limit | Connection limit. The maximum number of concurrent connections to the backend server. 0 for no connection limit. Size range: 0-1048576. Default is 0. | Optional |
| weight | The assigned relative preference among members. Higher values are more preferred and are assigned with connections more frequently. Relevant when the server pool group server balance=Server Balance. Size range: 1-9999. Default is 1. | Optional |
| health_check_inherit | Enable to use the health check specified by health in the server pool configuration. Disable to use the health check specified by health in this pool member configuration. Relevant when the server pool group server balance=Server Balance. Possible values are: enable, disable. | Optional |
| health_check_domain | The domain name of the server pool. Required when the server pool group server balance=Server Balance and health_check_inherit=enable. . | Optional |
| backup_server | Enter enable to configure this pool member as a backup server. FortiWeb only routes connections for the pool to a backup server when all the other members of the server pool fail their server health check. Relevant when the server pool group server balance=Server Balance.. Possible values are: enable, disable. | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. Default is disable. | Optional |
| implicit_ssl | Enable so that FortiWeb will communicate with the pool member using implicit SSL. Possible values are: enable, disable. Default is disable. | Optional |
| recover | The number of seconds to postpone forwarding traffic after downtime when a health check indicates that this server has become available again. Size range: 0-86400. Default is 0. | Optional |
| warm_up | Warm up, if the server cannot initially handle full connection load when it begins to respond to health checks. Size range: 0-86400. Default is 0. | Optional |
| warm_rate | The maximum connection rate per second while the server is starting up. Size range: 1-86400.. Default is 10. | Optional |
| domain | The fully-qualified domain name of the web server to include in the pool, such as www.example.com. Required when: (server_type=domain). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPoolGroup.Rule.id | String | The server pool rule ID. |

#### Command example
```!fortiwebvm-server-pool-ftp-rule-create group_name=ftp ip=1.2.3.4```
#### Context Example
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "Rule": {
                "id": "1"
            },
            "id": "ftp"
        }
    }
}
```

#### Human Readable Output

>### Server pool rule 1 was successfully added to server pool group ftp.
>|Id|
>|---|
>| 1 |


### fortiwebvm-server-pool-ftp-rule-update

***
Update a rule for an FTP server pool group (server pool rule is a member of server pool group). Supports API version 2 only.

#### Base Command

`fortiwebvm-server-pool-ftp-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| rule_id | Server pool rule ID (dependencies - use fortiwebvm-server-pool-rule-list command to get all server pool rules). | Required |
| status | Server pool rule status. Possible values are: enable, disable, maintenance. | Optional |
| server_type | Specify whether to specify the pool member by IP address or domain. Possible values are: IP, Domain. | Optional |
| ip | The IP address of the web server to include in the pool. Required when: (server_type=IP). | Optional |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . | Optional |
| connection_limit | Connection limit. The maximum number of concurrent connections to the backend server. 0 for no connection limit. Size range: 0-1048576. | Optional |
| weight | The assigned relative preference among members. Higher values are more preferred and are assigned with connections more frequently. Relevant when the server pool group server balance=Server Balance. Size range: 1-9999. | Optional |
| health_check_inherit | Enable to use the health check specified by health in the server pool configuration. Disable to use the health check specified by health in this pool member configuration. Relevant when the server pool group server balance=Server Balance. Possible values are: enable, disable. | Optional |
| health_check_domain | The domain name of the server pool. Required when the server pool group server balance=Server Balance and health_check_inherit=enable. . | Optional |
| backup_server | Enter enable to configure this pool member as a backup server. FortiWeb only routes connections for the pool to a backup server when all the other members of the server pool fail their server health check. Relevant when the server pool group server balance=Server Balance.. Possible values are: enable, disable. | Optional |
| enable_ssl | Enable to use SSL/TLS for connections between FortiWeb and the pool member. Possible values are: enable, disable. | Optional |
| implicit_ssl | Enable so that FortiWeb will communicate with the pool member using implicit SSL. Possible values are: enable, disable. | Optional |
| recover | The number of seconds to postpone forwarding traffic after downtime when a health check indicates that this server has become available again. Size range: 0-86400. | Optional |
| warm_up | Warm up, if the server cannot initially handle full connection load when it begins to respond to health checks. Size range: 0-86400. | Optional |
| warm_rate | The maximum connection rate per second while the server is starting up. Size range: 1-86400.. | Optional |
| domain | The fully-qualified domain name of the web server to include in the pool, such as www.example.com. Required when: (server_type=domain). | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-ftp-rule-update group_name=ftp rule_id=1 port=81```
#### Human Readable Output

>Server pool rule 1 was successfully updated!

### fortiwebvm-server-pool-adfs-rule-create

***
Create a rule for an ADFS server pool group (server pool rule is a member of server pool group). Supports API version 2 only. Server pool rule advanced SSL settings are not supported in this command.

#### Base Command

`fortiwebvm-server-pool-adfs-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| status | Server pool rule status. Possible values are: enable, disable, maintenance. Default is enable. | Optional |
| server_type | Specify whether to specify the pool member by IP address or domain. Possible values are: IP, Domain. | Required |
| ip | The IP address of the web server to include in the pool. Required when: (server_type=IP). | Optional |
| enable_ssl | The IP address of the web server to include in the pool. . Default is enable. | Optional |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . Default is 443. | Optional |
| connection_limit | Connection limit. The maximum number of concurrent connections to the backend server. 0 for no connection limit. Size range: 0-1048576. Default is 0. | Optional |
| health_check_inherit | Enable to use the health check specified by health in the server pool configuration. Disable to use the health check specified by health in this pool member configuration. Relevant when the server pool group server balance=Server Balance. Possible values are: enable, disable. | Optional |
| health_check_domain | The domain name of the server pool. Required when the server pool group server balance=Server Balance and health_check_inherit=enable. | Optional |
| backup_server | Enter enable to configure this pool member as a backup server. FortiWeb only routes connections for the pool to a backup server when all the other members of the server pool fail their server health check. Relevant when the server pool group server balance=Server Balance.. Possible values are: enable, disable. | Optional |
| registration_username | The username that will be used by FortiWeb to connect with the AD FS server. You should include the domain to which FortiWeb and the AD FS server belong. For example: administrator. | Required |
| registration_password | The password that will be used by FortiWeb to connect with the AD FS server. | Optional |
| client_certificate_file | The client certificate that FortiWeb uses to connect to this server pool member (dependencies - use fortiwebvm-local-certificate-list command to list all the local certificates). | Required |
| recover | The number of seconds to postpone forwarding traffic after downtime when a health check indicates that this server has become available again. Size range: 0-86400. Default is 0. | Optional |
| warm_up | Warm up, if the server cannot initially handle full connection load when it begins to respond to health checks. Size range: 0-86400. Default is 0. | Optional |
| warm_rate | The maximum connection rate per second while the server is starting up. Size range: 1-86400.. Default is 10. | Optional |
| domain | The fully-qualified domain name of the web server to include in the pool, such as www.example.com. Required when: (server_type=domain). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPoolGroup.Rule.id | String | The server pool rule ID. |

#### Command example
```!fortiwebvm-server-pool-adfs-rule-create group_name=adfs client_certificate_file=certificate registration_username=test server_type=Domain domain=test.com```
#### Context Example
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "Rule": {
                "id": "1"
            },
            "id": "adfs"
        }
    }
}
```

#### Human Readable Output

>### Server pool rule 1 was successfully added to server pool group adfs.
>|Id|
>|---|
>| 1 |


### fortiwebvm-server-pool-adfs-rule-update

***
Update a rule for an ADFS server pool group (server pool rule is a member of server pool group). Supports API version 2 only. Server pool rule advanced SSL settings are not supported in this command.

#### Base Command

`fortiwebvm-server-pool-adfs-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| rule_id | Server pool rule ID (dependencies - use fortiwebvm-server-pool-rule-list command to get all server pool rules). | Required |
| status | Server pool rule status. Possible values are: enable, disable, maintenance. | Optional |
| server_type | Specify whether to specify the pool member by IP address or domain. Possible values are: IP, Domain. | Optional |
| ip | The IP address of the web server to include in the pool. Required when: (server_type=IP). | Optional |
| port | The TCP port number where the pool member listens for connections. The valid range is 1–65,535. . | Optional |
| connection_limit | Connection limit. The maximum number of concurrent connections to the backend server. 0 for no connection limit. Size range: 0-1048576. | Optional |
| health_check_inherit | Enable to use the health check specified by health in the server pool configuration. Disable to use the health check specified by health in this pool member configuration. Relevant when the server pool group server balance=Server Balance. Possible values are: enable, disable. | Optional |
| health_check_domain | The domain name of the server pool. Required when the server pool group server balance=Server Balance and health_check_inherit=enable. | Optional |
| backup_server | Enter enable to configure this pool member as a backup server. FortiWeb only routes connections for the pool to a backup server when all the other members of the server pool fail their server health check. Relevant when the server pool group server balance=Server Balance.. Possible values are: enable, disable. | Optional |
| registration_username | The username that will be used by FortiWeb to connect with the AD FS server. You should include the domain to which FortiWeb and the AD FS server belong. For example: administrator. | Optional |
| registration_password | The password that will be used by FortiWeb to connect with the AD FS server. | Optional |
| client_certificate_file | The client certificate that FortiWeb uses to connect to this server pool member (dependencies - use fortiwebvm-local-certificate-list command to list all the local certificates). | Optional |
| recover | The number of seconds to postpone forwarding traffic after downtime when a health check indicates that this server has become available again. Size range: 0-86400. | Optional |
| warm_up | Warm up, if the server cannot initially handle full connection load when it begins to respond to health checks. Size range: 0-86400. | Optional |
| warm_rate | The maximum connection rate per second while the server is starting up. Size range: 1-86400.. | Optional |
| domain | The fully-qualified domain name of the web server to include in the pool, such as www.example.com. Required when: (server_type=domain). | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-adfs-rule-update group_name=adfs rule_id=1 port=81 client_certificate_file=certificate registration_username=test server_type=Domain domain=test2.com```
#### Human Readable Output

>Server pool rule 1 was successfully updated!

### fortiwebvm-server-pool-rule-delete

***
Delete server pool rule (server pool rule is a member of server pool). Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-pool-rule-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| rule_id | Server pool rule ID (dependencies - use fortiwebvm-server-pool-rule-list command to get all server pool rules). | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortiwebvm-server-pool-rule-delete group_name=rp rule_id=1```
#### Human Readable Output

>Server pool rule 1 was successfully deleted!

### fortiwebvm-server-pool-rule-list

***
List server pool rules (server pool rule is a member of server pool group). Supports API versions 1 & 2.

#### Base Command

`fortiwebvm-server-pool-rule-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | Server pool group name (dependencies - use fortiwebvm-server-pool-group-list command to get all server pool groups). | Required |
| rule_id | Server pool rule ID. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.ServerPoolGroup.Rule.id | String | Server pool rule rule ID. |
| FortiwebVM.ServerPoolGroup.Rule.server_type | String | Server pool rule type. |
| FortiwebVM.ServerPoolGroup.Rule.ip | String | Server pool rule IP. |
| FortiwebVM.ServerPoolGroup.Rule.domain | String | Server pool rule domain. |
| FortiwebVM.ServerPoolGroup.Rule.port | String | Server pool rule port. |
| FortiwebVM.ServerPoolGroup.Rule.weight | String | Server pool rule weight. |
| FortiwebVM.ServerPoolGroup.Rule.status | String | Server pool rule status. |
| FortiwebVM.ServerPoolGroup.Rule.backup_server | String | Server pool rule backup server. |
| FortiwebVM.ServerPoolGroup.Rule.connection_limit | String | The maximum number of concurrent connections to the backend server. 0 for no connection limit |
| FortiwebVM.ServerPoolGroup.Rule.http2 | String | Whether to allow HTTP/2 communication between the FortiWeb and this back-end web server for HTTP/2 security inspections. |
| FortiwebVM.ServerPoolGroup.Rule.ssl_settings | String | Server pool rule SSL settings. |

#### Command example
```!fortiwebvm-server-pool-rule-list group_name=test```
#### Context Example - API Version 1
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "Rule": [
                {
                    "backup_server": false,
                    "connection_limit": 0,
                    "domain": "test.com",
                    "http2": false,
                    "id": "1",
                    "ip": "",
                    "port": 80,
                    "server_type": 2,
                    "ssl_settings": false,
                    "status": 2,
                    "weight": ""
                }
            ],
            "group_name": "test"
        }
    }
}
```
#### Context Example - API Version 2
```json
{
    "FortiwebVM": {
        "ServerPoolGroup": {
            "Rule": [
                {
                    "backup_server": "disable",
                    "connection_limit": 0,
                    "domain": "test.com",
                    "http2": "disable",
                    "id": "1",
                    "ip": "1.2.3.4",
                    "port": 80,
                    "server_type": "domain",
                    "ssl_settings": "disable",
                    "status": "enable",
                    "weight": 1
                }
            ],
            "group_name": "test"
        }
    }
}

#### Human Readable Output

>### Server pool rule
>Showing page 1.
> Current page size: 50
>|Id|Server Type|Ip|Domain|Port|Status|Connection Limit|Http2|
>|---|---|---|---|---|---|---|---|
>| 1 | 2 |  | test.com | 80 | 2 | 0 | false |


### fortiwebvm-sdn-connector-list

***
List the SDN collector. The AWS and Azure connectors authorize FortiWeb to automatically retrieve the IP addresses of the back-end servers deployed on AWS or Azure. Supports API versions 2 only.

#### Base Command

`fortiwebvm-sdn-connector-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| search | Return all objects that include the specified string. For example: search=test will return objects like 'test1', 'test2', '5test', and any other objects containing the test string. | Optional |
| page | Page number of paginated results. Minimum value: 1. Default is 1. | Optional |
| page_size | The number of items per page. Default is 50. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiwebVM.SDNCollector.id | String | The SDN collector name. |

#### Command example
```!fortiwebvm-sdn-connector-list limit=1```
#### Context Example
```json
{
    "FortiwebVM": {
        "SDNCollector": {
            "id": "test"
        }
    }
}
```

#### Human Readable Output

>### SDN collectors:
>Showing page 1.
> Current page size: 50
>|Id|
>|---|
>| test |