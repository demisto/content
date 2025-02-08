FortiMail is a comprehensive email security solution by Fortinet, offering advanced threat protection, data loss prevention, encryption, and email authentication to safeguard organizations against email-based cyber threats and protect sensitive information.
This integration was integrated and tested with version 7.4 of fortimail.

## Configure FortiMail in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Account username | True |
| Password | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### fortimail-ip-group-create

***
Create an IP group. IP group is a container that contains members of IP address that can be used when configuring access control rules (define the source IP group of the SMTP client attempting to send the email message) and IP-based policies (define the IP group of the SMTP source/destination to which the policy applies).

#### Base Command

`fortimail-ip-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the IP group. The name must contain only alphanumeric characters. Spaces are not allowed. | Required |
| comment | A brief comment for the IP group. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.IPGroup.comment | String | A brief comment for the IP group. |
| FortiMail.IPGroup.mkey | String | The name of the IP group. |

#### Command example
```!fortimail-ip-group-create name=TestT```
#### Context Example
```json
{
    "FortiMail": {
        "IPGroup": {
            "comment": "",
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>### Ip Group created successfully
>|mkey|
>|---|
>| TestT |


### fortimail-ip-group-update

***
Update the comment of an IP group.

#### Base Command

`fortimail-ip-group-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the IP group to update. Use fortimail-ip-group-list to retrieve all the IP groups. | Required |
| comment | A brief comment for the IP group. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.IPGroup.comment | String | A brief comment for the IP group. |
| FortiMail.IPGroup.mkey | String | The name of the IP group. |

#### Command example
```!fortimail-ip-group-update name=TestT comment=comment```
#### Context Example
```json
{
    "FortiMail": {
        "IPGroup": {
            "comment": "comment",
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>### Ip Group updated successfully
>|mkey|comment|
>|---|---|
>| TestT | comment |


### fortimail-ip-group-delete

***
Delete an IP group.

#### Base Command

`fortimail-ip-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the IP group to remove. Use fortimail-ip-group-list to retrieve all the IP groups. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-ip-group-delete name=TestT```
#### Context Example
```json
{
    "FortiMail": {
        "IPGroup": {
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>Ip Group deleted successfully

### fortimail-ip-group-list

***
List IP groups. if a name is given, the command will return the information about the specified IP group.

#### Base Command

`fortimail-ip-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the IP group to retrieve. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.IPGroup.comment | String | A brief comment for the IP group. |
| FortiMail.IPGroup.mkey | String | The name of the IP group. |

#### Command example
```!fortimail-ip-group-list```
#### Context Example
```json
{
    "FortiMail": {
        "IPGroup": [
            {
                "comment": "TEST",
                "mkey": "TAL"
            },
            {
                "comment": "",
                "mkey": "TestGroup"
            },
            {
                "comment": "comment",
                "mkey": "TestT"
            },
            {
                "comment": "",
                "mkey": "TestTs"
            },
            {
                "comment": "first test",
                "mkey": "ben_lab_new"
            },
            {
                "comment": "",
                "mkey": "ben_lavV1"
            },
            {
                "comment": "lolamarish",
                "mkey": "ben_lavV1.1"
            },
            {
                "comment": "",
                "mkey": "tal_test"
            },
            {
                "comment": "dfsdfsdf",
                "isReferenced": 5,
                "mkey": "test"
            },
            {
                "comment": "test1",
                "isReferenced": 2,
                "mkey": "test1"
            }
        ]
    }
}
```

#### Human Readable Output

>### Ip Group list
>|Name|Comment|
>|---|---|
>| TAL | TEST |
>| TestGroup |  |
>| TestT | comment |
>| TestTs |  |
>| ben_lab_new | first test |
>| ben_lavV1 |  |
>| ben_lavV1.1 | lolamarish |
>| tal_test |  |
>| test | dfsdfsdf |
>| test1 | test1 |


### fortimail-ip-group-member-add

***
Add an IP group member (IP/Netmask or IP range) to an IP group. An IP group member is an IP address that can be used when configuring access control rules (define the source IP group of the SMTP client attempting to send the email message) and IP-based policies (define the IP group of the SMTP source/destination to which the policy applies).

#### Base Command

`fortimail-ip-group-member-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the IP group. Use fortimail-ip-group-list to retrieve all the IP groups. | Required |
| ip | The IP address and netmask that you want to include in the IP group. Use the netmask, the portion after the slash (/), to specify the matching subnet. For example, 10.10.10.10/24 or 172.20.130.10-172.20.130.30. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.IPGroup.mkey | String | The name of the IP group. |
| FortiMail.IPGroup.Member.mkey | String | The name of the IP member. |

#### Command example
```!fortimail-ip-group-member-add group_name=TestT ip=2.2.2.2```
#### Context Example
```json
{
    "FortiMail": {
        "IPGroup": {
            "Member": {
                "mkey": "2.2.2.2-2.2.2.2"
            },
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>Ip Group Member added successfully

### fortimail-ip-group-member-replace

***
Replace IP group members with new members. This command overwrites all the IP group members that was defined in the IP group.

#### Base Command

`fortimail-ip-group-member-replace`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the IP group. Use fortimail-ip-group-create to retrieve all the IP groups. | Required |
| ips | A comma-separated list of IP address that you want to replace in the IP group. Use the netmask, the portion after the slash (/), to specify the matching subnet. For example, 10.10.10.10/24,12.12.12.12/24,172.20.130.10-172.20.130.30. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-ip-group-member-replace group_name=TestT ips=3.3.3.3,4.4.4.4```
#### Context Example
```json
{
    "FortiMail": {
        "IPGroup": {
            "Member": [
                {
                    "mkey": "3.3.3.3-3.3.3.3"
                },
                {
                    "mkey": "4.4.4.4-4.4.4.4"
                }
            ],
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>Ip Group Member replaced successfully

### fortimail-ip-group-member-delete

***
Delete an IP group member from IP group.

#### Base Command

`fortimail-ip-group-member-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the IP group. Use fortimail-ip-group-list to retrieve all the IP groups. | Required |
| ip | The IP address member to remove from the IP group. Use fortimail-ip-group-member-list to retrieve all the IP group members. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-ip-group-member-delete group_name=TestT ip=4.4.4.4```
#### Context Example
```json
{
    "FortiMail": {
        "IPGroup": {
            "mkey": "4.4.4.4"
        }
    }
}
```

#### Human Readable Output

>Ip Group Member deleted successfully

### fortimail-ip-group-member-list

***
List IP group members. If an ip is given, the command will return the information about the specified IP group member.

#### Base Command

`fortimail-ip-group-member-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the IP group. Use fortimail-ip-group-list to retrieve all the IP groups. | Required |
| ip | The IP address that you want to retrieve. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.IPGroup.mkey | String | The name of the IP group. |
| FortiMail.IPGroup.Member.mkey | String | The name of the IP member. |

#### Command example
```!fortimail-ip-group-member-list group_name=TestT```
#### Context Example
```json
{
    "FortiMail": {
        "IPGroup": {
            "Member": [
                {
                    "mkey": "3.3.3.3-3.3.3.3"
                }
            ],
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>### Ip Group Member
>|Name|Group Name|
>|---|---|
>| 3.3.3.3-3.3.3.3 | TestT |


### fortimail-email-group-create

***
Create an email group. An email group is a container for a list of email addresses, allowing you to use it in configuring access control rules (for defining the sender and recipient matching) and recipient-based policies (for defining MAIL FROM addresses matching specific policies).

#### Base Command

`fortimail-email-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the email group. The name must contain only alphanumeric characters. Spaces are not allowed. | Required |
| comment | A brief comment for the email group. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.EmailGroup.comment | String | A brief comment for the email group. |
| FortiMail.EmailGroup.mkey | String | The name of the email group. |

#### Command example
```!fortimail-email-group-create name=TestT```
#### Context Example
```json
{
    "FortiMail": {
        "EmailGroup": {
            "comment": "",
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>### Email Group created successfully
>|mkey|
>|---|
>| TestT |


### fortimail-email-group-update

***
Update the comment of an email group.

#### Base Command

`fortimail-email-group-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the email group to update. Use fortimail-email-group-list to retrieve all the email groups. | Required |
| comment | A brief comment for the email group. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.EmailGroup.comment | String | A brief comment for the email group. |
| FortiMail.EmailGroup.mkey | String | The name of the email group. |

#### Command example
```!fortimail-email-group-update name=TestT comment=comment```
#### Context Example
```json
{
    "FortiMail": {
        "EmailGroup": {
            "comment": "comment",
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>### Email Group updated successfully
>|mkey|comment|
>|---|---|
>| TestT | comment |


### fortimail-email-group-delete

***
Delete an email group.

#### Base Command

`fortimail-email-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the email group to remove. Use fortimail-email-group-list to retrieve all the email groups. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-email-group-delete name=TestT```
#### Context Example
```json
{
    "FortiMail": {
        "EmailGroup": {
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>Email Group deleted successfully

### fortimail-email-group-list

***
List email groups. If a name is given, the command will return the information about the specified email group.

#### Base Command

`fortimail-email-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the email group to retrieve. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.EmailGroup.comment | String | A brief comment for the email group. |
| FortiMail.EmailGroup.mkey | String | The name of the email group. |

#### Command example
```!fortimail-email-group-list```
#### Context Example
```json
{
    "FortiMail": {
        "EmailGroup": [
            {
                "comment": "comment",
                "mkey": "TestT"
            },
            {
                "comment": "new_comment_update",
                "isReferenced": 4,
                "mkey": "new_version3242342.0"
            },
            {
                "comment": "",
                "isReferenced": 1,
                "mkey": "test"
            }
        ]
    }
}
```

#### Human Readable Output

>### Email Group list
>|Name|Comment|
>|---|---|
>| TestT | comment |
>| new_version3242342.0 | new_comment_update |
>| test |  |


### fortimail-email-group-member-add

***
Add an email group member (email address) to an email group.

#### Base Command

`fortimail-email-group-member-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the email group. Use fortimail-email-group-list to retrieve all the email groups. | Required |
| email | The email address that you want to include in the email group. For example, example@example.com. You can also use wildcards to enter partial patterns that can match multiple email addresses. The asterisk represents one or more characters and the question mark (?) represents any single character. For example, the pattern ??@*.com will match any email user with a two letter email user name from any “.com” domain name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.EmailGroup.mkey | String | The name of the email group. |
| FortiMail.EmailGroup.Member.mkey | String | The name of the email member. |

#### Command example
```!fortimail-email-group-member-add group_name=TestT email=t@t.com```
#### Context Example
```json
{
    "FortiMail": {
        "EmailGroup": {
            "Member": {
                "mkey": "t@t.com"
            },
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>Email Group Member added successfully

### fortimail-email-group-member-replace

***
Replace email group members with new members. This command overwrites all the email group members that were defined in the email group.

#### Base Command

`fortimail-email-group-member-replace`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the email group. Use fortimail-email-group-list to retrieve all the email groups. | Required |
| emails | A comma-separated list of email address that you want to replace in the email group. For example, test1@test.com,test2@test.com. You can also use wildcards to enter partial patterns that can match multiple email addresses. The asterisk represents one or more characters and the question mark (?) represents any single character. For example, the pattern ??@*.com will match any email user with a two letter email user name from any “.com” domain name. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-email-group-member-replace group_name=TestT emails=d@d.com,r@r.com```
#### Context Example
```json
{
    "FortiMail": {
        "EmailGroup": {
            "Member": [
                {
                    "mkey": "d@d.com"
                },
                {
                    "mkey": "r@r.com"
                }
            ],
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>Email Group Member replaced successfully

### fortimail-email-group-member-delete

***
Delete an email group member from an email group.

#### Base Command

`fortimail-email-group-member-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the email group. Use fortimail-email-group-list to retrieve all the email groups. | Required |
| email | The email member to remove from the email group. Use fortimail-email-group-member-list to retrieve all the email members. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-email-group-member-delete group_name=TestT email=r@r.com```
#### Context Example
```json
{
    "FortiMail": {
        "EmailGroup": {
            "mkey": "r@r.com"
        }
    }
}
```

#### Human Readable Output

>Email Group Member deleted successfully

### fortimail-email-group-member-list

***
List email group members. If an email is given, the command will return the information about the specified email group member.

#### Base Command

`fortimail-email-group-member-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_name | The name of the email group. Use fortimail-email-group-list to retrieve all the email groups. | Required |
| email | The email member to retrieve. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.EmailGroup.mkey | String | The name of the email group. |
| FortiMail.EmailGroup.Member.mkey | String | The name of the email member. |

#### Command example
```!fortimail-email-group-member-list group_name=TestT```
#### Context Example
```json
{
    "FortiMail": {
        "EmailGroup": {
            "Member": [
                {
                    "mkey": "d@d.com"
                }
            ],
            "mkey": "TestT"
        }
    }
}
```

#### Human Readable Output

>### Email Group Member
>|Name|Group Name|
>|---|---|
>| d@d.com | TestT |


### fortimail-system-safe-block-list

***
List the system Block/Safe list. Choose the specified list by the type argument.

#### Base Command

`fortimail-system-safe-block-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_type | The type of the list to retrieve. Possible values are: Blocklist, Safelist. | Required |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.SystemList.item | String | The value of the item in the list. |
| FortiMail.SystemList.list_type | String | The type of the list (safelist or blocklist). |

#### Command example
```!fortimail-system-safe-block-list list_type=Blocklist```
#### Context Example
```json
{
    "FortiMail": {
        "SystemList": [
            {
                "item": "1.1.1.1/24",
                "list_type": "Blocklist"
            },
            {
                "item": "1.1.1.5/24",
                "list_type": "Blocklist"
            },
            {
                "item": "1.1.5.5/24",
                "list_type": "Blocklist"
            },
            {
                "item": "1.1.5.6/24",
                "list_type": "Blocklist"
            },
            {
                "item": "1.2.2.1/24",
                "list_type": "Blocklist"
            },
            {
                "item": "1.2.5.6/24",
                "list_type": "Blocklist"
            },
            {
                "item": "3.5.7.8/24",
                "list_type": "Blocklist"
            },
            {
                "item": "5.5.5.5/24",
                "list_type": "Blocklist"
            },
            {
                "item": "7.7.7.7/24",
                "list_type": "Blocklist"
            }
        ]
    }
}
```

#### Human Readable Output

>### System Safe Block
>|item|list_type|
>|---|---|
>| 1.1.1.1/24 | Blocklist |
>| 1.1.1.5/24 | Blocklist |
>| 1.1.5.5/24 | Blocklist |
>| 1.1.5.6/24 | Blocklist |
>| 1.2.2.1/24 | Blocklist |
>| 1.2.5.6/24 | Blocklist |
>| 3.5.7.8/24 | Blocklist |
>| 5.5.5.5/24 | Blocklist |
>| 7.7.7.7/24 | Blocklist |


### fortimail-system-safe-block-add

***
Add an email address/ domain name/ IP address to the system safe/block list. Block/Safe List lets you reject, discard, or allow email messages based on email addresses, domain names, and IP addresses. As one of the first steps to detect spam, FortiMail units evaluate whether an email message matches a block list or safe list entry. Choose the specified list by the type argument.

#### Base Command

`fortimail-system-safe-block-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| values | Email address/ domain name/ IP address to add to the system safe/block list. The supported entry types are Email (For example, example@example.com, *@example.com), IP/Netmask: (For example, 10.10.10.10/24), and Reverse DNS (For example, http://example.com. You can use the following wild cards:*: Matches any number of characters. You can use the asterisk (*) anywhere in a character string.?: Matches a single alphabet in a specific position. | Required |
| list_type | The type of the list to add the values. Safelist - accept message. Blocklist - invoke block list action that was defined in the settings. Possible values are: Blocklist, Safelist. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-system-safe-block-add values=1.1.1.1 list_type=Blocklist```
#### Context Example
```json
{
    "FortiMail": {
        "SystemSafeBlock": {
            "item": "1.1.1.1",
            "list_type": "Blocklist"
        }
    }
}
```

#### Human Readable Output

>### System Block List Items Was Added Successfully
>|item|list_type|
>|---|---|
>| 1.1.1.1 | Blocklist |


### fortimail-system-safe-block-delete

***
Delete an email address/ domain name/ IP address from the system safe/block list. Choose the specified list by the type argument.

#### Base Command

`fortimail-system-safe-block-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| values | A comma-separated list of email addresses/ domain names/ IP addresses to remove from the system safe/block list. For example, test@test.com, test2@test.com or 1.1.1.1/0,1.1.1.2/0. Use system-safe-block-list to get all safe/block list values. | Required |
| list_type | The type of the list to add the values. Safelist - accept message. Blocklist - invoke block list action that was defined in the settings. Possible values are: Blocklist, Safelist. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-system-safe-block-delete values=1.1.1.1 list_type=Blocklist```
#### Context Example
```json
{
    "FortiMail": {
        "SystemList": {
            "mkey": "Blocklist"
        }
    }
}
```

#### Human Readable Output

>System Safe Block deleted successfully

### fortimail-ip-policy-create

***
Create an IP policy. IP-based policies lets you control emails based on IP/Netmask / IP Group/ GeoIP Group/ ISDB.

#### Base Command

`fortimail-ip-policy-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Whether to apply the policy. Possible values are: enable, disable. Default is enable. | Optional |
| source | The source of the policy. When source_type is IP/Netmask, enter the IP address and subnet mask of the SMTP client to whose connections this policy will apply. When source_type is IP Group, enter the IP group of the SMTP client to whose connections this policy will apply (use fortimail-ip-group-list to retrieve all the IP groups). When source_type is GeoIP, enter the Geo IP group. When source_type is ISDB, enter the name of an internet service provider. To match all clients, enter 0.0.0.0/0. Default is 0.0.0.0/0. | Optional |
| destination | The destination of the policy. When destination_type is IP/Netmask, enter the IP address and subnet mask of the SMTP client to whose connections this policy will apply. When destination_type is IP Group, enter the IP group of the SMTP client to whose connections this policy will apply (use fortimail-ip-group-list to retrieve all the IP groups). To match all clients, enter 0.0.0.0/0. Default is 0.0.0.0/0. | Optional |
| source_type | The type of the source. Insert the source argument corresponding to the type value. Possible values are: IP/Netmask, IP Group, GeoIP Group, ISDB. Default is IP/Netmask. | Optional |
| destination_type | The type of the destination. Insert the source argument corresponding to the type value. Possible values are: IP/Netmask, IP Group. Default is IP/Netmask. | Optional |
| action | An action for the policy. Proxy-bypass: Bypass the FortiMail unit’s scanning. This action is for transparent mode only.Scan: Accept the connection and perform any scans configured in the profiles selected in this policy. Reject: Reject the email and respond to the SMTP client with SMTP reply code 550, indicating a permanent failure. Fail Temporarily: Reject the email and respond to the SMTP client with SMTP reply code 451, indicating a temporary failure. Possible values are: Scan, Reject, Fail Temporarily, Proxy bypass. Default is Scan. | Optional |
| comment | A brief comment for the IP policy. | Optional |
| session_profile | The name of the session profile that you want to apply to connections matching the policy. Use fortimail-session-profile-list to retrieve all the session profiles. This option is applicable only if action is Scan. | Optional |
| antispam_profile | The name of an outgoing anti-spam profile, if any, that this policy will apply. Use fortimail-antispam-profile-list to retrieve all the anti-spam profiles. This option is applicable only if action is Scan. | Optional |
| antivirus_profile | The name of an antivirus profile, if any, that this policy will apply. Use fortimail-antivirus-profile-list to retrieve all the antivirus profiles. This option is applicable only if action is Scan. | Optional |
| content_profile | The name of the content profile that you want to apply to connections matching the policy. Use fortimail-content-profile-list to retrieve all the content profiles. This option is applicable only if action is Scan. | Optional |
| ip_pool_profile | The name of an IP pool profile, if any, that this policy will apply.The IP addresses in the IP pool are used as the source IP address for the SMTP sessions matching this policy.An IP pool in an IP policy will be used to deliver incoming email from FortiMail to the protected server. An IP pool (either in an IP policy or domain settings) will be used to deliver emails to the protected domain servers if the mail flow is from internal to internal domains. Use fortimail-ip-pool-list to retrieve all the IP pool profiles. | Optional |
| auth_type | The type of the authentication profile that this policy will apply. If you want the email user to authenticate using an external authentication server, select the authentication type of the profile (SMTP, POP3, IMAP, RADIUS, or LDAP). Possible values are: imap, ldap, pop3, radius, smpt. | Optional |
| auth_profile | The name of an authentication profile for the type. When auth_type is LDAP, insert LDAP authentication profile. Use fortimail-ldap-group-list to retrieve all the LDAP authentication profiles. When auth_type is RADIUS, insert RADIUS authentication profile. Use fortimail-radius-auth-profile to retrieve all the RADIUS authentication profiles. When auth_type is POP3, insert POP3 authentication profile. Use fortimail-pop3-auth-profile to retrieve all the POP3 authentication profiles. When auth_type is IMAP, insert IMAP authentication profile. Use fortimail-imap-auth-profile to retrieve all the IMAP authentication profiles. When auth_type is SMTP, insert SMTP authentication profile. Use fortimail-smtp-auth-profile to retrieve all the SMTP authentication profiles. Relevant when auth_type is chosen. | Optional |
| use_smtp_auth | Whether to authenticate SMTP connections using the authentication profile configured in sensitive-data. This option is available only if you have selected an auth_profile. Possible values are: enable, disable. Default is disable. | Optional |
| smtp_different | Whether to require that the sender uses the same identity for: authentication name, SMTP envelope MAIL FROM:, and header FROM:. Possible values are: enable, disable. Default is disable. | Optional |
| smtp_diff_identity_ldap | Whether to verify SMTP sender identity with LDAP for authenticated email. Possible values are: enable, disable. Default is disable. | Optional |
| smtp_diff_identity_ldap_profile | LDAP profile for SMTP sender identity verification. Use fortimail-ldap-group-list to retrieve all the LDAP authentication profiles. Required when smtp_diff_identity_ldap is enable. | Optional |
| exclusive | Whether to take precedence over recipient-based policy match. Enable to omit use of recipient-based policies for connections matching this IP-based policy. This option is applicable only if action is Scan. Possible values are: enable, disable. Default is disable. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.IPPolicy.smtp_diff_identity_ldap_profile | String | LDAP profile for SMTP sender identity verification. |
| FortiMail.IPPolicy.smtp_diff_identity_ldap | String | Whether to verify SMTP sender identity with LDAP for authenticated email. |
| FortiMail.IPPolicy.smtp_different | String | 'Whether to require that the sender uses the same identity for: authentication name, SMTP envelope MAIL FROM:, and header FROM:.' |
| FortiMail.IPPolicy.use_smtp_auth | String | Whether to authenticate SMTP connections using the authentication profile configured in sensitive-data. |
| FortiMail.IPPolicy.action | String | The action of the policy. |
| FortiMail.IPPolicy.comment | String | A brief comment for the IP policy. |
| FortiMail.IPPolicy.exclusive | Boolean | Whether to take precedence over recipient-based policy match. |
| FortiMail.IPPolicy.smtp_auth | String | The authentication profile when auth_type=SMTP. |
| FortiMail.IPPolicy.imap_auth | String | The authentication profile when auth_type=IMAP. |
| FortiMail.IPPolicy.pop3_auth | String | The authentication profile when auth_type=POP3. |
| FortiMail.IPPolicy.ldap_auth | String | The authentication profile when auth_type=LDAP. |
| FortiMail.IPPolicy.radius_auth | String | The authentication profile when auth_type=RADIUS. |
| FortiMail.IPPolicy.auth_type | String | The type of the authentication profile that this policy will apply. If you want the email user to authenticate using an external authentication server, select the authentication type of the profile (SMTP, POP3, IMAP, RADIUS, or LDAP). |
| FortiMail.IPPolicy.ip_pool_profile | String | The name of the content profile that you want to apply to connections matching the policy. |
| FortiMail.IPPolicy.content_profile | String | The name of the content profile that you want to apply to connections matching the policy. |
| FortiMail.IPPolicy.antivirus_profile | String | The name of an antivirus profile, if any, that this policy will apply. |
| FortiMail.IPPolicy.antispam_profile | String | The name of an outgoing anti-spam profile, if any, that this policy apply. |
| FortiMail.IPPolicy.session_profile | String | The name of the session profile that you want to apply to connections matching the policy. |
| FortiMail.IPPolicy.status | String | Whether the policy applied. |
| FortiMail.IPPolicy.server_ip_group | String | The destination IP group. Relevant when server_type is IP group. |
| FortiMail.IPPolicy.server | String | The destination IP/Netmask. Relevant when server_type is IP/Netmask. |
| FortiMail.IPPolicy.server_type | String | The type of the destination. |
| FortiMail.IPPolicy.client_isdb | String | The source ISDB. Relevant when client_type is ISDB. |
| FortiMail.IPPolicy.client_ip_group | String | The source IP group. Relevant when client_type is IP group. |
| FortiMail.IPPolicy.client_geoip_group | String | The Geo IP group. Relevant when client_type is Geo IP. |
| FortiMail.IPPolicy.client | String | The source IP/Netmask. Relevant when client_type is IP/Netmask. |
| FortiMail.IPPolicy.client_type | String | The type of the source. |
| FortiMail.IPPolicy.mkey | Number | The ID of the IP policy. |

#### Command example
```!fortimail-ip-policy-create status=enable comment=testTal```
#### Context Example
```json
{
    "FortiMail": {
        "IPPolicy": {
            "action": "Scan",
            "antispam_profile": "",
            "antivirus_profile": "",
            "client": "0.0.0.0/0",
            "client_geoip_group": "0.0.0.0/0",
            "client_ip_group": "0.0.0.0/0",
            "client_isdb": "0.0.0.0/0",
            "client_type": "IP/Netmask",
            "comment": "testTal",
            "content_profile": "",
            "exclusive": "disable",
            "imap_auth": "",
            "ip_pool_profile": "",
            "ldap_auth": "",
            "mkey": 1,
            "pop3_auth": "",
            "profile_dlp": "",
            "radius_auth": "",
            "server": "0.0.0.0/0",
            "server_ip_group": "0.0.0.0/0",
            "server_type": "IP/Netmask",
            "session_profile": "",
            "smtp_auth": "",
            "smtp_diff_identity_ldap": "disable",
            "smtp_diff_identity_ldap_profile": "",
            "smtp_different": "disable",
            "status": "enable",
            "use_smtp_auth": "disable"
        }
    }
}
```

#### Human Readable Output

>### Ip Policy created successfully
>|Action|Action On Failure|Client|Client Type|Comment|Name|Server|Server Type|Status|
>|---|---|---|---|---|---|---|---|---|
>| Scan | Scan | 0.0.0.0/0 | IP/Netmask | testTal | 1 | 0.0.0.0/0 | IP/Netmask | enable |


### fortimail-ip-policy-update

***
Update an IP policy.

#### Base Command

`fortimail-ip-policy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_policy_id | The ID of the IP policy. | Required |
| status | Whether to apply the policy. Possible values are: enable, disable. Default is enable. | Optional |
| source | The source of the policy. When source_type is IP/Netmask, enter the IP address and subnet mask of the SMTP client to whose connections this policy will apply. When source_type is IP Group, enter the IP group of the SMTP client to whose connections this policy will apply (use fortimail-ip-group-list to retrieve all the IP groups). When source_type is GeoIP, enter the Geo IP group. When source_type is ISDB, enter the name of an internet service provider. To match all clients, enter 0.0.0.0/0. | Optional |
| destination | The destination of the policy. When destination_type is IP/Netmask, enter the IP address and subnet mask of the SMTP client to whose connections this policy will apply. When destination_type is IP Group, enter the IP group of the SMTP client to whose connections this policy will apply (use fortimail-ip-group-list to retrieve all the IP groups). To match all clients, enter 0.0.0.0/0. | Optional |
| source_type | The type of the source. Insert the source argument corresponding to the type value. Possible values are: IP/Netmask, IP Group, GeoIP Group, ISDB. | Optional |
| destination_type | The type of the destination. Insert the source argument corresponding to the type value. Possible values are: IP/Netmask, IP Group. | Optional |
| action | An action for the policy. Proxy-bypass: Bypass the FortiMail unit’s scanning. This action is for transparent mode only.Scan: Accept the connection and perform any scans configured in the profiles selected in this policy. Reject: Reject the email and respond to the SMTP client with SMTP reply code 550, indicating a permanent failure. Fail Temporarily: Reject the email and respond to the SMTP client with SMTP reply code 451, indicating a temporary failure. Possible values are: Scan, Reject, Fail Temporarily, Proxy bypass. | Optional |
| comment | A brief comment for the IP policy. | Optional |
| session_profile | The name of the session profile that you want to apply to connections matching the policy. Use fortimail-session-profile-list to retrieve all the session profiles. This option is applicable only if action is Scan. | Optional |
| antispam_profile | The name of an outgoing anti-spam profile, if any, that this policy will apply. Use fortimail-antispam-profile-list to retrieve all the anti-spam profiles. This option is applicable only if action is Scan. | Optional |
| antivirus_profile | The name of an antivirus profile, if any, that this policy will apply. Use fortimail-antivirus-profile-list to retrieve all the antivirus profiles. This option is applicable only if action is Scan. | Optional |
| content_profile | The name of the content profile that you want to apply to connections matching the policy. Use fortimail-content-profile-list to retrieve all the content profiles. This option is applicable only if action is Scan. | Optional |
| ip_pool_profile | The name of an IP pool profile, if any, that this policy will apply.The IP addresses in the IP pool are used as the source IP address for the SMTP sessions matching this policy.An IP pool in an IP policy will be used to deliver incoming email from FortiMail to the protected server. An IP pool (either in an IP policy or domain settings) will be used to deliver emails to the protected domain servers if the mail flow is from internal to internal domains. Use fortimail-ip-pool-list to retrieve all the IP pool profiles. | Optional |
| auth_type | The type of the authentication profile that this policy will apply. If you want the email user to authenticate using an external authentication server, select the authentication type of the profile (SMTP, POP3, IMAP, RADIUS, or LDAP). Possible values are: imap, ldap, pop3, radius, smpt. | Optional |
| auth_profile | The name of an authentication profile for the type. When auth_type is LDAP, insert LDAP authentication profile. Use fortimail-ldap-group-list to retrieve all the LDAP authentication profiles. When auth_type is RADIUS, insert RADIUS authentication profile. Use fortimail-radius-auth-profile to retrieve all the RADIUS authentication profiles. When auth_type is POP3, insert POP3 authentication profile. Use fortimail-pop3-auth-profile to retrieve all the POP3 authentication profiles. When auth_type is IMAP, insert IMAP authentication profile. Use fortimail-imap-auth-profile to retrieve all the IMAP authentication profiles. When auth_type is SMTP, insert SMTP authentication profile. Use fortimail-smtp-auth-profile to retrieve all the SMTP authentication profiles. Relevant when auth_type is chosen. | Optional |
| use_smtp_auth | Whether to authenticate SMTP connections using the authentication profile configured in sensitive-data. This option is available only if you have selected an auth_profile. Possible values are: enable, disable. | Optional |
| smtp_different | Whether to require that the sender uses the same identity for: authentication name, SMTP envelope MAIL FROM:, and header FROM:. Possible values are: enable, disable. | Optional |
| smtp_diff_identity_ldap | Whether to verify SMTP sender identity with LDAP for authenticated email. Possible values are: enable, disable. | Optional |
| smtp_diff_identity_ldap_profile | LDAP profile for SMTP sender identity verification. Use fortimail-ldap-group-list to retrieve all the LDAP authentication profiles. Required when smtp_diff_identity_ldap is enable. | Optional |
| exclusive | Whether to take precedence over recipient-based policy match. Enable to omit use of recipient-based policies for connections matching this IP-based policy. This option is applicable only if action is Scan. Possible values are: enable, disable. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.IPPolicy.smtp_diff_identity_ldap_profile | String | LDAP profile for SMTP sender identity verification. |
| FortiMail.IPPolicy.smtp_diff_identity_ldap | String | Whether to verify SMTP sender identity with LDAP for authenticated email. |
| FortiMail.IPPolicy.smtp_different | String | 'Whether to require that the sender uses the same identity for: authentication name, SMTP envelope MAIL FROM:, and header FROM:.' |
| FortiMail.IPPolicy.use_smtp_auth | String | Whether to authenticate SMTP connections using the authentication profile configured in sensitive-data. |
| FortiMail.IPPolicy.action | String | The action of the policy. |
| FortiMail.IPPolicy.comment | String | A brief comment for the IP policy. |
| FortiMail.IPPolicy.exclusive | Boolean | Whether to take precedence over recipient-based policy match. |
| FortiMail.IPPolicy.smtp_auth | String | The authentication profile when auth_type=SMTP. |
| FortiMail.IPPolicy.imap_auth | String | The authentication profile when auth_type=IMAP. |
| FortiMail.IPPolicy.pop3_auth | String | The authentication profile when auth_type=POP3. |
| FortiMail.IPPolicy.ldap_auth | String | The authentication profile when auth_type=LDAP. |
| FortiMail.IPPolicy.radius_auth | String | The authentication profile when auth_type=RADIUS. |
| FortiMail.IPPolicy.auth_type | String | The type of the authentication profile that this policy will apply. If you want the email user to authenticate using an external authentication server, select the authentication type of the profile (SMTP, POP3, IMAP, RADIUS, or LDAP). |
| FortiMail.IPPolicy.ip_pool_profile | String | The name of the content profile that you want to apply to connections matching the policy. |
| FortiMail.IPPolicy.content_profile | String | The name of the content profile that you want to apply to connections matching the policy. |
| FortiMail.IPPolicy.antivirus_profile | String | The name of an antivirus profile, if any, that this policy will apply. |
| FortiMail.IPPolicy.antispam_profile | String | The name of an outgoing anti-spam profile, if any, that this policy apply. |
| FortiMail.IPPolicy.session_profile | String | The name of the session profile that you want to apply to connections matching the policy. |
| FortiMail.IPPolicy.status | String | Whether the policy applied. |
| FortiMail.IPPolicy.server_ip_group | String | The destination IP group. Relevant when server_type is IP group. |
| FortiMail.IPPolicy.server | String | The destination IP/Netmask. Relevant when server_type is IP/Netmask. |
| FortiMail.IPPolicy.server_type | String | The type of the destination. |
| FortiMail.IPPolicy.client_isdb | String | The source ISDB. Relevant when client_type is ISDB. |
| FortiMail.IPPolicy.client_ip_group | String | The source IP group. Relevant when client_type is IP group. |
| FortiMail.IPPolicy.client_geoip_group | String | The Geo IP group. Relevant when client_type is Geo IP. |
| FortiMail.IPPolicy.client | String | The source IP/Netmask. Relevant when client_type is IP/Netmask. |
| FortiMail.IPPolicy.client_type | String | The type of the source. |
| FortiMail.IPPolicy.mkey | Number | The ID of the IP policy. |

#### Command example
```!fortimail-ip-policy-update ip_policy_id=4 comment=test2```
#### Context Example
```json
{
    "FortiMail": {
        "IPPolicy": {
            "comment": "test2",
            "mkey": 4,
            "status": "enable"
        }
    }
}
```

#### Human Readable Output

>### Ip Policy updated successfully
>|Comment|Name|Status|
>|---|---|---|
>| test2 | 4 | enable |


### fortimail-ip-policy-move

***
Move an IP policy location in the policy list. FortiMail units match the policies in sequence, from the top of the list downwards. Therefore, you must put the more specific policies on top of the more generic ones.

#### Base Command

`fortimail-ip-policy-move`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the IP policy rule to be moved. Use fortimail-ip-policy-list to retrieve all the access control. | Required |
| reference_id | The reference ID of the IP policy rule when moving before/after. Required when action is before/ after. | Optional |
| action | The move action. When using before/ after, insert reference_id. Possible values are: up, down, before, after. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-ip-policy-move policy_id=4 action=up```
#### Human Readable Output

>Ip Policy moved successfully

### fortimail-ip-policy-delete

***
Delete an IP policy.

#### Base Command

`fortimail-ip-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the IP policy to remove. Use fortimail-ip-policy-list to retrieve all the access control. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-ip-policy-delete policy_id=9```
#### Context Example
```json
{
    "FortiMail": {
        "IPPolicy": {
            "mkey": "9"
        }
    }
}
```

#### Human Readable Output

>Ip Policy deleted successfully

### fortimail-ip-policy-list

***
List an IP policy. If an ID is given, the command will return the information about the specified IP policy.

#### Base Command

`fortimail-ip-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | The ID of the IP policy to retrieve. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.IPPolicy.status | String | Whether the policy applied. |
| FortiMail.IPPolicy.client_type | String | The type of the source. |
| FortiMail.IPPolicy.client | String | The source IP/Netmask. Relevant when client_type is IP/Netmask. |
| FortiMail.IPPolicy.client_ip_group | String | The source IP group. Relevant when client_type is IP group. |
| FortiMail.IPPolicy.client_geoip_group | String | The Geo IP group. Relevant when client_type is Geo IP. |
| FortiMail.IPPolicy.client_isdb | String | The source ISDB. Relevant when client_type is ISDB. |
| FortiMail.IPPolicy.server_type | String | The type of the destination. |
| FortiMail.IPPolicy.server | String | The destination IP/Netmask. Relevant when server_type is IP/Netmask. |
| FortiMail.IPPolicy.server_ip_group | String | The destination IP group. Relevant when server_type is IP group. |
| FortiMail.IPPolicy.action | String | The action of the policy. |
| FortiMail.IPPolicy.comment | String | A brief comment for the IP policy. |
| FortiMail.IPPolicy.session_profile | String | The name of the session profile that you want to apply to connections matching the policy. |
| FortiMail.IPPolicy.antispam_profile | String | The name of an outgoing anti-spam profile, if any, that this policy apply. |
| FortiMail.IPPolicy.antivirus_profile | String | The name of an antivirus profile, if any, that this policy will apply. |
| FortiMail.IPPolicy.content_profile | String | The name of the content profile that you want to apply to connections matching the policy. |
| FortiMail.IPPolicy.ip_pool_profile | String | The name of the content profile that you want to apply to connections matching the policy. |
| FortiMail.IPPolicy.auth_type | String | The type of the authentication profile that this policy will apply. If you want the email user to authenticate using an external authentication server, select the authentication type of the profile (SMTP, POP3, IMAP, RADIUS, or LDAP). |
| FortiMail.IPPolicy.smtp_auth | String | The authentication profile when auth_type=SMTP. |
| FortiMail.IPPolicy.imap_auth | String | The authentication profile when auth_type=IMAP. |
| FortiMail.IPPolicy.pop3_auth | String | The authentication profile when auth_type=POP3. |
| FortiMail.IPPolicy.ldap_auth | String | The authentication profile when auth_type=LDAP. |
| FortiMail.IPPolicy.radius_auth | String | The authentication profile when auth_type=RADIUS. |
| FortiMail.IPPolicy.use_smtp_auth | String | Whether to authenticate SMTP connections using the authentication profile configured in sensitive-data. |
| FortiMail.IPPolicy.smtp_different | String | 'Whether to require that the sender uses the same identity for: authentication name, SMTP envelope MAIL FROM:, and header FROM:.' |
| FortiMail.IPPolicy.smtp_diff_identity_ldap | String | Whether to verify SMTP sender identity with LDAP for authenticated email. |
| FortiMail.IPPolicy.smtp_diff_identity_ldap_profile | String | LDAP profile for SMTP sender identity verification. |
| FortiMail.IPPolicy.exclusive | Boolean | Whether to take precedence over recipient-based policy match. |
| FortiMail.IPPolicy.mkey | Number | The ID of the IP policy. |

#### Command example
```!fortimail-ip-policy-list```
#### Context Example
```json
{
    "FortiMail": {
        "IPPolicy": [
            {
                "antispam_profile": "",
                "antivirus_profile": "",
                "client": "0.0.0.0/0",
                "client_geoip_group": "",
                "client_ip_group": "",
                "client_isdb": "",
                "client_type": "IP/Netmask",
                "comment": "testTal",
                "content_profile": "",
                "exclusive": "disable",
                "imap_auth": "",
                "ip_pool_profile": "",
                "ldap_auth": "",
                "mkey": 1,
                "pop3_auth": "",
                "profile_dlp": "",
                "radius_auth": "",
                "server": "0.0.0.0/0",
                "server_ip_group": "",
                "session_profile": "",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam_profile": "",
                "antivirus_profile": "",
                "client": "0.0.0.0/0",
                "client_geoip_group": "",
                "client_ip_group": "",
                "client_isdb": "",
                "client_type": "IP/Netmask",
                "comment": "",
                "content_profile": "",
                "exclusive": "disable",
                "imap_auth": "",
                "ip_pool_profile": "",
                "ldap_auth": "",
                "mkey": 3,
                "pop3_auth": "",
                "profile_dlp": "",
                "radius_auth": "",
                "server": "0.0.0.0/0",
                "server_ip_group": "",
                "session_profile": "",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam_profile": "",
                "antivirus_profile": "",
                "client": "0.0.0.0/0",
                "client_geoip_group": "",
                "client_ip_group": "",
                "client_isdb": "",
                "client_type": "IP/Netmask",
                "comment": "test2",
                "content_profile": "",
                "exclusive": "disable",
                "imap_auth": "",
                "ip_pool_profile": "",
                "ldap_auth": "",
                "mkey": 4,
                "pop3_auth": "",
                "profile_dlp": "",
                "radius_auth": "",
                "server": "0.0.0.0/0",
                "server_ip_group": "",
                "session_profile": "",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam_profile": "",
                "antivirus_profile": "",
                "client": "0.0.0.0/0",
                "client_geoip_group": "",
                "client_ip_group": "",
                "client_isdb": "",
                "client_type": "IP/Netmask",
                "comment": "s",
                "content_profile": "",
                "exclusive": "disable",
                "imap_auth": "",
                "ip_pool_profile": "",
                "ldap_auth": "",
                "mkey": 5,
                "pop3_auth": "",
                "profile_dlp": "",
                "radius_auth": "",
                "server": "0.0.0.0/0",
                "server_ip_group": "",
                "session_profile": "",
                "smtp_auth": "",
                "status": "enable"
            }
        ]
    }
}
```

#### Human Readable Output

>### Ip Policy list
>|Name|Comment|Server|Client|Client Type|Status|
>|---|---|---|---|---|---|
>| 1 | testTal | 0.0.0.0/0 | 0.0.0.0/0 | IP/Netmask | enable |
>| 3 |  | 0.0.0.0/0 | 0.0.0.0/0 | IP/Netmask | enable |
>| 4 | test2 | 0.0.0.0/0 | 0.0.0.0/0 | IP/Netmask | enable |
>| 5 | s | 0.0.0.0/0 | 0.0.0.0/0 | IP/Netmask | enable |


### fortimail-access-control-create

***
Create an Access control rule. Access control rules take effect after the FortiMail unit has initiated or received an IP and TCP-level connection at the application layer of the network.

#### Base Command

`fortimail-access-control-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| status | Whether to activate the access rule. Possible values are: enable, disable. Default is enable. | Optional |
| sender_type | The method of the SMTP client attempting to send the email message. Select either User Defined and enter a complete or partial sender email address to match, or select: Internal: Match any email address from a protected domain. External: Match any email address from an unprotected domain. Email Group: Match any email address in the group. If you select this option, in the sender argument insert an email group. LDAP Group: Match any email address in the group. If you select this option, in the sender_ldap_profile argument insert an LDAP profile and in  sender insert an LDAP group name. LDAP Verification: Match any individual email address queried by the LDAP profile. If you select this option, in the sender_ldap_profile argument insert an LDAP profile. Regular Expression: Use regular expression syntax instead of wildcards to specify the pattern. User Defined: Specify the email addresses. The pattern can use wildcards or regular expressions. Possible values are: External, Internal, Email Group, LDAP Group, LDAP Verification, Regular Expression, User Defined. Default is User Defined. | Optional |
| sender | The sender. Relevant when sender_type is not External or Internal. When sender_type = Email Group, insert email group (use fortimail-email-group-list to retrieve all the email groups). When sender_type = LDAP Verification, insert LDAP group (use fortimail-ldap-group-list to retrieve all the LDAP groups). When sender_type= LDAP Group, insert LDAP group (use fortimail-ldap-group-list to retrieve all the LDAP groups). When sender_type = Regular Expression or User Defined, insert a pattern that defines recipient email addresses which match this rule, surrounded in slashes and single quotes (such as \'*\' ). Default is *. | Optional |
| recipient_type | The recipient pattern type. Either select User Defined and enter a complete or partial recipient email address to match, or select: Internal: Match any email address from a protected domain. External: Match any email address from a domain that is not protected. Email Group: Match any email address in the group. If you select this option, in the recipient argument insert an email group. LDAP Group: Match any email address in the group. If you select this option, in the recipient_ldap_profile argument insert an LDAP profile and in the recipient insert an LDAP group name. LDAP Verification: Match any individual email address queried by the LDAP profile. If you select this option, in the recipient_ldap_profile argument insert an LDAP profile. Regular Expression: Use regular expression syntax instead of wildcards to specify the pattern. User Defined: Specify the email addresses. The pattern can use wildcards or regular expressions. Possible values are: External, Internal, Email Group, LDAP Group, LDAP Verification, Regular Expression, User Defined. Default is User Defined. | Optional |
| recipient | The recipient. Relevant when recipient_type is not External or Internal. When recipient_type= Email Group, insert email group (use fortimail-email-group-list to retrieve all the email groups). When recipient_type= LDAP Verification, insert LDAP server. When recipient_type= LDAP Group, insert LDAP group (use fortimail-ldap-group-list to retrieve all the LDAP groups). When recipient_type= Regular Expression or User Defined, insert a pattern that defines recipient email addresses which match this rule, surrounded in slashes and single quotes (such as \'*\' ). Default is *. | Optional |
| sender_ldap_profile | Sender LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when sender_type= LDAP Group. | Optional |
| recipient_ldap_profile | Recipient LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when recipient_type= LDAP Group. | Optional |
| source_type | The method of the SMTP client attempting to send the email message. Possible values are: IP/Netmask, IP Group, GeoIP Group, ISDB. Default is IP/Netmask. | Optional |
| source | When sender_type = IP/Netmask insert the source IP address and netmask of the SMTP client attempting to send the email message. Use the netmask, the portion after the slash (/), to specify the matching subnet. When sender_type = IP Group, insert email group (use fortimail-ip-group-list to retrieve all the IP Groups). When sender_type = GeoIP Group, insert a Geo IP group (use fortimail-geoip-group-list to retrieve all the Geo IP groups)When sender_type = ISDB, insert an ISDB. Default is 0.0.0.0/0. | Optional |
| reverse_dns_pattern | A pattern to compare to the result of a reverse DNS look-up of the source IP address of the SMTP client attempting to send the email message. Default is *. | Optional |
| reverse_dns_pattern_regex | Whether to use regular expression syntax instead of wildcards to specify the reverse DNS pattern. Possible values are: enable, disable. | Optional |
| authentication_status | Authentication status. Indicate whether this rule applies only to messages delivered by clients that have authenticated with the FortiMail unit. any: Match or do not match this access control rule regardless of whether the client has authenticated with the FortiMail unit. authenticated: Match this access control rule only for clients that have authenticated with the FortiMail unit. not-authenticated: Match this access control rule only for clients that have not authenticated with the FortiMail unit. Possible values are: Any, Authenticated, Not Authenticated. Default is Any. | Optional |
| tls_profile | A TLS profile to allow or reject the connection based on whether the communication session attributes match the settings in the TLS profile. If matching, then perform the access control rule action {discard \| receive \| reject \| relay \| safe \| safe-relay}. If not matching, then perform the TLS profile failure action instead. Use fortimail-tls-profile-list to retrieve all the TLS profiles. | Optional |
| action | The delivery action that FortiMail unit will perform for SMTP sessions matching this access control rule. reject: Reject delivery of the email (SMTP reply code 550 Relaying denied).discard: Accept the email (SMTP reply code 250 OK), but then silently delete it and do not deliver it. relay:Accept the email (SMTP reply code 250 OK), regardless of authentication or protected domain. Do not greylist, but continue with remaining anti-spam and other scans. If all scans pass, the email is delivered.safe: Accept the email (SMTP reply code 250 OK) if the sender authenticates or recipient belongs to a protected domain. Greylist, but skip remaining anti-spam scans and but continue with others such as antivirus.Otherwise, if the sender does not authenticate, or the recipient does not belong to a protected domain, then reject delivery of the email (SMTP reply code 554 5.7.1 Relaying denied).In older FortiMail versions, this setting was named bypass.safe-relay: Like safe, except do not greylist.receive: Like relay, except greylist, and require authentication or protected domain.Otherwise, if the sender does not authenticate or the recipient does not belong to a protected domain, then FortiMail rejects (SMTP reply code 554 5.7.1 Relaying denied).Tip: Usually, the receive action is used when you need to apply a TLS profile, but do not want to safelist nor allow outbound, which Relay does. If you do not need to apply a TLS profile, then a rule with this action is often not required because by default, email inbound to protected domains is relayed/proxied. Possible values are: Discard, Receive, Reject, Relay, Safe, Safe &amp; Relay. Default is Reject. | Optional |
| comment | A brief comment for the Access control. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.AccessControl.comment | String | A brief comment for the access control. |
| FortiMail.AccessControl.action | Number | The delivery action that FortiMail unit will perform for SMTP sessions matching this access control rule. |
| FortiMail.AccessControl.tls_profile | String | A TLS profile to allow or reject the connection based on whether the communication session attributes match the settings in the TLS profile. |
| FortiMail.AccessControl.authenticated | Number | Authentication status. Indicate whether this rule applies only to messages delivered by clients that have authenticated with the FortiMail unit. |
| FortiMail.AccessControl.reverse_dns_pattern_regexp | Number | Whether to use a regular expression in the reverse DNS pastern. |
| FortiMail.AccessControl.reverse_dns_pattern | String | Whether to use regular expression syntax instead of wildcards to specify the reverse DNS pattern. |
| FortiMail.AccessControl.sender_ip_group | String | The sender IP group. Relevant when sender_type is IP Group. |
| FortiMail.AccessControl.sender_isdb | String | The sender ISDB. Relevant when sender_type is ISDB. |
| FortiMail.AccessControl.sender_geoip_group | String | The sender Geo IP group. Relevant when sender_type is Geo IP group. |
| FortiMail.AccessControl.sender_ip_mask | String | The sender IP/Netmask. Relevant when sender_type is IP address. |
| FortiMail.AccessControl.sender_ip_type | Number | 'The sender (source) type. Optional values: IP/Netmask,IP Group,GeoIP Group,ISDB.' |
| FortiMail.AccessControl.recipient_pattern_ldap_groupname | String | Recipient pattern. Relevant when recipient_pattern_type is LDAP Group. |
| FortiMail.AccessControl.recipient_pattern_ldap | String | Recipient pattern profile. Relevant when recipient_pattern_type is LDAP Group. |
| FortiMail.AccessControl.recipient_pattern_group | String | Recipient email group. Relevant when recipient_pattern_type is Email Group. |
| FortiMail.AccessControl.recipient_pattern | String | Recipient pattern. Relevant when recipient_pattern_type is Regular Expression or User Defined. |
| FortiMail.AccessControl.recipient_pattern_type | Number | Recipient pattern type. |
| FortiMail.AccessControl.sender_pattern_ldap_groupname | String | Sender pattern. Relevant when sender_pattern_type is LDAP Group. |
| FortiMail.AccessControl.sender_pattern_ldap | String | Sender pattern profile. Relevant when sender_pattern_type is LDAP Group. |
| FortiMail.AccessControl.sender_pattern_group | String | Sender email group. Relevant when sender_pattern_type is Email Group. |
| FortiMail.AccessControl.sender_pattern | String | Sender pattern. Relevant when sender_pattern_type is Regular Expression or User Defined. |
| FortiMail.AccessControl.sender_pattern_type | Number | 'Sender pattern type. Optional values: External,Internal,Email Group, LDAP Group,LDAP Verification,Regular Expression,User Defined.' |
| FortiMail.AccessControl.status | Boolean | Whether the access control is activated. |
| FortiMail.AccessControl.mkey | Number | The ID of the access control. |

#### Command example
```!fortimail-access-control-create status=enable comment=TalTest1```
#### Context Example
```json
{
    "FortiMail": {
        "AccessControl": {
            "action": "Reject",
            "authenticated": "Any",
            "comment": "TalTest1",
            "mkey": 3,
            "recipient_pattern": "*",
            "recipient_pattern_group": "*",
            "recipient_pattern_ldap": "",
            "recipient_pattern_ldap_groupname": "*",
            "recipient_pattern_type": "User Defined",
            "reverse_dns_pattern": "*",
            "reverse_dns_pattern_regexp": 0,
            "sender_geoip_group": "0.0.0.0/0",
            "sender_ip_group": "0.0.0.0/0",
            "sender_ip_mask": "0.0.0.0/0",
            "sender_ip_type": "IP/Netmask",
            "sender_isdb": "0.0.0.0/0",
            "sender_pattern": "*",
            "sender_pattern_group": "*",
            "sender_pattern_ldap": "",
            "sender_pattern_ldap_groupname": "*",
            "sender_pattern_type": "User Defined",
            "status": "enable",
            "tls_profile": ""
        }
    }
}
```

#### Human Readable Output

>### Access Control created successfully
>|Action|Action On Failure|Authenticated|Comment|Name|Recipient Pattern Type|Sender Geo IP Group|Sender Ip Group|Sender Ip Mask|Sender Ip Type|Sender Pattern|Sender Pattern Type|Status|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Reject | Reject | Any | TalTest1 | 3 | User Defined | 0.0.0.0/0 | 0.0.0.0/0 | 0.0.0.0/0 | IP/Netmask | * | User Defined | enable |


### fortimail-access-control-update

***
Update an access control.

#### Base Command

`fortimail-access-control-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| access_control_id | The ID of the access control. | Required |
| status | Whether to activate the access rule. Possible values are: enable, disable. Default is enable. | Optional |
| sender_type | The method of the SMTP client attempting to send the email message. Select either User Defined and enter a complete or partial sender email address to match, or select: Internal: Match any email address from a protected domain. External: Match any email address from an unprotected domain. Email Group: Match any email address in the group. If you select this option, in the sender argument insert an email group. LDAP Group: Match any email address in the group. If you select this option, in the sender_ldap_profile argument insert an LDAP profile and in sender insert an LDAP group name. LDAP Verification: Match any individual email address queried by the LDAP profile. If you select this option, in the sender_ldap_profile argument insert an LDAP profile. Regular Expression: Use regular expression syntax instead of wildcards to specify the pattern. User Defined: Specify the email addresses. The pattern can use wildcards or regular expressions. Possible values are: External, Internal, Email Group, LDAP Group, LDAP Verification, Regular Expression, User Defined. | Optional |
| sender | The sender. Relevant when sender_type is not External or Internal. When sender_type = Email Group, insert email group (use fortimail-email-group-list to retrieve all the email groups). When sender_type = LDAP Verification, insert LDAP group (use fortimail-ldap-group-list to retrieve all the LDAP groups). When sender_type= LDAP Group, insert LDAP group (use fortimail-ldap-group-list to retrieve all the LDAP groups). When sender_type = Regular Expression or User Defined, insert a pattern that defines recipient email addresses which match this rule, surrounded in slashes and single quotes (such as \'*\' ). | Optional |
| recipient_type | The recipient pattern type. Either select User Defined and enter a complete or partial recipient email address to match, or select: Internal: Match any email address from a protected domain. External: Match any email address from a domain that is not protected. Email Group: Match any email address in the group. If you select this option, in the recipient argument insert an email group. LDAP Group: Match any email address in the group. If you select this option, in the recipient_ldap_profile argument insert an LDAP profile and in recipient insert an LDAP group name. LDAP Verification: Match any individual email address queried by the LDAP profile. If you select this option, in the recipient_ldap_profile argument insert an LDAP profile. Regular Expression: Use regular expression syntax instead of wildcards to specify the pattern. User Defined: Specify the email addresses. The pattern can use wildcards or regular expressions. Possible values are: External, Internal, Email Group, LDAP Group, LDAP Verification, Regular Expression, User Defined. | Optional |
| recipient | The recipient. Relevant when recipient_type is not External or Internal. When recipient_type= Email Group, insert email group (use fortimail-email-group-list to retrieve all the email groups). When recipient_type= LDAP Verification, insert LDAP server. When recipient_type= LDAP Group, insert LDAP group (use fortimail-ldap-group-list to retrieve all the LDAP groups). When recipient_type= Regular Expression or User Defined, insert a pattern that defines recipient email addresses which match this rule, surrounded in slashes and single quotes (such as \'*\' ). | Optional |
| sender_ldap_profile | Sender LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when sender_type= LDAP Group. | Optional |
| recipient_ldap_profile | Recipient LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when recipient_type= LDAP Group. | Optional |
| source_type | The method of the SMTP client attempting to send the email message. Possible values are: IP/Netmask, IP Group, GeoIP Group, ISDB. | Optional |
| source | When sender_type = IP/Netmask insert the source IP address and netmask of the SMTP client attempting to send the email message. Use the netmask, the portion after the slash (/), to specify the matching subnet. When sender_type = IP Group, insert email group (use fortimail-ip-group-list to retrieve all the IP Groups). When sender_type = GeoIP Group, insert a Geo IP group. When sender_type = ISDB, insert an ISDB. | Optional |
| reverse_dns_pattern | A pattern to compare to the result of a reverse DNS look-up of the source IP address of the SMTP client attempting to send the email message. | Optional |
| reverse_dns_pattern_regex | Whether to use regular expression syntax instead of wildcards to specify the reverse DNS pattern. Possible values are: enable, disable. | Optional |
| authentication_status | Authentication status. Indicate whether this rule applies only to messages delivered by clients that have authenticated with the FortiMail unit. any: Match or do not match this access control rule regardless of whether the client has authenticated with the FortiMail unit. authenticated: Match this access control rule only for clients that have authenticated with the FortiMail unit. not-authenticated: Match this access control rule only for clients that have not authenticated with the FortiMail unit. Possible values are: Any, Authenticated, Not Authenticated. | Optional |
| tls_profile | A TLS profile to allow or reject the connection based on whether the communication session attributes match the settings in the TLS profile. If matching, then perform the access control rule action {discard \| receive \| reject \| relay \| safe \| safe-relay}. If not matching, then perform the TLS profile failure action instead. Use fortimail-tls-profile-list to retrieve all the TLS profiles. | Optional |
| action | The delivery action that FortiMail unit will perform for SMTP sessions matching this access control rule:reject: Reject delivery of the email (SMTP reply code 550 Relaying denied).discard: Accept the email (SMTP reply code 250 OK), but then silently delete it and do not deliver it.relay:Accept the email (SMTP reply code 250 OK), regardless of authentication or protected domain. Do not greylist, but continue with remaining anti-spam and other scans. If all scans pass, the email is delivered.safe: Accept the email (SMTP reply code 250 OK) if the sender authenticates or recipient belongs to a protected domain. Greylist, but skip remaining anti-spam scans and but continue with others such as antivirus.Otherwise, if the sender does not authenticate, or the recipient does not belong to a protected domain, then reject delivery of the email (SMTP reply code 554 5.7.1 Relaying denied).In older FortiMail versions, this setting was named bypass.safe-relay: Like safe, except do not greylist.receive: Like relay, except greylist, and require authentication or protected domain.Otherwise, if the sender does not authenticate or the recipient does not belong to a protected domain, then FortiMail rejects (SMTP reply code 554 5.7.1 Relaying denied).Tip: Usually, the receive action is used when you need to apply a TLS profile, but do not want to safelist nor allow outbound, which Relay does. If you do not need to apply a TLS profile, then a rule with this action is often not required because by default, email inbound to protected domains is relayed/proxied. Possible values are: Discard, Receive, Reject, Relay, Safe, Safe &amp; Relay. | Optional |
| comment | A brief comment for the Access control. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.AccessControl.comment | String | A brief comment for the access control. |
| FortiMail.AccessControl.action | Number | The delivery action that FortiMail unit will perform for SMTP sessions matching this access control rule. |
| FortiMail.AccessControl.tls_profile | String | A TLS profile to allow or reject the connection based on whether the communication session attributes match the settings in the TLS profile. |
| FortiMail.AccessControl.authenticated | Number | Authentication status. Indicate whether this rule applies only to messages delivered by clients that have authenticated with the FortiMail unit. |
| FortiMail.AccessControl.reverse_dns_pattern_regexp | Number | Whether to use a regular expression in the reverse DNS pastern. |
| FortiMail.AccessControl.reverse_dns_pattern | String | Whether to use regular expression syntax instead of wildcards to specify the reverse DNS pattern. |
| FortiMail.AccessControl.sender_ip_group | String | The sender IP group. Relevant when sender_type is IP Group. |
| FortiMail.AccessControl.sender_isdb | String | The sender ISDB. Relevant when sender_type is ISDB. |
| FortiMail.AccessControl.sender_geoip_group | String | The sender Geo IP group. Relevant when sender_type is Geo IP group. |
| FortiMail.AccessControl.sender_ip_mask | String | The sender IP/Netmask. Relevant when sender_type is IP address. |
| FortiMail.AccessControl.sender_ip_type | Number | 'The sender (source) type. Optional values: IP/Netmask,IP Group,GeoIP Group,ISDB.' |
| FortiMail.AccessControl.recipient_pattern_ldap_groupname | String | Recipient pattern. Relevant when recipient_pattern_type is LDAP Group. |
| FortiMail.AccessControl.recipient_pattern_ldap | String | Recipient pattern profile. Relevant when recipient_pattern_type is LDAP Group. |
| FortiMail.AccessControl.recipient_pattern_group | String | Recipient email group. Relevant when recipient_pattern_type is Email Group. |
| FortiMail.AccessControl.recipient_pattern | String | Recipient pattern. Relevant when recipient_pattern_type is Regular Expression or User Defined. |
| FortiMail.AccessControl.recipient_pattern_type | Number | Recipient pattern type. |
| FortiMail.AccessControl.sender_pattern_ldap_groupname | String | Sender pattern. Relevant when sender_pattern_type is LDAP Group. |
| FortiMail.AccessControl.sender_pattern_ldap | String | Sender pattern profile. Relevant when sender_pattern_type is LDAP Group. |
| FortiMail.AccessControl.sender_pattern_group | String | Sender email group. Relevant when sender_pattern_type is Email Group. |
| FortiMail.AccessControl.sender_pattern | String | Sender pattern. Relevant when sender_pattern_type is Regular Expression or User Defined. |
| FortiMail.AccessControl.sender_pattern_type | Number | 'Sender pattern type. Optional values: External,Internal,Email Group, LDAP Group,LDAP Verification,Regular Expression,User Defined.' |
| FortiMail.AccessControl.status | Boolean | Whether the access control is activated. |
| FortiMail.AccessControl.mkey | Number | The ID of the access control. |

#### Command example
```!fortimail-access-control-update access_control_id=1 comment=test2```
#### Context Example
```json
{
    "FortiMail": {
        "AccessControl": {
            "comment": "test2",
            "mkey": 1,
            "status": "enable"
        }
    }
}
```

#### Human Readable Output

>### Access Control updated successfully
>|Comment|Name|Status|
>|---|---|---|
>| test2 | 1 | enable |


### fortimail-access-control-delete

***
Delete an access control rule.

#### Base Command

`fortimail-access-control-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| access_control_id | The ID of the access rule to remove. Use fortimail-access-control-list to retrieve all the access control. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-access-control-delete access_control_id=19```
#### Context Example
```json
{
    "FortiMail": {
        "AccessControl": {
            "mkey": "19"
        }
    }
}
```

#### Human Readable Output

>Access Control deleted successfully

### fortimail-access-control-move

***
Move an Access control rule location in the rules list. FortiMail units match the policies in sequence, from the top of the list downwards. Therefore, you must put the more specific policies on top of the more generic ones.

#### Base Command

`fortimail-access-control-move`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| access_control_id | The ID of the access control to be moved. Use fortimail-access-control-list to retrieve all the access control. | Required |
| reference_id | The reference ID of the access control rule when moving before/after. | Optional |
| action | The move action. Possible values are: up, down, before, after. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-access-control-move access_control_id=2 action=down```
#### Human Readable Output

>Access Control moved successfully

### fortimail-access-control-list

***
List access control rules. If an ID is given, the command will return the information about the specified access control rule.

#### Base Command

`fortimail-access-control-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| access_control_id | The ID of the IP policy to retrieve. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.AccessControl.comment | String | A brief comment for the access control. |
| FortiMail.AccessControl.action | Number | The delivery action that FortiMail unit will perform for SMTP sessions matching this access control rule. |
| FortiMail.AccessControl.tls_profile | String | A TLS profile to allow or reject the connection based on whether the communication session attributes match the settings in the TLS profile. |
| FortiMail.AccessControl.authenticated | Number | Authentication status. Indicate whether this rule applies only to messages delivered by clients that have authenticated with the FortiMail unit. |
| FortiMail.AccessControl.reverse_dns_pattern_regexp | Number | Whether to use a regular expression in the reverse DNS pastern. |
| FortiMail.AccessControl.reverse_dns_pattern | String | Whether to use regular expression syntax instead of wildcards to specify the reverse DNS pattern. |
| FortiMail.AccessControl.sender_ip_group | String | The sender IP group. Relevant when sender_type is IP Group. |
| FortiMail.AccessControl.sender_isdb | String | The sender ISDB. Relevant when sender_type is ISDB. |
| FortiMail.AccessControl.sender_geoip_group | String | The sender Geo IP group. Relevant when sender_type is Geo IP group. |
| FortiMail.AccessControl.sender_ip_mask | String | The sender IP/Netmask. Relevant when sender_type is IP address. |
| FortiMail.AccessControl.sender_ip_type | Number | 'The sender (source) type. Optional values: IP/Netmask,IP Group,GeoIP Group,ISDB.' |
| FortiMail.AccessControl.recipient_pattern_ldap_groupname | String | Recipient pattern. Relevant when recipient_pattern_type is LDAP Group. |
| FortiMail.AccessControl.recipient_pattern_ldap | String | Recipient pattern profile. Relevant when recipient_pattern_type is LDAP Group. |
| FortiMail.AccessControl.recipient_pattern_group | String | Recipient email group. Relevant when recipient_pattern_type is Email Group. |
| FortiMail.AccessControl.recipient_pattern | String | Recipient pattern. Relevant when recipient_pattern_type is Regular Expression or User Defined. |
| FortiMail.AccessControl.recipient_pattern_type | Number | Recipient pattern type. |
| FortiMail.AccessControl.sender_pattern_ldap_groupname | String | Sender pattern. Relevant when sender_pattern_type is LDAP Group. |
| FortiMail.AccessControl.sender_pattern_ldap | String | Sender pattern profile. Relevant when sender_pattern_type is LDAP Group. |
| FortiMail.AccessControl.sender_pattern_group | String | Sender email group. Relevant when sender_pattern_type is Email Group. |
| FortiMail.AccessControl.sender_pattern | String | Sender pattern. Relevant when sender_pattern_type is Regular Expression or User Defined. |
| FortiMail.AccessControl.sender_pattern_type | Number | 'Sender pattern type. Optional values: External,Internal,Email Group, LDAP Group,LDAP Verification,Regular Expression,User Defined.' |
| FortiMail.AccessControl.status | Boolean | Whether the access control is activated. |
| FortiMail.AccessControl.mkey | Number | The ID of the access control. |

#### Command example
```!fortimail-access-control-list```
#### Context Example
```json
{
    "FortiMail": {
        "AccessControl": [
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "test2",
                "mkey": 1,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "User Defined",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "testTal",
                "mkey": 2,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "User Defined",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "TalTest1",
                "mkey": 3,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "User Defined",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Discard",
                "authenticated": "Any",
                "comment": "s",
                "mkey": 4,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "test",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "LDAP Verification",
                "reverse_dns_pattern": "*2323",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "test",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP Group",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "Regular Expression",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Discard",
                "authenticated": "Authenticated",
                "comment": "action 1",
                "mkey": 5,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "test",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*2323",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "Test_3",
                "sender_ip_group": "test",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "GeoIP Group",
                "sender_isdb": "8X8",
                "sender_pattern": "*",
                "sender_pattern_group": "new_version3242342.0",
                "sender_pattern_ldap": "tal",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "LDAP Group",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "",
                "mkey": 6,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "User Defined",
                "status": "disable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "",
                "mkey": 7,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "User Defined",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Discard",
                "authenticated": "Any",
                "comment": "",
                "mkey": 8,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "User Defined",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Discard",
                "authenticated": "Any",
                "comment": "",
                "mkey": 9,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "External",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "User Defined",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Discard",
                "authenticated": "Any",
                "comment": "Tal",
                "mkey": 10,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "Internal",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "User Defined",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "Test",
                "mkey": 11,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "User Defined",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "Test",
                "mkey": 12,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "new_version3242342.0",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "Email Group",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "Test",
                "mkey": 13,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "test",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "LDAP Group",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "Test",
                "mkey": 14,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "test",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "LDAP Verification",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "Test",
                "mkey": 15,
                "recipient_pattern": "*",
                "recipient_pattern_group": "new_version3242342.0",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "Email Group",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "test",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "LDAP Verification",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "Tesffft",
                "mkey": 16,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "test",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "LDAP Verification",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "Tt",
                "mkey": 17,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "test",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "LDAP Verification",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Safe & Relay",
                "authenticated": "Any",
                "comment": "action 1",
                "mkey": 18,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "test",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "LDAP Verification",
                "reverse_dns_pattern": "*2323",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "test",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP Group",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "test",
                "sender_pattern_ldap_groupname": "ttt",
                "sender_pattern_type": "LDAP Group",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Reject",
                "authenticated": "Any",
                "comment": "Talll",
                "mkey": 20,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "User Defined",
                "reverse_dns_pattern": "*",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP/Netmask",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "test",
                "sender_pattern_ldap_groupname": "test_group",
                "sender_pattern_type": "LDAP Group",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Safe & Relay",
                "authenticated": "Any",
                "comment": "action 1",
                "mkey": 21,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "test",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "LDAP Verification",
                "reverse_dns_pattern": "*2323",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "test",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP Group",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "test",
                "sender_pattern_ldap": "",
                "sender_pattern_ldap_groupname": "",
                "sender_pattern_type": "Email Group",
                "status": "enable",
                "tls_profile": ""
            },
            {
                "action": "Safe & Relay",
                "authenticated": "Any",
                "comment": "action 33331",
                "mkey": 23,
                "recipient_pattern": "*",
                "recipient_pattern_group": "",
                "recipient_pattern_ldap": "test",
                "recipient_pattern_ldap_groupname": "",
                "recipient_pattern_type": "LDAP Verification",
                "reverse_dns_pattern": "*2323",
                "reverse_dns_pattern_regexp": 0,
                "sender_geoip_group": "",
                "sender_ip_group": "test",
                "sender_ip_mask": "0.0.0.0/0",
                "sender_ip_type": "IP Group",
                "sender_isdb": "",
                "sender_pattern": "*",
                "sender_pattern_group": "",
                "sender_pattern_ldap": "test",
                "sender_pattern_ldap_groupname": "ttt",
                "sender_pattern_type": "LDAP Group",
                "status": "enable",
                "tls_profile": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### Access Control list
>|Name|Comment|Action On Failure|Status|Action|Authenticated|Sender Pattern|Sender Pattern Type|Sender Ip Type|Sender Ip Group|Sender Ip Mask|Sender Geo IP Group|Recipient Pattern Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1 | test2 | Reject | enable | Reject | Any | * | User Defined | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 2 | testTal | Reject | enable | Reject | Any | * | User Defined | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 3 | TalTest1 | Reject | enable | Reject | Any | * | User Defined | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 4 | s | Discard | enable | Discard | Any | * | Regular Expression | IP Group | test | 0.0.0.0/0 |  | LDAP Verification |
>| 5 | action 1 | Discard | enable | Discard | Authenticated | * | LDAP Group | GeoIP Group | test | 0.0.0.0/0 | Test_3 | User Defined |
>| 6 |  | Reject | disable | Reject | Any | * | User Defined | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 7 |  | Reject | enable | Reject | Any | * | User Defined | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 8 |  | Discard | enable | Discard | Any | * | User Defined | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 9 |  | Discard | enable | Discard | Any | * | User Defined | IP/Netmask |  | 0.0.0.0/0 |  | External |
>| 10 | Tal | Discard | enable | Discard | Any | * | User Defined | IP/Netmask |  | 0.0.0.0/0 |  | Internal |
>| 11 | Test | Reject | enable | Reject | Any | * | User Defined | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 12 | Test | Reject | enable | Reject | Any | * | Email Group | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 13 | Test | Reject | enable | Reject | Any | * | LDAP Group | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 14 | Test | Reject | enable | Reject | Any | * | LDAP Verification | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 15 | Test | Reject | enable | Reject | Any | * | LDAP Verification | IP/Netmask |  | 0.0.0.0/0 |  | Email Group |
>| 16 | Tesffft | Reject | enable | Reject | Any | * | LDAP Verification | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 17 | Tt | Reject | enable | Reject | Any | * | LDAP Verification | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 18 | action 1 | Safe & Relay | enable | Safe & Relay | Any | * | LDAP Group | IP Group | test | 0.0.0.0/0 |  | LDAP Verification |
>| 20 | Talll | Reject | enable | Reject | Any | * | LDAP Group | IP/Netmask |  | 0.0.0.0/0 |  | User Defined |
>| 21 | action 1 | Safe & Relay | enable | Safe & Relay | Any | * | Email Group | IP Group | test | 0.0.0.0/0 |  | LDAP Verification |
>| 23 | action 33331 | Safe & Relay | enable | Safe & Relay | Any | * | LDAP Group | IP Group | test | 0.0.0.0/0 |  | LDAP Verification |


### fortimail-recipient-policy-create

***
Create an Inbound/ Outbound Recipient policy. Recipient policies control email based on sender and recipient addresses. Recipient-based policies have precedence if an IP-based policy is also applicable but conflicts.

#### Base Command

`fortimail-recipient-policy-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The mail traffic direction. Possible values are: Inbound, Outbound. Default is Inbound. | Optional |
| status | Whether to apply the policy. Possible values are: enable, disable. Default is enable. | Optional |
| comment | A brief comment for the IP policy. | Optional |
| sender_type | Define sender (MAIL FROM:) email addresses that match this policy. If you enter LDAP group, also configure sender_ldap_profile by entering an LDAP profile in which you have enabled and configured a group query. If you enter Email address group, also configure sender_email_address_group by entering an Email group in which you have enabled and configured a group query. Possible values are: User (wildcard), User (regex), LDAP group, Email address group. | Optional |
| sender_pattern | The policy sender pattern. When sender_type is User (wildcard), insert email addresses that match this policy. For example, test@test.com. When sender_type is User (regex), insert the recipient email address regular expression pattern. When sender_type is LDAP group, insert the sender pattern. When sender_type is Email address group, insert email group (use fortimail-email-group-list to retrieve all the email groups). | Optional |
| sender_ldap_profile | Sender LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when sender_type=LDAP Group. | Optional |
| sender_email_address_group | Sender Email group (use fortimail-email-group-list to retrieve all the Email groups). Relevant when recipient_type=Email address group. | Optional |
| recipient_type | Define recipient (RCPT TO:) email addresses that match this policy. If you enter LDAP group, also configure recipient_ldap_profile by entering an LDAP profile in which you have enabled and configured a group query. If you enter Email address group, also configure recipient_email_address_group by entering an Email group in which you have enabled and configured a group query. Possible values are: User (wildcard), User (regex), LDAP group, Email address group. | Optional |
| recipient_pattern | The policy recipient pattern. When recipient_type is User (wildcard), insert the local part of recipient email address to define recipient (RCPT TO:) email addresses that match this policy and after insert @ and the  domain part of recipient email address to define recipient (RCPT TO:) email addresses that match this policy. For example, test@test.com. When recipient_type is User (regex), insert the recipient email address regular expression pattern. When recipient_type is LDAP group, insert the sender pattern. When recipient_type is Email address group, insert email group (use fortimail-email-group-list to retrieve all the email groups). | Optional |
| recipient_ldap_profile | Recipient LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when recipient_type= LDAP Group. | Optional |
| recipient_email_address_group | Recipient Email group (use fortimail-email-group-list to retrieve all the Email groups). Relevant when recipient_type=Email address group. | Optional |
| antispam_profile | The name of an outgoing anti-spam profile, if any, that this policy will apply. Use fortimail-antispam-profile-list to retrieve all the anti-spam profiles. | Optional |
| antivirus_profile | The name of an antivirus profile, if any, that this policy will apply. Use fortimail-antivirus-profile-list to retrieve all the antivirus profiles. | Optional |
| content_profile | The name of the content profile that you want to apply to connections matching the policy. Use fortimail-content-profile-list to retrieve all the content profiles. | Optional |
| resource_profile | The name of the resource profile that you want to apply to connections matching the policy. Use fortimail-resource-profile to retrieve all the resources. | Required |
| auth_type | The type of the authentication profile that this policy will apply. Possible values are: imap, ldap, pop3, radius, smpt. | Optional |
| auth_profile | The name of an authentication profile for the type. When auth_type is LDAP, insert LDAP authentication profile. Use fortimail-ldap-group-list to retrieve all the LDAP authentication profiles. When auth_type is RADIUS, insert RADIUS authentication profile. Use fortimail-radius-auth-profile to retrieve all the RADIUS authentication profiles. When auth_type is POP3, insert POP3 authentication profile. Use fortimail-pop3-auth-profile to retrieve all the POP3 authentication profiles. When auth_type is IMAP, insert IMAP authentication profile. Use fortimail-imap-auth-profile to retrieve all the IMAP authentication profiles. When auth_type is SMTP, insert SMTP authentication profile. Use fortimail-smtp-auth-profile to retrieve all the SMTP authentication profiles. Relevant when auth_type is chosen. | Optional |
| use_smtp_auth | Whether to authenticate SMTP connections using the authentication profile configured in sensitive-data. Possible values are: enable, disable. Default is disable. | Optional |
| smtp_different | Whether to reject different SMTP sender identity for authenticated user. Possible values are: enable, disable. Default is disable. | Optional |
| smtp_diff_identity_ldap | Whether to verify SMTP sender identity with LDAP for authenticated email. Possible values are: enable, disable. Default is disable. | Optional |
| smtp_diff_identity_ldap_profile | LDAP profile for SMTP sender identity verification. | Optional |
| enable_pki | Whether to allow email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. Possible values are: enable, disable. Default is disable. | Optional |
| pki_profile | The name of a PKI user. Relevant when enable_pki is enable. Use fortimail-pki-user-list to retrieve all the PKI users. | Optional |
| certificate_validation | Whether to require valid certificates only and disallow password-style fallback. If the email user’s web browser does not provide a valid personal certificate, the FortiMail unit will fall back to standard user name and password-style authentication. Possible values are: enable, disable. Default is disable. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.RecipientPolicy.comment | String | A brief comment for the IP policy. |
| FortiMail.RecipientPolicy.mkey | Number | The ID of the recipient policy. |
| FortiMail.RecipientPolicy.direction | String | 'The type of the recipient policy. 1: Inbound, 2: Outbound.' |
| FortiMail.RecipientPolicy.sender_type | String | 'Define sender (MAIL FROM:) email addresses that match this policy. 0: User (wildcard), 2: LDAP group, 3: Email address group, 4: User(regex).' |
| FortiMail.RecipientPolicy.sender_pattern | String | The local part of sender email address to define sender (MAIL FROM:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.sender_domain | String | The domain part of sender email address to define sender (MAIL FROM:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.sender_ldap_profile | String | Sender LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when recipient_type= LDAP Group. |
| FortiMail.RecipientPolicy.sender_email_address_group | String | The sender email group (use fortimail-email-group-list to retrieve all the email groups). |
| FortiMail.RecipientPolicy.sender_pattern_regex | String | The sender email address regular expression pattern. |
| FortiMail.RecipientPolicy.groupmode | String | 'Define recipient (RCPT TO:) email addresses that match this policy. 0: User (wildcard), 2: LDAP group, 3: Email address group, 4: User(regex).' |
| FortiMail.RecipientPolicy.recipient_pattern | String | The local part of recipient email address to define recipient (RCPT TO:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.recipient_domain | String | The domain part of recipient email address to define recipient (RCPT TO:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.ldap_profile | String | Recipient LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when recipient_type= LDAP Group. |
| FortiMail.RecipientPolicy.recipient_email_address_group | String | The recipient email group (use fortimail-email-group-list to retrieve all the email groups). |
| FortiMail.RecipientPolicy.recipient_pattern_regex | String | The recipient email address regular expression pattern. |
| FortiMail.RecipientPolicy.antispam | String | The name of an outgoing anti-spam profile, if any, that this policy will apply. Use fortimail-antispam-profile-list to retrieve all the anti-spam profiles. |
| FortiMail.RecipientPolicy.content | String | The name of the content profile that you want to apply to connections matching the policy. Use fortimail-content-profile-list to retrieve all the content profiles. |
| FortiMail.RecipientPolicy.profile_dlp | String | The name of the resource profile that you want to apply to connections matching the policy. Use fortimail-resource-profile to retrieve all the resources. |
| FortiMail.RecipientPolicy.antivirus | String | The name of an antivirus profile, if any, that this policy will apply. Use fortimail-antivirus-profile-list to retrieve all the antivirus profiles. |
| FortiMail.RecipientPolicy.misc | String | The type of the authentication profile that this policy apply. |
| FortiMail.RecipientPolicy.auth | String | RADIUS authentication profile. Use fortimail-radius-auth-profile to retrieve all the RADIUS authentication profiles. |
| FortiMail.RecipientPolicy.radius_auth | String | LDAP authentication profile. Use fortimail-ldap-group-list to retrieve all the LDAP authentication profiles. |
| FortiMail.RecipientPolicy.ldap_auth | String | POP3 authentication profile. Use fortimail-pop3-auth-profile to retrieve all the POP3 authentication profiles. |
| FortiMail.RecipientPolicy.pop3_auth | String | IMAP authentication profile. Use fortimail-imap-auth-profile to retrieve all the IMAP authentication profiles. |
| FortiMail.RecipientPolicy.imap_auth | String | SMTP authentication profile. Use fortimail-smtp-auth-profile to retrieve all the SMTP authentication profiles. |
| FortiMail.RecipientPolicy.smtp_auth | String | Whether the policy allows email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. |
| FortiMail.RecipientPolicy.pkiauth | String | Whether to allow email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. |
| FortiMail.RecipientPolicy.pkiuser | String | The name of a PKI user. Relevant when enable_pki is enable. |
| FortiMail.RecipientPolicy.auth_allow_smtp | String | Whether to authenticate SMTP connections using the authentication profile configured in sensitive-data. |
| FortiMail.RecipientPolicy.smtp_diff_identity | String | Whether to reject different SMTP sender identity for authenticated user. |
| FortiMail.RecipientPolicy.smtp_diff_identity_ldap | String | Whether to verify SMTP sender identity with LDAP for authenticated email. |
| FortiMail.RecipientPolicy.smtp_diff_identity_ldap_profile | String | LDAP profile for SMTP sender identity verification. |
| FortiMail.RecipientPolicy.certificate_required | String | Whether to allow email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. |

#### Command example
```!fortimail-recipient-policy-create comment=TalTest1 resource_profile=Res_Default```
#### Context Example
```json
{
    "FortiMail": {
        "RecipientPolicy": {
            "antispam": "",
            "antivirus": "",
            "comment": "TalTest1",
            "content": "",
            "direction": "Inbound",
            "groupmode": 0,
            "imap_auth": "",
            "ldap_auth": "",
            "ldap_profile": "",
            "misc": "Res_Default",
            "mkey": 15,
            "pkiauth": "disable",
            "pkiuser": "",
            "pop3_auth": "",
            "profile_dlp": "",
            "profile_user_import_recipient": "",
            "profile_user_import_sender": "",
            "radius_auth": "",
            "recipient_domain": "*",
            "recipient_email_address_group": "",
            "recipient_import_attribute_name": "",
            "recipient_import_attribute_value": "",
            "recipient_pattern": "*",
            "recipient_pattern_regex": ".*",
            "sender_domain": "*",
            "sender_email_address_group": "",
            "sender_import_attribute_name": "",
            "sender_import_attribute_value": "",
            "sender_ldap_profile": "",
            "sender_pattern": "*",
            "sender_pattern_regex": ".*",
            "sender_type": "User (wildcard)",
            "smtp_auth": "",
            "smtp_diff_identity_ldap": "disable",
            "smtp_diff_identity_ldap_profile": "",
            "status": "enable"
        }
    }
}
```

#### Human Readable Output

>### Recipient Policy created successfully
>|Comment|Direction|Name|PKI Auth|Recipient Pattern Regex|Resource Profile|Sender Pattern|Sender Type|Status|
>|---|---|---|---|---|---|---|---|---|
>| TalTest1 | Inbound | 15 | disable | .* | Res_Default | * | User (wildcard) | enable |


### fortimail-recipient-policy-update

***
Update a recipient policy.

#### Base Command

`fortimail-recipient-policy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| recipient_policy_id | The ID of the recipient policy. | Required |
| type | The mail traffic direction. Possible values are: Inbound, Outbound. | Optional |
| status | Whether to apply the policy. Possible values are: enable, disable. Default is enable. | Optional |
| comment | A brief comment for the IP policy. | Optional |
| sender_type | Define sender (MAIL FROM:) email addresses that match this policy. If you enter LDAP group, also configure sender_ldap_profile by entering an LDAP profile in which you have enabled and configured a group query. If you enter Email address group, also configure sender_email_address_group by entering an Email group in which you have enabled and configured a group query. Possible values are: User (wildcard), User (regex), LDAP group, Email address group. | Optional |
| sender_pattern | The policy sender pattern. When sender_type is User (wildcard), insert email addresses that match this policy. For example, test@test.com. When sender_type is User (regex), insert the recipient email address regular expression pattern. When sender_type is LDAP group, insert the sender pattern. When sender_type is Email address group, insert email group (use fortimail-email-group-list to retrieve all the email groups). | Optional |
| sender_ldap_profile | Sender LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when sender_type= LDAP Group. | Optional |
| sender_email_address_group | Sender Email group (use fortimail-email-group-list to retrieve all the Email groups). Relevant when recipient_type=Email address group. | Optional |
| recipient_type | Define recipient (RCPT TO:) email addresses that match this policy. If you enter LDAP group, also configure recipient_ldap_profile by entering an LDAP profile in which you have enabled and configured a group query. If you enter Email address group, also configure recipient_email_address_group by entering an Email group in which you have enabled and configured a group query. Possible values are: User (wildcard), User (regex), LDAP group, Email address group. | Optional |
| recipient_pattern | The policy recipient pattern. When recipient_type is User (wildcard), insert the local part of recipient email address to define recipient (RCPT TO:) email addresses that match this policy and after insert @ and the  domain part of recipient email address to define recipient (RCPT TO:) email addresses that match this policy. For example, test@test.com. When recipient_type is User (regex), insert the recipient email address regular expression pattern. When recipient_type is LDAP group, insert the sender pattern. When recipient_type is Email address group, insert email group (use fortimail-email-group-list to retrieve all the email groups). | Optional |
| recipient_ldap_profile | Recipient LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when recipient_type= LDAP Group. | Optional |
| recipient_email_address_group | Recipient Email group (use fortimail-email-group-list to retrieve all the Email groups). Relevant when recipient_type=Email address group. | Optional |
| antispam_profile | The name of an outgoing anti-spam profile, if any, that this policy will apply. Use fortimail-antispam-profile-list to retrieve all the anti-spam profiles. | Optional |
| antivirus_profile | The name of an antivirus profile, if any, that this policy will apply. Use fortimail-antivirus-profile-list to retrieve all the antivirus profiles. | Optional |
| content_profile | The name of the content profile that you want to apply to connections matching the policy. Use fortimail-content-profile-list to retrieve all the content profiles. | Optional |
| resource_profile | The name of the resource profile that you want to apply to connections matching the policy. Use fortimail-resource-profile to retrieve all the resources. | Optional |
| auth_type | The type of the authentication profile that this policy will apply. Possible values are: imap, ldap, pop3, radius, smpt. | Optional |
| auth_profile | The name of an authentication profile for the type. When auth_type is LDAP, insert LDAP authentication profile. Use fortimail-ldap-group-list to retrieve all the LDAP authentication profiles. When auth_type is RADIUS, insert RADIUS authentication profile. Use fortimail-radius-auth-profile to retrieve all the RADIUS authentication profiles. When auth_type is POP3, insert POP3 authentication profile. Use fortimail-pop3-auth-profile to retrieve all the POP3 authentication profiles. When auth_type is IMAP, insert IMAP authentication profile. Use fortimail-imap-auth-profile to retrieve all the IMAP authentication profiles. When auth_type is SMTP, insert SMTP authentication profile. Use fortimail-smtp-auth-profile to retrieve all the SMTP authentication profiles. Relevant when auth_type is chosen. | Optional |
| use_smtp_auth | Whether to authenticate SMTP connections using the authentication profile configured in sensitive-data. Possible values are: enable, disable. | Optional |
| smtp_different | Whether to reject different SMTP sender identity for authenticated user. Possible values are: enable, disable. | Optional |
| smtp_diff_identity_ldap | Whether to verify SMTP sender identity with LDAP for authenticated email. Possible values are: enable, disable. | Optional |
| smtp_diff_identity_ldap_profile | LDAP profile for SMTP sender identity verification. | Optional |
| enable_pki | Whether to allow email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. Possible values are: enable, disable. | Optional |
| pki_profile | The name of a PKI user. Relevant when enable_pki is enable. Use fortimail-pki-user-list to retrieve all the PKI users. | Optional |
| certificate_validation | Whether to require valid certificates only and disallow password-style fallback. If the email user’s web browser does not provide a valid personal certificate, the FortiMail unit will fall back to standard user name and password-style authentication. Possible values are: enable, disable. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.RecipientPolicy.comment | String | A brief comment for the IP policy. |
| FortiMail.RecipientPolicy.mkey | Number | The ID of the recipient policy. |
| FortiMail.RecipientPolicy.direction | String | 'The type of the recipient policy. 1: Inbound, 2: Outbound.' |
| FortiMail.RecipientPolicy.sender_type | String | 'Define sender (MAIL FROM:) email addresses that match this policy. 0: User (wildcard), 2: LDAP group, 3:Email address group, 4: User(regex).' |
| FortiMail.RecipientPolicy.sender_pattern | String | The local part of sender email address to define sender (MAIL FROM:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.sender_domain | String | The domain part of sender email address to define sender (MAIL FROM:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.sender_ldap_profile | String | Sender LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when recipient_type= LDAP Group. |
| FortiMail.RecipientPolicy.sender_email_address_group | String | The sender email group (use fortimail-email-group-list to retrieve all the email groups). |
| FortiMail.RecipientPolicy.sender_pattern_regex | String | The sender email address regular expression pattern. |
| FortiMail.RecipientPolicy.groupmode | String | 'Define recipient (RCPT TO:) email addresses that match this policy. 0: User (wildcard), 2: LDAP group, 3:Email address group, 4: User(regex).' |
| FortiMail.RecipientPolicy.recipient_pattern | String | The local part of recipient email address to define recipient (RCPT TO:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.recipient_domain | String | The domain part of recipient email address to define recipient (RCPT TO:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.ldap_profile | String | Recipient LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when recipient_type= LDAP Group. |
| FortiMail.RecipientPolicy.recipient_email_address_group | String | The recipient email group (use fortimail-email-group-list to retrieve all the email groups). |
| FortiMail.RecipientPolicy.recipient_pattern_regex | String | The recipient email address regular expression pattern. |
| FortiMail.RecipientPolicy.antispam | String | The name of an outgoing anti-spam profile, if any, that this policy will apply. Use fortimail-antispam-profile-list to retrieve all the anti-spam profiles. |
| FortiMail.RecipientPolicy.content | String | The name of the content profile that you want to apply to connections matching the policy. Use fortimail-content-profile-list to retrieve all the content profiles. |
| FortiMail.RecipientPolicy.profile_dlp | String | The name of the resource profile that you want to apply to connections matching the policy. Use fortimail-resource-profile to retrieve all the resources. |
| FortiMail.RecipientPolicy.antivirus | String | The name of an antivirus profile, if any, that this policy will apply. Use fortimail-antivirus-profile-list to retrieve all the antivirus profiles. |
| FortiMail.RecipientPolicy.misc | String | The type of the authentication profile that this policy apply. |
| FortiMail.RecipientPolicy.auth | String | RADIUS authentication profile. Use fortimail-radius-auth-profile to retrieve all the RADIUS authentication profiles. |
| FortiMail.RecipientPolicy.radius_auth | String | LDAP authentication profile. Use fortimail-ldap-group-list to retrieve all the LDAP authentication profiles. |
| FortiMail.RecipientPolicy.ldap_auth | String | POP3 authentication profile. Use fortimail-pop3-auth-profile to retrieve all the POP3 authentication profiles. |
| FortiMail.RecipientPolicy.pop3_auth | String | IMAP authentication profile. Use fortimail-imap-auth-profile to retrieve all the IMAP authentication profiles. |
| FortiMail.RecipientPolicy.imap_auth | String | SMTP authentication profile. Use fortimail-smtp-auth-profile to retrieve all the SMTP authentication profiles. |
| FortiMail.RecipientPolicy.smtp_auth | String | Whether the policy allows email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. |
| FortiMail.RecipientPolicy.pkiauth | String | Whether to allow email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. |
| FortiMail.RecipientPolicy.pkiuser | String | The name of a PKI user. Relevant when enable_pki is enable. |
| FortiMail.RecipientPolicy.auth_allow_smtp | String | Whether to authenticate SMTP connections using the authentication profile configured in sensitive-data. |
| FortiMail.RecipientPolicy.smtp_diff_identity | String | Whether to reject different SMTP sender identity for authenticated user. |
| FortiMail.RecipientPolicy.smtp_diff_identity_ldap | String | Whether to verify SMTP sender identity with LDAP for authenticated email. |
| FortiMail.RecipientPolicy.smtp_diff_identity_ldap_profile | String | LDAP profile for SMTP sender identity verification. |
| FortiMail.RecipientPolicy.certificate_required | String | Whether to allow email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. |

#### Command example
```!fortimail-recipient-policy-update recipient_policy_id=1 comment=test2```
#### Context Example
```json
{
    "FortiMail": {
        "RecipientPolicy": {
            "comment": "test2",
            "mkey": 1,
            "status": "enable"
        }
    }
}
```

#### Human Readable Output

>### Recipient Policy updated successfully
>|Comment|Name|Status|
>|---|---|---|
>| test2 | 1 | enable |


### fortimail-recipient-policy-delete

***
Delete a recipient policy.

#### Base Command

`fortimail-recipient-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| recipient_policy_id | The ID of the recipient policy to be remove. Use fortimail-recipient-policy-list to retrieve all the recipient policies. | Required |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-recipient-policy-delete recipient_policy_id=14```
#### Context Example
```json
{
    "FortiMail": {
        "RecipientPolicy": {
            "mkey": "14"
        }
    }
}
```

#### Human Readable Output

>Recipient Policy deleted successfully

### fortimail-recipient-policy-move

***
Move a recipient policy location in the policy list. FortiMail units match the policies in sequence, from the top of the list downwards. Therefore, you must put the more specific policies on top of the more generic ones.

#### Base Command

`fortimail-recipient-policy-move`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| recipient_policy_id | The ID of the recipient policy to be moved. Use fortimail-recipient-policy-list to retrieve all the recipient policies. | Required |
| reference_id | The reference ID of the access control rule when moving before/after. | Optional |
| action | The move action. Possible values are: up, down, before, after. | Optional |

#### Context Output

There is no context output for this command.
#### Command example
```!fortimail-recipient-policy-move recipient_policy_id=1 reference_id=5 action=after```
#### Human Readable Output

>Recipient Policy moved successfully

### fortimail-recipient-policy-list

***
List recipient policies. If an ID is given, the command will return the information about the specified recipient policy.

#### Base Command

`fortimail-recipient-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| recipient_policy_id | The ID of the recipient policy. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.RecipientPolicy.comment | String | A brief comment for the IP policy. |
| FortiMail.RecipientPolicy.mkey | Number | The ID of the recipient policy. |
| FortiMail.RecipientPolicy.direction | String | 'The type of the recipient policy. 1: Inbound, 2: Outbound.' |
| FortiMail.RecipientPolicy.sender_type | String | 'Define sender (MAIL FROM:) email addresses that match this policy. 0: User (wildcard), 2: LDAP group, 3:Email address group, 4: User(regex).' |
| FortiMail.RecipientPolicy.sender_pattern | String | The local part of sender email address to define sender (MAIL FROM:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.sender_domain | String | The domain part of sender email address to define sender (MAIL FROM:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.sender_ldap_profile | String | Sender LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when recipient_type= LDAP Group. |
| FortiMail.RecipientPolicy.sender_email_address_group | String | The sender email group (use fortimail-email-group-list to retrieve all the email groups). |
| FortiMail.RecipientPolicy.sender_pattern_regex | String | The sender email address regular expression pattern. |
| FortiMail.RecipientPolicy.groupmode | String | 'Define recipient (RCPT TO:) email addresses that match this policy. 0: User (wildcard), 2: LDAP group, 3:Email address group, 4: User(regex).' |
| FortiMail.RecipientPolicy.recipient_pattern | String | The local part of recipient email address to define recipient (RCPT TO:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.recipient_domain | String | The domain part of recipient email address to define recipient (RCPT TO:) email addresses that match this policy. |
| FortiMail.RecipientPolicy.ldap_profile | String | Recipient LDAP profile (use fortimail-ldap-group-list to retrieve all the LDAP profiles). Relevant when recipient_type= LDAP Group. |
| FortiMail.RecipientPolicy.recipient_email_address_group | String | The recipient email group (use fortimail-email-group-list to retrieve all the email groups). |
| FortiMail.RecipientPolicy.recipient_pattern_regex | String | The recipient email address regular expression pattern. |
| FortiMail.RecipientPolicy.antispam | String | The name of an outgoing anti-spam profile, if any, that this policy will apply. Use fortimail-antispam-profile-list to retrieve all the anti-spam profiles. |
| FortiMail.RecipientPolicy.content | String | The name of the content profile that you want to apply to connections matching the policy. Use fortimail-content-profile-list to retrieve all the content profiles. |
| FortiMail.RecipientPolicy.profile_dlp | String | The name of the resource profile that you want to apply to connections matching the policy. Use fortimail-resource-profile to retrieve all the resources. |
| FortiMail.RecipientPolicy.antivirus | String | The name of an antivirus profile, if any, that this policy will apply. Use fortimail-antivirus-profile-list to retrieve all the antivirus profiles. |
| FortiMail.RecipientPolicy.misc | String | The type of the authentication profile that this policy apply. |
| FortiMail.RecipientPolicy.auth | String | RADIUS authentication profile. Use fortimail-radius-auth-profile to retrieve all the RADIUS authentication profiles. |
| FortiMail.RecipientPolicy.radius_auth | String | LDAP authentication profile. Use fortimail-ldap-group-list to retrieve all the LDAP authentication profiles. |
| FortiMail.RecipientPolicy.ldap_auth | String | POP3 authentication profile. Use fortimail-pop3-auth-profile to retrieve all the POP3 authentication profiles. |
| FortiMail.RecipientPolicy.pop3_auth | String | IMAP authentication profile. Use fortimail-imap-auth-profile to retrieve all the IMAP authentication profiles. |
| FortiMail.RecipientPolicy.imap_auth | String | SMTP authentication profile. Use fortimail-smtp-auth-profile to retrieve all the SMTP authentication profiles. |
| FortiMail.RecipientPolicy.smtp_auth | String | Whether the policy allows email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. |
| FortiMail.RecipientPolicy.pkiauth | String | Whether to allow email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. |
| FortiMail.RecipientPolicy.pkiuser | String | The name of a PKI user. Relevant when enable_pki is enable. |
| FortiMail.RecipientPolicy.auth_allow_smtp | String | Whether to authenticate SMTP connections using the authentication profile configured in sensitive-data. |
| FortiMail.RecipientPolicy.smtp_diff_identity | String | Whether to reject different SMTP sender identity for authenticated user. |
| FortiMail.RecipientPolicy.smtp_diff_identity_ldap | String | Whether to verify SMTP sender identity with LDAP for authenticated email. |
| FortiMail.RecipientPolicy.smtp_diff_identity_ldap_profile | String | LDAP profile for SMTP sender identity verification. |
| FortiMail.RecipientPolicy.certificate_required | String | Whether to allow email users to log in to their per-recipient spam quarantine by presenting a certificate rather than a user name and password. |

#### Command example
```!fortimail-recipient-policy-list```
#### Context Example
```json
{
    "FortiMail": {
        "RecipientPolicy": [
            {
                "antispam": "AS_Inbound@system",
                "antivirus": "AV_Discard@system",
                "comment": "",
                "content": "CF_Inbound@system",
                "direction": "Inbound",
                "groupmode": 4,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "test",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 5,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "new_version3242342.0@system",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "tal",
                "sender_pattern": "*",
                "sender_pattern_regex": ".*",
                "sender_type": "User (regex)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Inbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 1,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "****@ron.com",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "auth": "ldap",
                "comment": "",
                "content": "",
                "direction": "Inbound",
                "groupmode": 4,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 6,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "test",
                "sender_pattern": "*",
                "sender_pattern_regex": ".*",
                "sender_type": "LDAP group",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Inbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 3,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "*",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Outbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "",
                "mkey": 4,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "*",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Inbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 7,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "****@ron.com",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Inbound",
                "groupmode": 3,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "tal",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 8,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "new_version3242342.0@system",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "new_version3242342.0@system",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "tal",
                "sender_pattern": "*",
                "sender_pattern_regex": ".*",
                "sender_type": "Email address group",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Inbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 9,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "****@ron.com",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Inbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 10,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "****@ron.com",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Inbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 11,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "****@ron.com",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Outbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "",
                "mkey": 12,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "****@ron.com",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Outbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "",
                "mkey": 13,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "****@ron.com",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Inbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 2,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "*",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            },
            {
                "antispam": "",
                "antivirus": "",
                "comment": "",
                "content": "",
                "direction": "Inbound",
                "groupmode": 0,
                "imap_auth": "",
                "ldap_auth": "",
                "ldap_profile": "",
                "mdomain": "system",
                "misc": "Res_Default@system",
                "mkey": 15,
                "pkiauth": "disable",
                "pkiuser": "",
                "pop3_auth": "",
                "profile_dlp": "",
                "profile_user_import_recipient": "",
                "profile_user_import_sender": "",
                "radius_auth": "",
                "recipient_domain": "*",
                "recipient_email_address_group": "",
                "recipient_import_attribute_name": "",
                "recipient_import_attribute_value": "",
                "recipient_pattern": "*",
                "recipient_pattern_regex": ".*",
                "sender_domain": "*",
                "sender_email_address_group": "",
                "sender_import_attribute_name": "",
                "sender_import_attribute_value": "",
                "sender_ldap_profile": "",
                "sender_pattern": "*",
                "sender_pattern_regex": ".*",
                "sender_type": "User (wildcard)",
                "smtp_auth": "",
                "status": "enable"
            }
        ]
    }
}
```

#### Human Readable Output

>### Recipient Policy list
>|Name|Status|Sender Type|Sender Pattern|Recipient Pattern Regex|anti-spam|Content|PKI Auth|Direction|Antivirus|Resource Profile|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 5 | enable | User (regex) | * | .* | AS_Inbound@system | CF_Inbound@system | disable | Inbound | AV_Discard@system | Res_Default@system |
>| 1 | enable | User (wildcard) | ****@ron.com | .* |  |  | disable | Inbound |  | Res_Default@system |
>| 6 | enable | LDAP group | * | .* |  |  | disable | Inbound |  | Res_Default@system |
>| 3 | enable | User (wildcard) | * | .* |  |  | disable | Inbound |  | Res_Default@system |
>| 4 | enable | User (wildcard) | * | .* |  |  | disable | Outbound |  |  |
>| 7 | enable | User (wildcard) | ****@ron.com | .* |  |  | disable | Inbound |  | Res_Default@system |
>| 8 | enable | Email address group | * | .* |  |  | disable | Inbound |  | Res_Default@system |
>| 9 | enable | User (wildcard) | ****@ron.com | .* |  |  | disable | Inbound |  | Res_Default@system |
>| 10 | enable | User (wildcard) | ****@ron.com | .* |  |  | disable | Inbound |  | Res_Default@system |
>| 11 | enable | User (wildcard) | ****@ron.com | .* |  |  | disable | Inbound |  | Res_Default@system |
>| 12 | enable | User (wildcard) | ****@ron.com | .* |  |  | disable | Outbound |  |  |
>| 13 | enable | User (wildcard) | ****@ron.com | .* |  |  | disable | Outbound |  |  |
>| 2 | enable | User (wildcard) | * | .* |  |  | disable | Inbound |  | Res_Default@system |
>| 15 | enable | User (wildcard) | * | .* |  |  | disable | Inbound |  | Res_Default@system |


### fortimail-tls-profile-list

***
List TLS profiles. TLS profiles allow you to selectively disable or enable TLS for specific email recipient patterns, IP subnets, and so on. A common use of TLS profiles is to enforce TLS transport to a specific domain and verify the certificate of the receiving servers. If a name is given, the command will return the information about the specified TLS profile. Mainly used in the configuration of access control rule.

#### Base Command

`fortimail-tls-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the TLS profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.TLSprofile.mkey | String | The name of the TLS profile. |
| FortiMail.TLSprofile.level | Number | The TLS level. |
| FortiMail.TLSprofile.action | String | The TLS action on failure. |
| FortiMail.TLSprofile.comment | String | A brief comment for the TLS profile. |
| FortiMail.TLSprofile.is_referenced | Number | Number of referencing entities. |

#### Command example
```!fortimail-tls-profile-list```
#### Context Example
```json
{
    "FortiMail": {
        "TLSprofile": [
            {
                "action": true,
                "comment": "tal",
                "level": 2,
                "mkey": "tal"
            },
            {
                "action": false,
                "comment": "test",
                "level": 4,
                "mkey": "test"
            }
        ]
    }
}
```

#### Human Readable Output

>### Tls Profile list
>|Name|Comment|TLS level|Action On Failure|Action|
>|---|---|---|---|---|
>| tal | tal | 2 | true | true |
>| test | test | 4 | false | false |


### fortimail-ldap-group-list

***
List LDAP profiles. LDAP groups lets to allow match email addresses as sender or recipients with the LDAP profile authentication in the access control rule configuration and is the authentication profile in case the authentication type in IP policy is LDAP. If a name is given, the command will return the information about the specified LDAP profile. Mainly used in the configuration of access control rule and the IP policy.

#### Base Command

`fortimail-ldap-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the anti-spam LDAP profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.LDAPprofile.mkey | String | The name of the LDAP profile. |
| FortiMail.LDAPprofile.server | Number | The LDAP profile server. |
| FortiMail.LDAPprofile.port | String | The LDAP profile port. |
| FortiMail.LDAPprofile.comment | String | A brief comment for the LDAP group. |
| FortiMail.LDAPprofile.is_referenced | Number | Number of referencing entities. |

#### Command example
```!fortimail-ldap-group-list```
#### Context Example
```json
{
    "FortiMail": {
        "LDAPprofile": [
            {
                "access_override": false,
                "access_override_attribute": "",
                "address_map_state": false,
                "alias_state": true,
                "asav_state": false,
                "authstate": true,
                "cache_state": true,
                "comment": "",
                "domain_lookup_enable": false,
                "domain_override": false,
                "domain_override_attribute": "",
                "groupstate": false,
                "isReferenced": 2,
                "mkey": "tal",
                "port": 389,
                "result": "",
                "routing_state": false,
                "separate_bind_alias": false,
                "server": "2.2.2.2",
                "webmailstatus": false
            },
            {
                "access_override": false,
                "access_override_attribute": "",
                "address_map_state": false,
                "alias_state": true,
                "asav_state": false,
                "authstate": true,
                "cache_state": true,
                "comment": "",
                "domain_lookup_enable": false,
                "domain_override": false,
                "domain_override_attribute": "",
                "groupstate": false,
                "isReferenced": 12,
                "mkey": "test",
                "port": 389,
                "result": "",
                "routing_state": false,
                "separate_bind_alias": false,
                "server": "",
                "webmailstatus": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Ldap Group list
>|Name|Server|Port|Group State|Auth State|Alias State|Routing State|Address Map State|Cache State|
>|---|---|---|---|---|---|---|---|---|
>| tal | 2.2.2.2 | 389 | false | true | true | false | false | true |
>| test |  | 389 | false | true | true | false | false | true |


### fortimail-geoip-group-list

***
List GeoIP groups. FortiMail utilizes the GeoIP database to map the geo locations of client IP addresses. You can use GeoIP groups in access control rules and IP-based policies to geo-targeting spam and virus devices. If a name is given, the command will return the information about the specified GeoIP profile. Mainly used in the configuration of access control rule and the IP policy.

#### Base Command

`fortimail-geoip-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the anti-spam GeoIP group. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.GeoIPgroup.mkey | String | The name of the GeoIP group. |
| FortiMail.GeoIPgroup.country | Number | A list of the GeoIP group countries. |
| FortiMail.GeoIPgroup.comment | String | A brief comment for the GeoIP group countries. |
| FortiMail.GeoIPgroup.is_referenced | Number | Number of referencing entities. |

#### Command example
```!fortimail-geoip-group-list```
#### Context Example
```json
{
    "FortiMail": {
        "GeoIPgroup": [
            {
                "comment": "",
                "country": "AO,AR,AW,AT,BF,CM,CV,KY,CF",
                "isReferenced": 1,
                "mkey": "Test_3"
            },
            {
                "comment": "",
                "country": "",
                "mkey": "test_2"
            },
            {
                "comment": "test",
                "country": "AL,DZ,AD,AQ",
                "mkey": "test_ben"
            }
        ]
    }
}
```

#### Human Readable Output

>### Geoip Group list
>|Name|Comment|Country|
>|---|---|---|
>| Test_3 |  | AO,AR,AW,AT,BF,CM,CV,KY,CF |
>| test_2 |  |  |
>| test_ben | test | AL,DZ,AD,AQ |


### fortimail-antispam-profile-list

***
List AntiSpam profiles. Antispam profiles are sets of antispam scans that you can apply by selecting one in a policy. If a name is given, the command will return the information about the specified AntiSpam profile. Mainly used in the configuration of IP policy.

#### Base Command

`fortimail-antispam-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the anti-spam profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.AntispamProfile.mkey | String | The name of the anti-spam profile. |
| FortiMail.AntispamProfile.dictionary_type | Number | The type of the dictionary type. |
| FortiMail.AntispamProfile.minimum_dictionary_score | Number | The minimum number of the dictionary score. |
| FortiMail.AntispamProfile.comment | String | A brief comment for the anti-spam profile. |
| FortiMail.AntispamProfile.isReferenced | Number | Number of referencing entities. |

#### Command example
```!fortimail-antispam-profile-list```
#### Context Example
```json
{
    "FortiMail": {
        "AntispamProfile": [
            {
                "comment": "",
                "dictionary_type": 1,
                "isReferenced": 1,
                "minimum_dictionary_score": 1,
                "mkey": "AS_Inbound"
            },
            {
                "comment": "",
                "dictionary_type": 1,
                "minimum_dictionary_score": 1,
                "mkey": "AS_Inbound_High"
            },
            {
                "comment": "",
                "dictionary_type": 1,
                "minimum_dictionary_score": 1,
                "mkey": "AS_Outbound"
            },
            {
                "comment": "fortimail-antispam-profile-listfortimail-antispam-profile-listfortimail-antispam-profile-list",
                "dictionary_type": 1,
                "minimum_dictionary_score": 1,
                "mkey": "fortimail-antispam-profile-list"
            }
        ]
    }
}
```

#### Human Readable Output

>### Antispam Profile list
>|Name|Comment|
>|---|---|
>| AS_Inbound |  |
>| AS_Inbound_High |  |
>| AS_Outbound |  |
>| fortimail-antispam-profile-list | fortimail-antispam-profile-listfortimail-antispam-profile-listfortimail-antispam-profile-list |


### fortimail-antivirus-profile-list

***
List AntiVirus profiles. if the FortiMail unit detects a virus, it will take actions as you define in the antivirus action profiles. If a name is given, the command will return the information about the specified AntiVirus profile. Mainly used in the configuration of IP policy.

#### Base Command

`fortimail-antivirus-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the antivirus profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.AntivirusProfile.mkey | String | The name of the antivirus profile. |
| FortiMail.AntivirusProfile.comment | String | A brief comment for the antivirus profile. |

#### Command example
```!fortimail-antivirus-profile-list```
#### Context Example
```json
{
    "FortiMail": {
        "AntivirusProfile": [
            {
                "comment": "",
                "isReferenced": 1,
                "mkey": "AV_Discard"
            },
            {
                "comment": "",
                "mkey": "AV_Reject"
            },
            {
                "comment": "",
                "mkey": "AV_SysQuarantine"
            },
            {
                "comment": "fortimail-antivirus-profile-list",
                "mkey": "fortimail-antivirus-profile-list"
            }
        ]
    }
}
```

#### Human Readable Output

>### Antivirus Profile list
>|Name|Comment|
>|---|---|
>| AV_Discard |  |
>| AV_Reject |  |
>| AV_SysQuarantine |  |
>| fortimail-antivirus-profile-list | fortimail-antivirus-profile-list |


### fortimail-content-profile-list

***
List Content profiles. Content profiles enable matching emails based upon its subject line, message body, and attachments. If a name is given, the command will return the information about the specified content profile. Mainly used in the configuration of IP policy.

#### Base Command

`fortimail-content-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the content profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.ContentProfile.mkey | String | The name of the content profile. |
| FortiMail.ContentProfile.comment | String | A brief comment for the content profile. |
| FortiMail.ContentProfile.isReferenced | Number | Number of referencing entities. |

#### Command example
```!fortimail-content-profile-list```
#### Context Example
```json
{
    "FortiMail": {
        "ContentProfile": [
            {
                "comment": "",
                "isReferenced": 1,
                "mkey": "CF_Inbound"
            },
            {
                "comment": "",
                "mkey": "CF_Outbound"
            },
            {
                "comment": "fortimail-content-profile-list",
                "mkey": "fortimail-content-profile-list"
            }
        ]
    }
}
```

#### Human Readable Output

>### Content Profile list
>|Name|Comment|
>|---|---|
>| CF_Inbound |  |
>| CF_Outbound |  |
>| fortimail-content-profile-list | fortimail-content-profile-list |


### fortimail-ip-pool-list

***
List IP pool profiles. IP pools define a range of IP addresses, and can be used in multiple ways: To define source IP addresses used by the FortiMail unit if you want outgoing email to originate from a range of IP addresses. To define destination addresses used by the FortiMail unit if you want incoming email to destine to the virtual host on a range of IP addresses. If a name is given, the command will return the information about the specified IP pool. Mainly used in the configuration of IP policy.

#### Base Command

`fortimail-ip-pool-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the IP pool. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.IPPool.mkey | String | The name of the IP pool. |
| FortiMail.IPPool.ip_range | Number | The IP pool IP group. |
| FortiMail.IPPool.smtp_certificate | String | The SMTP certificate. |
| FortiMail.IPPool.smtp_certificate_direction | String | The SMTP certificate direction. |
| FortiMail.IPPool.smtp_greeting_reply_name | Number | The SMTP greeting name. |
| FortiMail.IPPool.comment | String | A brief comment for the anti-spam profile. |
| FortiMail.IPPool.is_certificate_expired | Boolean | Whether the certificate expired. |

#### Command example
```!fortimail-ip-pool-list```
#### Context Example
```json
{
    "FortiMail": {
        "IPPool": [
            {
                "comment": "fortimail-ip-pool-list",
                "ip_range": "test1",
                "is_certificate_expired": false,
                "mkey": "fortimail-ip-pool-list",
                "smtp_certificate": "Factory",
                "smtp_certificate_direction": 3,
                "smtp_greeting_reply_name": "fortimail-ip-pool-list"
            },
            {
                "comment": "",
                "ip_range": "test",
                "is_certificate_expired": false,
                "mkey": "tal-pool",
                "smtp_certificate": "",
                "smtp_certificate_direction": 2,
                "smtp_greeting_reply_name": ""
            },
            {
                "comment": "tal test",
                "ip_range": "test1",
                "is_certificate_expired": false,
                "mkey": "test_tal",
                "smtp_certificate": "Self",
                "smtp_certificate_direction": 3,
                "smtp_greeting_reply_name": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### Ip Pool list
>|Name|Comment|IP Group|SMTP Certificate|SMTP Certificate Direction|SMTP Greeting Name|
>|---|---|---|---|---|---|
>| fortimail-ip-pool-list | fortimail-ip-pool-list | test1 | Factory | 3 | fortimail-ip-pool-list |
>| tal-pool |  | test |  | 2 |  |
>| test_tal | tal test | test1 | Self | 3 |  |


### fortimail-session-profile-list

***
List IP session profiles. Session profiles focus on the connection and envelope portion of the SMTP session. If a name is given, the command will return the information about the specified session profile. Mainly used in the configuration of IP policy.

#### Base Command

`fortimail-session-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the session profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.SessionProfile.mkey | String | The name of the session profile. |
| FortiMail.SessionProfile.comment | String | A brief comment for the anti-spam profile. |
| FortiMail.SessionProfile.action | Boolean | The action of the session profile. |

#### Command example
```!fortimail-session-profile-list```
#### Context Example
```json
{
    "FortiMail": {
        "SessionProfile": [
            {
                "action": "",
                "comment": "fortimail-session-profile-list",
                "mkey": "Inbound_Session"
            },
            {
                "action": "",
                "comment": "",
                "mkey": "Outbound_Session"
            }
        ]
    }
}
```

#### Human Readable Output

>### Session Profile list
>|Name|Comment|
>|---|---|
>| Inbound_Session | fortimail-session-profile-list |
>| Outbound_Session |  |


### fortimail-radius-auth-profile-list

***
List RADIUS authentication profiles. If a name is given, the command will return the information about the specified RADIUS authentication profile. Mainly used in the configuration of IP policy.

#### Base Command

`fortimail-radius-auth-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the RADIUS auth profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.RadiusAuthProfile.mkey | String | The name of the RADIUS authentication profile. |
| FortiMail.RadiusAuthProfile.comment | String | A brief comment for the RADIUS authentication profile. |
| FortiMail.RadiusAuthProfile.server | Boolean | The server name of the RADIUS authentication profile. |
| FortiMail.RadiusAuthProfile.authport | Number | The server port of the RADIUS authentication profile. |

#### Command example
```!fortimail-radius-auth-profile-list```
#### Context Example
```json
{
    "FortiMail": {
        "RadiusAuthProfile": {
            "access_override_vendor": 12356,
            "access_profile_override": true,
            "access_profile_override_attribute": 6,
            "authport": 1812,
            "comment": "fortimail-radius-auth-profile-list",
            "domain_override": true,
            "domain_override_attribute": 3,
            "domain_override_vendor": 12356,
            "mkey": "fortimail-radius-auth-profile-list",
            "server": "127.0.0.1"
        }
    }
}
```

#### Human Readable Output

>### Radius Auth Profile list
>|Name|Comment|Server|Auth Port|Access Override Vendor|Domain Override Vendor|
>|---|---|---|---|---|---|
>| fortimail-radius-auth-profile-list | fortimail-radius-auth-profile-list | 127.0.0.1 | 1812 | 12356 | 12356 |


### fortimail-pop3-auth-profile-list

***
List POP3 authentication profiles. If a name is given, the command will return the information about the specified POP3 authentication profile. Mainly used in the configuration of IP policy.

#### Base Command

`fortimail-pop3-auth-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the POP3 auth profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.Pop3AuthProfile.mkey | String | The name of the POP3 authentication profile. |
| FortiMail.Pop3AuthProfile.comment | String | A brief comment for the POP3 authentication profile. |
| FortiMail.Pop3AuthProfile.server | Boolean | The server name of the POP3 authentication profile. |
| FortiMail.Pop3AuthProfile.port | Number | The port of the POP3 authentication profile. |
| FortiMail.Pop3AuthProfile.auth_type | Number | The authentication type of the POP3 authentication profile. |

#### Command example
```!fortimail-pop3-auth-profile-list```
#### Context Example
```json
{
    "FortiMail": {
        "Pop3AuthProfile": {
            "auth_type": 0,
            "comment": "fortimail-radius-auth-profile-list",
            "mkey": "fortimail-radius-auth-profile-listpop",
            "port": 110,
            "server": "1.1.1.1"
        }
    }
}
```

#### Human Readable Output

>### Pop3 Auth Profile list
>|Name|Comment|Server|Auth Type|Port|
>|---|---|---|---|---|
>| fortimail-radius-auth-profile-listpop | fortimail-radius-auth-profile-list | 1.1.1.1 | 0 | 110 |


### fortimail-imap-auth-profile-list

***
List IMAP authentication profiles. If a name is given, the command will return the information about the specified IMAP authentication profile. Mainly used in the configuration of IP policy.

#### Base Command

`fortimail-imap-auth-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the IMAP auth profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.ImapAuthProfile.mkey | String | The name of the IMAP authentication profile. |
| FortiMail.ImapAuthProfile.comment | String | A brief comment for the IMAP authentication profile. |
| FortiMail.ImapAuthProfile.server | Boolean | The server name of the IMAP authentication profile. |
| FortiMail.ImapAuthProfile.port | Number | The port of the IMAP authentication profile. |
| FortiMail.ImapAuthProfile.auth_type | Number | The authentication type of the IMAP authentication profile. |

#### Command example
```!fortimail-imap-auth-profile-list```
#### Context Example
```json
{
    "FortiMail": {
        "ImapAuthProfile": {
            "auth_type": 3,
            "comment": "fortimail-radius-auth-profile-list",
            "mkey": "fortimail-radius-auth-profile-listimap",
            "port": 143,
            "server": "2.2.2.2"
        }
    }
}
```

#### Human Readable Output

>### Imap Auth Profile list
>|Name|Comment|Server|Auth Type|Port|
>|---|---|---|---|---|
>| fortimail-radius-auth-profile-listimap | fortimail-radius-auth-profile-list | 2.2.2.2 | 3 | 143 |


### fortimail-smtp-auth-profile-list

***
List SMTP authentication profiles. If a name is given, the command will return the information about the specified SMTP authentication profile. Mainly used in the configuration of IP policy.

#### Base Command

`fortimail-smtp-auth-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the SMTP auth profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.SmtpAuthProfile.mkey | String | The name of the SMTP authentication profile. |
| FortiMail.SmtpAuthProfile.comment | String | A brief comment for the SMTP authentication profile. |
| FortiMail.SmtpAuthProfile.server | Boolean | The server name of the SMTP authentication profile. |
| FortiMail.SmtpAuthProfile.port | Number | The port of the SMTP authentication profile. |
| FortiMail.SmtpAuthProfile.auth_type | Number | The authentication type of the SMTP authentication profile. |

#### Command example
```!fortimail-smtp-auth-profile-list```
#### Context Example
```json
{
    "FortiMail": {
        "SmtpAuthProfile": {
            "auth_type": 1,
            "comment": "fortimail-radius-auth-profile-list",
            "mkey": "fortimail-radius-auth-profile-listsmtp",
            "port": 25,
            "server": "3.3.3.3"
        }
    }
}
```

#### Human Readable Output

>### Smtp Auth Profile list
>|Name|Comment|Server|Auth Type|Port|
>|---|---|---|---|---|
>| fortimail-radius-auth-profile-listsmtp | fortimail-radius-auth-profile-list | 3.3.3.3 | 1 | 25 |


### fortimail-resource-profile-list

***
List resource profiles. Resouce profile configure miscellaneous aspects of the email user accounts, such as disk space quota. If a name is given, the command will return the information about the specified resource profile. Mainly used in the configuration of IP policy.

#### Base Command

`fortimail-resource-profile-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the resource profile. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.ResourceProfile.mkey | String | The name of the resource profile. |
| FortiMail.ResourceProfile.comment | String | A brief comment for the resource profile. |
| FortiMail.ResourceProfile.is_referenced | Number | Number of referencing entities. |

#### Command example
```!fortimail-resource-profile-list```
#### Context Example
```json
{
    "FortiMail": {
        "ResourceProfile": {
            "comment": "",
            "isReferenced": 11,
            "mkey": "Res_Default"
        }
    }
}
```

#### Human Readable Output

>### Resource Profile list
>|Name|
>|---|
>| Res_Default |


### fortimail-pki-user-list

***
List PKI users. PKI users can authenticate by presenting a valid client certificate, rather than by entering a username and password. If a name is given, the command will return the information about the specified PKI user. Mainly used in the configuration of recipient policy.

#### Base Command

`fortimail-pki-user-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the PKI user. | Optional |
| all_results | Whether to retrieve all results by overriding the default limit. Possible values are: true, false. Default is false. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FortiMail.PKIuser.mkey | String | The name of the PKI user. |
| FortiMail.PKIuser.domain | String | The domain of the PKI user. |
| FortiMail.PKIuser.subject | Number | The subject of the PKI user. |
| FortiMail.PKIuser.ldapprofile | String | The LDAP profile of the PKI user. |

#### Command example
```!fortimail-pki-user-list```
#### Context Example
```json
{
    "FortiMail": {
        "PKIuser": [
            {
                "ca_certificate": "",
                "domain": "",
                "ldapfield": 0,
                "ldapprofile": "",
                "ldapquery": true,
                "mkey": "lior",
                "ocspaction": 1,
                "ocspca": "",
                "ocspurl": "",
                "ocspverify": false,
                "subject": "tola"
            },
            {
                "ca_certificate": "",
                "domain": "",
                "ldapfield": 0,
                "ldapprofile": "tal",
                "ldapquery": true,
                "mkey": "tal",
                "ocspaction": 1,
                "ocspca": "",
                "ocspurl": "",
                "ocspverify": false,
                "subject": ""
            }
        ]
    }
}
```

#### Human Readable Output

>### Pki User list
>|Name|Subject|LDAP Profile|LDAP Query|OCSP verify|
>|---|---|---|---|---|
>| lior | tola |  | true | false |
>| tal |  | tal | true | false |