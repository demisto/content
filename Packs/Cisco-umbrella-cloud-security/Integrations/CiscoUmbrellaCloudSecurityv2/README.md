Cisco Umbrella is a cloud security platform providing the first line of defense against internet threats. It uses DNS-layer security to block malicious requests before a connection is established, offering protection against malware, ransomware, phishing, and more. It offers real-time reporting, integrates with other Cisco solutions for layered security, and uses machine learning to uncover and predict threats.
This integration was tested with version 2 of Cisco Umbrella Cloud Security

## Configure Cisco Umbrella Cloud Security v2 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| API Key | True |
| API Secret | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### umbrella-destinations-list

***
Get destinations within a destination list. A destination is a URL, IP or fully qualified domain name.

#### Base Command

`umbrella-destinations-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination_list_id | The ID of the destination list. Destination lists can be fetched with the `umbrella-destination-lists-list` command. | Required |
| destination_ids | Comma-separated list of destination IDs to be retrieved from a list of destinations. | Optional |
| destinations | Comma-separated list of destinations to retrieve, a destination may be a domain, URL, or IP address. | Optional |
| page | Page number of paginated results. Minimum 1; Default 1. | Optional |
| page_size | The number of items per page. Minimum 1; Maximum 100; Default 50. | Optional |
| limit | The number of items per page. Minimum 1. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.Destinations.id | String | The unique ID of the destination. |
| Umbrella.Destinations.destination | String | A destination may be a domain, URL, or IP address. |
| Umbrella.Destinations.type | String | The type of destination within the destination list. |
| Umbrella.Destinations.comment | String | A comment about the destination. |
| Umbrella.Destinations.createdAt | Date | The date and time when the destination list was created. |

#### Command example

```!umbrella-destinations-list destination_list_id=17425859 limit=3```

#### Context Example

```json
{
    "Umbrella": {
        "Destinations": [
            {
                "comment": "Added from XSOAR",
                "createdAt": "2023-07-19 18:21:11",
                "destination": "www.facebook.com",
                "id": "154",
                "type": "domain"
            },
            {
                "comment": "Lior",
                "createdAt": "2023-07-06 04:42:55",
                "destination": "cisco.com",
                "id": "30058",
                "type": "domain"
            },
            {
                "comment": "Sabri",
                "createdAt": "2023-07-06 04:42:55",
                "destination": "www.pokemon.com",
                "id": "138036",
                "type": "domain"
            }
        ]
    }
}
```

#### Human Readable Output

>### Destination(s):

>|Id|Destination|Type|Comment|Created At|
>|---|---|---|---|---|
>| 154 | www.facebook.com | domain | Added from XSOAR | 2023-07-19 18:21:11 |
>| 30058 | cisco.com | domain | Pikachu | 2023-07-06 04:42:55 |
>| 138036 | www.pokemon.com | domain | Choose | 2023-07-06 04:42:55 |

### umbrella-destination-add

***
Add a destination to a destination list. A destination is a URL, IPv4, CIDR or fully qualified domain name. Accepted types for destination list with the access "allow" are: DOMAIN, IPv4 and CIDR. Accepted types for destination list with the access "block" are: URL and DOMAIN.

#### Base Command

`umbrella-destination-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination_list_id | The ID of the destination list. Destination lists can be fetched with the `umbrella-destination-lists-list` command. | Required |
| destinations | Comma-separated list of destinations. A destination may be a URL, IPv4, CIDR or fully qualified domain name. | Required |
| comment | A comment about all the inserted destinations. Default is Added from XSOAR. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.DestinationLists.id | Number | The unique ID of the destination list. |
| Umbrella.DestinationLists.organizationId | Number | The organization ID. |
| Umbrella.DestinationLists.access | String | The type of access for the destination list. Valid values are: allow or block. |
| Umbrella.DestinationLists.isGlobal | Boolean | Specifies whether the destination list is a global destination list. There is only one default destination list of type 'allow' or 'block' for an organization. |
| Umbrella.DestinationLists.name | String | The name of the destination list. |
| Umbrella.DestinationLists.thirdpartyCategoryId | Number | The third-party category ID of the destination list. |
| Umbrella.DestinationLists.createdAt | Number | The date and time when the destination list was created. |
| Umbrella.DestinationLists.modifiedAt | Number | The date and time when the destination list was modified. |
| Umbrella.DestinationLists.isMspDefault | Boolean | Specifies whether MSP is the default. |
| Umbrella.DestinationLists.markedForDeletion | Boolean | Specifies whether the destination list is marked for deletion. |
| Umbrella.DestinationLists.bundleTypeId | Number | The number that represents the type of the Umbrella policy associated with the destination list. Umbrella returns '1' for the DNS policy or '2' for the Web policy. |
| Umbrella.DestinationLists.meta.destinationCount | Number | The total number of destinations in a destination list. |

#### Base Command

`umbrella-destination-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination_list_id | The ID of the destination list. Destination Lists can be fetched with `umbrella-destination-lists-list`. | Required |
| destinations | Comma separated list of destinations. A destination may be a URL, IPv4, CIDR or fully qualified domain name. | Required |
| comment | A comment about all the inserted destinations. Default value: "Added from XSOAR". Default is Added from XSOAR. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.DestinationLists.id | Number | The unique ID of the destination list. |
| Umbrella.DestinationLists.organizationId | Number | The organization ID. |
| Umbrella.DestinationLists.access | String | The type of access for the destination list. Valid values are: allow or block. |
| Umbrella.DestinationLists.isGlobal | Boolean | Specifies whether the destination list is a global destination list. There is only one default destination list of type 'allow' or 'block' for an organization. |
| Umbrella.DestinationLists.name | String | The name of the destination list. |
| Umbrella.DestinationLists.thirdpartyCategoryId | Number | The third-party category ID of the destination list. |
| Umbrella.DestinationLists.createdAt | Number | The date and time when the destination list was created. |
| Umbrella.DestinationLists.modifiedAt | Number | The date and time when the destination list was modified. |
| Umbrella.DestinationLists.isMspDefault | Boolean | Specifies whether MSP is the default. |
| Umbrella.DestinationLists.markedForDeletion | Boolean | Specifies whether the destination list is marked for deletion. |
| Umbrella.DestinationLists.bundleTypeId | Number | The number that represents the type of the Umbrella policy associated with the destination list. Umbrella returns '1' for the DNS policy or '2' for the Web policy. |
| Umbrella.DestinationLists.meta.destinationCount | Number | The total number of destinations in a destination list. |

#### Command example

```!umbrella-destination-add destination_list_id=17463731 destinations="www.LiorSabri.com,1.1.1.1"```

#### Human Readable Output

>The destination(s) "['www.LiorSabri.com', '1.1.1.1']" were successfully added to the destination list "17463731"

### umbrella-destination-delete

***
Remove a destination from a destination list. A destination is a URL, IP or fully qualified domain name.

#### Base Command

`umbrella-destination-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination_list_id | The ID of the destination list. Destination lists can be fetched with the `umbrella-destination-lists-list` command. | Required |
| destination_ids | Comma-separated list of destination IDs. Destinations can be fetched with the `umbrella-destination-list` command. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.DestinationLists.id | Number | The unique ID of the destination list. |
| Umbrella.DestinationLists.organizationId | Number | The organization ID. |
| Umbrella.DestinationLists.access | String | The type of access for the destination list. Valid values are: allow or block. |
| Umbrella.DestinationLists.isGlobal | Boolean | Specifies whether the destination list is a global destination list. There is only one default destination list of type 'allow' or 'block' for an organization. |
| Umbrella.DestinationLists.name | String | The name of the destination list. |
| Umbrella.DestinationLists.thirdpartyCategoryId | Number | The third-party category ID of the destination list. |
| Umbrella.DestinationLists.createdAt | Number | The date and time when the destination list was created. |
| Umbrella.DestinationLists.modifiedAt | Number | The date and time when the destination list was modified. |
| Umbrella.DestinationLists.isMspDefault | Boolean | Specifies whether MSP is the default. |
| Umbrella.DestinationLists.markedForDeletion | Boolean | Specifies whether the destination list is marked for deletion. |
| Umbrella.DestinationLists.bundleTypeId | Number | The number that represents the type of the Umbrella policy associated with the destination list. Umbrella returns '1' for the DNS policy or '2' for the Web policy. |
| Umbrella.DestinationLists.meta.destinationCount | Number | The total number of destinations in a destination list. |

#### Command example

```!umbrella-destination-delete destination_list_id=17463733 destination_ids=25826```

#### Human Readable Output

>The destination(s) "[25826]" were successfully removed from the destination list "17463733"

### umbrella-destination-lists-list

***
Get destination lists. A list of destinations (for example, domain name or URL) to which you can block or allow access.

#### Base Command

`umbrella-destination-lists-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination_list_id | The ID of the destination list to retrieve. | Optional |
| page | Page number of paginated results. Minimum 1; Default 1. | Optional |
| page_size | The number of items per page. Minimum 1; Maximum 100; Default 50. | Optional |
| limit | The maximum number of records to retrieve. Minimum 1. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.DestinationLists.id | Number | The unique ID of the destination list. |
| Umbrella.DestinationLists.organizationId | Number | The organization ID. |
| Umbrella.DestinationLists.access | String | The type of access for the destination list. Valid values are: allow or block. |
| Umbrella.DestinationLists.isGlobal | Boolean | Specifies whether the destination list is a global destination list. There is only one default destination list of type 'allow' or 'block' for an organization. |
| Umbrella.DestinationLists.name | String | The name of the destination list. |
| Umbrella.DestinationLists.thirdpartyCategoryId | Number | The third-party category ID of the destination list. |
| Umbrella.DestinationLists.createdAt | Number | The date and time when the destination list was created. |
| Umbrella.DestinationLists.modifiedAt | Number | The date and time when the destination list was modified. |
| Umbrella.DestinationLists.isMspDefault | Boolean | Specifies whether MSP is the default. |
| Umbrella.DestinationLists.markedForDeletion | Boolean | Specifies whether the destination list is marked for deletion. |
| Umbrella.DestinationLists.bundleTypeId | Number | The number that represents the type of the Umbrella policy associated with the destination list. Umbrella returns '1' for the DNS policy or '2' for the Web policy. |
| Umbrella.DestinationLists.meta.destinationCount | Number | The total number of destinations in a destination list. |
| Umbrella.DestinationLists.meta.domainCount | Number | The total number of domains in a destination list. Domains are part of the total number of destinations in a destination list. |
| Umbrella.DestinationLists.meta.ipv4Count | Number | The total number of IP addresses in a destination list. IP addresses are part of the total number of destinations in a destination list. |
| Umbrella.DestinationLists.meta.urlCount | Number | The total number of URLs in a destination list. URLs are part of the total number of destinations in a destination list. |
| Umbrella.DestinationLists.meta.applicationCount | Number | The total number or applications in a destination list. Applications are part of the total number of destinations in a destination list. |

#### Command example

```!umbrella-destination-lists-list limit=3```

#### Context Example

```json
{
    "Umbrella": {
        "DestinationLists": [
            {
                "access": "allow",
                "bundleTypeId": 1,
                "createdAt": 1690184121,
                "id": 17463749,
                "isGlobal": false,
                "isMspDefault": false,
                "markedForDeletion": false,
                "meta": {
                    "applicationCount": 0,
                    "destinationCount": 1,
                    "domainCount": 0,
                    "ipv4Count": 1,
                    "urlCount": 0
                },
                "modifiedAt": 1690184121,
                "name": "Lior",
                "organizationId": 123456,
                "thirdpartyCategoryId": null
            },
            {
                "access": "allow",
                "bundleTypeId": 1,
                "createdAt": 1690184234,
                "id": 17463756,
                "isGlobal": false,
                "isMspDefault": false,
                "markedForDeletion": false,
                "meta": {
                    "applicationCount": 0,
                    "destinationCount": 8,
                    "domainCount": 4,
                    "ipv4Count": 4,
                    "urlCount": 0
                },
                "modifiedAt": 1690184435,
                "name": "LiorSB",
                "organizationId": 123456,
                "thirdpartyCategoryId": null
            },
            {
                "access": "allow",
                "bundleTypeId": 1,
                "createdAt": 1638798710,
                "id": 15609454,
                "isGlobal": true,
                "isMspDefault": false,
                "markedForDeletion": false,
                "meta": {
                    "applicationCount": 0,
                    "destinationCount": 14,
                    "domainCount": 10,
                    "ipv4Count": 4,
                    "urlCount": 0
                },
                "modifiedAt": 1690183660,
                "name": "Global Allow List",
                "organizationId": 123456,
                "thirdpartyCategoryId": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Destination List:

>|Id|Name|Access|Is Global|Destination Count|
>|---|---|---|---|---|
>| 17463749 | Lior | allow | false | 1 |
>| 17463756 | LiorSB | allow | false | 8 |
>| 15609454 | Global Allow List | allow | true | 14 |

### umbrella-destination-list-create

***
Create a destination list. A list of destinations (for example, domain name or URL) to which you can block or allow access. Accepted types for destination list with the access "allow" are: DOMAIN, IPv4 and CIDR. Accepted types for destination list with the access "block" are: URL and DOMAIN.

#### Base Command

`umbrella-destination-list-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bundle_type | The type of the Umbrella policy associated with the destination list. If the field is not specified, the default value is 'DNS'. Possible values are: DNS, WEB. | Optional |
| access | The type of access for the destination list. Valid values are "allow" or "block". Accepted types for destination list with the access "allow" are: DOMAIN, IPv4 and CIDR. Accepted types for destination list with the access "block" are: URL and DOMAIN. Possible values are: allow, block. | Required |
| is_global | Specifies whether the destination list is a global destination list. There is only one default destination list of type 'allow' or 'block' for an organization. Possible values are: True, False. | Required |
| name | The name of the destination list. | Required |
| destinations | Comma-separated list of destinations. A destination may be a URL, IPv4, CIDR or fully qualified domain name. | Optional |
| destinations_comment | A comment about all the inserted destinations. Default is Added from XSOAR. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.DestinationLists.id | Number | The unique ID of the destination list. |
| Umbrella.DestinationLists.organizationId | Number | The organization ID. |
| Umbrella.DestinationLists.access | String | The type of access for the destination list. Valid values are: allow or block. |
| Umbrella.DestinationLists.isGlobal | Boolean | Specifies whether the destination list is a global destination list. There is only one default destination list of type 'allow' or 'block' for an organization. |
| Umbrella.DestinationLists.name | String | The name of the destination list. |
| Umbrella.DestinationLists.thirdpartyCategoryId | Number | The third-party category ID of the destination list. |
| Umbrella.DestinationLists.createdAt | Number | The date and time when the destination list was created. |
| Umbrella.DestinationLists.modifiedAt | Number | The date and time when the destination list was modified. |
| Umbrella.DestinationLists.isMspDefault | Boolean | Specifies whether MSP is the default. |
| Umbrella.DestinationLists.markedForDeletion | Boolean | Specifies whether the destination list is marked for deletion. |
| Umbrella.DestinationLists.bundleTypeId | Number | The number that represents the type of the Umbrella policy associated with the destination list. Umbrella returns '1' for the DNS policy or '2' for the Web policy. |
| Umbrella.DestinationLists.meta.destinationCount | Number | The total number of destinations in a destination list. |

#### Command example

```!umbrella-destination-list-create access=allow is_global=False name=LiorSBList bundle_type=WEB destinations="https://pokemon.com"```

#### Context Example

```json
{
    "Umbrella": {
        "DestinationLists": {
            "access": "allow",
            "bundleTypeId": 1,
            "createdAt": 1690208665,
            "id": 17464621,
            "isGlobal": false,
            "isMspDefault": false,
            "markedForDeletion": false,
            "meta": {
                "destinationCount": 1
            },
            "modifiedAt": 1690208665,
            "name": "LiorSBList",
            "organizationId": 123456,
            "thirdpartyCategoryId": null
        }
    }
}
```

#### Human Readable Output

>### Destination List:

>|Id|Name|Access|Is Global|Destination Count|
>|---|---|---|---|---|
>| 17464621 | LiorSBList | allow | false | 1 |

### umbrella-destination-list-update

***
Edit a destination list. A list of destinations (for example, domain name or URL) to which you can block or allow access.

#### Base Command

`umbrella-destination-list-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination_list_id | The ID of the destination list. Destination lists can be fetched with the `umbrella-destination-lists-list` command. | Required |
| name | The name of the destination list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Umbrella.DestinationLists.id | Number | The unique ID of the destination list. |
| Umbrella.DestinationLists.organizationId | Number | The organization ID. |
| Umbrella.DestinationLists.access | String | The type of access for the destination list. Valid values are: allow or block. |
| Umbrella.DestinationLists.isGlobal | Boolean | Specifies whether the destination list is a global destination list. There is only one default destination list of type 'allow' or 'block' for an organization. |
| Umbrella.DestinationLists.name | String | The name of the destination list. |
| Umbrella.DestinationLists.thirdpartyCategoryId | Number | The third-party category ID of the destination list. |
| Umbrella.DestinationLists.createdAt | Number | The date and time when the destination list was created. |
| Umbrella.DestinationLists.modifiedAt | Number | The date and time when the destination list was modified. |
| Umbrella.DestinationLists.isMspDefault | Boolean | Specifies whether MSP is the default. |
| Umbrella.DestinationLists.markedForDeletion | Boolean | Specifies whether the destination list is marked for deletion. |
| Umbrella.DestinationLists.bundleTypeId | Number | The number that represents the type of the Umbrella policy associated with the destination list. Umbrella returns '1' for the DNS policy or '2' for the Web policy. |
| Umbrella.DestinationLists.meta.destinationCount | Number | The total number of destinations in a destination list. |

#### Command example

```!umbrella-destination-list-update destination_list_id=17463733 name=LiorUpdated```

#### Context Example

```json
{
    "Umbrella": {
        "DestinationLists": {
            "access": "allow",
            "bundleTypeId": 1,
            "createdAt": 1690183414,
            "id": 17463733,
            "isGlobal": false,
            "isMspDefault": false,
            "markedForDeletion": false,
            "meta": {
                "destinationCount": 0
            },
            "modifiedAt": 1690208670,
            "name": "LiorUpdated",
            "organizationId": 123456,
            "thirdpartyCategoryId": null
        }
    }
}
```

#### Human Readable Output

>### Destination List:

>|Id|Name|Access|Is Global|Destination Count|
>|---|---|---|---|---|
>| 17463733 | LiorUpdated | allow | false | 0 |

### umbrella-destination-list-delete

***
Delete a destination list. A list of destinations (for example, domain name or URL) to which you can block or allow access.

#### Base Command

`umbrella-destination-list-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| destination_list_id | The ID of the destination list. Destination lists can be fetched with the `umbrella-destination-lists-list` command. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!umbrella-destination-list-delete destination_list_id=17463733```

#### Human Readable Output

>The destination list "17463733" was successfully deleted


## Breaking changes from the previous version of this integration - Cisco Umbrella Cloud Security v2
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *umbrella-get-destination-lists* - this command was replaced by *umbrella-destination-lists-list*.
* *umbrella-add-domain* - this command was replaced by *umbrella-destination-add*.
* *umbrella-remove-domain* - this command was replaced by *umbrella-destination-delete*.
* *umbrella-get-destination-domain* - this command was replaced by *umbrella-destinations-list*.
* *umbrella-get-destination-domains* - this command was replaced by *umbrella-destinations-list*.
* *umbrella-search-destination-domains* - this command was replaced by *umbrella-destinations-list*.

### Arguments
#### The following arguments were removed in this version:

In the *umbrella-get-destination-lists* command:
* *orgId* - this argument was removed.
In the *umbrella-add-domain* command:
* *orgId* - this argument was removed.
In the *umbrella-remove-domain* command:
* *orgId* - this argument was removed.
In the *umbrella-get-destination-domain* command:
* *orgId* - this argument was removed.
In the *umbrella-get-destination-domains* command:
* *orgId* - this argument was removed.
In the *umbrella-search-destination-domains* command:
* *orgId* - this argument was removed.


#### The behavior of the following arguments was changed:

In the *umbrella-add-domain* command:
* *destId* - this argument was replaced by *destination_list_id*.
* *domains* - this argument was replaced by *destinations*.
In the *umbrella-remove-domain* command:
* *destId* - this argument was replaced by *destination_list_id*.
* *domainIds* - this argument was replaced by *destination_ids*.
In the *umbrella-get-destination-domain* command:
* *destId* - this argument was replaced by *destination_list_id*.
In the *umbrella-get-destination-domains* command:
* *destId* - this argument was replaced by *destination_list_id*.
In the *umbrella-search-destination-domains* command:
* *destId* - this argument was replaced by *destination_list_id*.
* *domains* - this argument was replaced by *destinations*.