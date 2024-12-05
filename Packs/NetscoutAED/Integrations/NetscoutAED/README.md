The Netscout Arbor Edge Defense (AED) integration enables you to block and allow outbound and inbound traffic.

## What does this pack do?
Using the Netscout AED integration you can:

- Get, add, and remove hosts, countries, domains, and URLs from the inbound block list.
- Get, add, and remove hosts from the inbound allow list.
- Get, add, and remove hosts and countries from the outbound blaock list.
- Get, add, and remove hosts from the outbound all.
- Get and update the protection group (the IPv4 or IPv6 hosts that you need to protect).

## Configure NetscoutAED in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Token | If using 6.0.2 or lower version, put your API Key in the **Password** field, leave the **User** field empty. | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### na-ed-outbound-blacklisted-countries-list
***
Gets the countries on the outbound block list. By default, 10 block listed countries are returned.


#### Base Command

### na-ed-country-code-list
***
Gets a country or list of countries (country name and ISO-standardized country code).


#### Base Command

`na-ed-country-code-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search strings, separated by “+” to filter the results. (For example: "AZ+BS"). | Optional | 
| page | The page of the results to return. | Optional | 
| limit | The maximum number of results returned per page. Default: 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.Country.country_name | String | The country's name. | 
| NetscoutAED.Country.iso_code | String | The ISO-standardized country code. | 


#### Command Example
```!na-ed-country-code-list limit=5```

#### Context Example
```json
{
    "NetscoutAED": {
        "Country": [
            {
                "country_name": "6to4 Relay Anycast",
                "iso_code": "XF"
            },
            {
                "country_name": "Afghanistan",
                "iso_code": "AF"
            },
            {
                "country_name": "Aland Islands",
                "iso_code": "AX"
            },
            {
                "country_name": "Albania",
                "iso_code": "AL"
            },
            {
                "country_name": "Algeria",
                "iso_code": "DZ"
            }
        ]
    }
}
```

#### Human Readable Output

>### Netscout AED Countries List
>|Country Name|Iso Code|
>|---|---|
>| 6to4 Relay Anycast | XF |
>| Afghanistan | AF |
>| Aland Islands | AX |
>| Albania | AL |
>| Algeria | DZ |



`na-ed-outbound-blacklisted-countries-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| country | An ISO-standardized country code to get a specific country in the results. Can be retrieved by running the "na-ed-country-code-list" command. | Optional | 
| query | Search strings, separated by “+” to filter the results. (For example: "AZ+BS"). | Optional | 
| page | The page of the results to return. | Optional | 
| limit | The maximum number of results returned per page. Default: 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.OutboundBlacklistCountry.annotation | String | A message associated with each country in the outbound block list. | 
| NetscoutAED.OutboundBlacklistCountry.country | String | An ISO-standardized country code. | 
| NetscoutAED.OutboundBlacklistCountry.update_time | Date | The time that the country code was added to the list. | 


#### Command Example
```!na-ed-outbound-blacklisted-countries-list```

#### Context Example
```json
{
    "NetscoutAED": {
        "OutboundBlacklistCountry": [
            {
                "annotation": "example1",
                "country": "AZ",
                "update_time": "2021-04-13T13:06:43.000Z"
            },
            {
                "annotation": "example2",
                "country": "IS",
                "update_time": "2021-04-19T15:28:13.000Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Blacklisted Countries
>|Country|Update Time|Annotation|
>|---|---|---|
>| AZ | 2021-04-13T13:06:43.000Z | example1 |
>| IS | 2021-04-19T15:28:13.000Z | example2 |


### na-ed-outbound-blacklisted-countries-add
***
Adds one or more countries to the outbound block list.


#### Base Command

`na-ed-outbound-blacklisted-countries-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| country | An ISO-standardized country code or a comma-separated list of country codes. Can be retrieved by running the "na-ed-country-code-list" command. | Required | 
| annotation | A message to associate with each country that you add to the outbound block list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.OutboundBlacklistCountry.annotation | String | A message associated with each country in the outbound block list. | 
| NetscoutAED.OutboundBlacklistCountry.country | String | An ISO-standardized country code. | 
| NetscoutAED.OutboundBlacklistCountry.update_time | Date | The time that the country code was added to the list. | 


#### Command Example
```!na-ed-outbound-blacklisted-countries-add country=AU```

#### Context Example
```json
{
    "NetscoutAED": {
        "OutboundBlacklistCountry": {
            "annotation": null,
            "country": "AU",
            "update_time": "2021-05-24T08:58:03.000Z"
        }
    }
}
```

#### Human Readable Output

>Countries were successfully added to the outbound block listed list
>### Added Countries
>|Country|Update Time|
>|---|---|
>| AU | 2021-05-24T08:58:03.000Z |


### na-ed-outbound-blacklisted-countries-remove
***
Removes one or more countries from the outbound block list.


#### Base Command

`na-ed-outbound-blacklisted-countries-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| country | An ISO-standardized country code or a comma-separated list of ISO-standardized country codes to remove. Can be retrieved by running the "na-ed-country-code-list" command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!na-ed-outbound-blacklisted-countries-remove country=AU```

#### Human Readable Output

>Countries were successfully removed from the outbound block listed list

### na-ed-inbound-blacklisted-countries-list
***
Gets the inbound block listed countries. By default, 10 block listed countries are returned. To return block listed countries for specific protection groups, specify a list of protection group IDs or central configuration IDs. An ID of -1 selects countries that are globally block listed.


#### Base Command

`na-ed-inbound-blacklisted-countries-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid | A comma-separated list of central configuration IDs. Cannot be used with the pgid parameter.| Optional | 
| pgid | A comma-separated list of protection group IDs. Cannot be used with the cid parameter. | Optional | 
| country | An ISO-standardized country code to get a specific country in the results. Can be retrieved by running the "na-ed-country-code-list" command. | Optional | 
| query | Search strings, separated by “+” to filter the results. (For example: "AZ+BS"). | Optional | 
| page | The page of the results to return. | Optional | 
| limit | The maximum number of results returned per page. Default: 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundBlacklistCountry.annotation | Unknown | List of messages associated with each country in the inbound block list. | 
| NetscoutAED.InboundBlacklistCountry.cid | Unknown | List of central configuration IDs. | 
| NetscoutAED.InboundBlacklistCountry.country | String | An ISO-standardized country code. | 
| NetscoutAED.InboundBlacklistCountry.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundBlacklistCountry.update_time | Date | The time that the country code was added to the list. | 


#### Command Example
```!na-ed-inbound-blacklisted-countries-list country=AM```

#### Context Example
```json
{
    "NetscoutAED": {
        "InboundBlacklistCountry": {
            "annotation": [
                "example1"
            ],
            "cid": [],
            "country": "AM",
            "pgid": [
                52
            ],
            "update_time": "2021-04-19T15:36:00.000Z"
        }
    }
}
```

#### Human Readable Output

>### Blacklisted Countries
>|Country|Update Time|Annotation|Pgid|
>|---|---|---|---|
>| AM | 2021-04-19T15:36:00.000Z | example1 | 52 |


### na-ed-inbound-blacklisted-countries-add
***
Adds one or more countries to the inbound block list by pgid or cid.


#### Base Command

`na-ed-inbound-blacklisted-countries-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid | A specific central configuration ID or -1 for global. Cannot be used with the pgid parameter. | Optional | 
| pgid | A specific protection group ID or -1 for global. Cannot be used with the cid parameter. | Optional | 
| annotation | A message to associate with each country that you add to the block list. | Optional | 
| country | ISO-standardized country code or a comma-separated list of country codes. Can be retrieved by running the "na-ed-country-code-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundBlacklistCountry.annotation | Unknown | List of messages associated with each country in the outbound block list. | 
| NetscoutAED.InboundBlacklistCountry.cid | Unknown | List of central configuration IDs. | 
| NetscoutAED.InboundBlacklistCountry.country | String | An ISO-standardized country code. | 
| NetscoutAED.InboundBlacklistCountry.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundBlacklistCountry.update_time | Date | The time that the country code was added to the list. | 


#### Command Example
```!na-ed-inbound-blacklisted-countries-add country=AU```

#### Context Example
```json
{
    "NetscoutAED": {
        "InboundBlacklistCountry": {
            "annotation": [],
            "cid": [
                -1
            ],
            "country": "AU",
            "pgid": [
                -1
            ],
            "update_time": "2021-05-24T08:57:58.000Z"
        }
    }
}
```

#### Human Readable Output

>Countries were successfully added to the inbound block listed list
>### Added Countries
>|Country|Cid|Pgid|Update Time|
>|---|---|---|---|
>| AU | -1 | -1 | 2021-05-24T08:57:58.000Z |


### na-ed-inbound-blacklisted-countries-remove
***
Removes one or more countries from the block list for a specific protection group or for all protection groups.


#### Base Command

`na-ed-inbound-blacklisted-countries-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid | A specific central configuration ID or -1 for global. Cannot be used with the pgid parameter. | Optional | 
| pgid | A specific protection group ID or -1 for global. Cannot be used with the cid parameter. | Optional | 
| country | ISO-standardized country code or a comma-separated list of country codes. Can be retrieved by running the "na-ed-country-code-list" command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!na-ed-inbound-blacklisted-countries-remove country=AU```

#### Human Readable Output

>Countries were successfully removed from the inbound block listed list

### na-ed-outbound-blacklisted-hosts-list
***
Gets the outbound block listed hosts. By default, 10 block listed hosts are returned.


#### Base Command

`na-ed-outbound-blacklisted-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | Comma-separated list of IPv4 host addresses or CIDRs. | Optional | 
| query | Search strings, separated by “+” to filter the results. (example: "AZ+BS"). | Optional | 
| page | The page of the results to return. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.OutboundBlacklistHost.annotation | String | A description of the host. | 
| NetscoutAED.OutboundBlacklistHost.host_address | String | IPv4 host address or CIDRs. | 
| NetscoutAED.OutboundBlacklistHost.update_time | Date | The time the host was last updated/set. | 


#### Command Example
```!na-ed-outbound-blacklisted-hosts-list```

#### Context Example
```json
{
    "NetscoutAED": {
        "OutboundBlacklistHost": [
            {
              "annotation": "",
              "host_address": "1.1.1.1",
              "update_time": "2021-05-24T08:58:07.000Z"
            },
            {
              "annotation": "",
              "host_address": "2.2.2.2",
              "update_time": "2021-05-24T08:58:07.000Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Blacklisted Hosts
>|Host Address|Update Time|
>|---|---|
>| 1.1.1.1 | 2021-05-24T08:58:07.000Z |
>| 2.2.2.2 | 2021-05-24T08:58:07.000Z |


### na-ed-outbound-blacklisted-hosts-add
***
Adds one or more hosts to the outbound block list.


#### Base Command

`na-ed-outbound-blacklisted-hosts-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 host address or CIDR or a comma-separated list of IPv4 host addresses or CIDRs. | Required | 
| annotation | A single description that applies to all of the specified hosts or a comma-separated list of descriptions, each of which applies to a specific host. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.OutboundBlacklistHost.annotation | String | A description of the host. | 
| NetscoutAED.OutboundBlacklistHost.host_address | String | IPv4 host address or CIDRs. | 
| NetscoutAED.OutboundBlacklistHost.update_time | Date | The time the host was last updated/set | 


#### Command Example
```!na-ed-outbound-blacklisted-hosts-add host_address=1.2.3.4```

#### Context Example
```json
{
    "NetscoutAED": {
        "OutboundBlacklistHost": {
            "annotation": "",
            "host_address": "1.2.3.4",
            "update_time": "2021-05-24T08:58:07.000Z"
        }
    }
}
```

#### Human Readable Output

>Hosts were successfully added to the outbound block list list
>### New Hosts
>|Host Address|Update Time|
>|---|---|
>| 1.2.3.4 | 2021-05-24T08:58:07.000Z |


### na-ed-outbound-blacklisted-hosts-replace
***
Replaces all the hosts on the outbound block listed list.


#### Base Command

`na-ed-outbound-blacklisted-hosts-replace`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 host address or CIDR or a comma-separated list of IPv4 host addresses or CIDRs. | Required | 
| annotation | A single description that applies to all of the specified hosts or a comma-separated list of descriptions, each of which applies to a specific host. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.OutboundBlacklistHost.annotation | String | A description of the host. | 
| NetscoutAED.OutboundBlacklistHost.host_address | String | IPv4 host address or CIDRs. | 
| NetscoutAED.OutboundBlacklistHost.update_time | Date | The time the host was last updated/set. | 


#### Command Example
```!na-ed-outbound-blacklisted-hosts-replace host_address=5.2.3.4```

#### Context Example
```json
{
    "NetscoutAED": {
        "OutboundBlacklistHost": {
            "annotation": "",
            "host_address": "5.2.3.4",
            "update_time": "2021-05-24T08:58:08.000Z"
        }
    }
}
```

#### Human Readable Output

>Hosts were successfully replaced in the outbound block list list
>### New Hosts
>|Host Address|Update Time|
>|---|---|
>| 5.2.3.4 | 2021-05-24T08:58:08.000Z |


### na-ed-outbound-blacklisted-hosts-remove
***
Removes one or more hosts or CIDRS from the outbound block list.


#### Base Command

`na-ed-outbound-blacklisted-hosts-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 host address or CIDR to remove, or a comma-separated list of IPv4 host addresses or CIDRs to remove. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!na-ed-outbound-blacklisted-hosts-remove host_address=5.2.3.4```

#### Human Readable Output

>Hosts were successfully removed from the outbound block list list

### na-ed-outbound-whitelisted-hosts-list
***
Gets the outbound allow listed hosts. By default, 10 hosts on allow list are returned.


#### Base Command

`na-ed-outbound-whitelisted-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | Comma-separated list of IPv4 host addresses or CIDRs. | Optional | 
| query | Search strings, separated by “+” to filter the results. (example: "AZ+BS"). | Optional | 
| page | The page of the results to return. | Optional | 
| limit | Maximal number of results to retrieve. Also sets the size of the returned page. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.OutboundWhitelistHost.annotation | String | A description of the host. | 
| NetscoutAED.OutboundWhitelistHost.host_address | String | IPv4 host address or CIDRs. | 
| NetscoutAED.OutboundWhitelistHost.update_time | Date | The time the host was last updated/set. | 


#### Command Example
```!na-ed-outbound-whitelisted-hosts-list```

#### Context Example
```json
{
    "NetscoutAED": {
        "OutboundWhitelistHost": {
            "annotation": "",
            "host_address": "4.4.4.4",
            "update_time": "2021-05-24T08:53:20.000Z"
        }
    }
}
```

#### Human Readable Output

>### Whitelisted Hosts
>|Host Address|Update Time|
>|---|---|
>| 4.4.4.4 | 2021-05-24T08:53:20.000Z |


### na-ed-outbound-whitelisted-hosts-add
***
Adds one or more hosts to the outbound allow listed list.


#### Base Command

`na-ed-outbound-whitelisted-hosts-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 host address or CIDR or a comma-separated list of IPv4 host addresses or CIDRs to add. | Required | 
| annotation | A single description that applies to all of the specified hosts or a comma-separated list of descriptions, each of which applies to a specific host. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.OutboundWhitelistHost.annotation | String | A description of the host. | 
| NetscoutAED.OutboundWhitelistHost.host_address | String | IPv4 host address or CIDRs. | 
| NetscoutAED.OutboundWhitelistHost.update_time | Date | The time the host was last updated/set. | 


#### Command Example
```!na-ed-outbound-whitelisted-hosts-add host_address=3.3.3.3```

#### Context Example
```json
{
    "NetscoutAED": {
        "OutboundWhitelistHost": {
            "annotation": "",
            "host_address": "3.3.3.3",
            "update_time": "2021-05-24T08:58:19.000Z"
        }
    }
}
```

#### Human Readable Output

>Hosts were successfully added to the outbound allow list list
>### New Hosts
>|Host Address|Update Time|
>|---|---|
>| 3.3.3.3 | 2021-05-24T08:58:19.000Z |


### na-ed-outbound-whitelisted-hosts-replace
***
Replaces all the hosts on the outbound allow listed list.


#### Base Command

`na-ed-outbound-whitelisted-hosts-replace`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 host address or CIDR or a comma-separated list of IPv4 host addresses or CIDRs to update. | Required | 
| annotation | A single description that applies to all of the specified hosts or a comma-separated list of descriptions, each of which applies to a specific host. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.OutboundWhitelistHost.annotation | String | A description of the host. | 
| NetscoutAED.OutboundWhitelistHost.host_address | String | IPv4 host address or CIDRs. | 
| NetscoutAED.OutboundWhitelistHost.update_time | Date | The time the host was last updated/set. | 


#### Command Example
```!na-ed-outbound-whitelisted-hosts-replace host_address=3.3.3.3,4.4.4.4```

#### Context Example
```json
{
    "NetscoutAED": {
        "OutboundWhitelistHost": [
            {
                "annotation": "",
                "host_address": "3.3.3.3",
                "update_time": "2021-05-24T08:58:21.000Z"
            },
            {
                "annotation": "",
                "host_address": "4.4.4.4",
                "update_time": "2021-05-24T08:58:21.000Z"
            }
        ]
    }
}
```

#### Human Readable Output

>Hosts were successfully replaced in the outbound allow list list
>### New Hosts
>|Host Address|Update Time|
>|---|---|
>| 3.3.3.3 | 2021-05-24T08:58:21.000Z |
>| 4.4.4.4 | 2021-05-24T08:58:21.000Z |


### na-ed-protection-groups-update
***
Updates the settings for one or more protection groups.


#### Base Command

`na-ed-protection-groups-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pgid | List of protection group IDs. | Required | 
| active | Set the protection group mode to active (true) or inactive (false). Default: true. Possible values are: true, false. | Optional | 
| protection_level | The protection level (None = use the global protection level, low, medium, high). Default: low. Possible values are: None, low, medium, high. | Optional | 
| profiling | Turn traffic profiling on (true) or off (false) for one or more of the protection groups. Possible values are: true, false. | Optional | 
| profiling_duration | Required when profiling is set to true. Specify the number of days, from 1 to 14, over which profiling will run. Possible values are: 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.ProtectionGroup.active | Boolean | True if the protection group mode is active, false if inactive. | 
| NetscoutAED.ProtectionGroup.bps_dropped | Number | Number of dropped bps. | 
| NetscoutAED.ProtectionGroup.bps_passed | Number | Number of passed bps. | 
| NetscoutAED.ProtectionGroup.bytes_dropped | Number | Number of dropped bytes. | 
| NetscoutAED.ProtectionGroup.bytes_passed | Unknown | Number of passed bytes. | 
| NetscoutAED.ProtectionGroup.description | String | Description of the protection group. | 
| NetscoutAED.ProtectionGroup.name | String | Protection group name. | 
| NetscoutAED.ProtectionGroup.packets_dropped | Number | Number of dropped packets. | 
| NetscoutAED.ProtectionGroup.packets_passed | Number | Number of passed packets. | 
| NetscoutAED.ProtectionGroup.pgid | Number | Protection group identifier. | 
| NetscoutAED.ProtectionGroup.pps_passed | Number | Number of passed pps. | 
| NetscoutAED.ProtectionGroup.pps_dropped | Number | Number of dropped pps. | 
| NetscoutAED.ProtectionGroup.prefixes | Unknown | List of ‘,’ delimited prefixes belonging to the protection group. | 
| NetscoutAED.ProtectionGroup.profiling | Boolean | A traffic profile capture for a protection group’s rate-based protection settings is running \(true\) or not \(false\). | 
| NetscoutAED.ProtectionGroup.profiling_duration | Number | The duration, in days, of an active traffic profile capture. A 0 indicates that profiling is not active. | 
| NetscoutAED.ProtectionGroup.profiling_start | Date | A UNIX epoch timestamp that indicates when a traffic profile capture began. A 0 indicates that profiling was never started. | 
| NetscoutAED.ProtectionGroup.protection_level | Unknown | The protection level \(None = use the global protection level, low, medium, high\). | 
| NetscoutAED.ProtectionGroup.server_name | String | The protection group’s server name. | 
| NetscoutAED.ProtectionGroup.server_type | Number | The protection group’s server type. | 
| NetscoutAED.ProtectionGroup.time_created | Date | The time when the protection group was created. | 


#### Command Example
```!na-ed-protection-groups-update pgid=52 active=false```

#### Context Example
```json
{
    "NetscoutAED": {
        "ProtectionGroup": {
            "active": false,
            "bps_dropped": 0,
            "bps_passed": 0,
            "bytes_dropped": 0,
            "bytes_passed": 0,
            "description": "",
            "name": "test2",
            "packets_dropped": 0,
            "packets_passed": 0,
            "pgid": 52,
            "pps_dropped": 0,
            "pps_passed": 0,
            "prefixes": [
                "1.1.1.1/32"
            ],
            "profiling": false,
            "profiling_duration": 0,
            "profiling_start": 0,
            "protection_level": "global protection level",
            "server_name": "test2",
            "server_type": 35,
            "time_created": "2021-04-13T14:41:23.000Z"
        }
    }
}
```

#### Human Readable Output

>Successfully updated the protection group object with protection group id: 52
>### Protection Groups
>|Name|Pgid|Protection Level|Active|Server Name|Profiling|Profiling Duration|Time Created|
>|---|---|---|---|---|---|---|---|
>| test2 | 52 | global protection level | false | test2 | false | 0 | 2021-04-13T14:41:23.000Z |


### na-ed-protection-groups-list
***
Gets a list of the protection groups.


#### Base Command

`na-ed-protection-groups-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pgid | Protection group identifier. | Optional | 
| name | Protection group name. | Optional | 
| active | Whether the protection group is active or not. Possible values are: true, false. | Optional | 
| query | Search strings, separated by “+” to filter the results. (For example: "AZ+BS"). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.ProtectionGroup.active | Boolean | True if the protection group mode is active, false if inactive. | 
| NetscoutAED.ProtectionGroup.bps_dropped | Number | Number of dropped bps. | 
| NetscoutAED.ProtectionGroup.bps_passed | Number | Number of passed bps. | 
| NetscoutAED.ProtectionGroup.bytes_dropped | Number | Number of dropped bytes. | 
| NetscoutAED.ProtectionGroup.bytes_passed | Unknown | Number of passed bytes. | 
| NetscoutAED.ProtectionGroup.description | String | Description of the protection group. | 
| NetscoutAED.ProtectionGroup.name | String | Protection group name. | 
| NetscoutAED.ProtectionGroup.packets_dropped | Number | Number of dropped packets. | 
| NetscoutAED.ProtectionGroup.packets_passed | Number | Number of passed packets. | 
| NetscoutAED.ProtectionGroup.pgid | Number | Protection group identifier. | 
| NetscoutAED.ProtectionGroup.pps_passed | Number | Number of passed pps. | 
| NetscoutAED.ProtectionGroup.pps_dropped | Number | Number of dropped pps. | 
| NetscoutAED.ProtectionGroup.prefixes | Unknown | Comma-separated list of prefixes belonging to the protection group. | 
| NetscoutAED.ProtectionGroup.profiling | Boolean | A traffic profile capture for a protection group’s rate-based protection settings is running \(true\) or not \(false\). | 
| NetscoutAED.ProtectionGroup.profiling_duration | Number | The duration, in days, of an active traffic profile capture. A 0 indicates that profiling is not active. | 
| NetscoutAED.ProtectionGroup.profiling_start | Date | A UNIX epoch timestamp that indicates when a traffic profile capture began. A 0 indicats that profiling was never started. | 
| NetscoutAED.ProtectionGroup.protection_level | Unknown | The protection level \(None = use the global protection level, low, medium, high\). | 
| NetscoutAED.ProtectionGroup.server_name | String | The protection group’s server name. | 
| NetscoutAED.ProtectionGroup.server_type | Number | The protection group’s server type. | 
| NetscoutAED.ProtectionGroup.time_created | Date | The time when the protection group was created. | 
| NetscoutAED.ProtectionGroup.cid | Number | Central configuration ID. | 


#### Command Example
```!na-ed-protection-groups-list active=true```

#### Context Example
```json
{
    "NetscoutAED": {
        "ProtectionGroup": {
            "active": false,
            "bps_dropped": 0,
            "bps_passed": 0,
            "bytes_dropped": 0,
            "bytes_passed": 0,
            "description": "",
            "name": "test2",
            "packets_dropped": 0,
            "packets_passed": 0,
            "pgid": 52,
            "pps_dropped": 0,
            "pps_passed": 0,
            "prefixes": [
                "1.1.1.1/32"
            ],
            "profiling": true,
            "profiling_duration": 0,
            "profiling_start": 0,
            "protection_level": "global protection level",
            "server_name": "test2",
            "server_type": 35,
            "time_created": "2021-04-13T14:41:23.000Z"
        }
    }
}
```

#### Human Readable Output

>### Protection Groups
>|Name|Pgid|Protection Level|Active|Server Name|Profiling|Profiling Duration|Time Created|
>|---|---|---|---|---|---|---|---|
>| test2 | 52 | global protection level | true | test2 | false | 0 | 2021-04-13T14:41:23.000Z |

### na-ed-inbound-blacklisted-hosts-list
***
Gets the inbound block listed hosts. By default, 10 block listed hosts are returned. To return block listed hosts for specific protection groups, specify a list of protection group IDs or central configuration IDs. An ID of -1 selects hosts that are globally block listed.


#### Base Command

`na-ed-inbound-blacklisted-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | List of ‘,’ delimited IPv4 host addresses or CIDRs. | Optional | 
| query | Search strings, separated by “+” to filter the results. (For example: "AZ+BS"). | Optional | 
| page | The page of the results to return. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundBlacklistHost.annotation | Unknown | List of messages associated with each host in the inbound block list. | 
| NetscoutAED.InboundBlacklistHost.cid | Unknown | List of central configuration IDs. | 
| NetscoutAED.InboundBlacklistHost.host_address | String | IPv4 host addresses or CIDRs. | 
| NetscoutAED.InboundBlacklistHost.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundBlacklistHost.update_time | Date | The time that the host address was added to the list. | 


#### Command Example
```!na-ed-inbound-blacklisted-hosts-list```
#### Context Example
```json
{
    "NetscoutAED": {
        "InboundBlacklistHost": {
            "annotation": [
                ""
            ],
            "cid": [
                -1
            ],
            "host_address": "1.1.1.1",
            "pgid": [
                -1
            ],
            "update_time": "2021-05-24T08:58:13.000Z"
        }
    }
}
```

#### Human Readable Output

>### Blacklisted Hosts
>|Host Address|Pgid|Cid|Update Time|Annotation|
>|---|---|---|---|---|
>| 1.1.1.1 | -1 | -1 | 2021-05-24T08:58:13.000Z |  |


### na-ed-inbound-blacklisted-hosts-add
***
Adds one or more hosts to the inbound block listed list.


#### Base Command

`na-ed-inbound-blacklisted-hosts-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 or IPv6 host address or CIDR or a comma-separated list of host addresses or CIDRs. | Required | 
| annotation | A single description that applies to all of the specified hosts or a comma-separated list of descriptions, each of which applies to a specific host. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundBlacklistHost.annotation | Unknown | List of messages associated with each host in the inbound block list. | 
| NetscoutAED.InboundBlacklistHost.cid | Unknown | List of central configuration IDs | 
| NetscoutAED.InboundBlacklistHost.host_address | String | IPv4 host addresses or CIDRs. | 
| NetscoutAED.InboundBlacklistHost.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundBlacklistHostupdate_time | Date | The time that the host address was added to the list. | 


#### Command Example
```!na-ed-inbound-blacklisted-hosts-add host_address=1.2.3.4```

#### Context Example
```json
{
    "NetscoutAED": {
        "InboundBlacklistHost": {
            "annotation": [
                ""
            ],
            "cid": [
                -1
            ],
            "host_address": "1.2.3.4",
            "pgid": [
                -1
            ],
            "update_time": "2021-05-24T08:58:13.000Z"
        }
    }
}
```

#### Human Readable Output

>Hosts were successfully added to the inbound block list list
>### New Hosts
>|Host Address|Pgid|Cid|Update Time|Annotation|
>|---|---|---|---|---|
>| 1.2.3.4 | -1 | -1 | 2021-05-24T08:58:13.000Z |  |


### na-ed-inbound-blacklisted-hosts-replace
***
Replaces all the hosts on the inbound block list.


#### Base Command

`na-ed-inbound-blacklisted-hosts-replace`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 or IPv6 host address or CIDR or a comma-separated list of host addresses or CIDRs. | Required | 
| annotation | A single description that applies to all of the specified hosts or a comma-separated list of descriptions, each of which applies to a specific host. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundBlacklistHost.annotation | Unknown | List of messages associated with each host in the inbound block list. | 
| NetscoutAED.InboundBlacklistHost.cid | Unknown | List of central configuration IDs | 
| NetscoutAED.InboundBlacklistHost.host_address | String | IPv4 host addresses or CIDRs. | 
| NetscoutAED.InboundBlacklistHost.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundBlacklistHost.update_time | Date | The time that the host address was added to the list. | 


#### Command Example
```!na-ed-inbound-blacklisted-hosts-replace host_address=5.2.3.4```

#### Context Example
```json
{
    "NetscoutAED": {
        "InboundBlacklistHost": {
            "annotation": [
                ""
            ],
            "cid": [
                -1
            ],
            "host_address": "5.2.3.4",
            "pgid": [
                -1
            ],
            "update_time": "2021-05-24T08:58:15.000Z"
        }
    }
}
```

#### Human Readable Output

>Hosts were successfully replaced in the inbound block list list
>### New Hosts
>|Host Address|Pgid|Cid|Update Time|Annotation|
>|---|---|---|---|---|
>| 5.2.3.4 | -1 | -1 | 2021-05-24T08:58:15.000Z |  |


### na-ed-inbound-blacklisted-hosts-remove
***
Removes one or more hosts or CIDRs from the block list for a specific protection group or for all protection groups.


#### Base Command

`na-ed-inbound-blacklisted-hosts-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 or IPv6 host address or CIDR, or a comma-separated list of host addresses or CIDRs. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!na-ed-inbound-blacklisted-hosts-remove host_address=5.2.3.4```

#### Human Readable Output

>Hosts were successfully removed from the inbound block list list

### na-ed-inbound-whitelisted-hosts-list
***
Get the hosts on allow list. By default, 10 hosts on allow list are returned. To return hosts on allow list for specific protection groups, specify a list of protection group IDs or central configuration IDs. An ID of -1 selects hosts that are globally on allow list.


#### Base Command

`na-ed-inbound-whitelisted-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | Comma-separated list of IPv4 or IPv6 host addresses or CIDRs. | Optional | 
| query | Search strings, separated by “+” to filter the results. (example: "AZ+BS"). | Optional | 
| page | The page of the results to return. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundWhitelistHost.annotation | Unknown | List of messages associated with each host in the inbound allow listed list. | 
| NetscoutAED.InboundWhitelistHost.cid | Unknown | List of central configuration IDs | 
| NetscoutAED.InboundWhitelistHost.host_address | String | IPv4 host addresses or CIDRs. | 
| NetscoutAED.InboundWhitelistHost.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundWhitelistHost.update_time | Date | The time that the host address was added to the list. | 


#### Command Example
```!na-ed-inbound-whitelisted-hosts-list```

```json
{
    "NetscoutAED": {
        "InboundWhitelistHost": {
            "annotation": [
                ""
            ],
            "cid": [
                -1
            ],
            "host_address": "2.2.2.2",
            "pgid": [
                -1
            ],
            "update_time": "2021-05-24T08:58:25.000Z"
        }
    }
}
```

#### Human Readable Output

>### Whitelisted Hosts
>|Host Address|Pgid|Cid|Update Time|Annotation|
>|---|---|---|---|---|
>| 2.2.2.2 | -1 | -1 | 2021-05-24T08:58:25.000Z |  |


### na-ed-inbound-whitelisted-hosts-add
***
Adds one or more hosts to the inbound allow listed list.


#### Base Command

`na-ed-inbound-whitelisted-hosts-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 or IPv6 host address or CIDR or a comma-separated list of host addresses or CIDRs to add. | Required | 
| annotation | A single description that applies to all of the specified hosts or a comma-separated list of descriptions, each of which applies to a specific host. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundWhitelistHost.annotation | Unknown | List of messages associated with each host in the inbound allow listed list. | 
| NetscoutAED.InboundWhitelistHost.cid | Unknown | List of central configuration IDs | 
| NetscoutAED.InboundWhitelistHost.host_address | String | IPv4 host addresses or CIDRs. | 
| NetscoutAED.InboundWhitelistHost.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundWhitelistHost.update_time | Date | The time that the host address was added to the list. | 


#### Command Example
```!na-ed-inbound-whitelisted-hosts-add host_address=1.2.3.4```

#### Context Example
```json
{
    "NetscoutAED": {
        "InboundWhitelistHost": {
            "annotation": [
                ""
            ],
            "cid": [
                -1
            ],
            "host_address": "1.2.3.4",
            "pgid": [
                -1
            ],
            "update_time": "2021-05-24T08:58:25.000Z"
        }
    }
}
```

#### Human Readable Output

>Hosts were successfully added to the inbound allow list list
>### New Hosts
>|Host Address|Pgid|Cid|Update Time|Annotation|
>|---|---|---|---|---|
>| 1.2.3.4 | -1 | -1 | 2021-05-24T08:58:25.000Z |  |


### na-ed-inbound-whitelisted-hosts-replace
***
Replaces all the hosts on the inbound allow list.


#### Base Command

`na-ed-inbound-whitelisted-hosts-replace`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 or IPv6 host address or CIDR or a comma-separated list of host addresses or CIDRs to update. | Required | 
| annotation | A single description that applies to all of the specified hosts or a comma-separated list of descriptions, each of which applies to a specific host. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundWhitelistHost.annotation | Unknown | List of messages associated with each host in the inbound allow listed list. | 
| NetscoutAED.InboundWhitelistHost.cid | Unknown | List of central configuration IDs | 
| NetscoutAED.InboundWhitelistHost.host_address | String | IPv4 host addresses or CIDRs. | 
| NetscoutAED.InboundWhitelistHost.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundWhitelistHost.update_time | Date | The time that the host address was added to the list. | 


#### Command Example
```!na-ed-inbound-whitelisted-hosts-replace host_address=5.2.3.4```

#### Context Example
```json
{
    "NetscoutAED": {
        "InboundWhitelistHost": {
            "annotation": [
                ""
            ],
            "cid": [
                -1
            ],
            "host_address": "5.2.3.4",
            "pgid": [
                -1
            ],
            "update_time": "2021-05-24T08:58:26.000Z"
        }
    }
}
```

#### Human Readable Output

>Hosts were successfully replaced in the inbound allow list list
>### New Hosts
>|Host Address|Pgid|Cid|Update Time|Annotation|
>|---|---|---|---|---|
>| 5.2.3.4 | -1 | -1 | 2021-05-24T08:58:26.000Z |  |


### na-ed-inbound-whitelisted-hosts-remove
***
Removes one or more hosts or CIDRs from the allow list for a specific protection group or for all protection groups.


#### Base Command

`na-ed-inbound-whitelisted-hosts-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 or IPv6 host address or CIDR, or a comma-separated list of host addresses or CIDRs to remove. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!na-ed-inbound-whitelisted-hosts-remove host_address=5.2.3.4```

#### Human Readable Output

>Hosts were successfully removed from the inbound whitelist list

### na-ed-inbound-blacklisted-domains-list
***
Gets the block listed domains. By default, 10 block listed domains are returned. To return block listed domains for specific protection groups, specify a list of protection group IDs or central configuration IDs. An ID of -1 selects domains that are globally block listed.


#### Base Command

`na-ed-inbound-blacklisted-domains-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid | Comma-separated list of central configuration IDs. Cannot be used with the pgid parameter. | Optional | 
| pgid | Comma-separated list of protection group IDs. Cannot be used with the cid parameter. | Optional | 
| domain | Comma-separated list of domains. | Optional | 
| query | Search strings, separated by “+” to filter the results. (example: "AZ+BS"). | Optional | 
| page | The page of the results to return. | Optional | 
| limit | The maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundBlacklistDomain.annotation | Unknown | List of messages associated with each domain in the inbound block list. | 
| NetscoutAED.InboundBlacklistDomain.cid | Unknown | List of central configuration IDs. | 
| NetscoutAED.InboundBlacklistDomain.domain | String | Domain name. | 
| NetscoutAED.InboundBlacklistDomain.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundBlacklistDomain.update_time | Date | The time that the domain was added to the list. | 


#### Command Example
```!na-ed-inbound-blacklisted-domains-list```

#### Context Example
```json
{
    "NetscoutAED": {
        "InboundBlacklistDomain": [
            {
                "annotation": [
                    "try1"
                ],
                "cid": [
                    -1
                ],
                "domain": "sport.co.il",
                "pgid": [
                    -1
                ],
                "update_time": "2021-03-15T16:00:24.000Z"
            },
            {
                "annotation": [],
                "cid": [
                    -1
                ],
                "domain": "sport.com",
                "pgid": [
                    -1
                ],
                "update_time": "2021-03-18T17:25:26.000Z"
            },
            {
                "annotation": [],
                "cid": [
                    -1
                ],
                "domain": "ynet.com",
                "pgid": [
                    -1
                ],
                "update_time": "2021-03-18T16:49:50.000Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### Blacklisted Domains
>|Domain|Pgid|Cid|Update Time|Annotation|
>|---|---|---|---|---|
>| sport.co.il | -1 | -1 | 2021-03-15T16:00:24.000Z | try1 |
>| sport.com | -1 | -1 | 2021-03-18T17:25:26.000Z |  |
>| ynet.com | -1 | -1 | 2021-03-18T16:49:50.000Z |  |


### na-ed-inbound-blacklisted-domains-add
***
Adds one or more domains to the block list by pgid or cid.


#### Base Command

`na-ed-inbound-blacklisted-domains-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid | A specific central configuration ID or -1 for global. Cannot be used with the pgid parameter. | Optional | 
| pgid | A specific protection group ID or -1 for global. Cannot be used with the cid parameter. | Optional | 
| domain | Domain name or a comma-separated list of domain names. | Required | 
| annotation | A message to associate with each domain that you add to the block list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundBlacklistDomain.annotation | Unknown | List of messages associated with each domain in the inbound blaok list. | 
| NetscoutAED.InboundBlacklistDomain.cid | Unknown | List of central configuration IDs. | 
| NetscoutAED.InboundBlacklistDomain.domain | String | Domain name. | 
| NetscoutAED.InboundBlacklistDomain.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundBlacklistDomain.update_time | Unknown | The time that the domain was added to the list. | 


#### Command Example
```!na-ed-inbound-blacklisted-domains-add domain=goo.com```

#### Context Example
```json
{
    "NetscoutAED": {
        "InboundBlacklistDomain": {
            "annotation": [],
            "cid": [
                -1
            ],
            "domain": "goo.com",
            "pgid": [
                -1
            ],
            "update_time": "2021-05-24T08:58:34.000Z"
        }
    }
}
```

#### Human Readable Output

>Domains were successfully added to the inbound block listed list
>### Added Domains
>|Domain|Pgid|Cid|Update Time|
>|---|---|---|---|
>| goo.com | -1 | -1 | 2021-05-24T08:58:34.000Z |


### na-ed-inbound-blacklisted-domains-remove
***
Removes one or more domains from the block list for a specific protection group or for all protection groups.


#### Base Command

`na-ed-inbound-blacklisted-domains-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name or a comma-separated list of domain names. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!na-ed-inbound-blacklisted-domains-remove domain=goo.com```

#### Human Readable Output

>Domains were successfully removed from the inbound block listed list

### na-ed-inbound-blacklisted-urls-list
***
Gets the block listed URLs. By default, 10 block listed URLs are returned. To return block listed URLs for specific protection groups, specify a list of protection group IDs or central configuration IDs. An ID of -1 selects URLs that are globally block listed.


#### Base Command

`na-ed-inbound-blacklisted-urls-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid | Comma-separated list of central configuration IDs. Cannot be used with the pgid parameter. | Optional | 
| pgid | Comma-separated list of protection group IDs. Cannot be used with the cid parameter. | Optional | 
| url | Comma-separated list of URLs. | Optional | 
| query | Search strings, separated by “+” to filter the results. (example: "AZ+BS"). | Optional | 
| page | The page of the results to return. | Optional | 
| limit | Maximum number of results to retrieve. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundBlacklistUrl.annotation | Unknown | List of messages associated with each URL in the inbound block list. | 
| NetscoutAED.InboundBlacklistUrl.cid | Unknown | List of central configuration ID.s | 
| NetscoutAED.InboundBlacklistUrl.url | String | URL address. | 
| NetscoutAED.InboundBlacklistUrl.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundBlacklistUrl.update_time | Date | The time that the domain was added to the list. | 


#### Command Example
```!na-ed-inbound-blacklisted-urls-list limit=3```

#### Context Example
```json
{
    "NetscoutAED": {
        "InboundBlacklistUrl": [
            {
                "annotation": [],
                "cid": [
                    -1
                ],
                "pgid": [
                    -1
                ],
                "update_time": "2021-03-18T16:52:26.000Z",
                "url": "google.com"
            },
            {
                "annotation": [
                    "Google Maps"
                ],
                "cid": [
                    -1
                ],
                "pgid": [
                    -1
                ],
                "update_time": "2021-03-18T18:08:39.000Z",
                "url": "maps.google.com"
            },
            {
                "annotation": [
                    "Google Maps"
                ],
                "cid": [
                    -1
                ],
                "pgid": [
                    -1
                ],
                "update_time": "2021-03-18T18:08:27.000Z",
                "url": "maps.google.com/sport.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Blacklisted URLs
>|Url|Pgid|Cid|Update Time|Annotation|
>|---|---|---|---|---|
>| google.com | -1 | -1 | 2021-03-18T16:52:26.000Z |  |
>| maps.google.com | -1 | -1 | 2021-03-18T18:08:39.000Z | Google Maps |
>| maps.google.com/sport.com | -1 | -1 | 2021-03-18T18:08:27.000Z | Google Maps |


### na-ed-inbound-blacklisted-urls-add
***
Adds one or more URLs to the block list by pgid or cid.


#### Base Command

`na-ed-inbound-blacklisted-urls-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cid | A specific central configuration ID or -1 for global. Cannot be used with the pgid parameter. | Optional | 
| pgid | A specific protection group ID or -1 for global. Cannot be used with the cid parameter. | Optional | 
| url | URL or a comma-separated list of URLs to add. | Required | 
| annotation | A message to associate with each URL that you add to the block list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| NetscoutAED.InboundBlacklistUrl.annotation | Unknown | List of messages associated with each url in the inbound block list. | 
| NetscoutAED.InboundBlacklistUrl.cid | Unknown | List of central configuration IDs | 
| NetscoutAED.InboundBlacklistUrl.url | String | URL address. | 
| NetscoutAED.InboundBlacklistUrl.pgid | Unknown | List of protection group ID. | 
| NetscoutAED.InboundBlacklistUrl.update_time | Date | The time that the domain was added to the list. | 


#### Command Example
```!na-ed-inbound-blacklisted-urls-add url=www.goo.com```

#### Context Example
```json
{
    "NetscoutAED": {
        "InboundBlacklistUrl": {
            "annotation": [],
            "cid": [
                -1
            ],
            "pgid": [
                -1
            ],
            "update_time": "2021-05-24T08:58:39.000Z",
            "url": "www.goo.com"
        }
    }
}
```

#### Human Readable Output

>Urls were successfully added to the inbound block listed list
>### Added Urls
>|Url|Pgid|Cid|Update Time|
>|---|---|---|---|
>| www.goo.com | -1 | -1 | 2021-05-24T08:58:39.000Z |


### na-ed-inbound-blacklisted-urls-remove
***
Removes one or more URLs from the block list for a specific protection group or for all protection groups.


#### Base Command

`na-ed-inbound-blacklisted-urls-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL or a comma-separated list of URLs. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!na-ed-inbound-blacklisted-urls-remove url=www.goo.com```

#### Human Readable Output

>Urls were successfully removed from the inbound block listed list

### na-ed-outbound-whitelisted-hosts-remove
***
Removes one or more hosts or CIDRs from the outbound allow list.


#### Base Command

`na-ed-outbound-whitelisted-hosts-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_address | A single IPv4 host address or CIDR, or a comma-separated list of IPv4 host addresses or CIDRs to remove. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!na-ed-outbound-whitelisted-hosts-remove host_address=3.3.3.3```

#### Human Readable Output

>Hosts were successfully removed from the outbound allow list list