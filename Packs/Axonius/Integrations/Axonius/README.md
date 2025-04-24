This integration is for fetching information about assets in Axonius.
This integration was integrated and tested with version 3.9 of Axonius

## Configure Axonius in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://example.net) | True |
| Axonius API Key | True |
| Axonius API Secret | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### axonius-get-devices-by-savedquery
***
Gather device info by saved query


#### Base Command

`axonius-get-devices-by-savedquery`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| saved_query_name | The name of the devices saved query within Axonius. See https://docs.axonius.com/docs/saved-queries-devices. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Devices.adapters | String | The specific adapter names with asset information | 
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Devices.hostname | String | The hostnames of the assset | 
| Axonius.Devices.name | String | The names of the asset | 
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset | 
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset | 
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\) | 
| Axonius.Devices.labels | String | Tags assigned to the asset | 

#### Command Example
```!axonius-get-devices-by-savedquery saved_query_name=example_query```

#### Context Example
```
{
    "Axonius": {
        "Devices": {
            "adapter_list_length": 5,
            "adapters": [
                "nexpose_adapter",
                "esx_adapter",
                "active_directory_adapter",
                "solarwinds_orion_adapter",
                "crowd_strike_adapter",
                "esx_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "esx_adapter"
            ],
            "aggregated_hostname": [
                "DC4"
            ],
            "aggregated_last_seen": "2020-09-08T06:44:31+00:00",
            "aggregated_name": [
                "Windows%20Server%202012%20r2%20dc4.TestDomain.test%20(Avidor)",
                "DC4",
                "Windows Server 2012 R2",
                "Windows Server - 2012 - R2"
            ],
            "aggregated_network_interfaces_ips": [
                "x.x.x.x",
            ],
            "aggregated_network_interfaces_mac": [
                "00:0C:29:B6:DA:46",
                "00:50:56:91:DE:BB",
                "00:50:56:91:3A:EC",
                "00:50:56:91:33:E2",
                "00:50:56:91:21:B3"
            ],
            "aggregated_os_type": [
                "Windows"
            ],
            "internal_axon_id": "d530db3cfef6a2220b315d54fa1901b2"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_hostname|aggregated_last_seen|aggregated_name|aggregated_network_interfaces_ips|aggregated_network_interfaces_mac|aggregated_os_type|internal_axon_id|
>|---|---|---|---|---|---|---|---|---|
>| 5 | nexpose_adapter,<br/>esx_adapter,<br/>active_directory_adapter,<br/>solarwinds_orion_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter | DC4 | 2020-09-08T06:44:31+00:00 | Windows%20Server%202012%20r2%20dc4.TestDomain.test%20(Avidor),<br/>DC4,<br/>Windows Server 2012 R2,<br/>Windows Server - 2012 - R2 | 192.168.20.17,<br/>192.168.20.58,<br/>fe80::2dba:9118:1fc8:7759,<br/>192.168.20.36,<br/>192.168.20.50,<br/>192.168.20.61 | 00:0C:29:B6:DA:46,<br/>00:50:56:91:DE:BB,<br/>00:50:56:91:3A:EC,<br/>00:50:56:91:33:E2,<br/>00:50:56:91:21:B3 | Windows | d530db3cfef6a2220b315d54fa1901b2 |

### axonius-get-devices-by-aql
***
Gather devices info by AQL query


#### Base Command

`axonius-get-devices-by-aql`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The AQL query to filter devices by. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Devices.adapters | String | The specific adapter names with asset information | 
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Devices.hostname | String | The hostnames of the assset | 
| Axonius.Devices.name | String | The names of the asset | 
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset | 
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset | 
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\) | 
| Axonius.Devices.labels | String | Tags assigned to the asset | 

#### Command Example
```!axonius-get-devices-by-aql query="((\"specific_data.data.name\" == ({\"$exists\":true,\"$ne\":\"\"})))" max_results="50"```

#### Context Example
```
{
    "Axonius": {
        "Devices": {
            "adapter_list_length": 5,
            "adapters": [
                "nexpose_adapter",
                "esx_adapter",
                "active_directory_adapter",
                "solarwinds_orion_adapter",
                "crowd_strike_adapter",
                "esx_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "esx_adapter"
            ],
            "aggregated_hostname": [
                "DC4"
            ],
            "aggregated_last_seen": "2020-09-08T06:44:31+00:00",
            "aggregated_name": [
                "Windows%20Server%202012%20r2%20dc4.TestDomain.test%20(Avidor)",
                "DC4",
                "Windows Server 2012 R2",
                "Windows Server - 2012 - R2"
            ],
            "aggregated_network_interfaces_ips": [
                "x.x.x.x",
            ],
            "aggregated_network_interfaces_mac": [
                "00:0C:29:B6:DA:46",
                "00:50:56:91:DE:BB",
                "00:50:56:91:3A:EC",
                "00:50:56:91:33:E2",
                "00:50:56:91:21:B3"
            ],
            "aggregated_os_type": [
                "Windows"
            ],
            "internal_axon_id": "d530db3cfef6a2220b315d54fa1901b2"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_hostname|aggregated_last_seen|aggregated_name|aggregated_network_interfaces_ips|aggregated_network_interfaces_mac|aggregated_os_type|internal_axon_id|
>|---|---|---|---|---|---|---|---|---|
>| 5 | nexpose_adapter,<br/>esx_adapter,<br/>active_directory_adapter,<br/>solarwinds_orion_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter | DC4 | 2020-09-08T06:44:31+00:00 | Windows%20Server%202012%20r2%20dc4.TestDomain.test%20(Avidor),<br/>DC4,<br/>Windows Server 2012 R2,<br/>Windows Server - 2012 - R2 | 192.168.20.17,<br/>192.168.20.58,<br/>fe80::2dba:9118:1fc8:7759,<br/>192.168.20.36,<br/>192.168.20.50,<br/>192.168.20.61 | 00:0C:29:B6:DA:46,<br/>00:50:56:91:DE:BB,<br/>00:50:56:91:3A:EC,<br/>00:50:56:91:33:E2,<br/>00:50:56:91:21:B3 | Windows | d530db3cfef6a2220b315d54fa1901b2 |

### axonius-get-users-by-aql
***
Gather users info by AQL query


#### Base Command

`axonius-get-users-by-aql`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The AQL query to filter users by. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Users.adapters | String | The specific adapter names with asset information | 
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Users.username | String | Username of the asset | 
| Axonius.Users.mail | String | Email address of the asset | 
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges | 
| Axonius.Users.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Users.labels | String | Tags assigned to the asset | 


#### Command Example
```!axonius-get-users-by-aql query="((\"specific_data.data.username\" == ({\"$exists\":true,\"$ne\":\"\"})))" max_results="50"```

#### Context Example
```
{
    "Axonius": {
        "Users": {
            "adapter_list_length": 1,
            "adapters": [
                "active_directory_adapter"
            ],
            "aggregated_domain": "TestDomain.test",
            "aggregated_is_admin": false,
            "aggregated_last_seen": "2018-11-01T14:48:59+00:00",
            "aggregated_username": "test_ldap_login_user",
            "internal_axon_id": "4d5f47f067388e8ffc53b6bbe8a10800"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_domain|aggregated_is_admin|aggregated_last_seen|aggregated_username|internal_axon_id|
>|---|---|---|---|---|---|---|
>| 1 | active_directory_adapter | TestDomain.test | false | 2018-11-01T14:48:59+00:00 | test_ldap_login_user | 4d5f47f067388e8ffc53b6bbe8a10800 |

### axonius-get-users-by-savedquery
***
Gather user info by saved query


#### Base Command

`axonius-get-users-by-savedquery`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| saved_query_name | The name of the users saved query within Axonius. See https://docs.axonius.com/docs/saved-queries-users. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Users.adapters | String | The specific adapter names with asset information | 
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Users.username | String | Username of the asset | 
| Axonius.Users.mail | String | Email address of the asset | 
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges | 
| Axonius.Users.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Users.labels | String | Tags assigned to the asset | 


#### Command Example
```!axonius-get-users-by-savedquery saved_query_name=example_query```

#### Context Example
```
{
    "Axonius": {
        "Users": {
            "adapter_list_length": 1,
            "adapters": [
                "active_directory_adapter"
            ],
            "aggregated_domain": "TestDomain.test",
            "aggregated_is_admin": false,
            "aggregated_last_seen": "2018-11-01T14:48:59+00:00",
            "aggregated_username": "test_ldap_login_user",
            "internal_axon_id": "4d5f47f067388e8ffc53b6bbe8a10800"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_domain|aggregated_is_admin|aggregated_last_seen|aggregated_username|internal_axon_id|
>|---|---|---|---|---|---|---|
>| 1 | active_directory_adapter | TestDomain.test | false | 2018-11-01T14:48:59+00:00 | test_ldap_login_user | 4d5f47f067388e8ffc53b6bbe8a10800 |

### axonius-get-users-by-mail
***
Gather user info by email address


#### Base Command

`axonius-get-users-by-mail`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The user email address to search for within Axonius. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Users.adapters | String | The specific adapter names with asset information | 
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Users.username | String | Username of the asset | 
| Axonius.Users.mail | String | Email address of the asset | 
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges | 
| Axonius.Users.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Users.labels | String | Tags assigned to the asset | 

#### Command Example
```!axonius-get-users-by-mail value=Administrator@testdomain.test```

#### Context Example
```
{
    "Axonius": {
        "Users": {
            "adapter_list_length": 1,
            "adapters": [
                "active_directory_adapter"
            ],
            "aggregated_mail": [
                "Administrator@testdomain.test"
            ],
            "aggregated_username": [
                "Administrator"
            ],
            "internal_axon_id": "a6f0d051a30d401b7f73416fbc90a3cf"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_mail|aggregated_username|internal_axon_id|
>|---|---|---|---|---|
>| 1 | active_directory_adapter | Administrator@testdomain.test | Administrator | a6f0d051a30d401b7f73416fbc90a3cf |

### axonius-get-users-by-mail-regex
***
Gather user info by email address using regex


#### Base Command

`axonius-get-users-by-mail-regex`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The user email address to search for within Axonius. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Users.adapters | String | The specific adapter names with asset information | 
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Users.username | String | Username of the asset | 
| Axonius.Users.mail | String | Email address of the asset | 
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges | 
| Axonius.Users.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Users.labels | String | Tags assigned to the asset | 


#### Command Example
```!axonius-get-users-by-mail-regex value=Administrator```

#### Context Example
```
{
    "Axonius": {
        "Users": {
            "adapter_list_length": 1,
            "adapters": [
                "active_directory_adapter"
            ],
            "aggregated_mail": [
                "Administrator@testdomain.test"
            ],
            "aggregated_username": [
                "Administrator"
            ],
            "internal_axon_id": "a6f0d051a30d401b7f73416fbc90a3cf"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_mail|aggregated_username|internal_axon_id|
>|---|---|---|---|---|
>| 1 | active_directory_adapter | Administrator@testdomain.test | Administrator | a6f0d051a30d401b7f73416fbc90a3cf |


### axonius-get-users-by-username
***
Gather user info by username


#### Base Command

`axonius-get-users-by-username`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The username to search for within Axonius. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Users.adapters | String | The specific adapter names with asset information | 
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Users.username | String | Username of the asset | 
| Axonius.Users.mail | String | Email address of the asset | 
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges | 
| Axonius.Users.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Users.labels | String | Tags assigned to the asset | 


#### Command Example
```!axonius-get-users-by-username value=test_ldap_login_user```

#### Context Example
```
{
    "Axonius": {
        "Users": {
            "adapter_list_length": 1,
            "adapters": [
                "active_directory_adapter"
            ],
            "aggregated_username": "test_ldap_login_user",
            "internal_axon_id": "4d5f47f067388e8ffc53b6bbe8a10800"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_username|internal_axon_id|
>|---|---|---|---|
>| 1 | active_directory_adapter | test_ldap_login_user | 4d5f47f067388e8ffc53b6bbe8a10800 |

### axonius-get-users-by-username-regex
***
Gather user info by username using regex


#### Base Command

`axonius-get-users-by-username-regex`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The username to search for within Axonius. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Users.adapters | String | The specific adapter names with asset information | 
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Users.username | String | Username of the asset | 
| Axonius.Users.mail | String | Email address of the asset | 
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges | 
| Axonius.Users.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Users.labels | String | Tags assigned to the asset | 

#### Command Example
```!axonius-get-users-by-username-regex value=test```

#### Context Example
```
{
    "Axonius": {
        "Users": {
            "adapter_list_length": 1,
            "adapters": [
                "active_directory_adapter"
            ],
            "aggregated_username": "test_ldap_login_user",
            "internal_axon_id": "4d5f47f067388e8ffc53b6bbe8a10800"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_username|internal_axon_id|
>|---|---|---|---|
>| 1 | active_directory_adapter | test_ldap_login_user | 4d5f47f067388e8ffc53b6bbe8a10800 |

### axonius-get-devices-by-hostname
***
Gather device info by hostname


#### Base Command

`axonius-get-devices-by-hostname`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The hostname to search for within Axonius. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Devices.adapters | String | The specific adapter names with asset information | 
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Devices.hostname | String | The hostnames of the assset | 
| Axonius.Devices.name | String | The names of the asset | 
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset | 
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset | 
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\) | 
| Axonius.Devices.labels | String | Tags assigned to the asset | 

#### Command Example
```!axonius-get-devices-by-hostname value=DC4```

#### Context Example
```
{
    "Axonius": {
        "Devices": {
            "adapter_list_length": 5,
            "adapters": [
                "nexpose_adapter",
                "esx_adapter",
                "active_directory_adapter",
                "solarwinds_orion_adapter",
                "crowd_strike_adapter",
                "esx_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "esx_adapter"
            ],
            "aggregated_hostname": [
                "DC4"
            ],
            "aggregated_network_interfaces_ips": [
                "x.x.x.x",
            ],
            "aggregated_network_interfaces_mac": [
                "00:0C:29:B6:DA:46",
                "00:50:56:91:DE:BB",
                "00:50:56:91:3A:EC",
                "00:50:56:91:33:E2",
                "00:50:56:91:21:B3"
            ],
            "aggregated_network_interfaces_subnets": [
                "x.x.x.x/24"
            ],
            "internal_axon_id": "d530db3cfef6a2220b315d54fa1901b2"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_hostname|aggregated_network_interfaces_ips|aggregated_network_interfaces_mac|aggregated_network_interfaces_subnets|internal_axon_id|
>|---|---|---|---|---|---|---|
>| 5 | nexpose_adapter,<br/>esx_adapter,<br/>active_directory_adapter,<br/>solarwinds_orion_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter | DC4 | 192.168.20.17,<br/>192.168.20.58,<br/>fe80::2dba:9118:1fc8:7759,<br/>192.168.20.36,<br/>192.168.20.50,<br/>192.168.20.61 | 00:0C:29:B6:DA:46,<br/>00:50:56:91:DE:BB,<br/>00:50:56:91:3A:EC,<br/>00:50:56:91:33:E2,<br/>00:50:56:91:21:B3 | x.x.x.x/24 | d530db3cfef6a2220b315d54fa1901b2 |

### axonius-get-devices-by-hostname-regex
***
Gather device info by hostname using regex


#### Base Command

`axonius-get-devices-by-hostname-regex`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The hostname to search for within Axonius using regex. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Devices.adapters | String | The specific adapter names with asset information | 
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Devices.hostname | String | The hostnames of the assset | 
| Axonius.Devices.name | String | The names of the asset | 
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset | 
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset | 
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\) | 
| Axonius.Devices.labels | String | Tags assigned to the asset | 


#### Command Example
```!axonius-get-devices-by-hostname-regex value=DC4```

#### Context Example
```
{
    "Axonius": {
        "Devices": {
            "adapter_list_length": 5,
            "adapters": [
                "nexpose_adapter",
                "esx_adapter",
                "active_directory_adapter",
                "solarwinds_orion_adapter",
                "crowd_strike_adapter",
                "esx_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "esx_adapter"
            ],
            "aggregated_hostname": [
                "DC4"
            ],
            "aggregated_network_interfaces_ips": [
                "x.x.x.x",
            ],
            "aggregated_network_interfaces_mac": [
                "00:0C:29:B6:DA:46",
                "00:50:56:91:DE:BB",
                "00:50:56:91:3A:EC",
                "00:50:56:91:33:E2",
                "00:50:56:91:21:B3"
            ],
            "aggregated_network_interfaces_subnets": [
                "x.x.x.x/24"
            ],
            "internal_axon_id": "d530db3cfef6a2220b315d54fa1901b2"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_hostname|aggregated_network_interfaces_ips|aggregated_network_interfaces_mac|aggregated_network_interfaces_subnets|internal_axon_id|
>|---|---|---|---|---|---|---|
>| 5 | nexpose_adapter,<br/>esx_adapter,<br/>active_directory_adapter,<br/>solarwinds_orion_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter | DC4 | 192.168.20.17,<br/>192.168.20.58,<br/>fe80::2dba:9118:1fc8:7759,<br/>192.168.20.36,<br/>192.168.20.50,<br/>192.168.20.61 | 00:0C:29:B6:DA:46,<br/>00:50:56:91:DE:BB,<br/>00:50:56:91:3A:EC,<br/>00:50:56:91:33:E2,<br/>00:50:56:91:21:B3 | x.x.x.x/24 | d530db3cfef6a2220b315d54fa1901b2 |


### axonius-get-devices-by-ip
***
Gather device info by IP address


#### Base Command

`axonius-get-devices-by-ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The IP address to search for within Axonius. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Devices.adapters | String | The specific adapter names with asset information | 
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Devices.hostname | String | The hostnames of the assset | 
| Axonius.Devices.name | String | The names of the asset | 
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset | 
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset | 
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\) | 
| Axonius.Devices.labels | String | Tags assigned to the asset | 


#### Command Example
```!axonius-get-devices-by-ip value=192.168.20.17```

#### Context Example
```
{
    "Axonius": {
        "Devices": {
            "adapter_list_length": 5,
            "adapters": [
                "nexpose_adapter",
                "esx_adapter",
                "active_directory_adapter",
                "solarwinds_orion_adapter",
                "crowd_strike_adapter",
                "esx_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "esx_adapter"
            ],
            "aggregated_hostname": [
                "DC4"
            ],
            "aggregated_network_interfaces_ips": [
                "x.x.x.x",
            ],
            "aggregated_network_interfaces_mac": [
                "00:0C:29:B6:DA:46",
                "00:50:56:91:DE:BB",
                "00:50:56:91:3A:EC",
                "00:50:56:91:33:E2",
                "00:50:56:91:21:B3"
            ],
            "aggregated_network_interfaces_subnets": [
                "x.x.x.x/24"
            ],
            "internal_axon_id": "d530db3cfef6a2220b315d54fa1901b2"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_hostname|aggregated_network_interfaces_ips|aggregated_network_interfaces_mac|aggregated_network_interfaces_subnets|internal_axon_id|
>|---|---|---|---|---|---|---|
>| 5 | nexpose_adapter,<br/>esx_adapter,<br/>active_directory_adapter,<br/>solarwinds_orion_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter | DC4 | 192.168.20.17,<br/>192.168.20.58,<br/>fe80::2dba:9118:1fc8:7759,<br/>192.168.20.36,<br/>192.168.20.50,<br/>192.168.20.61 | 00:0C:29:B6:DA:46,<br/>00:50:56:91:DE:BB,<br/>00:50:56:91:3A:EC,<br/>00:50:56:91:33:E2,<br/>00:50:56:91:21:B3 | x.x.x.x/24 | d530db3cfef6a2220b315d54fa1901b2 |

### axonius-get-devices-by-ip-regex
***
Gather device info by IP address using regex


#### Base Command

`axonius-get-devices-by-ip-regex`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The IP address to search for within Axonius. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Devices.adapters | String | The specific adapter names with asset information | 
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Devices.hostname | String | The hostnames of the assset | 
| Axonius.Devices.name | String | The names of the asset | 
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset | 
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset | 
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\) | 
| Axonius.Devices.labels | String | Tags assigned to the asset | 


#### Command Example
```!axonius-get-devices-by-ip-regex value=192.168```

#### Context Example
```
{
    "Axonius": {
        "Devices": {
            "adapter_list_length": 5,
            "adapters": [
                "nexpose_adapter",
                "esx_adapter",
                "active_directory_adapter",
                "solarwinds_orion_adapter",
                "crowd_strike_adapter",
                "esx_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "esx_adapter"
            ],
            "aggregated_hostname": [
                "DC4"
            ],
            "aggregated_network_interfaces_ips": [
                "x.x.x.x",
            ],
            "aggregated_network_interfaces_mac": [
                "00:0C:29:B6:DA:46",
                "00:50:56:91:DE:BB",
                "00:50:56:91:3A:EC",
                "00:50:56:91:33:E2",
                "00:50:56:91:21:B3"
            ],
            "aggregated_network_interfaces_subnets": [
                "x.x.x.x/24"
            ],
            "internal_axon_id": "d530db3cfef6a2220b315d54fa1901b2"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_hostname|aggregated_network_interfaces_ips|aggregated_network_interfaces_mac|aggregated_network_interfaces_subnets|internal_axon_id|
>|---|---|---|---|---|---|---|
>| 5 | nexpose_adapter,<br/>esx_adapter,<br/>active_directory_adapter,<br/>solarwinds_orion_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter | DC4 | 192.168.20.17,<br/>192.168.20.58,<br/>fe80::2dba:9118:1fc8:7759,<br/>192.168.20.36,<br/>192.168.20.50,<br/>192.168.20.61 | 00:0C:29:B6:DA:46,<br/>00:50:56:91:DE:BB,<br/>00:50:56:91:3A:EC,<br/>00:50:56:91:33:E2,<br/>00:50:56:91:21:B3 | x.x.x.x/24 | d530db3cfef6a2220b315d54fa1901b2 |

### axonius-get-devices-by-mac
***
Gather device info by MAC address


#### Base Command

`axonius-get-devices-by-mac`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The MAC address to search for within Axonius. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Devices.adapters | String | The specific adapter names with asset information | 
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Devices.hostname | String | The hostnames of the assset | 
| Axonius.Devices.name | String | The names of the asset | 
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset | 
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset | 
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\) | 
| Axonius.Devices.labels | String | Tags assigned to the asset | 


#### Command Example
```!axonius-get-devices-by-mac value=00:0C:29:B6:DA:46```

#### Context Example
```
{
    "Axonius": {
        "Devices": {
            "adapter_list_length": 5,
            "adapters": [
                "nexpose_adapter",
                "esx_adapter",
                "active_directory_adapter",
                "solarwinds_orion_adapter",
                "crowd_strike_adapter",
                "esx_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "esx_adapter"
            ],
            "aggregated_hostname": [
                "DC4"
            ],
            "aggregated_network_interfaces_ips": [
                "x.x.x.x",
            ],
            "aggregated_network_interfaces_mac": [
                "00:0C:29:B6:DA:46",
                "00:50:56:91:DE:BB",
                "00:50:56:91:3A:EC",
                "00:50:56:91:33:E2",
                "00:50:56:91:21:B3"
            ],
            "aggregated_network_interfaces_subnets": [
                "x.x.x.x/24"
            ],
            "internal_axon_id": "d530db3cfef6a2220b315d54fa1901b2"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_hostname|aggregated_network_interfaces_ips|aggregated_network_interfaces_mac|aggregated_network_interfaces_subnets|internal_axon_id|
>|---|---|---|---|---|---|---|
>| 5 | nexpose_adapter,<br/>esx_adapter,<br/>active_directory_adapter,<br/>solarwinds_orion_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter | DC4 | 192.168.20.17,<br/>192.168.20.58,<br/>fe80::2dba:9118:1fc8:7759,<br/>192.168.20.36,<br/>192.168.20.50,<br/>192.168.20.61 | 00:0C:29:B6:DA:46,<br/>00:50:56:91:DE:BB,<br/>00:50:56:91:3A:EC,<br/>00:50:56:91:33:E2,<br/>00:50:56:91:21:B3 | x.x.x.x/24 | d530db3cfef6a2220b315d54fa1901b2 |

### axonius-get-devices-by-mac-regex
***
Gather device info by MAC address using regex


#### Base Command

`axonius-get-devices-by-mac-regex`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The MAC address to search for within Axonius. | Required | 
| max_results | The maximum number of results to return. Default is 50. | Optional | 
| fields | Comma separated list of Axonius fields to return. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset | 
| Axonius.Devices.adapters | String | The specific adapter names with asset information | 
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset | 
| Axonius.Devices.hostname | String | The hostnames of the assset | 
| Axonius.Devices.name | String | The names of the asset | 
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset | 
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset | 
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset | 
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\) | 
| Axonius.Devices.labels | String | Tags assigned to the asset | 


#### Command Example
```!axonius-get-devices-by-mac-regex value=DA:46```

#### Context Example
```
{
    "Axonius": {
        "Devices": {
            "adapter_list_length": 5,
            "adapters": [
                "nexpose_adapter",
                "esx_adapter",
                "active_directory_adapter",
                "solarwinds_orion_adapter",
                "crowd_strike_adapter",
                "esx_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "crowd_strike_adapter",
                "esx_adapter"
            ],
            "aggregated_hostname": [
                "DC4"
            ],
            "aggregated_network_interfaces_ips": [
                "x.x.x.x",
            ],
            "aggregated_network_interfaces_mac": [
                "00:0C:29:B6:DA:46",
                "00:50:56:91:DE:BB",
                "00:50:56:91:3A:EC",
                "00:50:56:91:33:E2",
                "00:50:56:91:21:B3"
            ],
            "aggregated_network_interfaces_subnets": [
                "x.x.x.x/24"
            ],
            "internal_axon_id": "d530db3cfef6a2220b315d54fa1901b2"
        }
    }
}
```

#### Human Readable Output

>### Results
>|adapter_list_length|adapters|aggregated_hostname|aggregated_network_interfaces_ips|aggregated_network_interfaces_mac|aggregated_network_interfaces_subnets|internal_axon_id|
>|---|---|---|---|---|---|---|
>| 5 | nexpose_adapter,<br/>esx_adapter,<br/>active_directory_adapter,<br/>solarwinds_orion_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>crowd_strike_adapter,<br/>esx_adapter | DC4 | 192.168.20.17,<br/>192.168.20.58,<br/>fe80::2dba:9118:1fc8:7759,<br/>192.168.20.36,<br/>192.168.20.50,<br/>192.168.20.61 | 00:0C:29:B6:DA:46,<br/>00:50:56:91:DE:BB,<br/>00:50:56:91:3A:EC,<br/>00:50:56:91:33:E2,<br/>00:50:56:91:21:B3 | x.x.x.x/24 | d530db3cfef6a2220b315d54fa1901b2 |


### axonius-add-note
***
Add note to assets


#### Base Command

`axonius-add-note`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| note | Note to add. | Required | 
| ids | IDs of assets. | Required | 
| type | Type of Asset. Device or User. Possible values are: devices, users. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.assets.updates | Number | Number of assets updated | 


### axonius-add-tag
***
Add tag to assets


#### Base Command

`axonius-add-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | Name of tag to add. | Required | 
| ids | IDs of assets. | Required | 
| type | Type of Asset. Device or User. Possible values are: devices, users. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.assets.updates | Number | Number of assets updated | 


### axonius-remove-tag
***
Remove tag from assets


#### Base Command

`axonius-remove-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | Name of tag to remove. | Required | 
| ids | IDs of assets. | Required | 
| type | Type of Asset. Devices or Users. Possible values are: devices, users. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.asset.updates | Number | Number of assets updated | 

### axonius-get-saved-queries
***
Get all saved query of a given asset type.


#### Base Command

`axonius-get-saved-queries`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of Asset. Device or User. Possible values are: devices, users. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Devices.saved_queries | Unknown | Saved queries | 
| Axonius.Users.saved_queries | Unknown | Saved queries | 

### axonius-get-tags
***
Get all tags of a given asset type.


#### Base Command

`axonius-get-tags`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of Asset. Device or User. Possible values are: devices, users. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.tags | Unknown | Axonius Tags | 