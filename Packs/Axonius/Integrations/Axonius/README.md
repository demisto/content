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
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Devices.adapters | String | The specific adapter names with asset information. |
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Devices.hostname | String | The hostnames of the assset. |
| Axonius.Devices.name | String | The names of the asset. |
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset. |
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset. |
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\). |
| Axonius.Devices.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Devices.adapters | String | The specific adapter names with asset information. |
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Devices.hostname | String | The hostnames of the assset. |
| Axonius.Devices.name | String | The names of the asset. |
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset. |
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset. |
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\). |
| Axonius.Devices.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Users.adapters | String | The specific adapter names with asset information. |
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Users.username | String | Username of the asset. |
| Axonius.Users.mail | String | Email address of the asset. |
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges. |
| Axonius.Users.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Users.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Users.adapters | String | The specific adapter names with asset information. |
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Users.username | String | Username of the asset. |
| Axonius.Users.mail | String | Email address of the asset. |
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges. |
| Axonius.Users.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Users.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Users.adapters | String | The specific adapter names with asset information. |
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Users.username | String | Username of the asset. |
| Axonius.Users.mail | String | Email address of the asset. |
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges. |
| Axonius.Users.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Users.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Users.adapters | String | The specific adapter names with asset information. |
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Users.username | String | Username of the asset. |
| Axonius.Users.mail | String | Email address of the asset. |
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges. |
| Axonius.Users.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Users.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Users.adapters | String | The specific adapter names with asset information. |
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Users.username | String | Username of the asset. |
| Axonius.Users.mail | String | Email address of the asset. |
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges. |
| Axonius.Users.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Users.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Users.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Users.adapters | String | The specific adapter names with asset information. |
| Axonius.Users.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Users.username | String | Username of the asset. |
| Axonius.Users.mail | String | Email address of the asset. |
| Axonius.Users.is_admin | Boolean | If the asset has admin privileges. |
| Axonius.Users.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Users.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Devices.adapters | String | The specific adapter names with asset information. |
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Devices.hostname | String | The hostnames of the assset. |
| Axonius.Devices.name | String | The names of the asset. |
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset. |
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset. |
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\). |
| Axonius.Devices.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Devices.adapters | String | The specific adapter names with asset information. |
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Devices.hostname | String | The hostnames of the assset. |
| Axonius.Devices.name | String | The names of the asset. |
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset. |
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset. |
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\). |
| Axonius.Devices.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Devices.adapters | String | The specific adapter names with asset information. |
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Devices.hostname | String | The hostnames of the assset. |
| Axonius.Devices.name | String | The names of the asset. |
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset. |
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset. |
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\). |
| Axonius.Devices.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Devices.adapters | String | The specific adapter names with asset information. |
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Devices.hostname | String | The hostnames of the assset. |
| Axonius.Devices.name | String | The names of the asset. |
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset. |
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset. |
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\). |
| Axonius.Devices.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Devices.adapters | String | The specific adapter names with asset information. |
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Devices.hostname | String | The hostnames of the assset. |
| Axonius.Devices.name | String | The names of the asset. |
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset. |
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset. |
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\). |
| Axonius.Devices.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.Devices.adapter_list_length | Number | The number of adapters with information about the asset. |
| Axonius.Devices.adapters | String | The specific adapter names with asset information. |
| Axonius.Devices.internal_axon_id | String | The internal unique Axonius identifier for the asset. |
| Axonius.Devices.hostname | String | The hostnames of the assset. |
| Axonius.Devices.name | String | The names of the asset. |
| Axonius.Devices.last_seen | Date | Last seen date/time of the asset. |
| Axonius.Devices.network_interfaces_macs | String | The MAC addresses of the asset. |
| Axonius.Devices.network_interfaces_ips | String | The IP addresses of the asset. |
| Axonius.Devices.os_type | String | The OS type \(Windows, Linux, macOS,...\). |
| Axonius.Devices.labels | String | Tags assigned to the asset. |

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
>
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
| Axonius.assets.updates | Number | Number of assets updated. |

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
| Axonius.assets.updates | Number | Number of assets updated. |

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
| Axonius.asset.updates | Number | Number of assets updated. |

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
| Axonius.Devices.saved_queries | Unknown | Saved queries. |
| Axonius.Users.saved_queries | Unknown | Saved queries. |

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
| Axonius.tags | Unknown | Axonius Tags. |

### axonius-get-assets

***
Fetch assets of any type using the Axonius v2 API (POST /api/v2/assets/{asset_type}). Supports all asset types including vulnerability_instances. Use next_token for pagination. Large responses (>10 MB) may be stored as a downloadable file by XSOAR instead of being written to the context. NOTE: All calls write to the fixed context key Axonius.Assets regardless of asset_type. If a playbook calls this command more than once with different asset types, each call overwrites the previous result. To avoid data loss, store or transform the context output (e.g. using Set) before issuing a second call with a different type.

#### Base Command

`axonius-get-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | The asset type to fetch (e.g. devices, users, vulnerability_instances). See axonius-get-asset-types for all supported values. | Required |
| query | The AQL filter string to narrow the returned assets. | Optional |
| fields | A comma-separated list of fields to include in the response. | Optional |
| fields_to_exclude | A comma-separated list of fields to exclude from the response. | Optional |
| page_size | The number of assets to request per page (1–2000). Keep this value small for large asset types (e.g. vulnerability_instances) to avoid XSOAR context size limits (~10 MB). Default is 50. | Optional |
| limit | The maximum number of assets to return from the page (defaults to page_size). | Optional |
| next_token | The pagination cursor returned from a previous call as Axonius.Assets.next_token. Pass this value to retrieve the next page of results. | Optional |
| include_metadata | Whether to include metadata in the response. Possible values are: true, false. Default is false. | Optional |
| include_details | Whether to include detailed asset data in the response. Possible values are: true, false. Default is false. | Optional |
| use_cache_entry | Whether to use a cached response entry if available. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Assets.asset_type | String | The asset type that was queried. |
| Axonius.Assets.assets | Unknown | The list of asset records returned by the query. |
| Axonius.Assets.count | Number | The number of assets returned in this page. |
| Axonius.Assets.total_count | Number | The total number of assets matching the query (when available). |
| Axonius.Assets.next_token | String | The pagination cursor for the next page of results. Pass this as next_token in the next call. |

### axonius-get-asset-types

***
Return the list of all available asset types in the Axonius instance (GET /api/v2/assets/asset_types).

#### Base Command

`axonius-get-asset-types`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.AssetTypes.asset_type | String | The asset type name. |
| Axonius.AssetTypes | Unknown | The list of available asset types. |

### axonius-get-custom-data

***
List custom data management entries (GET /api/v2/custom_data_management).

#### Base Command

`axonius-get-custom-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number to retrieve (1-indexed). Default is 1. | Optional |
| page_size | The number of entries to return per page. Default is 50. | Optional |
| limit | The maximum number of entries to return (defaults to page_size). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.CustomData.id | String | The custom data entry unique identifier. |
| Axonius.CustomData | Unknown | The list of custom data entries. |

### axonius-create-custom-data

***
Create a new custom data entry (POST /api/v2/custom_data_management).

#### Base Command

`axonius-create-custom-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| payload | The JSON string representing the custom data payload to create. Refer to Axonius API documentation for the required schema. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.CustomData | Unknown | The created custom data entry. |

### axonius-delete-custom-data

***
Delete a custom data entry by ID (DELETE /api/v2/custom_data_management/{id}).

#### Base Command

`axonius-delete-custom-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the custom data entry to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.CustomData.id | String | The ID of the deleted custom data entry. |
| Axonius.CustomData.deleted | Boolean | The flag indicating whether the entry was deleted. |

### axonius-get-enforcements

***
List enforcement sets (GET /api/v2/enforcements).

#### Base Command

`axonius-get-enforcements`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The page number to retrieve (1-indexed). Default is 1. | Optional |
| page_size | The number of enforcements to return per page. Default is 50. | Optional |
| limit | The maximum number of enforcements to return (defaults to page_size). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Enforcements.uuid | String | The enforcement unique identifier. |
| Axonius.Enforcements.name | String | The enforcement name. |
| Axonius.Enforcements | Unknown | The full list of enforcement objects. |

### axonius-run-enforcement

***
Trigger an enforcement run (POST /api/v2/enforcements/{enforcement_id}/run).

#### Base Command

`axonius-run-enforcement`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| enforcement_id | The UUID of the enforcement to run. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Enforcements.enforcement_id | String | The ID of the enforcement that was triggered. |
| Axonius.Enforcements.triggered | Boolean | The flag indicating whether the enforcement was triggered successfully. |

### axonius-get-queries

***
List saved queries (GET /api/v2/queries).

#### Base Command

`axonius-get-queries`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | The asset type to filter queries by (e.g. devices, users). | Optional |
| page | The page number to retrieve (1-indexed). Default is 1. | Optional |
| page_size | The number of queries to return per page. Default is 50. | Optional |
| limit | The maximum number of queries to return (defaults to page_size). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Queries.uuid | String | The query unique identifier. |
| Axonius.Queries.name | String | The query name. |
| Axonius.Queries | Unknown | The full list of query objects. |

### axonius-create-query

***
Create a new saved query (POST /api/v2/queries).

#### Base Command

`axonius-create-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name for the new saved query. | Required |
| query | The AQL filter string for the query. | Required |
| asset_type | The asset type this query applies to. Default is devices. | Optional |
| description | The optional description for the query. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Queries.uuid | String | The UUID of the created query. |
| Axonius.Queries.name | String | The name of the created query. |
| Axonius.Queries | Unknown | The created query object. |

### axonius-delete-query

***
Delete a saved query (DELETE /api/v2/queries/{query_id}).

#### Base Command

`axonius-delete-query`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | The UUID of the query to delete. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.Queries.query_id | String | The ID of the deleted query. |
| Axonius.Queries.deleted | Boolean | The flag indicating whether the query was deleted. |

### axonius-get-grouped-vulnerabilities

***
Fetch all vulnerability instances, flatten them, group by CVE ID, and return the Top N CVEs sorted by affected host count. Computes average_cvss_score per CVE. Outputs as Axonius.GroupedVulnerabilities keyed by cve_id.

#### Base Command

`axonius-get-grouped-vulnerabilities`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The optional AQL filter applied before grouping. | Optional |
| team_name | The team name to filter vulnerability instances by. | Optional |
| urgent | Whether to filter by urgency on vulnerability instances. Possible values are: true, false. | Optional |
| top_n | The number of top CVEs to return (sorted by affected_hosts_count descending). Default is 10. | Optional |
| page_size | The number of records per page when fetching all instances. Default is 100. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Axonius.GroupedVulnerabilities.cve_id | String | The CVE identifier. |
| Axonius.GroupedVulnerabilities.affected_hosts_count | Number | The number of hosts affected by this CVE. |
| Axonius.GroupedVulnerabilities.average_cvss_score | Number | The average CVSS score across all instances of this CVE. |
