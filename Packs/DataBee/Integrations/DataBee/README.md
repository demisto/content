DataBee, from Comcast Technology Solutions, is a cloud-native security and compliance data fabric that ingests data from multiple disparate feeds and then aggregates, compresses, standardizes, enriches, correlates, and normalizes the data before transferring a full time-series dataset to your data lake of choice.
This integration was integrated and tested with version 1.0 of DataBee.

## Configure DataBee in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL |  | True |
| Incident type |  | False |
| Username |  | True |
| Password |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Additional findings context outputs | Choose additional context data to retrieve from the API. Be aware that requesting extensive context data may impact your server's performance. | False |
| Fetch incidents |  | False |
| Maximum incidents per fetch |  | True |
| First fetch timestamp | Timestamp in ISO format or &lt;number&gt; &lt;time unit&gt;, e.g., 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | True |
| Severity Filter | Filter findings based on their severity level. For example, a level such as "High" is acceptable. | False |
| Impact Filter | Filter findings based on their impact level. For example, a level such as "High" is acceptable. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### databee-device-search

***
Search for devices based on filters.

#### Base Command

`databee-device-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional |
| page_size | The optional 0-based index of the page to retrieve. Must be an integer greater than or equal to 0. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| search_operator | The search operator applied to filter criteria such as the hostname, MAC address, name, and IP address. It accommodates list objects for filter values, enabling the specification of multiple filter values separated by commas. Specifically, when using the "In" or "Not In" operators, you can input values in formats like "test.com" for a single entry or "test.com,test2.com" for multiple entries. Possible values are: In, Not In. | Optional |
| hostname | Filter devices based on their hostname, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "test.com" is acceptable. For "In" or "Not In," you can specify a single hostname or a list of hostnames separated by commas, such as "test.com" or "test.com,test2.com". | Optional |
| uid | Filter devices based on their UID, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single ID such as "aa3437c2-a938-419e-95ea-15c04e8bdb98" is acceptable. For "In" or "Not In," you can specify a single hostname or a list of hostnames separated by commas, such as "aa3437c2-a938-419e-95ea-15c04e8bdb98" or "aa3437c2-a938-419e-95ea-15c04e8bdb98,ed3437c2-a938-419e-95ea-15c04e8bdb98". | Optional |
| mac | Filter devices based on their MAC address, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "00-00-00-00-00-00" is acceptable. For "In" or "Not In," you can specify a single MAC address or a list of MAC addresses separated by commas, such as "00-00-00-00-00-00" or "00-00-00-00-00-00,11-11-11-11-11-11". | Optional |
| name | Filter devices based on their name, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "test" is acceptable. For "In" or "Not In," you can specify a single name or a list of names separated by commas, such as "test" or "test,test2". | Optional |
| ip | Filter devices based on their IP address, using one of the following operators: "CIDR Block", "In", or "Not In". The default is "CIDR Block”.Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "1.2.3.4" is acceptable. For "In" or "Not In," you can specify a single IP address or a list of IP addresses separated by commas, such as "1.2.3.4,1.2.3.5". | Optional |
| query | Insert a query instead of using the filters. The format should be {filter} {operator} {value}. “and” separates between queries. Wrap with brackets when the value has special letters. Using this argument overrides the other filter arguments. For example, hostname contains test and mac in (00-00-00-00-00-00) and domain in (test.com). | Optional |
| time_range | Filter to devices with a verbal time range. The verbal field are: X Minutes, X Hour, X Days, X Months. For example, 1 Week. Using the time range automatically cancels the start time and end time arguments. | Optional |
| start_time | Filter to devices that was created between the start_time and the end_time arguments. For example, 2024-03-26T11:03:18Z. | Optional |
| end_time | Filter to devices that was created between the start_time and the end_time arguments. For example, 2024-03-26T11:03:18Z. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DataBee.Device.uid | String | A unique identifier for the device. |
| DataBee.Device.type | String | The type of the device. |
| DataBee.Device.region | String | The region where the virtual machine is located. For example, an AWS Region. |
| DataBee.Device.owner | String | The primary owner of a device. |
| DataBee.Device.name | String | The alternate device name. |
| DataBee.Device.ip | String | The device IP address, in either IPv4 or IPv6 format. |
| DataBee.Device.mac | String | The device MAC address. |
| DataBee.Device.interface_uid | String | The unique identifier of the network interface. |
| DataBee.Device.interface_name | String | The name of the network interface \(e.g., eth2\). |
| DataBee.Device.instance_uid | String | The unique identifier of a VM instance. |
| DataBee.Device.hostname | String | The device hostname. |
| DataBee.Device.end_time | String | The end time of when a particular state of the user was valid. |
| DataBee.Device.start_time | String | The start time when a particular state of the user became valid. |
| DataBee.Device.modified_time | String | The time when the device was modified. |

#### Command example
```!databee-device-search hostname=a limit=1```
#### Context Example
```json
{
    "DataBee": {
        "Device": {
            "Os": {
                "build": "BCKFLR98UX",
                "language": "hsb",
                "name": "Windows",
                "type": "Windows",
                "type_id": 100,
                "version": "0.10"
            },
            "Owner": {
                "account": {
                    "name": "Guest Account",
                    "type": "AWS IAM User",
                    "type_id": 3,
                    "uid": "g2468101"
                },
                "backtrace": {
                    "email_addr": {
                        "feed": "sap",
                        "provider": "sap_successfactors",
                        "source": "17:11:41.830"
                    },
                    "name": {
                        "feed": "sap",
                        "provider": "sap_successfactors",
                        "source": "17:11:41.830"
                    }
                },
                "credential_uid": "7C8C8617-5E39-45D2-847F-4E1F849B783D",
                "domain": "secret",
                "email_addr": "secret",
                "employee_uid": "62626",
                "end_time": "2024-06-07T07:20:02.352612",
                "full_name": "Stephen Osborne",
                "given_name": "Stephen",
                "groups": [
                    {
                        "name": "Legal",
                        "type": "Contract",
                        "uid": "Kc7rVYkS"
                    },
                    {
                        "name": "Accounting",
                        "type": "Parttime",
                        "uid": "F4EeDpX9"
                    }
                ],
                "id": 556,
                "job_title": "Developer-2 Technical sales engineer",
                "location": {
                    "city": "Sterling",
                    "continent": "na",
                    "coordinates": [
                        39.00622,
                        -77.4286
                    ],
                    "country": "us",
                    "desc": "City :Sterling,Latitude",
                    "is_on_premises": true,
                    "isp": "comcast cable",
                    "postal_code": "12390",
                    "provider": "Bing maps",
                    "region": "east-2"
                },
                "manager": {
                    "account": {
                        "name": "User",
                        "type": "LDAP Account",
                        "type_id": 1,
                        "uid": "u1234567"
                    },
                    "backtrace": {
                        "email_addr": {
                            "feed": "microsoft",
                            "provider": "microsoft_graph_api",
                            "source": "2024-06-07 04:13:04.961"
                        },
                        "name": {
                            "feed": "microsoft",
                            "provider": "microsoft_graph_api",
                            "source": "2024-06-07 04:13:04.961"
                        }
                    },
                    "credential_uid": "2DEEB170-C56D-4E0E-B234-39AC4B67BF8E",
                    "domain": "secret",
                    "email_addr": "secret",
                    "employee_uid": "82891",
                    "end_time": "2024-05-30T20:13:22.403195",
                    "full_name": "Tracy Carr",
                    "given_name": "Tracy",
                    "groups": [
                        {
                            "name": "Legal",
                            "type": "Contract",
                            "uid": "Kc7rVYkS"
                        },
                        {
                            "name": "Customer Service",
                            "type": "Parttime",
                            "uid": "b6LzGnC0"
                        }
                    ],
                    "id": 169,
                    "job_title": "Director-2 Homeopath",
                    "location": {
                        "city": "Kendall",
                        "continent": "na",
                        "coordinates": [
                            25.67927,
                            -80.31727
                        ],
                        "country": "us",
                        "desc": "City :Kendall,Latitude",
                        "is_on_premises": true,
                        "isp": "AT&T",
                        "postal_code": "72203",
                        "provider": "others",
                        "region": "west-1"
                    },
                    "name": "tracy548",
                    "org": {
                        "name": "Rodriguez, Rodriguez and Hoffman"
                    },
                    "start_time": "2024-05-29T19:55:53.093122",
                    "sur_name": "Carr",
                    "type": "User",
                    "type_id": 1,
                    "uid": "a5e67347dc1ea0f81173cd6bfbb18cf9b256decadb0ebc360d6a18b570b1d132"
                },
                "name": "stephen253",
                "org": {
                    "name": "Rodriguez, Rodriguez and Hoffman"
                },
                "start_time": "2024-06-07T01:34:50.139715",
                "sur_name": "Osborne",
                "type": "User",
                "type_id": 1,
                "uid": "d46e7818712a815121f2e1a58288eda8f69d4237e8d7294961e4eadcfae4c703"
            },
            "hostname": "secret",
            "instance_uid": "especially",
            "interface_name": "follow",
            "interface_uid": "skin",
            "ip": "test",
            "mac": "70-a7-1d-da-0c-cd",
            "modified_time": "2024-06-11T19:08:41.429310",
            "name": "GDFE654-FAKE",
            "start_time": "2024-06-09T14:39:18.801072",
            "type": "Browser",
            "uid": "143795e5-741a-4914-b29c-186a060d430f"
        }
    }
}
```

#### Human Readable Output

>### Device List
>|Uid|Type|Name|Ip|Interface Uid|Interface Name|Instance Uid|Hostname|Start Time|Modified Time|
>|---|---|---|---|---|---|---|---|---|---|
>| 143795e5-741a-4914-b29c-186a060d430f | Browser | GDFE654-FAKE | test | skin | follow | especially | secret | 2024-06-09T14:39:18.801072 | 2024-06-11T19:08:41.429310 |


### databee-user-search

***
Search for users based on filters.

#### Base Command

`databee-user-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional |
| page_size | The optional 0-based index of the page to retrieve. Must be an integer greater than or equal to 0. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| search_operator | The search operator applied to filter criteria such as the email address, full name, and name. It accommodates list objects for filter values, enabling the specification of multiple filter values separated by commas. Specifically, when using the "In" or "Not In" operators, you can input values in formats like "test" for a single entry or "test,test2" for multiple entries. Possible values are: In, Not In. | Optional |
| email_address | Filter users based on their email address, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "test@test.com" is acceptable. For "In" or "Not In," you can specify a single email address or a list of email addresses separated by commas, such as "test@test.com" or "test@test.com,test2@test.com". | Optional |
| full_name | Filter users based on their full name, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "Bob Dan" is acceptable. For "In" or "Not In," you can specify a single full name or a list of full names separated by commas, such as "Bob Dan" or "Bob Dan,Alice Dan". | Optional |
| name | Filter users based on their name, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "Bob" is acceptable. For "In" or "Not In," you can specify a single name or a list of names separated by commas, such as "Bob" or "Bob,Alice". | Optional |
| query | Insert a query instead of using the filters. The format should be {filter} {operator} {value}. “and” separates between queries. Wrap with brackets when the value has special letters. Using this argument overrides the other filter arguments. For example, hostname contains test and mac in (00-00-00-00-00-00). | Optional |
| time_range | Filter to devices with a verbal time range. The verbal field are: X Minutes, X Hour, X Days, X Months. For example, 1 Week. Using the time range automatically cancels the start time and end time arguments. | Optional |
| start_time | Filter to devices that was created between the start_time and the end_time arguments. For example, 2024-03-26T11:03:18Z. | Optional |
| end_time | Filter to devices that was created between the start_time and the end_time arguments. For example, 2024-03-26T11:03:18Z. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DataBee.User.uid | String | The unique user identifier. |
| DataBee.User.type | String | The type of the user. For example, System, AWS IAM User, etc. |
| DataBee.User.name | String | The username. |
| DataBee.User.start_time | String | The start time when a particular state of the user became valid. |
| DataBee.User.end_time | String | The end time of when a particular state of the user was valid. |
| DataBee.User.modified_time | String | The time when the user was modified. |

#### Command example
```!databee-user-search full_name=a limit=1```
#### Context Example
```json
{
    "DataBee": {
        "User": {
            "modified_time": "2024-06-13T13:17:51.025057",
            "name": "bradley459",
            "start_time": "2024-06-10T06:58:37.202327",
            "type": "User",
            "uid": "4c12656e73b90df215e63ca7e3317ace78b8e21540961831b207e69313d7dc5a"
        }
    }
}
```

#### Human Readable Output

>### User List
>|Uid|Type|Name|Start Time|Modified Time|
>|---|---|---|---|---|
>| 4c12656e73b90df215e63ca7e3317ace78b8e21540961831b207e69313d7dc5a | User | bradley459 | 2024-06-10T06:58:37.202327 | 2024-06-13T13:17:51.025057 |


### databee-finding-search

***
Search for security findings based on filters.

#### Base Command

`databee-finding-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | The optional size of the page to retrieve. Must be an integer greater than 0 or less than or equal to 1000. | Optional |
| page_size | The optional 0-based index of the page to retrieve. Must be an integer greater than or equal to 0. | Optional |
| limit | The maximum number of records to retrieve. Default is 50. | Optional |
| search_operator | The search operator applied to filter criteria such as the analytic name, confidence level, device environment, device risk level, impact, risk level, and severity. It accommodates list objects for filter values, enabling the specification of multiple filter values separated by commas. Specifically, when using the "In" or "Not In" operators, you can input values in formats like "High" for a single entry or "High,Low" for multiple entries. Possible values are: In, Not In. | Optional |
| analytic_name | Filter findings based on their analytic name, using one of the following operators: "In", or "Not In". The default operator is "In". You can specify a single analytic name or a list of analytic names separated by commas, such as "about" or "about, matter". | Optional |
| confidence | Filter findings based on their confidence level, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single confidence level such as "High" is acceptable. For "In" or "Not In," you can specify a single confidence level or a list of confidence levels separated by commas, such as "High" or "High,Medium". Possible values are: High, Medium, Low, Other, Unknown, Stable. | Optional |
| device_environment | Filter findings based on their device environment, using one of the following operators: "In", or "Not In". The default operator is "In". You can specify a single device environment or a list of device environments separated by commas, such as "Development" or "Development,Production". | Optional |
| device_risk_level | Filter findings based on their device environment, using one of the following operators: "In", or "Not In". The default operator is "In". You can specify a single device risk level or a list of device risk levels separated by commas, such as "Critical" or "Critical,High". Possible values are: Critical, High, Info. | Optional |
| impact | Filter findings based on their impact level, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single impact level such as "High" is acceptable. For "In" or "Not In," you can specify a single impact level or a list of impact levels separated by commas, such as "High" or "High,Medium". Possible values are: Critical, High, Medium, Low, Other, Unknown. | Optional |
| risk_level | Filter findings based on their risk level, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single risk level such as "High" is acceptable. For "In" or "Not In," you can specify a single risk level or a list of risk levels separated by commas, such as "High" or "High,Medium". Possible values are: Critical, High, Medium, Low, Info. | Optional |
| severity | Filter findings based on their severity level, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single severity level such as "High" is acceptable. For "In" or "Not In," you can specify a single severity level or a list of severity levels separated by commas, such as "High" or "High,Medium". Possible values are: Fatal, Critical, High, Medium, Low, Information, Other, Unknown. | Optional |
| query | Insert a query instead of using the filters. The format should be {filter} {operator} {value}. “and” separates between queries. Wrap with brackets when the value has special letters. Using this argument overrides the other filter arguments. For example, hostname contains test and mac in (00-00-00-00-00-00). | Optional |
| time_range | Filter to devices with a verbal time range. The verbal field are: X Minutes, X Hour, X Days, X Months. For example, 1 Week. Using the time range automatically cancels the start time and end time arguments. | Optional |
| start_time | Filter to devices that was created between the start_time and the end_time arguments. For example, 2024-03-26T11:03:18Z. | Optional |
| end_time | Filter to devices that was created between the start_time and the end_time arguments. For example, 2024-03-26T11:03:18Z. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DataBee.Finding.device_id | Integer | Unique identifier of the device involved in the finding. |
| DataBee.Finding.user_id | Integer | Unique identifier of the user involved in the finding. |
| DataBee.Finding.activity_id | Integer | Identifier for the activity associated with the finding. |
| DataBee.Finding.activity_name | String | Name of the activity related to the finding. |
| DataBee.Finding.Analytic.category | String | Category of the analytics used in the finding. |
| DataBee.Finding.Analytic.desc | String | Detailed description of the analytic approach or rule. |
| DataBee.Finding.Analytic.name | String | Name of the analytic rule or method used. |
| DataBee.Finding.Analytic.type | String | Type of analytic method employed, such as rule-based or heuristic. |
| DataBee.Finding.Analytic.uid | String | Unique identifier for the specific analytic method used. |
| DataBee.Finding.Attack.Tactic.id | String | Unique identifier for each tactic involved in the attack. |
| DataBee.Finding.Attack.Tactic.name | String | Name of the tactic used in the attack. |
| DataBee.Finding.Attack.Tactic.uid | String | Unique identifier \(UID\) of the tactic used in the attack. |
| DataBee.Finding.Attack.Technique.id | String | Unique identifier for the technique used within the attack. |
| DataBee.Finding.Attack.Technique.name | String | Name of the technique employed in the attack. |
| DataBee.Finding.Attack.Technique.uid | String | Unique identifier \(UID\) for the technique used in the attack. |
| DataBee.Finding.category_name | String | Name of the category to which the finding is classified. |
| DataBee.Finding.CisCsc.control | String | Description of the control measure from CIS CSC associated with the finding. |
| DataBee.Finding.CisCsc.id | Integer | Identifier for the CIS CSC control relevant to the finding. |
| DataBee.Finding.CisCsc.version | String | Version information of the CIS CSC control relevant to the finding. |
| DataBee.Finding.class_name | String | Classification of the finding that indicates its nature and type. |
| DataBee.Finding.confidence | String | confidence. |
| DataBee.Finding.data_source | String | List of data sources that provided information for the finding. |
| DataBee.Finding.Device.ip | String | IP address of the device associated with the finding. |
| DataBee.Finding.Device.mac | String | MAC address of the device associated with the finding. |
| DataBee.Finding.Device.hostname | String | Hostname of the device involved in the finding. |
| DataBee.Finding.Device.os | Unknown | Operating system running on the device at the time of the finding. |
| DataBee.Finding.duration | String | Duration over which the finding was active or observed. |
| DataBee.Finding.end_time | String | Timestamp marking the end of the occurrence or observation of the finding. |
| DataBee.Finding.Evidence | Unkonwn | Comprehensive details of all evidence related to the finding, documenting the activities, actors, devices, and processes involved. |
| DataBee.Finding.Finding.created_time | String | The timestamp when the finding was initially created in the monitoring or detection system. |
| DataBee.Finding.Finding.desc | String | A brief description of the finding, outlining the main observations or conclusions. |
| DataBee.Finding.Finding.first_seen_time | String | The first time the issue or behavior described in the finding was observed. |
| DataBee.Finding.Finding.last_seen_time | String | The last time the issue or behavior described in the finding was observed, marking the duration of its known activity. |
| DataBee.Finding.Finding.modified_time | String | The timestamp when the finding record was last updated or modified. |
| DataBee.Finding.Finding.product_uid | String | Unique identifier for the product or system associated with the finding, which can be used to track back to specific tools or systems. |
| DataBee.Finding.Finding.RelatedEvent | Unkonwn | Any events that are related to the finding, providing connections or correlations with other incidents or activities. |
| DataBee.Finding.Finding.Remediation | Unkonwn | Remediation steps or recommendations provided to address or mitigate the finding. |
| DataBee.Finding.Finding.src_url | String | A URL or link to more detailed information or a full report concerning the finding, often pointing to an internal knowledge base or external resource. |
| DataBee.Finding.Finding.supporting_data | Unknown | Supporting data or additional documentation that helps to substantiate or explain the finding, which may include logs, images, or other forensic materials. |
| DataBee.Finding.Finding.title | String | The title of the finding, which typically summarizes the issue or key point in a concise format. |
| DataBee.Finding.Finding.types_ | String | The types or categories of the finding, which help to classify the nature of the issue within established frameworks or standards. |
| DataBee.Finding.Finding.uid | String | A unique identifier assigned to the finding, used for tracking and management within the system. |
| DataBee.Finding.id | Integer | Unique identifier of the finding. |
| DataBee.Finding.impact | String | Describes the impact of the finding on the organization or system. |
| DataBee.Finding.impact_score | Integer | Numerical score representing the severity of the impact from the finding. |
| DataBee.Finding.KillChain | String | Identifies the stages of the kill chain that the finding relates to. |
| DataBee.Finding.message | String | Summary or detailed message explaining the finding. |
| DataBee.Finding.Metadata | Unkonwn | Metadata associated with the finding that provides additional context or background information. |
| DataBee.Finding.Observable.name | String | The name or identifier of the observable item, providing a descriptor of the observable's nature or purpose. |
| DataBee.Finding.Observable.Reputation | Unkonwn | Reputation details associated with the observable, including scores and source information. |
| DataBee.Finding.Observable.type | String | The type of observable, such as IP address, URL, file hash, etc., classifying the observable's format or domain. |
| DataBee.Finding.Observable.value | String | The value of the observable, which could be an IP address, a file hash, a URL, or any other relevant data point. |
| DataBee.Finding.Process.cmd_line | String | The command line used to initiate the process, providing insights into the process's function or purpose. |
| DataBee.Finding.Process.container | String | Identifies whether the process is running within a container, specifying the container environment if applicable. |
| DataBee.Finding.Process.created_time | String | The timestamp when the process was initiated or first observed. |
| DataBee.Finding.Process.File | Unkonwn | Details about files associated with the process, including names, paths, and security details. |
| DataBee.Finding.Process.File.company_name | String | The name of the company associated with the file, often indicating software ownership or authorship. |
| DataBee.Finding.Process.File.desc | String | A description of the file's purpose or functionality. |
| DataBee.Finding.Process.File.Hashes | Unkonwn | Contains hash values of the file for integrity and identification purposes, such as MD5, SHA-1, or SHA-256. |
| DataBee.Finding.Process.File.is_system | Boolean | Indicates whether the file is a system file, helping to identify its criticality and origin within the operating system. |
| DataBee.Finding.Process.File.md5 | String | MD5 hash of the file, used for verifying the file's integrity and for quick identification in threat intelligence databases. |
| DataBee.Finding.Process.File.mime_type | String | MIME type of the file, describing the file's format and potentially its intended use or behavior. |
| DataBee.Finding.Process.File.modified_time | String | Timestamp of the last modification made to the file, providing context for its use or alteration. |
| DataBee.Finding.Process.File.name | String | Name of the file involved in the process, which may indicate its functionality or relevance. |
| DataBee.Finding.Process.File.owner | String | Owner of the file, which could be a user name or system account under whose authority the file operates. |
| DataBee.Finding.Process.File.parent_folder | String | The directory in which the file resides, providing context for its location within the file system. |
| DataBee.Finding.Process.File.path | String | Full path to the file, detailing its exact location on the file system. |
| DataBee.Finding.Process.File.security_descriptor | String | Security settings and permissions associated with the file, outlining access controls and protection mechanisms. |
| DataBee.Finding.Process.File.sha1 | String | SHA-1 hash of the file, used for more secure integrity checking compared to MD5. |
| DataBee.Finding.Process.File.sha256 | String | SHA-256 hash of the file, providing a highly reliable method for verifying the file's integrity. |
| DataBee.Finding.Process.File.sha512 | String | SHA-512 hash of the file, offering an even more robust hashing option for security purposes. |
| DataBee.Finding.Process.File.signature | String | Information about any digital signatures attached to the file, which can verify its authenticity and source. |
| DataBee.Finding.Process.File.size | Integer | The size of the file in bytes, providing a basic measure of its content and potential load when processed. |
| DataBee.Finding.Process.File.type | String | Type of file, such as executable, document, or archive, which helps classify its role and usage. |
| DataBee.Finding.Process.File.xattributes | String | Extended attributes of the file, offering additional metadata or control flags specific to certain operating systems. |
| DataBee.Finding.Process.name | String | Name of the process associated with the finding, often indicative of the process's purpose or origin. |
| DataBee.Finding.Process.namespace_pid | Integer | Process ID specific to a particular namespace, used in environments where processes are isolated or containerized. |
| DataBee.Finding.Process.parent_process | String | Identifier of the parent process from which the current process was spawned. |
| DataBee.Finding.Process.pid | Integer | Process ID \(PID\) of the process, uniquely identifying it within the system at the time of observation. |
| DataBee.Finding.Process.sandbox | String | Indicates whether the process is running within a sandboxed environment, which can affect its ability to interact with the system. |
| DataBee.Finding.Process.user | String | User account under which the process is running, providing insights into the process's permissions and role within the system. |
| DataBee.Finding.risk_level | String | Categorizes the finding by the level of risk it poses to the organization or system. |
| DataBee.Finding.risk_score | Integer | A calculated score that quantifies the risk level of the finding. |
| DataBee.Finding.severity | String | The severity rating of the finding, which helps prioritize responses and remediation efforts. |
| DataBee.Finding.start_time | String | The time when the incident or activity that led to the finding began. |
| DataBee.Finding.state | String | The current state of the finding within the incident response or review process. |
| DataBee.Finding.status | String | Current status of the finding, indicating where it is in the workflow or lifecycle. |
| DataBee.Finding.status_detail | String | Provides additional details on the status of the finding, offering more granular insights into its processing state. |
| DataBee.Finding.time | String | The timestamp documenting when the finding was last observed or updated. |
| DataBee.Finding.type_name | String | The type name categorizes the finding according to a predefined classification system. |
| DataBee.Finding.User | Unkonwn | Information about the user associated with the finding, if applicable. |

#### Command example
```!databee-finding-search impact=High limit=1```
#### Context Example
```json
{
    "DataBee": {
        "Finding": {
            "Analytic": {
                "category": null,
                "desc": null,
                "name": "Potential AD User Enumeration From Non-Machine Account",
                "type": "Rule",
                "uid": "ab6bffca-beff-4baa-af11-6733f296d57a"
            },
            "Attack": [
                {
                    "Tactic": [
                        {
                            "id": 606,
                            "name": "interview",
                            "uid": "TA0002"
                        },
                        {
                            "id": 272,
                            "name": "certain",
                            "uid": "TA0010"
                        }
                    ],
                    "Technique": {
                        "id": 538,
                        "name": "moment",
                        "uid": "T1036.004"
                    }
                },
                {
                    "Tactic": [
                        {
                            "id": 914,
                            "name": "TV",
                            "uid": "TA0043"
                        },
                        {
                            "id": 368,
                            "name": "risk",
                            "uid": "TA0010"
                        }
                    ],
                    "Technique": {
                        "id": 316,
                        "name": "provide",
                        "uid": "T1070.004"
                    }
                }
            ],
            "CisCsc": [
                {
                    "control": "anyone",
                    "id": 697,
                    "version": "unit"
                },
                {
                    "control": "act",
                    "id": 717,
                    "version": "institution"
                }
            ],
            "Device": {
                "hostname": "secret",
                "ip": "secret",
                "mac": "e4-b0-ba-5c-a7-ad",
                "os": {
                    "build": "ZPD3QQJEKH",
                    "language": "sk",
                    "name": "AIX",
                    "type": "AIX",
                    "type_id": 401,
                    "version": "1.2"
                }
            },
            "Evidence": {},
            "Finding": {
                "RelatedEvent": null,
                "Remediation": null,
                "created_time": "2024-05-10 09:25:21.512958",
                "desc": "decade",
                "first_seen_time": "2024-05-19 01:49:44.121595",
                "last_seen_time": "2024-06-02 07:29:06.277547",
                "modified_time": "2024-05-13 20:00:36.121908",
                "product_uid": "practice",
                "src_url": "secret",
                "supporting_data": {
                    "director": "prevent"
                },
                "title": "assume",
                "types_": null,
                "uid": "P-8043"
            },
            "KillChain": [
                {
                    "id": 238,
                    "phase": "black",
                    "phase_id": 7
                },
                {
                    "id": 73,
                    "phase": "apply",
                    "phase_id": 7
                }
            ],
            "Metadata": {},
            "Observable": [
                {
                    "Reputation": {
                        "base_score": 0.8084,
                        "id": 320,
                        "provider": "Congress",
                        "score": "move",
                        "score_id": 10
                    },
                    "name": "our",
                    "type": "shake",
                    "value": "plan"
                },
                {
                    "Reputation": {
                        "base_score": 2.8203,
                        "id": 460,
                        "provider": "east",
                        "score": "gun",
                        "score_id": 10
                    },
                    "name": "eye",
                    "type": "oil",
                    "value": "guess"
                }
            ],
            "Process": {},
            "User": {
                "account": {
                    "name": "User",
                    "type": "LDAP Account",
                    "type_id": 1,
                    "uid": "u1234567"
                },
                "backtrace": {
                    "email_addr": {
                        "feed": "ping",
                        "provider": "ping_one",
                        "source": "2024-06-07 11:47:57.905"
                    },
                    "name": {
                        "feed": "ping",
                        "provider": "ping_one",
                        "source": "2024-06-07 11:47:57.905"
                    }
                },
                "cost_center": "tend",
                "created_time": "2024-05-12 19:01:23.687349",
                "credential_uid": "0A16A88C-5332-4791-A1A2-7630245D373A",
                "deleted_time": "2024-06-03 20:12:44.361040",
                "domain": "test.com",
                "email_addr": "test.com",
                "email_addresses": [],
                "employee_uid": "54873",
                "end_time": null,
                "full_name": "Kathleen Moore",
                "given_name": "Kathleen",
                "groups": [
                    {
                        "name": "HR",
                        "type": "Intern",
                        "uid": "X3tPwGzR"
                    },
                    {
                        "name": "Marketing",
                        "type": "Fulltime",
                        "uid": "v5JmQnU1"
                    }
                ],
                "hid": 528,
                "hire_datetime": "2024-05-12 14:49:51.534152",
                "id": 356,
                "job_title": "Developer-2 Chartered accountant",
                "labels": [
                    "approach",
                    "today"
                ],
                "last_login_time": "2024-05-26 15:58:28.269928",
                "ldap_person": {
                    "cost_center": "tend",
                    "created_time": "2024-05-12 19:01:23.687349",
                    "deleted_time": "2024-06-03 20:12:44.361040",
                    "email_addrs": [],
                    "employee_uid": "54873",
                    "given_name": "Kathleen",
                    "hire_time": "2024-05-17 07:29:01.749971",
                    "id": 356,
                    "job_title": "Developer-2 Chartered accountant",
                    "labels": [
                        "approach",
                        "today"
                    ],
                    "last_login_time": "2024-05-26 15:58:28.269928",
                    "ldap_cn": "worry",
                    "ldap_dn": "risk",
                    "leave_time": "2024-06-02 02:50:40.018950",
                    "location": {
                        "city": "Far Rockaway",
                        "continent": "na",
                        "coordinates": [
                            40.60538,
                            -73.75513
                        ],
                        "country": "us",
                        "desc": "City :Far Rockaway,Latitude",
                        "is_on_premises": true,
                        "isp": "comcast cable",
                        "postal_code": "91823",
                        "provider": "Bing maps",
                        "region": "west-1"
                    },
                    "manager": {
                        "account": {
                            "name": "Guest Account",
                            "type": "AWS IAM User",
                            "type_id": 3,
                            "uid": "g2468101"
                        },
                        "backtrace": {
                            "email_addr": {
                                "feed": "ping",
                                "provider": "ping_one",
                                "source": "22:23:01.919"
                            },
                            "name": {
                                "feed": "ping",
                                "provider": "ping_one",
                                "source": "22:23:01.919"
                            }
                        },
                        "credential_uid": "25ECFB7D-2372-4787-A584-9B068DE54F22",
                        "domain": "test.com",
                        "email_addr": "test.com",
                        "employee_uid": "99342",
                        "end_time": "2024-06-02T08:45:59.223622",
                        "full_name": "Mr. Juan Young",
                        "given_name": "Mr.",
                        "groups": [
                            {
                                "name": "Procurement",
                                "type": "Fulltime",
                                "uid": "S2JrDkV0"
                            }
                        ],
                        "id": 250,
                        "job_title": "Director-1 Environmental education officer",
                        "location": {
                            "city": "Brenham",
                            "continent": "na",
                            "coordinates": [
                                30.16688,
                                -96.39774
                            ],
                            "country": "us",
                            "desc": "City :Brenham,Latitude",
                            "is_on_premises": true,
                            "isp": "comcast cable",
                            "postal_code": "20248",
                            "provider": "google maps",
                            "region": "north-1"
                        },
                        "merge_history": [],
                        "name": "mr.728",
                        "org": {
                            "name": "Rodriguez, Rodriguez and Hoffman"
                        },
                        "start_time": "2024-05-18T23:56:45.184722",
                        "sur_name": "Young",
                        "type": "User",
                        "type_id": 1,
                        "uid": "25c758bdf94e7356eec4afd5ffb0075085d52cae83703191ffa2d47d2b135323"
                    },
                    "modified_time": "2024-05-25 12:28:48.049312",
                    "office_location": "give",
                    "surname": "Moore"
                },
                "leave_datetime": "2024-05-16 16:46:41.852020",
                "location": {
                    "city": "Far Rockaway",
                    "continent": "na",
                    "coordinates": [
                        40.60538,
                        -73.75513
                    ],
                    "country": "us",
                    "desc": "City :Far Rockaway,Latitude",
                    "is_on_premises": true,
                    "isp": "comcast cable",
                    "postal_code": "91823",
                    "provider": "Bing maps",
                    "region": "west-1"
                },
                "manager": {
                    "account": {
                        "name": "Guest Account",
                        "type": "AWS IAM User",
                        "type_id": 3,
                        "uid": "g2468101"
                    },
                    "backtrace": {
                        "email_addr": {
                            "feed": "ping",
                            "provider": "ping_one",
                            "source": "22:23:01.919"
                        },
                        "name": {
                            "feed": "ping",
                            "provider": "ping_one",
                            "source": "22:23:01.919"
                        }
                    },
                    "credential_uid": "25ECFB7D-2372-4787-A584-9B068DE54F22",
                    "domain": "test.com",
                    "email_addr": "test.com",
                    "employee_uid": "99342",
                    "end_time": "2024-06-02T08:45:59.223622",
                    "full_name": "Mr. Juan Young",
                    "given_name": "Mr.",
                    "groups": [
                        {
                            "name": "Procurement",
                            "type": "Fulltime",
                            "uid": "S2JrDkV0"
                        }
                    ],
                    "id": 250,
                    "job_title": "Director-1 Environmental education officer",
                    "location": {
                        "city": "Brenham",
                        "continent": "na",
                        "coordinates": [
                            30.16688,
                            -96.39774
                        ],
                        "country": "us",
                        "desc": "City :Brenham,Latitude",
                        "is_on_premises": true,
                        "isp": "comcast cable",
                        "postal_code": "20248",
                        "provider": "google maps",
                        "region": "north-1"
                    },
                    "merge_history": [],
                    "name": "mr.728",
                    "org": {
                        "name": "Rodriguez, Rodriguez and Hoffman"
                    },
                    "start_time": "2024-05-18T23:56:45.184722",
                    "sur_name": "Young",
                    "type": "User",
                    "type_id": 1,
                    "uid": "25c758bdf94e7356eec4afd5ffb0075085d52cae83703191ffa2d47d2b135323"
                },
                "merge_history": [],
                "modified_time": "2024-05-25 12:28:48.049312",
                "name": "kathleen302",
                "office_location": "give",
                "org": {
                    "name": "Rodriguez, Rodriguez and Hoffman"
                },
                "risk_level": "sure",
                "risk_level_id": 4,
                "risk_score": 275,
                "start_time": "2024-06-07T10:09:23.330821",
                "surname": "Moore",
                "type": "User",
                "type_id": 1,
                "uid": "cf8df11ed6bc75707ef66a58d25e013253463a386ed834d2d983edd44b201415",
                "uid_alt": "watch"
            },
            "activity_id": 1,
            "activity_name": "Create",
            "category_name": "Findings",
            "class_name": "Security Finding",
            "confidence": "Medium",
            "data_source": [
                "inside",
                "challenge"
            ],
            "device_id": 1852,
            "duration": 679,
            "end_time": "2024-06-05T20:26:55.159433",
            "id": 2004,
            "impact": "High",
            "impact_score": 739,
            "message": "Activity from Suspicious IP Addresses user",
            "risk_level": "Low",
            "risk_score": 243,
            "severity": "High",
            "start_time": "2024-06-05T19:44:15.659120",
            "state": "Completed",
            "status": "Completed",
            "status_detail": "Link Clicked",
            "time": "2024-06-16T06:24:02.639735",
            "type_name": "Security Finding: Create",
            "user_id": 356
        }
    }
}
```

#### Human Readable Output

>### Finding List
>|Time|Activity Name|Impact|State|Severity|Confidence|
>|---|---|---|---|---|---|
>| 2024-06-16T06:24:02.639735 | Create | High | Completed | High | Medium |


### endpoint

***
Returns information about an endpoint.

#### Base Command

`endpoint`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The endpoint ID. | Optional |
| ip | The endpoint IP address. | Optional |
| hostname | The endpoint hostname. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Endpoint.Hostname | String | The endpoint's hostname. |
| Endpoint.OS | String | The endpoint's operation system. |
| Endpoint.IPAddress | String | The endpoint's IP address. |
| Endpoint.ID | String | The endpoint's ID. |
| Endpoint.MACAddress | String | The endpoint's MAC address. |
| Endpoint.Vendor | String | The integration name of the endpoint vendor. |
| Endpoint.OSVersion | String | The endpoint's operation system version. |

#### Command example
```!endpoint ip=8.8.8.8```
#### Context Example
```json
{
    "Endpoint": {
        "Hostname": "test.com",
        "ID": "ed3437c2-a938-419e-95ea-15c04e8bdb98",
        "IPAddress": "8.8.8.8",
        "MACAddress": "aa-fa-fd-37-0a-de",
        "OS": "Linux",
        "OSVersion": "1.4",
        "Vendor": "DataBee"
    }
}
```

#### Human Readable Output

>### DataBee Endpoint
>|Hostname|ID|IPAddress|MACAddress|OS|OSVersion|Vendor|
>|---|---|---|---|---|---|---|
>| test.com | ed3437c2-a938-419e-95ea-15c04e8bdb98 | 8.8.8.8 | aa-fa-fd-37-0a-de | Linux | 1.4 | DataBee |