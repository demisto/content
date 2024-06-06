DataBee, from Comcast Technology Solutions,is a cloud-native security and compliance data fabric that ingests data from multiple disparate feeds, then aggregates, compresses, standardizes, enriches, correlates, and normalizes before transferring a full time-series dataset to your data lake of choice.
This integration was integrated and tested with version xx of DataBee.

## Configure DataBee on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DataBee.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Base URL | DataBee base URL | True |
    | Username | DataBee username | False |
    | Password | DataBee Password / API key | True |
    | Trust any certificate (not secure) | Trust any certificate (not secure) | False |
    | Use system proxy settings | Use system proxy settings | False |
    | Additional findings context outputs | Choose additional context data you wish to retrieve from the API. Be aware that requesting extensive context data may impact your server's performance. | False |fetch incidents | True |
    | Maximum incidents per fetch | Maximum incidents per fetch | True |
    | First fetch timestamp | Timestamp in ISO format or &lt;number&gt; &lt;time unit&gt;, e.g. 2022-01-01T00:00:00.000Z, 12 hours, 7 days, 3 months, now. | True |
    | Severity Filter | This parameter allows you to filter findings based on their severity level. For eample, a level such as "High" is acceptable. | False |
    | Impact Filter | This parameter allows you to filter findings based on their impact level. For eample, a level such as "High" is acceptable. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| search_operator | This parameter defines the search operator applied to filter criteria such as the hostname, MAC address, name, and IP address.It accommodates list objects for filter values, enabling the specification of multiple filter values separated by commas. Specifically, when using the "In" or "Not In" operators, you can input values in formats like "test.com" for a single entry or "test.com,test2.com" for multiple entries. Possible values are: In, Not In. | Optional |
| hostname | This parameter allows you to filter devices based on their hostname, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "test.com" is acceptable. For "In" or "Not In," you can specify a single hostname or a list of hostnames separated by commas, such as "test.com" or "test.com,test2.com". | Optional |
| mac | This parameter allows you to filter devices based on their MAC address, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "00-00-00-00-00-00" is acceptable. For "In" or "Not In," you can specify a single MAC address or a list of MAC addresses separated by commas, such as "00-00-00-00-00-00" or "00-00-00-00-00-00,11-11-11-11-11-11". | Optional |
| name | This parameter allows you to filter devices based on their name, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "test" is acceptable. For "In" or "Not In," you can specify a single name or a list of names separated by commas, such as "test" or "test,test2". | Optional |
| ip | This parameter allows you to filter devices based on their IP address, using one of the following operators: "CIDR Block", "In", or "Not In". The default is "CIDR Block”.Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "1.2.3.4" is acceptable. For "In" or "Not In," you can specify a single IP address or a list of IP addresses separated by commas, such as "1.2.3.4,1.2.3.4" or "test,test2". | Optional |
| query | Insert a query instead of using the filters. The format should be {filter} {operator} {value}. “and” separate between queries. Wrap with brackets when the value has special letters. Using this argument overrides the other filter arguments. For example, hostname contains test and mac in (00-00-00-00-00-00) and domain in (test.com). | Optional |
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
| DataBee.Device.interface_uid | String | The unique identifier of the network interface. |
| DataBee.Device.interface_name | String | The name of the network interface \(e.g. eth2\). |
| DataBee.Device.instance_uid | String | The unique identifier of a VM instance. |
| DataBee.Device.hostname | String | The device hostname. |
| DataBee.Device.end_time | String | The end time of when a particular state of the user was valid. |
| DataBee.Device.start_time | String | The start time when a particular state of the user became valid |

#### Command example
```!databee-device-search hostname=a limit=1```
#### Context Example
```json
{
    "DataBee": {
        "Device": {
            "Os": {
                "build": "Q1N48LMPIP",
                "language": "ps",
                "name": "Windows",
                "type": "Windows",
                "type_id": 100,
                "version": "5.4"
            },
            "Owner": {
                "account": {
                    "name": "Domain Admin",
                    "type": "AWS IAM Role",
                    "type_id": 4,
                    "uid": "d53455865"
                },
                "backtrace": {
                    "email_addr": {
                        "feed": "ping",
                        "provider": "ping_one",
                        "source": "secret 12:17:13.658"
                    },
                    "name": {
                        "feed": "ping",
                        "provider": "ping_one",
                        "source": "secret 12:17:13.658"
                    }
                },
                "credential_uid": "A094386C-A6FF-48DC-A9FD-054D6A2365E2",
                "domain": "security.kennedyltd.com",
                "email_addr": "secret",
                "employee_uid": "86763",
                "end_time": "2024-04-22T16:49:18.186464",
                "full_name": "Joseph Silva",
                "given_name": "Joseph",
                "groups": [
                    {
                        "name": "Legal",
                        "type": "Contract",
                        "uid": "Kc7rVYkS"
                    }
                ],
                "id": 631,
                "job_title": "Developer-3 Engineer, chemical",
                "location": {
                    "city": "Nampa",
                    "continent": "na",
                    "coordinates": [
                        43.54072,
                        -116.56346
                    ],
                    "country": "us",
                    "desc": "teacher",
                    "is_on_premises": true,
                    "isp": "weight",
                    "postal_code": "17262",
                    "provider": "generation",
                    "region": "q83"
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
                            "feed": "azure",
                            "provider": "azure_ad",
                            "source": "secret 08:04:16.159"
                        },
                        "name": {
                            "feed": "azure",
                            "provider": "azure_ad",
                            "source": "secret 08:04:16.159"
                        }
                    },
                    "credential_uid": "BB08039D-806C-4232-BBEE-5EC807FE77F3",
                    "domain": "secret",
                    "email_addr": "secret",
                    "employee_uid": "18825",
                    "end_time": "2024-04-28T20:30:53.435473",
                    "full_name": "Amy Harper",
                    "given_name": "Amy",
                    "groups": [
                        {
                            "name": "Engineering",
                            "type": "Contract",
                            "uid": "E7XsLmC5"
                        },
                        {
                            "name": "IT",
                            "type": "Fulltime",
                            "uid": "q8Dy2aH6"
                        },
                        {
                            "name": "Sales",
                            "type": "Fulltime",
                            "uid": "d9PmRyV4"
                        }
                    ],
                    "id": 224,
                    "job_title": "Director-3 Quantity surveyor",
                    "location": {
                        "city": "Odessa",
                        "continent": "na",
                        "coordinates": [
                            31.84568,
                            -102.36764
                        ],
                        "country": "us",
                        "desc": "spend",
                        "is_on_premises": false,
                        "isp": "doctor",
                        "postal_code": "73446",
                        "provider": "success",
                        "region": "7ye"
                    },
                    "name": "amy490",
                    "org": {
                        "name": "Kennedy Ltd"
                    },
                    "start_time": "2024-04-26T08:47:05.626278",
                    "sur_name": "Harper",
                    "type": "User",
                    "type_id": 1,
                    "uid": "1ee49ae52410b6a7b43a9405c865f50b51b51bc09c2508990ef60efb9b0dabf0"
                },
                "name": "joseph506",
                "org": {
                    "name": "Kennedy Ltd"
                },
                "start_time": "2024-04-06T11:28:39.711836",
                "sur_name": "Silva",
                "type": "User",
                "type_id": 1,
                "uid": "c55e7d8186b4a8090a425bee034e21679049a3ed35de52737e685b48e5b08f0b"
            },
            "hostname": "secret",
            "instance_uid": "fact",
            "interface_name": "water",
            "interface_uid": "hard",
            "ip": "secret",
            "name": "NZ314-FAKE",
            "start_time": "2024-04-06T13:51:50.163072",
            "type": "Other",
            "uid": "5aa168e1-7f47-43f1-8a66-5e3c3b16d496"
        }
    }
}
```

#### Human Readable Output

>### Device List
>|Uid|Type|Name|Ip|Interface Uid|Interface Name|Instance Uid|Hostname|Start Time|
>|---|---|---|---|---|---|---|---|---|
>| 5aa168e1-7f47-43f1-8a66-5e3c3b16d496 | Other | NZ314-FAKE | secret | hard | water | fact | secret | 2024-04-06T13:51:50.163072 |


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
| search_operator | This parameter defines the search operator applied to filter criteria such as the email address, full name, and name.It accommodates list objects for filter values, enabling the specification of multiple filter values separated by commas. Specifically, when using the "In" or "Not In" operators, you can input values in formats like "test" for a single entry or "test,test2" for multiple entries. Possible values are: In, Not In. | Optional |
| email_address | This parameter allows you to filter users based on their email address, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "test@test.com" is acceptable. For "In" or "Not In," you can specify a single email address or a list of email addresses separated by commas, such as "test@test.com" or "test@test.com,test2@test.com". | Optional |
| full_name | This parameter allows you to filter users based on their full name, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "Bob Dan" is acceptable. For "In" or "Not In," you can specify a single full name or a list of full names separated by commas, such as "Bob Dan" or "Bob Dan,Alice Dan". | Optional |
| name | This parameter allows you to filter users based on their name, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single hostname such as "Bob" is acceptable. For "In" or "Not In," you can specify a single name or a list of names separated by commas, such as "Bob" or "Bob,Alice". | Optional |
| query | Insert a query instead of using the filters. The format should be {filter} {operator} {value}. “and” separate between queries. Wrap with brackets when the value has special letters. Using this argument overrides the other filter arguments. For example, hostname contains test and mac in (00-00-00-00-00-00). | Optional |
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

#### Command example
```!databee-user-search full_name=a limit=1```
#### Context Example
```json
{
    "DataBee": {
        "User": {
            "name": "larry727",
            "start_time": "2024-04-05T17:18:01.568858",
            "type": "User",
            "uid": "f8ec232ba08707719f276d24034d6007f1316091c07e84745bae7cce2d8bc9bc"
        }
    }
}
```

#### Human Readable Output

>### User List
>|Uid|Type|Name|Start Time|
>|---|---|---|---|
>| f8ec232ba08707719f276d24034d6007f1316091c07e84745bae7cce2d8bc9bc | User | larry727 | 2024-04-05T17:18:01.568858 |


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
| search_operator | This parameter defines the search operator applied to filter criteria such as the analytic name, confidence level, device environment, device risk level, impact, risk level, and severity.It accommodates list objects for filter values, enabling the specification of multiple filter values separated by commas. Specifically, when using the "In" or "Not In" operators, you can input values in formats like "High" for a single entry or "High,Low" for multiple entries. Possible values are: In, Not In. | Optional |
| analytic_name | This parameter allows you to filter findings based on their analytic name, using one of the following operators: "In", or "Not In". The default operator is "In". You can specify a single analytic name or a list of analytic names separated by commas, such as "about" or "about, matter". | Optional |
| confidence | This parameter allows you to filter findings based on their confidence level, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single confidence level such as "High" is acceptable. For "In" or "Not In," you can specify a single confidence level or a list of confidence levels separated by commas, such as "High" or "High,Medium". Possible values are: High, Medium, Low, Other, Unknown, Stable. | Optional |
| device_environment | This parameter allows you to filter findings based on their device environment, using one of the following operators: "In", or "Not In". The default operator is "In". You can specify a single device environment or a list of device environments separated by commas, such as "Development" or "Development,Production". | Optional |
| device_risk_level | This parameter allows you to filter findings based on their device environment, using one of the following operators: "In", or "Not In". The default operator is "In". You can specify a single device risk level or a list of device risk levels separated by commas, such as "Critical" or "Critical,High". Possible values are: Critical, High, Info. | Optional |
| impact | This parameter allows you to filter findings based on their impact level, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single impact level such as "High" is acceptable. For "In" or "Not In," you can specify a single impact level or a list of impact levels separated by commas, such as "High" or "High,Medium". Possible values are: Critical, High, Medium, Low, Other, Unknown. | Optional |
| risk_level | This parameter allows you to filter findings based on their risk level, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single risk level such as "High" is acceptable. For "In" or "Not In," you can specify a single risk level or a list of risk levels separated by commas, such as "High" or "High,Medium". Possible values are: Critical, High, Medium, Low, Info. | Optional |
| severity | This parameter allows you to filter findings based on their severity level, using one of the following operators: "Contains", "In", or "Not In". The default operator is "Contains". Depending on the selected operator, the format for the value varies. For "Contains", a single severity level such as "High" is acceptable. For "In" or "Not In," you can specify a single severity level or a list of severity levels separated by commas, such as "High" or "High,Medium". Possible values are: Fatal, Critical, High, Medium, Low, Information, Other, Unknown. | Optional |
| query | Insert a query instead of using the filters. The format should be {filter} {operator} {value}. “and” separate between queries. Wrap with brackets when the value has special letters. Using this argument overrides the other filter arguments. For example, hostname contains test and mac in (00-00-00-00-00-00). | Optional |
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
                "name": "SMB Create Remote File Admin Share",
                "type": "Rule",
                "uid": "b210394c-ba12-4f89-9117-44a2464b9511"
            },
            "Attack": [
                {
                    "Tactic": [
                        {
                            "id": 470,
                            "name": "low",
                            "uid": "TA0005"
                        },
                        {
                            "id": 706,
                            "name": "indeed",
                            "uid": "TA0043"
                        }
                    ],
                    "Technique": {
                        "id": 992,
                        "name": "society",
                        "uid": "T1574.012"
                    }
                },
                {
                    "Tactic": [
                        {
                            "id": 855,
                            "name": "before",
                            "uid": "TA0040"
                        },
                        {
                            "id": 662,
                            "name": "scientist",
                            "uid": "TA0003"
                        }
                    ],
                    "Technique": {
                        "id": 51,
                        "name": "value",
                        "uid": "T1553.003"
                    }
                }
            ],
            "CisCsc": [
                {
                    "control": "PM",
                    "id": 388,
                    "version": "why"
                },
                {
                    "control": "play",
                    "id": 339,
                    "version": "country"
                }
            ],
            "Device": {
                "hostname": "secret",
                "ip": "secret",
                "mac": "ec-d6-71-31-07-33",
                "os": {
                    "build": "3CQ4RC6KMG",
                    "language": "nr",
                    "name": "iPadOS",
                    "type": "iPadOS",
                    "type_id": 302,
                    "version": "6.10"
                }
            },
            "Evidence": {},
            "Finding": {
                "RelatedEvent": null,
                "Remediation": null,
                "created_time": "2024-04-14 13:57:58.645249",
                "desc": "art",
                "first_seen_time": "2024-04-05 18:44:43.263042",
                "last_seen_time": "2024-04-11 11:00:34.208306",
                "modified_time": "2024-04-20 18:41:49.745148",
                "product_uid": "rule",
                "src_url": "secret/",
                "supporting_data": {
                    "window": "himself"
                },
                "title": "buy",
                "types_": null,
                "uid": "P-5277"
            },
            "KillChain": [
                {
                    "id": 463,
                    "phase": "save",
                    "phase_id": 4
                },
                {
                    "id": 3,
                    "phase": "report",
                    "phase_id": 5
                }
            ],
            "Metadata": {},
            "Observable": [
                {
                    "Reputation": {
                        "base_score": 6.5996,
                        "id": 138,
                        "provider": "product",
                        "score": "form",
                        "score_id": 3
                    },
                    "name": "other",
                    "type": "child",
                    "value": "join"
                },
                {
                    "Reputation": {
                        "base_score": 1.9556,
                        "id": 433,
                        "provider": "measure",
                        "score": "together",
                        "score_id": 5
                    },
                    "name": "culture",
                    "type": "lawyer",
                    "value": "worker"
                }
            ],
            "Process": {},
            "User": {
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
                        "source": "secret 16:06:52.305"
                    },
                    "name": {
                        "feed": "ping",
                        "provider": "ping_one",
                        "source": "secret 16:06:52.305"
                    }
                },
                "cost_center": "building",
                "created_time": "2024-04-05 01:07:43.128742",
                "credential_uid": "44A33EBF-705D-4D17-B1A0-D7040F9E08F5",
                "deleted_time": "2024-04-05 17:25:40.219087",
                "domain": "sales.kennedyltd.com",
                "email_addr": "secret",
                "email_addresses": [],
                "employee_uid": "64254",
                "end_time": null,
                "full_name": "Sandy Parker Md",
                "given_name": "Sandy",
                "groups": [
                    {
                        "name": "Marketing",
                        "type": "Fulltime",
                        "uid": "v5JmQnU1"
                    },
                    {
                        "name": "Accounting",
                        "type": "Parttime",
                        "uid": "F4EeDpX9"
                    },
                    {
                        "name": "HR",
                        "type": "Intern",
                        "uid": "X3tPwGzR"
                    }
                ],
                "hid": 71,
                "hire_datetime": "2024-04-20 18:39:31.213224",
                "id": 415,
                "job_title": "intern Engineer, site",
                "labels": [
                    "maybe",
                    "end"
                ],
                "last_login_time": "2024-04-02 03:51:16.055244",
                "ldap_person": {
                    "cost_center": "building",
                    "created_time": "2024-04-05 01:07:43.128742",
                    "deleted_time": "2024-04-05 17:25:40.219087",
                    "email_addrs": [],
                    "employee_uid": "64254",
                    "given_name": "Sandy",
                    "hire_time": "2024-04-03 09:17:00.686714",
                    "id": 415,
                    "job_title": "intern Engineer, site",
                    "labels": [
                        "maybe",
                        "end"
                    ],
                    "last_login_time": "2024-04-02 03:51:16.055244",
                    "ldap_cn": "discuss",
                    "ldap_dn": "president",
                    "leave_time": "2024-04-25 09:24:46.775911",
                    "location": {
                        "city": "Bon Air",
                        "continent": "na",
                        "coordinates": [
                            37.52487,
                            -77.55777
                        ],
                        "country": "us",
                        "desc": "clear",
                        "is_on_premises": true,
                        "isp": "class",
                        "postal_code": "66989",
                        "provider": "leg",
                        "region": "jkj"
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
                                "feed": "sap",
                                "provider": "sap_successfactors",
                                "source": "secret 09:47:21.601"
                            },
                            "name": {
                                "feed": "sap",
                                "provider": "sap_successfactors",
                                "source": "secret 09:47:21.601"
                            }
                        },
                        "credential_uid": "A52B4E2E-5641-4826-BA1C-E3EF3077452F",
                        "domain": "it.kennedyltd.com",
                        "email_addr": "secret",
                        "employee_uid": "72238",
                        "end_time": "2024-04-26T03:26:10.837526",
                        "full_name": "Linda Vaughn",
                        "given_name": "Linda",
                        "groups": [
                            {
                                "name": "IT",
                                "type": "Fulltime",
                                "uid": "q8Dy2aH6"
                            }
                        ],
                        "id": 258,
                        "job_title": "Director-3 Estate manager/land agent",
                        "location": {
                            "city": "Opportunity",
                            "continent": "na",
                            "coordinates": [
                                47.64995,
                                -117.23991
                            ],
                            "country": "us",
                            "desc": "firm",
                            "is_on_premises": true,
                            "isp": "majority",
                            "postal_code": "39076",
                            "provider": "mouth",
                            "region": "t31"
                        },
                        "merge_history": [],
                        "name": "linda162",
                        "org": {
                            "name": "Kennedy Ltd"
                        },
                        "start_time": "2024-04-06T08:55:38.391775",
                        "sur_name": "Vaughn",
                        "type": "Other",
                        "type_id": 99,
                        "uid": "ecd51e740c72e70b76efc92cdef55ef6557d29864dc30b52e6d99b15f485a715"
                    },
                    "modified_time": "2024-04-07 00:49:01.358074",
                    "office_location": "effort",
                    "surname": "MD"
                },
                "leave_datetime": "2024-04-14 01:52:02.087098",
                "location": {
                    "city": "Bon Air",
                    "continent": "na",
                    "coordinates": [
                        37.52487,
                        -77.55777
                    ],
                    "country": "us",
                    "desc": "clear",
                    "is_on_premises": true,
                    "isp": "class",
                    "postal_code": "66989",
                    "provider": "leg",
                    "region": "jkj"
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
                            "feed": "sap",
                            "provider": "sap_successfactors",
                            "source": "secret 09:47:21.601"
                        },
                        "name": {
                            "feed": "sap",
                            "provider": "sap_successfactors",
                            "source": "secret 09:47:21.601"
                        }
                    },
                    "credential_uid": "A52B4E2E-5641-4826-BA1C-E3EF3077452F",
                    "domain": "it.kennedyltd.com",
                    "email_addr": "secret",
                    "employee_uid": "72238",
                    "end_time": "2024-04-26T03:26:10.837526",
                    "full_name": "Linda Vaughn",
                    "given_name": "Linda",
                    "groups": [
                        {
                            "name": "IT",
                            "type": "Fulltime",
                            "uid": "q8Dy2aH6"
                        }
                    ],
                    "id": 258,
                    "job_title": "Director-3 Estate manager/land agent",
                    "location": {
                        "city": "Opportunity",
                        "continent": "na",
                        "coordinates": [
                            47.64995,
                            -117.23991
                        ],
                        "country": "us",
                        "desc": "firm",
                        "is_on_premises": true,
                        "isp": "majority",
                        "postal_code": "39076",
                        "provider": "mouth",
                        "region": "t31"
                    },
                    "merge_history": [],
                    "name": "linda162",
                    "org": {
                        "name": "Kennedy Ltd"
                    },
                    "start_time": "2024-04-06T08:55:38.391775",
                    "sur_name": "Vaughn",
                    "type": "Other",
                    "type_id": 99,
                    "uid": "ecd51e740c72e70b76efc92cdef55ef6557d29864dc30b52e6d99b15f485a715"
                },
                "merge_history": [],
                "modified_time": "2024-04-07 00:49:01.358074",
                "name": "sandy529",
                "office_location": "effort",
                "org": {
                    "name": "Kennedy Ltd"
                },
                "start_time": "2024-04-10T15:56:55.016313",
                "surname": "MD",
                "type": "User",
                "type_id": 1,
                "uid": "214ed338920e903b99e1e29d60017a71ab67cf747e7a5f89e7034126ccc76ba6",
                "uid_alt": "bad"
            },
            "activity_id": 1,
            "activity_name": "Create",
            "category_name": "Findings",
            "class_name": "Security Finding",
            "confidence": "Low",
            "data_source": [
                "wish",
                "can"
            ],
            "device_id": 1960,
            "duration": 566,
            "end_time": "2024-04-29T14:17:19.702663",
            "id": 2565,
            "impact": "High",
            "impact_score": 240,
            "message": "HTTP traffic matched Suspicious Tor Connection signature user",
            "risk_level": "Medium",
            "risk_score": 368,
            "severity": "Low",
            "start_time": "2024-04-19T10:38:39.810536",
            "state": "Completed",
            "status": "Completed",
            "status_detail": "Link Clicked",
            "time": "2024-04-10T23:49:59.486534",
            "type_name": "Security Finding: Create",
            "user_id": 415
        }
    }
}
```

#### Human Readable Output

>### Finding List
>|Time|Activity Name|Impact|State|Severity|
>|---|---|---|---|---|
>| 2024-04-10T23:49:59.486534 | Create | High | Completed | Low |
