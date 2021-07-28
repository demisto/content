Malware information sharing platform and threat sharing.

Some changes have been made that might affect your existing content.
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-misp-v3).

## Configure MISP V3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MISP V3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | MISP server URL (e.g., https://192.168.0.1) |  | True |
    | API Key |  | False |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Malicious tag IDs | Comma separated list of event's or attribute's malicious tag IDs. Malicious tags are stronger than suspicious tags. | False |
    | Suspicious tag IDs | Comma separated list of event's or attribute's suspicious tag IDs. Malicious tags are stronger than suspicious tags. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Maximum attributes to be returned | This field limits the number of attributes that will be written to the context for every reputation command. Please pay attention, raising the number of attributes may result in high memory and disk usage. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### misp-search-events
***
Search for events in MISP. This search command will return only information about the matched events. In case you want to get information about attributes, please use the commands misp-search-attributes.


#### Base Command

`misp-search-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Search for events that include the specified attribute type. Use any valid MISP attribute type. | Optional |
| value | Search for events that include the specified attribute value. | Optional |
| category | Search for events that include the specified attribute category. Use any valid MISP attribute category. | Optional |
| org | Search by creator organization by supplying the organization ID. | Optional |
| tags | A comma-separated list of tags to include in the results. To exclude a tag, prefix the tag name with "!". Can be: "AND", "OR", and "NOT" followed by ":". To chain logical operators use ";". for example, "AND:tag1,tag2;OR:tag3". | Optional |
| from | Event search start date (2015-02-15). This date refers to the event creation date. | Optional |
| to | Event search end date (2015-02-15). This date refers to the event creation date. | Optional |
| last | Events published within the last "x" amount of time. Valid time values are days, hours, and minutes (for example "5d", "12h", "30m"). This filter uses the published timestamp of the event. | Optional |
| event_id | A comma-separated list of event ids to be returned by the search. | Optional |
| uuid | The event UUID to be returned by the search. e.g., 59523300-4be8-4fa6-8867-0037ac110002. | Optional |
| page | If a limit is set, sets the page to be returned. page 3, limit 100 will return records 201-&gt;300). | Optional |
| limit | Limit the number of events returned. Default is 50 events. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | string | MISP event ID. |
| MISP.Event.Distribution | string | MISP event distribution. |
| MISP.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). |
| MISP.Event.PublishTimestamp | number | Timestamp of the publish time \(if published\). |
| MISP.Event.EventCreatorEmail | string | Email address of the event creator. |
| MISP.Event.Info | string | Event name. |
| MISP.Event.AttributeCount | string | Number of attributes of the event. |
| MISP.Event.OrganisationID | string | Event organization ID. |
| MISP.Event.CreationDate | date | Event creation date. |
| MISP.Event.Locked | boolean | Is the event locked. |
| MISP.Event.Organisation.ID | number | Organization ID. |
| MISP.Event.Organisation.Name | string | Organization name. |
| MISP.Event.Organisation.UUID | string | Organization UUID. |
| MISP.Event.Organisation.local | boolean | Is the organization local. |
| MISP.Event.OwnerOrganisation.ID | number | Owner organization ID. |
| MISP.Event.OwnerOrganisation.Name | string | Owner organization name. |
| MISP.Event.OwnerOrganisation.UUID | string | Owner organization UUID. |
| MISP.Event.OwnerOrganisation.local | boolean | Is the owner organization local. |
| MISP.Event.ProposalEmailLock | boolean | If email lock proposed. |
| MISP.Event.LastChanged | date | Last change event timestamp. |
| MISP.Event.Galaxy.Description | string | Event's galaxy description. |
| MISP.Event.Galaxy.Name | string | Galaxy name. |
| MISP.Event.Galaxy.Type | number | Galaxy type. |
| MISP.Event.Published | boolean | Is the event published. |
| MISP.Event.DisableCorrelation | boolean | Is correlation disabled. |
| MISP.Event.UUID | string | Event UUID. |
| MISP.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). |
| MISP.Event.SharingGroupID | string | Event sharing group ID. |
| MISP.Event.Tag.Name | string | All tag names in the event. |
| MISP.Event.Tag.is_galaxy | boolean | Is the tag is galaxy. |
| MISP.Event.Object.Name | String | Name of the object. |
| MISP.Event.Object.Description | String | Description of the object. |
| MISP.Event.Object.ID | Number | ID of the object. |
| MISP.Event.Object.UUID | String | UUID of the object. |


#### Command Example
```!misp-search-events category="Other" limit=3 page=1```

#### Context Example
```json
{
    "MISP": {
        "Event": [
            {
                "Analysis": "2",
                "AttributeCount": "147",
                "CreationDate": "2019-03-18",
                "DisableCorrelation": false,
                "Distribution": "1",
                "Galaxy": [],
                "ID": "238",
                "Info": "New Targets Enterprise Wireless Presentation & Display Systems",
                "Locked": false,
                "Object": [
                    {
                        "Description": "url object describes an url along with its normalized field (like extracted using faup parsing library) and its metadata.",
                        "ID": "16142",
                        "Name": "url",
                        "UUID": "c139891b-ba75-469f-b814-bda63942003c"
                    },
                    {
                        "Description": "A domain/hostname and IP address seen as a tuple in a specific time frame.",
                        "ID": "16341",
                        "Name": "domain-ip",
                        "UUID": "a9e1a62c-9a61-4edc-b097-d15f7d000c06"
                    },
                    {
                        "Description": "url object describes an url along with its normalized field (like extracted using faup parsing library) and its metadata.",
                        "ID": "16348",
                        "Name": "url",
                        "UUID": "8a6021bd-ff01-43e2-9057-2e4df06440af"
                    },
                    {
                        "Description": "An IP address (or domain or hostname) and a port seen as a tuple (or as a triple) in a specific time frame.",
                        "ID": "16374",
                        "Name": "ip-port",
                        "UUID": "76db4ff4-f808-442a-a029-ec4d568d6427"
                    },
                    {
                        "Description": "Vehicle object template to describe a vehicle information and registration",
                        "ID": "16381",
                        "Name": "vehicle",
                        "UUID": "9e5d6801-6c7d-41f3-aace-734bcefed248"
                    },
                    {
                        "Description": "File object describing a file with meta-information",
                        "ID": "16403",
                        "Name": "file",
                        "UUID": "26be8488-3fa0-45d7-a95e-96045d4d2dc7"
                    }
                ],
                "Organisation": {
                    "ID": "1",
                    "Name": "ORGNAME",
                    "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                    "local": true
                },
                "OrganisationID": "1",
                "OwnerOrganisation": {
                    "ID": "7",
                    "Name": "CUDESO",
                    "UUID": "56c42374-fdb8-4544-a218-41ffc0a8ab16",
                    "local": false
                },
                "OwnerOrganisation.ID": "7",
                "ProposalEmailLock": false,
                "PublishTimestamp": "2021-06-23 13:50:21",
                "Published": false,
                "RelatedEvent": [],
                "SharingGroupID": "0",
                "Tag": [
                    {
                        "Name": "tlp:white",
                        "is_galaxy": false
                    }
                ],
                "ThreatLevelID": "3",
                "LastChanged": "2021-07-18 13:10:09",
                "UUID": "5c93d7f7-7de4-4548-ae4c-403ec0a8ab16"
            },
            {
                "Analysis": "2",
                "AttributeCount": "9",
                "CreationDate": "2020-04-06",
                "DisableCorrelation": false,
                "Distribution": "1",
                "Galaxy": [],
                "ID": "239",
                "Info": "Coronavirus-themed Email Campaign",
                "Locked": false,
                "Object": [
                    {
                        "Description": "url object describes an url along with its normalized field (like extracted using faup parsing library) and its metadata.",
                        "ID": "16141",
                        "Name": "url",
                        "UUID": "a7ed8921-e22b-450e-bc84-8fd8932d2a32"
                    }
                ],
                "Organisation": {
                    "ID": "1",
                    "Name": "ORGNAME",
                    "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                    "local": true
                },
                "OrganisationID": "1",
                "OwnerOrganisation": {
                    "ID": "7",
                    "Name": "CUDESO",
                    "UUID": "56c42374-fdb8-4544-a218-41ffc0a8ab16",
                    "local": false
                },
                "OwnerOrganisation.ID": "7",
                "ProposalEmailLock": false,
                "PublishTimestamp": "2021-06-23 13:50:22",
                "Published": false,
                "RelatedEvent": [],
                "SharingGroupID": "0",
                "Tag": [
                    {
                        "Name": "tlp:white",
                        "is_galaxy": false
                    }
                ],
                "ThreatLevelID": "2",
                "LastChanged": "2021-07-01 12:34:41",
                "UUID": "5e8b8ba5-df0c-4e7b-bfb4-b27ec0a8ab16"
            },
            {
                "Analysis": "2",
                "AttributeCount": "22",
                "CreationDate": "2021-04-17",
                "DisableCorrelation": false,
                "Distribution": "1",
                "Galaxy": [],
                "ID": "241",
                "Info": "Detecting and Preventing Malicious Domains Proactively with DNS Security",
                "Locked": false,
                "Object": [
                    {
                        "Description": "Technique for creating SSL client fingerprints that are easy to produce and can be easily shared for threat intelligence. Fingerprints are composed of Client Hello packet; SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats.",
                        "ID": "11131",
                        "Name": "ja3",
                        "UUID": "f95b8b4f-d31a-4b41-b30f-5f0bfe9ae788"
                    }
                ],
                "Organisation": {
                    "ID": "1",
                    "Name": "ORGNAME",
                    "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                    "local": true
                },
                "OrganisationID": "1",
                "OwnerOrganisation": {
                    "ID": "7",
                    "Name": "CUDESO",
                    "UUID": "56c42374-fdb8-4544-a218-41ffc0a8ab16",
                    "local": false
                },
                "OwnerOrganisation.ID": "7",
                "ProposalEmailLock": false,
                "PublishTimestamp": "2021-06-23 13:50:23",
                "Published": true,
                "RelatedEvent": [],
                "SharingGroupID": "0",
                "Tag": [
                    {
                        "Name": "tlp:white",
                        "is_galaxy": false
                    }
                ],
                "ThreatLevelID": "3",
                "LastChanged": "2021-05-04 18:49:48",
                "UUID": "e74cba52-0314-43c2-9958-43a55619fcf5"
            }
        ]
    }
}
```

#### Human Readable Output

>### MISP search-events returned 3 events
>|Event Distribution|Event ID|Event Info|Event Objects|Event Org ID|Event Orgc ID|Event Tags|Event UUID|Publish Timestamp|
>|---|---|---|---|---|---|---|---|---|
>| 1 | 238 | New Targets Enterprise Wireless Presentation & Display Systems | 16142,<br/>16341,<br/>16348,<br/>16374,<br/>16381,<br/>16403 | 1 | 7 | tlp:white | 5c93d7f7-7de4-4548-ae4c-403ec0a8ab16 | 2021-06-23 13:50:21 |
>| 1 | 239 | New RedLine Stealer Distributed Using Coronavirus-themed Email Campaign | 16141 | 1 | 7 | tlp:white | 5e8b8ba5-df0c-4e7b-bfb4-b27ec0a8ab16 | 2021-06-23 13:50:22 |
>| 1 | 241 | Detecting and Preventing Malicious Domains Proactively with DNS Security | 11131 | 1 | 7 | tlp:white | e74cba52-0314-43c2-9958-43a55619fcf5 | 2021-06-23 13:50:23 |
>Current page number: 1
> Page size: 3

### domain
***
Checks the reputation of the given domain.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to search. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain of the indicator. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| MISP.Attribute.Distribution | string | Attribute distribution. |
| MISP.Attribute.Value | string | Attribute value. |
| MISP.Attribute.EventID | string | Attribute event ID. |
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. |
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. |
| MISP.Attribute.LastChanged | date | Attribute creation timestamp. |
| MISP.Attribute.ObjectID | string | Attribute object id. |
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. |
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled? |
| MISP.Attribute.Type | string | Attribute type. |
| MISP.Attribute.ID | string | Attribute ID. |
| MISP.Attribute.UUID | string | Attribute UUID. |
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. |
| MISP.Attribute.Category | string | Attribute category. |
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. |
| MISP.Attribute.Comment | string | Attribute comment. |
| MISP.Attribute.Event.ID | string | MISP event ID. |
| MISP.Attribute.Event.Distribution | string | MISP event distribution. |
| MISP.Attribute.Event.Info | string | MISP event name. |
| MISP.Attribute.Event.LastChanged | string | Timestamp of the event. |
| MISP.Attribute.Event.Published | boolean | Is the event published. |
| MISP.Attribute.Event.CreationDate | date | Event creation date. |
| MISP.Attribute.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). |
| MISP.Attribute.Event.PublishTimestamp | string | Timestamp of the publish time \(if published\). |
| MISP.Attribute.Event.OrganisationID | string | MISP event organisation ID. |
| MISP.Attribute.Event.OwnerOrganisation.ID | string | Owner organization ID. |
| MISP.Attribute.Event.OwnerOrganisation.Name | string | Owner organization name. |
| MISP.Attribute.Event.OwnerOrganisation.UUID | string | Owner organization UUID. |
| MISP.Attribute.Event.OwnerOrganisation.local | boolean | Is owner organization is local. |
| MISP.Attribute.Event.UUID | string | MISP event UUID. |
| MISP.Attribute.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). |
| MISP.Attribute.Event.SharingGroupID | string | Event sharing group ID. |
| MISP.Attribute.Event.Tag.Name | string | Event tag name. |
| MISP.Attribute.Event.Tag.ID | string | Event tag ID. |
| MISP.Attribute.Tag.Name | string | Attribute tag name. |
| MISP.Attribute.Tag.ID | string | Attribute tag ID. |
| MISP.Attribute.Sighting.Type | string | Attribute's sighting type. |


#### Command Example
```!domain domain=ahaaa0.com```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "ahaaa0.com",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "domain",
        "Vendor": "MISP V3"
    },
    "Domain": {
        "Malicious": {
            "Description": "Match found in MISP",
            "Vendor": "MISP V3"
        },
        "Name": "ahaaa0.com"
    },
    "MISP": {
        "Attribute": [
            {
                "Category": "Network activity",
                "Comment": "",
                "DecayScore": [
                    {
                        "DecayingModel": {
                            "ID": "3",
                            "Name": "test3"
                        },
                        "base_score": 0,
                        "decayed": true,
                        "score": 0
                    }
                ],
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Analysis": "2",
                    "CreationDate": "2014-11-13",
                    "Distribution": "1",
                    "ID": "1208",
                    "Info": "OSINT Expansion campaign",
                    "OrganisationID": "1",
                    "OwnerOrganisation": {
                        "ID": "3",
                        "Name": "CL.be",
                        "UUID": "55f6ea5f-fd34-43b8-ac1d-40cb950d210f",
                        "local": false
                    },
                    "OwnerOrganisation.ID": "3",
                    "PublishTimestamp": "2021-07-20 08:18:45",
                    "Published": true,
                    "SharingGroupID": "0",
                    "Tag": [
                        {
                            "ID": "5",
                            "Name": "type:OSINT"
                        },
                        {
                            "ID": "3",
                            "Name": "tlp:green"
                        }
                    ],
                    "ThreatLevelID": "2",
                    "LastChanged": "2014-11-13 14:32:53",
                    "UUID": "5464bf96-1f14-43f1-af86-08ce950d210b",
                    "extends_uuid": ""
                },
                "EventID": "1208",
                "ID": "111718",
                "ObjectID": "0",
                "ObjectRelation": null,
                "SharingGroupID": "0",
                "Sighting": [],
                "Tag": [
                    {
                        "ID": "5",
                        "Name": "type:OSINT"
                    },
                    {
                        "ID": "3",
                        "Name": "tlp:green"
                    }
                ],
                "LastChanged": "2014-11-13 14:30:17",
                "ToIDs": true,
                "Type": "domain",
                "UUID": "5464c079-3a08-4195-8bc9-491c950d210b",
                "Value": "ahaaa0.com",
                "first_seen": null,
                "last_seen": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Results found in MISP for value: ahaaa0.com
>|Attribute Category|Attribute Type|Attribute Value|Dbot Score|Timestamp|
>|---|---|---|---|---|
>| Network activity | domain | ahaaa0.com | 3 | 2014-11-13 14:30:17 |
>### Related events
>|Event ID|Event Name|Threat Level ID|
>|---|---|---|
>| 1208 | OSINT Expansion campaign | 2 |


### email
***
Checks the reputation of the given email address.


#### Base Command

`email`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | Email address to search. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Email.Address | String | The email address of the indicator. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| MISP.Attribute.Distribution | string | Attribute distribution. |
| MISP.Attribute.Value | string | Attribute value. |
| MISP.Attribute.EventID | string | Attribute event ID. |
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. |
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. |
| MISP.Attribute.LastChanged | date | Attribute creation timestamp. |
| MISP.Attribute.ObjectID | string | Attribute object id. |
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. |
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled? |
| MISP.Attribute.Type | string | Attribute type. |
| MISP.Attribute.ID | string | Attribute ID. |
| MISP.Attribute.UUID | string | Attribute UUID. |
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. |
| MISP.Attribute.Category | string | Attribute category. |
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. |
| MISP.Attribute.Comment | string | Attribute comment. |
| MISP.Attribute.Event.ID | string | MISP event ID. |
| MISP.Attribute.Event.Distribution | string | MISP event distribution. |
| MISP.Attribute.Event.Info | string | MISP event name. |
| MISP.Attribute.Event.LastChanged | string | Timestamp of the event. |
| MISP.Attribute.Event.Published | boolean | Is the event published. |
| MISP.Attribute.Event.CreationDate | date | Event creation date. |
| MISP.Attribute.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). |
| MISP.Attribute.Event.PublishTimestamp | string | Timestamp of the publish time \(if published\). |
| MISP.Attribute.Event.OrganisationID | string | MISP event organisation ID. |
| MISP.Attribute.Event.OwnerOrganisation.ID | string | Owner organization ID. |
| MISP.Attribute.Event.OwnerOrganisation.Name | string | Owner organization name. |
| MISP.Attribute.Event.OwnerOrganisation.UUID | string | Owner organization UUID. |
| MISP.Attribute.Event.OwnerOrganisation.local | boolean | Is owner organization is local. |
| MISP.Attribute.Event.UUID | string | MISP event UUID. |
| MISP.Attribute.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). |
| MISP.Attribute.Event.SharingGroupID | string | Event sharing group ID. |
| MISP.Attribute.Event.Tag.Name | string | Event tag name. |
| MISP.Attribute.Event.Tag.ID | string | Event tag ID. |
| MISP.Attribute.Tag.Name | string | Attribute tag name. |
| MISP.Attribute.Tag.ID | string | Attribute tag ID. |
| MISP.Attribute.Sighting.Type | string | Attribute's sighting type. |


#### Command Example
```!email email=example@gmail.com```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "example@gmail.com",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "email",
        "Vendor": "MISP V3"
    },
    "Email": {
        "Address": "example@gmail.com"
    },
    "MISP": {
        "Attribute": [
            {
                "Category": "Payload delivery",
                "Comment": "",
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Analysis": "2",
                    "CreationDate": "2014-10-03",
                    "Distribution": "1",
                    "ID": "517",
                    "Info": "OSINT New Indicators of Compromise for APT Group",
                    "OrganisationID": "1",
                    "OwnerOrganisation": {
                        "ID": "3",
                        "Name": "C.be",
                        "UUID": "55f6ea5f-fd34-43b8-ac1d-40cb950d210f",
                        "local": false
                    },
                    "OwnerOrganisation.ID": "3",
                    "PublishTimestamp": "2021-06-29 13:26:22",
                    "Published": false,
                    "SharingGroupID": "0",
                    "Tag": [
                        {
                            "ID": "5",
                            "Name": "type:OSINT"
                        },
                        {
                            "ID": "3",
                            "Name": "tlp:green"
                        }
                    ],
                    "ThreatLevelID": "2",
                    "LastChanged": "2021-07-22 12:10:08",
                    "UUID": "54323f2c-e50c-4268-896c-4867950d210b",
                    "extends_uuid": ""
                },
                "EventID": "517",
                "ID": "112893",
                "ObjectID": "0",
                "ObjectRelation": null,
                "SharingGroupID": "0",
                "Sighting": [],
                "Tag": [
                    {
                        "ID": "5",
                        "Name": "type:OSINT"
                    },
                    {
                        "ID": "3",
                        "Name": "tlp:green"
                    }
                ],
                "LastChanged": "2021-07-20 14:58:00",
                "ToIDs": true,
                "Type": "email",
                "UUID": "ad6337d0-3e2b-4923-bafb-16f32d20a8ac",
                "Value": "example@gmail.com",
                "first_seen": null,
                "last_seen": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Results found in MISP for value: example@gmail.com
>|Attribute Category|Attribute Type|Attribute Value|Dbot Score|Timestamp|
>|---|---|---|---|---|
>| Payload delivery | email | example@gmail.com | 3 | 2021-07-20 14:58:00 |
>### Related events
>|Event ID|Event Name|Threat Level ID|
>|---|---|---|
>| 517 | OSINT New Indicators of Compromise for APT Group | 2 |


### file
***
Checks the file reputation of the given hash.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Hash of the file to query. Supports MD5, SHA-1, and SHA-256. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.SHA1 | String | The SHA1 hash of the file. |
| File.SHA256 | String | The SHA256 hash of the file. |
| File.MD5 | String | The MD5 hash of the file. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| MISP.Attribute.Distribution | string | Attribute distribution. |
| MISP.Attribute.Value | string | Attribute value. |
| MISP.Attribute.EventID | string | Attribute event ID. |
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. |
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. |
| MISP.Attribute.LastChanged | date | Attribute creation timestamp. |
| MISP.Attribute.ObjectID | string | Attribute object id. |
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. |
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled? |
| MISP.Attribute.Type | string | Attribute type. |
| MISP.Attribute.ID | string | Attribute ID. |
| MISP.Attribute.UUID | string | Attribute UUID. |
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. |
| MISP.Attribute.Category | string | Attribute category. |
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. |
| MISP.Attribute.Comment | string | Attribute comment. |
| MISP.Attribute.Event.ID | string | MISP event ID. |
| MISP.Attribute.Event.Distribution | string | MISP event distribution. |
| MISP.Attribute.Event.Info | string | MISP event name. |
| MISP.Attribute.Event.LastChanged | string | Timestamp of the event. |
| MISP.Attribute.Event.Published | boolean | Is the event published. |
| MISP.Attribute.Event.CreationDate | date | Event creation date. |
| MISP.Attribute.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). |
| MISP.Attribute.Event.PublishTimestamp | string | Timestamp of the publish time \(if published\). |
| MISP.Attribute.Event.OrganisationID | string | MISP event organisation ID. |
| MISP.Attribute.Event.OwnerOrganisation.ID | string | Owner organization ID. |
| MISP.Attribute.Event.OwnerOrganisation.Name | string | Owner organization name. |
| MISP.Attribute.Event.OwnerOrganisation.UUID | string | Owner organization UUID. |
| MISP.Attribute.Event.OwnerOrganisation.local | boolean | Is owner organization is local. |
| MISP.Attribute.Event.UUID | string | MISP event UUID. |
| MISP.Attribute.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). |
| MISP.Attribute.Event.SharingGroupID | string | Event sharing group ID. |
| MISP.Attribute.Event.Tag.Name | string | Event tag name. |
| MISP.Attribute.Event.Tag.ID | string | Event tag ID. |
| MISP.Attribute.Tag.Name | string | Attribute tag name. |
| MISP.Attribute.Tag.ID | string | Attribute tag ID. |
| MISP.Attribute.Sighting.Type | string | Attribute's sighting type. |


#### Command Example
```!file file=6c73d338ec64e0e44bd54ea61b6988b2```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "6c73d338ec64e0e44bd54ea61b6988b2",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "file",
        "Vendor": "MISP V3"
    },
    "File": {
        "MD5": "6c73d338ec64e0e44bd54ea61b6988b2",
        "Malicious": {
            "Description": "Match found in MISP",
            "Vendor": "MISP V3"
        }
    },
    "MISP": {
        "Attribute": [
            {
                "Category": "Payload delivery",
                "Comment": "",
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Analysis": "0",
                    "CreationDate": "2020-03-13",
                    "Distribution": "3",
                    "ID": "149",
                    "Info": "Capitalizing on Coronavirus Panic, Threat Actors Target Victims Worldwide",
                    "OrganisationID": "1",
                    "OwnerOrganisation": {
                        "ID": "8",
                        "Name": "CERT.be",
                        "UUID": "5cf66e53-b5f8-43e7-be9a-49880a3b4631",
                        "local": false
                    },
                    "OwnerOrganisation.ID": "8",
                    "PublishTimestamp": "2021-07-19 14:10:30",
                    "Published": false,
                    "SharingGroupID": "0",
                    "Tag": [
                        {
                            "ID": "121",
                            "Name": "misp-galaxy:malpedia"
                        },
                        {
                            "ID": "122",
                            "Name": "misp-galaxy:mitre-malware"
                        },
                        {
                            "ID": "123",
                            "Name": "Recorded"
                        },
                        {
                            "ID": "74",
                            "Name": "osint:source-type=\"technical-report\""
                        },
                        {
                            "ID": "2",
                            "Name": "tlp:white"
                        },
                        {
                            "ID": "124",
                            "Name": "Phishing"
                        },
                        {
                            "ID": "125",
                            "Name": "misp-galaxy:target-information=\"United States\""
                        },
                        {
                            "ID": "127",
                            "Name": "misp-galaxy:mitre-malware=\"Agent \""
                        },
                        {
                            "ID": "128",
                            "Name": "misp-galaxy:target-information=\"China\""
                        },
                        {
                            "ID": "129",
                            "Name": "misp-galaxy:target-information=\"Iran\""
                        },
                        {
                            "ID": "130",
                            "Name": "misp-galaxy:target-information=\"Italy\""
                        },
                        {
                            "ID": "131",
                            "Name": "misp-galaxy:target-information=\"Ukraine\""
                        }
                    ],
                    "ThreatLevelID": "1",
                    "LastChanged": "2021-07-20 11:50:07",
                    "UUID": "5e6b322a-9f80-4e2f-9f2a-3cab0a3b4631",
                    "extends_uuid": ""
                },
                "EventID": "149",
                "ID": "70942",
                "ObjectID": "0",
                "ObjectRelation": null,
                "SharingGroupID": "0",
                "Sighting": [
                    {
                        "EventID": "149",
                        "ID": "406",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "5efbf8b2-88de-40a5-8b47-bdd6ffd4cb43",
                        "attribute_id": "70942",
                        "attribute_uuid": "5e6b336e-5224-445f-b1b3-457dd7dd9f6d",
                        "date_sighting": "1625043306",
                        "source": ""
                    }
                ],
                "Tag": [
                    {
                        "ID": "279",
                        "Name": "misp-galaxy:financial-fraud=\"Scam\""
                    },
                    {
                        "ID": "104",
                        "Name": "test1"
                    },
                    {
                        "ID": "123",
                        "Name": "Recorded"
                    },
                    {
                        "ID": "74",
                        "Name": "osint:source-type=\"technical-report\""
                    },
                    {
                        "ID": "2",
                        "Name": "tlp:white"
                    },
                    {
                        "ID": "124",
                        "Name": "Phishing"
                    },
                    {
                        "ID": "125",
                        "Name": "misp-galaxy:target-information=\"United States\""
                    },
                    {
                        "ID": "127",
                        "Name": "misp-galaxy:mitre-malware=\"Agent\""
                    },
                    {
                        "ID": "128",
                        "Name": "misp-galaxy:target-information=\"China\""
                    },
                    {
                        "ID": "129",
                        "Name": "misp-galaxy:target-information=\"Iran\""
                    },
                    {
                        "ID": "130",
                        "Name": "misp-galaxy:target-information=\"Italy\""
                    },
                    {
                        "ID": "131",
                        "Name": "misp-galaxy:target-information=\"Ukraine\""
                    }
                ],
                "LastChanged": "2021-07-18 08:06:40",
                "ToIDs": true,
                "Type": "md5",
                "UUID": "5e6b336e-5224-445f-b1b3-457dd7dd9f6d",
                "Value": "6c73d338ec64e0e44bd54ea61b6988b2",
                "first_seen": null,
                "last_seen": null
            },
            {
                "Category": "Payload delivery",
                "Comment": "",
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Analysis": "2",
                    "CreationDate": "2017-05-03",
                    "Distribution": "1",
                    "ID": "144",
                    "Info": "Snake: Coming soon in Mac OS X flavour",
                    "OrganisationID": "1",
                    "OwnerOrganisation": {
                        "ID": "7",
                        "Name": "CUDESO",
                        "UUID": "56c42374-fdb8-4544-a218-41ffc0a8ab16",
                        "local": false
                    },
                    "OwnerOrganisation.ID": "7",
                    "PublishTimestamp": "2021-06-15 08:31:04",
                    "Published": false,
                    "SharingGroupID": "0",
                    "Tag": [
                        {
                            "ID": "2",
                            "Name": "tlp:white"
                        }
                    ],
                    "ThreatLevelID": "3",
                    "LastChanged": "2021-07-14 08:20:25",
                    "UUID": "590c76a9-0bac-4d1e-b8af-416ac0a8ab16",
                    "extends_uuid": ""
                },
                "EventID": "144",
                "ID": "71741",
                "ObjectID": "0",
                "ObjectRelation": null,
                "SharingGroupID": "0",
                "Sighting": [],
                "Tag": [
                    {
                        "ID": "247",
                        "Name": "passivetotal:class=\"suspicious\""
                    },
                    {
                        "ID": "2",
                        "Name": "tlp:white"
                    }
                ],
                "LastChanged": "2021-07-14 08:20:25",
                "ToIDs": true,
                "Type": "md5",
                "UUID": "f6b054cf-3dbb-4c7b-aab1-a37193e5e841",
                "Value": "6c73d338ec64e0e44bd54ea61b6988b2",
                "first_seen": null,
                "last_seen": null
            },
            {
                "Category": "Payload delivery",
                "Comment": "",
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Analysis": "2",
                    "CreationDate": "2016-01-04",
                    "Distribution": "1",
                    "ID": "145",
                    "Info": "DDOS.TF = (new)",
                    "OrganisationID": "1",
                    "OwnerOrganisation": {
                        "ID": "7",
                        "Name": "CUDESO",
                        "UUID": "56c42374-fdb8-4544-a218-41ffc0a8ab16",
                        "local": false
                    },
                    "OwnerOrganisation.ID": "7",
                    "PublishTimestamp": "2021-06-24 12:31:10",
                    "Published": false,
                    "SharingGroupID": "0",
                    "Tag": [
                        {
                            "ID": "2",
                            "Name": "tlp:white"
                        }
                    ],
                    "ThreatLevelID": "2",
                    "LastChanged": "2021-06-28 07:33:03",
                    "UUID": "56d76936-0d34-44ff-a8c5-5280c0a8ab16",
                    "extends_uuid": ""
                },
                "EventID": "145",
                "ID": "71742",
                "ObjectID": "0",
                "ObjectRelation": null,
                "SharingGroupID": "0",
                "Sighting": [],
                "Tag": [
                    {
                        "ID": "247",
                        "Name": "passivetotal:class=\"suspicious\""
                    },
                    {
                        "ID": "278",
                        "Name": "misp-galaxy:mitre-attack-pattern"
                    },
                    {
                        "ID": "2",
                        "Name": "tlp:white"
                    }
                ],
                "LastChanged": "2021-06-28 07:33:03",
                "ToIDs": false,
                "Type": "md5",
                "UUID": "ec686712-d0a5-4dd8-8736-330da8abefa6",
                "Value": "6c73d338ec64e0e44bd54ea61b6988b2",
                "first_seen": null,
                "last_seen": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Results found in MISP for value: 6c73d338ec64e0e44bd54ea61b6988b2
>|Attribute Category|Attribute Type|Attribute Value|Dbot Score|Events with the scored tag|Scored Tag ID|Scored Tag Name|Timestamp|
>|---|---|---|---|---|---|---|---|
>| Payload delivery | md5 | 6c73d338ec64e0e44bd54ea61b6988b2 | 3 | {'Event_ID': '144', 'Event_Name': 'Snake: Coming soon in Mac OS X flavour'},<br/>{'Event_ID': '145', 'Event_Name': 'DDOS.TF = (new)'} | 247 | passivetotal:class="suspicious" | 2021-07-18 08:06:40 |
>### Related events
>|Event ID|Event Name|Threat Level ID|
>|---|---|---|
>| 149 | Capitalizing on Coronavirus Panic, Threat Actors Target Victims Worldwide | 1 |
>| 144 | Snake: Coming soon in Mac OS X flavour | 3 |
>| 145 | DDOS.TF = (new) | 2 |


### url
***
Checks the reputation of the given email address.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | URL address to check. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The url of the indicator. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| MISP.Attribute.Distribution | string | Attribute distribution. |
| MISP.Attribute.Value | string | Attribute value. |
| MISP.Attribute.EventID | string | Attribute event ID. |
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. |
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. |
| MISP.Attribute.LastChanged | date | Attribute creation timestamp. |
| MISP.Attribute.ObjectID | string | Attribute object id. |
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. |
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled? |
| MISP.Attribute.Type | string | Attribute type. |
| MISP.Attribute.ID | string | Attribute ID. |
| MISP.Attribute.UUID | string | Attribute UUID. |
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. |
| MISP.Attribute.Category | string | Attribute category. |
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. |
| MISP.Attribute.Comment | string | Attribute comment. |
| MISP.Attribute.Event.ID | string | MISP event ID. |
| MISP.Attribute.Event.Distribution | string | MISP event distribution. |
| MISP.Attribute.Event.Info | string | MISP event name. |
| MISP.Attribute.Event.LastChanged | string | Timestamp of the event. |
| MISP.Attribute.Event.Published | boolean | Is the event published. |
| MISP.Attribute.Event.CreationDate | date | Event creation date. |
| MISP.Attribute.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). |
| MISP.Attribute.Event.PublishTimestamp | string | Timestamp of the publish time \(if published\). |
| MISP.Attribute.Event.OrganisationID | string | MISP event organisation ID. |
| MISP.Attribute.Event.OwnerOrganisation.ID | string | Owner organization ID. |
| MISP.Attribute.Event.OwnerOrganisation.Name | string | Owner organization name. |
| MISP.Attribute.Event.OwnerOrganisation.UUID | string | Owner organization UUID. |
| MISP.Attribute.Event.OwnerOrganisation.local | boolean | Is owner organization is local. |
| MISP.Attribute.Event.UUID | string | MISP event UUID. |
| MISP.Attribute.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). |
| MISP.Attribute.Event.SharingGroupID | string | Event sharing group ID. |
| MISP.Attribute.Event.Tag.Name | string | Event tag name. |
| MISP.Attribute.Event.Tag.ID | string | Event tag ID. |
| MISP.Attribute.Tag.Name | string | Attribute tag name. |
| MISP.Attribute.Tag.ID | string | Attribute tag ID. |
| MISP.Attribute.Sighting.Type | string | Attribute's sighting type. |


#### Command Example
```!url url=www.example.com```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "www.example.com",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "url",
        "Vendor": "MISP V3"
    },
    "MISP": {
        "Attribute": [
            {
                "Category": "Network activity",
                "Comment": "",
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Analysis": "2",
                    "CreationDate": "2019-03-18",
                    "Distribution": "1",
                    "ID": "238",
                    "Info": "New Variant Targets Enterprise Wireless Presentation & Display Systems",
                    "OrganisationID": "1",
                    "OwnerOrganisation": {
                        "ID": "7",
                        "Name": "CUDESO",
                        "UUID": "56c42374-fdb8-4544-a218-41ffc0a8ab16",
                        "local": false
                    },
                    "OwnerOrganisation.ID": "7",
                    "PublishTimestamp": "2021-06-23 13:50:21",
                    "Published": false,
                    "SharingGroupID": "0",
                    "Tag": [
                        {
                            "ID": "2",
                            "Name": "tlp:white"
                        }
                    ],
                    "ThreatLevelID": "3",
                    "LastChanged": "2021-07-18 13:10:09",
                    "UUID": "5c93d7f7-7de4-4548-ae4c-403ec0a8ab16",
                    "extends_uuid": ""
                },
                "EventID": "238",
                "ID": "105988",
                "Object": {
                    "Distribution": "5",
                    "ID": "16348",
                    "SharingGroupID": "0"
                },
                "ObjectID": "16348",
                "ObjectRelation": "url",
                "SharingGroupID": "0",
                "Sighting": [
                    {
                        "EventID": "238",
                        "ID": "645",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "a8713fe9-c01a-4f64-986f-4837dd05ddc1",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1625559050",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "662",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "ce0bee18-34cc-4ac7-be2e-9a02d007d207",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1625562799",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "678",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "9a5f8e9d-695f-4abd-8358-f46d325ba8ec",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1625562959",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "683",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "279b8b3a-b6fc-4712-ad5c-99da8a4924aa",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1625563255",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "693",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "24d35e0e-75d8-4b70-a5a4-2d653c39d608",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1625565094",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "705",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "0151d3ec-9f4c-46b0-8527-94d840bd6733",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1625565220",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "717",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "497c607e-b66a-44d5-a745-4eb321eb878c",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1625565618",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "726",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "6f0d1e4f-7080-4af4-9f99-8caae323f889",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1625565779",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "737",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "094ca68a-e148-4b33-8bd8-e244e8a169ea",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1625565824",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "745",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "e0288f76-709e-4226-99aa-776a24787b8b",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1625570192",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1147",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "f3435f97-0d64-40e0-9de2-45edbec03557",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626267334",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1154",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "0ea8d703-be63-4d91-8246-a8f3906bc77d",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626267453",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1169",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "e2b7f418-6759-430c-b630-f59f52d71cbd",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626268114",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1182",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "be61a059-59cf-4bfe-b4f3-18ceed2b40f8",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626268277",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1270",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "ac03faba-9086-41b2-9ff8-6697add1c3aa",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626331820",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1285",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "0ecb835e-c06a-4c74-92d0-e755dc04611b",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626332445",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1299",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "89473477-0ded-42d2-9165-9eebfb7b517b",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626332523",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1303",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "1aace9d2-037b-490d-964c-af96cda2b547",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626332919",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1407",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "7e3d7387-afa9-4e0c-8ed6-bd999972f36f",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626613339",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1427",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "1afc5b0b-1050-418d-9bf6-845e37ba6252",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626613534",
                        "source": ""
                    },
                    {
                        "EventID": "238",
                        "ID": "1438",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "9806ad50-4506-4de6-b1e3-dd39d6db3dda",
                        "attribute_id": "105988",
                        "attribute_uuid": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                        "date_sighting": "1626613815",
                        "source": ""
                    }
                ],
                "Tag": [
                    {
                        "ID": "2",
                        "Name": "tlp:white"
                    }
                ],
                "LastChanged": "2021-07-18 13:10:09",
                "ToIDs": true,
                "Type": "url",
                "UUID": "dc8cdcff-110f-4c6e-b92d-4609ef50c788",
                "Value": "www.example.com",
                "first_seen": null,
                "last_seen": null
            },
            {
                "Category": "Other",
                "Comment": "",
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Analysis": "2",
                    "CreationDate": "2019-03-18",
                    "Distribution": "1",
                    "ID": "238",
                    "Info": "New Variant Targets Enterprise Wireless Presentation & Display Systems",
                    "OrganisationID": "1",
                    "OwnerOrganisation": {
                        "ID": "7",
                        "Name": "CUDESO",
                        "UUID": "56c42374-fdb8-4544-a218-41ffc0a8ab16",
                        "local": false
                    },
                    "OwnerOrganisation.ID": "7",
                    "PublishTimestamp": "2021-06-23 13:50:21",
                    "Published": false,
                    "SharingGroupID": "0",
                    "Tag": [
                        {
                            "ID": "2",
                            "Name": "tlp:white"
                        }
                    ],
                    "ThreatLevelID": "3",
                    "LastChanged": "2021-07-18 13:10:09",
                    "UUID": "5c93d7f7-7de4-4548-ae4c-403ec0a8ab16",
                    "extends_uuid": ""
                },
                "EventID": "238",
                "ID": "105989",
                "Object": {
                    "Distribution": "5",
                    "ID": "16348",
                    "SharingGroupID": "0"
                },
                "ObjectID": "16348",
                "ObjectRelation": "resource_path",
                "SharingGroupID": "0",
                "Sighting": [],
                "Tag": [
                    {
                        "ID": "2",
                        "Name": "tlp:white"
                    }
                ],
                "LastChanged": "2021-07-06 07:50:18",
                "ToIDs": false,
                "Type": "text",
                "UUID": "cc4a2000-b453-412e-8bdd-e5c562d15c78",
                "Value": "www.example.com",
                "first_seen": null,
                "last_seen": null
            }
        ]
    },
    "URL": {
        "Data": "www.example.com",
        "Malicious": {
            "Description": "Match found in MISP",
            "Vendor": "MISP V3"
        }
    }
}
```

#### Human Readable Output

>### Results found in MISP for value: www.example.com
>|Attribute Category|Attribute Type|Attribute Value|Dbot Score|Timestamp|
>|---|---|---|---|---|
>| Network activity | url | www.example.com | 3 | 2021-07-18 13:10:09 |
>### Related events
>|Event ID|Event Name|Threat Level ID|
>|---|---|---|
>| 238 | New Variant Targets Enterprise Wireless Presentation & Display Systems | 3 |


### ip
***
Checks the reputation of an IP address.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address to check. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The ip address. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| MISP.Attribute.Distribution | string | Attribute distribution. |
| MISP.Attribute.Value | string | Attribute value. |
| MISP.Attribute.EventID | string | Attribute event ID. |
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. |
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. |
| MISP.Attribute.LastChanged | date | Attribute creation timestamp. |
| MISP.Attribute.ObjectID | string | Attribute object id. |
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. |
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled? |
| MISP.Attribute.Type | string | Attribute type. |
| MISP.Attribute.ID | string | Attribute ID. |
| MISP.Attribute.UUID | string | Attribute UUID. |
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. |
| MISP.Attribute.Category | string | Attribute category. |
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. |
| MISP.Attribute.Comment | string | Attribute comment. |
| MISP.Attribute.Event.ID | string | MISP event ID. |
| MISP.Attribute.Event.Distribution | string | MISP event distribution. |
| MISP.Attribute.Event.Info | string | MISP event name. |
| MISP.Attribute.Event.LastChanged | string | Timestamp of the event. |
| MISP.Attribute.Event.Published | boolean | Is the event published. |
| MISP.Attribute.Event.CreationDate | date | Event creation date. |
| MISP.Attribute.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). |
| MISP.Attribute.Event.PublishTimestamp | string | Timestamp of the publish time \(if published\). |
| MISP.Attribute.Event.OrganisationID | string | MISP event organisation ID. |
| MISP.Attribute.Event.OwnerOrganisation.ID | string | Owner organization ID. |
| MISP.Attribute.Event.OwnerOrganisation.Name | string | Owner organization name. |
| MISP.Attribute.Event.OwnerOrganisation.UUID | string | Owner organization UUID. |
| MISP.Attribute.Event.OwnerOrganisation.local | boolean | Is owner organization is local. |
| MISP.Attribute.Event.UUID | string | MISP event UUID. |
| MISP.Attribute.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). |
| MISP.Attribute.Event.SharingGroupID | string | Event sharing group ID. |
| MISP.Attribute.Event.Tag.Name | string | Event tag name. |
| MISP.Attribute.Event.Tag.ID | string | Event tag ID. |
| MISP.Attribute.Tag.Name | string | Attribute tag name. |
| MISP.Attribute.Tag.ID | string | Attribute tag ID. |
| MISP.Attribute.Sighting.Type | string | Attribute's sighting type. |


#### Command Example
```!ip ip=1.2.3.4```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.2.3.4",
        "Reliability": "B - Usually reliable",
        "Score": 3,
        "Type": "ip",
        "Vendor": "MISP V3"
    },
    "IP": {
        "Address": "1.2.3.4",
        "Malicious": {
            "Description": "Match found in MISP",
            "Vendor": "MISP V3"
        }
    },
    "MISP": {
        "Attribute": [
            {
                "Category": "External analysis",
                "Comment": "adda",
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Analysis": "1",
                    "CreationDate": "2021-06-29",
                    "Distribution": "2",
                    "ID": "488",
                    "Info": "final create test",
                    "OrganisationID": "1",
                    "OwnerOrganisation": {
                        "ID": "1",
                        "Name": "ORGNAME",
                        "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                        "local": true
                    },
                    "OwnerOrganisation.ID": "1",
                    "PublishTimestamp": "1970-01-01 00:00:00",
                    "Published": false,
                    "SharingGroupID": "0",
                    "Tag": [
                        {
                            "ID": "80",
                            "Name": "certsi:critical-sector=\"energy\""
                        },
                        {
                            "ID": "283",
                            "Name": "test234"
                        },
                        {
                            "ID": "284",
                            "Name": "test2345"
                        }
                    ],
                    "ThreatLevelID": "3",
                    "LastChanged": "2021-07-18 13:05:31",
                    "UUID": "2bf3a888-f2e0-40e9-944c-e87590b637b9",
                    "extends_uuid": ""
                },
                "EventID": "488",
                "ID": "80040",
                "ObjectID": "0",
                "ObjectRelation": null,
                "SharingGroupID": "0",
                "Sighting": [
                    {
                        "EventID": "488",
                        "ID": "387",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "b7f5e0d2-6436-4609-b19d-2cee79239e61",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1624966956",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "616",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "92f032a5-f696-4065-aed7-eb9a1c9adabd",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625496709",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "638",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "ebe00dbf-10d6-40e6-ac3c-575cdd0ad917",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625559050",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "660",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "69b77f1c-41c7-4fbf-80e2-4af131ae0ac0",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625562799",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "669",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "354cd85a-8bb7-4c9d-80e1-d2bfff499b28",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625562959",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "687",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "107a0b06-1ced-4a09-a9aa-de033f28683b",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625563256",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "698",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "99ea6831-3f4b-4907-8a99-08ad259d30ba",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625565095",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "703",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "dbbd4b5d-7122-43c5-9db7-caaa9d8b6d47",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625565220",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "713",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "a11dc840-30c4-4eb6-b469-1f2f1db2c044",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625565618",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "729",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "3058290e-bbff-4748-9ca7-55c3ef6a6fe4",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625565779",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "738",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "a049c84a-de5b-4996-b149-45fd5075a387",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625565824",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "750",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "190f829a-16fa-4985-8154-39c754ced744",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1625570192",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "1168",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "bfd5b4de-c2df-482c-95cf-375ac5998815",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1626268114",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "1181",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "3e6b84c4-ff5e-4012-9845-13bdc511b929",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1626268276",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "1267",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "99b904f8-cbb2-4626-a1c5-3d8f6aaa2887",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1626331820",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "1282",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "ba3be4ba-e228-4358-ba27-382484049460",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1626332445",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "1289",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "b117864b-cee5-4396-b140-198464adf3ed",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1626332522",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "1308",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "06a08a98-4a09-4085-a1fe-15f95719c53d",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1626332919",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "1401",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "4e69267d-6625-4792-999b-d90f24dc30c3",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1626613339",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "1415",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "f58a95cc-21ea-496c-b87f-bc4a4de2ed4c",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1626613442",
                        "source": ""
                    },
                    {
                        "EventID": "488",
                        "ID": "1422",
                        "Organisation": {
                            "ID": "1",
                            "Name": "ORGNAME",
                            "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002"
                        },
                        "OrganisationID": "1",
                        "Type": "0",
                        "UUID": "dda6512b-a373-4ad0-b198-2813e96f67a1",
                        "attribute_id": "80040",
                        "attribute_uuid": "f8d0501b-1c59-444a-be0c-52af8815a304",
                        "date_sighting": "1626613534",
                        "source": ""
                    }
                ],
                "Tag": [
                    {
                        "ID": "283",
                        "Name": "test234"
                    },
                    {
                        "ID": "285",
                        "Name": "test222"
                    },
                    {
                        "ID": "80",
                        "Name": "certsi:critical-sector=\"energy\""
                    },
                    {
                        "ID": "282",
                        "Name": "misp-galaxy:financial-fraud"
                    },
                    {
                        "ID": "283",
                        "Name": "test234"
                    },
                    {
                        "ID": "284",
                        "Name": "test2345"
                    }
                ],
                "LastChanged": "2021-07-18 13:05:31",
                "ToIDs": false,
                "Type": "other",
                "UUID": "f8d0501b-1c59-444a-be0c-52af8815a304",
                "Value": "1.2.3.4",
                "first_seen": null,
                "last_seen": null
            },
            {
                "Category": "Network activity",
                "Comment": "",
                "DecayScore": [
                    {
                        "DecayingModel": {
                            "ID": "2",
                            "Name": "test2"
                        },
                        "base_score": 0,
                        "decayed": true,
                        "score": 0
                    },
                    {
                        "DecayingModel": {
                            "ID": "3",
                            "Name": "test3"
                        },
                        "base_score": 0,
                        "decayed": true,
                        "score": 0
                    }
                ],
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Analysis": "1",
                    "CreationDate": "2021-06-29",
                    "Distribution": "2",
                    "ID": "488",
                    "Info": "final create test",
                    "OrganisationID": "1",
                    "OwnerOrganisation": {
                        "ID": "1",
                        "Name": "ORGNAME",
                        "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                        "local": true
                    },
                    "OwnerOrganisation.ID": "1",
                    "PublishTimestamp": "1970-01-01 00:00:00",
                    "Published": false,
                    "SharingGroupID": "0",
                    "Tag": [
                        {
                            "ID": "80",
                            "Name": "certsi:critical-sector=\"energy\""
                        },
                        {
                            "ID": "283",
                            "Name": "test234"
                        },
                        {
                            "ID": "284",
                            "Name": "test2345"
                        }
                    ],
                    "ThreatLevelID": "3",
                    "LastChanged": "2021-07-18 13:05:31",
                    "UUID": "2bf3a888-f2e0-40e9-944c-e87590b637b9",
                    "extends_uuid": ""
                },
                "EventID": "488",
                "ID": "104119",
                "Object": {
                    "Distribution": "5",
                    "ID": "16035",
                    "SharingGroupID": "0"
                },
                "ObjectID": "16035",
                "ObjectRelation": "ip",
                "SharingGroupID": "0",
                "Sighting": [],
                "Tag": [
                    {
                        "ID": "80",
                        "Name": "certsi:critical-sector=\"energy\""
                    },
                    {
                        "ID": "283",
                        "Name": "test234"
                    },
                    {
                        "ID": "284",
                        "Name": "test2345"
                    }
                ],
                "LastChanged": "2021-06-30 07:37:32",
                "ToIDs": true,
                "Type": "ip-dst",
                "UUID": "d777a0f6-5aa7-4798-b193-bd7da635dc42",
                "Value": "1.2.3.4",
                "first_seen": null,
                "last_seen": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Results found in MISP for value: 1.2.3.4
>|Attribute Category|Attribute Type|Attribute Value|Dbot Score|Timestamp|
>|---|---|---|---|---|
>| External analysis | other | 1.2.3.4 | 3 | 2021-07-18 13:05:31 |
>### Related events
>|Event ID|Event Name|Threat Level ID|
>|---|---|---|
>| 488 | final create test | 3 |


### misp-create-event
***
Creates a new MISP event.


#### Base Command

`misp-create-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Attribute type to be created as part of the new event. Default is other. | Optional |
| category | Attribute category to be created as part of the new event. Default is External analysis. | Optional |
| to_ids | Whether to create the event's attribute with the Intrusion Detection System flag. Possible values are: true, false. Default is true. | Optional |
| distribution | Where to distribute the event. Possible values are: Your_organisation_only, This_community_only, Connected_communities, All_communities, Inherit_event. Default is Your_organisation_only. | Optional |
| comment | Attribute comment to be created as part of the new event. | Optional |
| value | Attribute value to be created as part of the new event. | Required |
| info | Event name. | Required |
| published | Whether to publish the event. Possible values are: false, true. Default is false. | Optional |
| threat_level_id | MISP Threat level ID. Possible values are: High, Medium, Low, Unknown. Default is High. | Optional |
| analysis | The analysis event level. Possible values are: initial, ongoing, completed. Default is initial. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | string | MISP event ID. |
| MISP.Event.Distribution | string | MISP event distribution. |
| MISP.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). |
| MISP.Event.PublishTimestamp | number | Timestamp of the publish time \(if published\). |
| MISP.Event.EventCreatorEmail | string | Email address of the event creator. |
| MISP.Event.Info | string | Event name. |
| MISP.Event.AttributeCount | string | Number of attributes of the event. |
| MISP.Event.OrganisationID | string | Event organization ID. |
| MISP.Event.CreationDate | date | Event creation date. |
| MISP.Event.Locked | boolean | Is the event locked. |
| MISP.Event.Organisation.ID | number | Organization ID. |
| MISP.Event.Organisation.Name | string | Organization name. |
| MISP.Event.Organisation.UUID | string | Organization UUID. |
| MISP.Event.Organisation.local | boolean | Is the organization local. |
| MISP.Event.OwnerOrganisation.ID | number | Owner organization ID. |
| MISP.Event.OwnerOrganisation.Name | string | Owner organization name. |
| MISP.Event.OwnerOrganisation.UUID | string | Owner organization UUID. |
| MISP.Event.OwnerOrganisation.local | boolean | Is the owner organization local. |
| MISP.Event.ProposalEmailLock | boolean | If email lock proposed. |
| MISP.Event.LastChanged | date | Last change event timestamp. |
| MISP.Event.Galaxy.Description | string | Event's galaxy description. |
| MISP.Event.Galaxy.Name | string | Galaxy name. |
| MISP.Event.Galaxy.Type | number | Galaxy type. |
| MISP.Event.Published | boolean | Is the event published. |
| MISP.Event.DisableCorrelation | boolean | Is correlation disabled. |
| MISP.Event.UUID | string | Event UUID. |
| MISP.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). |
| MISP.Event.SharingGroupID | string | Event sharing group ID. |
| MISP.Event.Tag.Name | string | All tag names in the event. |
| MISP.Event.Tag.is_galaxy | boolean | Is the tag is galaxy. |
| MISP.Event.Object.Name | String | Name of the object. |
| MISP.Event.Object.Description | String | Description of the object. |
| MISP.Event.Object.ID | Number | ID of the object. |
| MISP.Event.Object.UUID | String | UUID of the object. |


#### Command Example
```!misp-create-event info="New Event" value=example.com```

#### Context Example
```json
{
    "MISP": {
        "Event": {
            "Analysis": "0",
            "AttributeCount": "1",
            "CreationDate": "2021-07-25",
            "DisableCorrelation": false,
            "Distribution": "0",
            "EventCreatorEmail": "admin@admin.test",
            "Galaxy": [],
            "ID": "1388",
            "Info": "New Event",
            "Locked": false,
            "Object": [],
            "Organisation": {
                "ID": "1",
                "Name": "ORGNAME",
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                "local": true
            },
            "OrganisationID": "1",
            "OwnerOrganisation": {
                "ID": "1",
                "Name": "ORGNAME",
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                "local": true
            },
            "OwnerOrganisation.ID": "1",
            "ProposalEmailLock": false,
            "PublishTimestamp": "1970-01-01 00:00:00",
            "Published": false,
            "RelatedEvent": [],
            "SharingGroupID": "0",
            "ThreatLevelID": "1",
            "LastChanged": "2021-07-25 08:40:34",
            "UUID": "b91cfab1-aef5-4552-a74a-64367c3bf945"
        }
    }
}
```

#### Human Readable Output

>## MISP create event
>New event with ID: 1388 has been successfully created.


### misp-add-attribute
***
Adds an attribute to an existing MISP event.


#### Base Command

`misp-add-attribute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | MISP event ID. | Required |
| type | Attribute type. Default is other. | Optional |
| category | Attribute category. Default is External analysis. | Optional |
| to_ids | Whether to create the attribute with the Intrusion Detection System flag. Possible values are: true, false. Default is true. | Optional |
| distribution | Where to distribute the event. Possible values are: Your_organisation_only, This_community_only, Connected_communities, All_communities, Inherit_event. Default is Inherit_event. | Optional |
| comment | Comment for the attribute. | Optional |
| value | Attribute value. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Attribute.Distribution | string | Attribute distribution. |
| MISP.Attribute.Value | string | Attribute value. |
| MISP.Attribute.EventID | string | Attribute event ID. |
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. |
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. |
| MISP.Attribute.LastChanged | date | Attribute creation timestamp. |
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. |
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled? |
| MISP.Attribute.Type | string | Attribute type. |
| MISP.Attribute.ID | string | Attribute ID. |
| MISP.Attribute.UUID | string | Attribute UUID. |
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. |
| MISP.Attribute.Category | string | Attribute category. |
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. |
| MISP.Attribute.Comment | string | Attribute comment. |
| MISP.Attribute.Event.ID | string | MISP event ID. |
| MISP.Attribute.Event.Distribution | string | MISP event distribution. |
| MISP.Attribute.Event.Info | string | MISP event name. |
| MISP.Attribute.Event.OrganisationID | string | MISP event organisation ID. |
| MISP.Attribute.Event.OwnerOrganisation.ID | string | Event owner organization ID. |
| MISP.Attribute.Event.UUID | string | MISP event UUID. |


#### Command Example
```!misp-add-attribute event_id=1386 value=1.1.1.2 distribution=All_communities comment=test```

#### Context Example
```json
{
    "MISP": {
        "Attribute": {
            "Category": "External analysis",
            "Comment": "test",
            "Deleted": false,
            "DisableCorrelation": false,
            "Distribution": "3",
            "Event": {
                "Distribution": "0",
                "ID": "1386",
                "Info": "New Event",
                "OrganisationID": "1",
                "OwnerOrganisation.ID": "1",
                "UUID": "bd3adb29-4404-4b54-8f88-e87a58325ba1"
            },
            "EventID": "1386",
            "ID": "113885",
            "ObjectID": "0",
            "ObjectRelation": null,
            "SharingGroupID": "0",
            "LastChanged": "2021-07-25 08:40:36",
            "ToIDs": true,
            "Type": "other",
            "UUID": "a5ce7c0f-0473-48f8-8e25-9e517c40d350",
            "Value": "1.1.1.2",
            "first_seen": null,
            "last_seen": null
        }
    }
}
```

#### Human Readable Output

>## MISP add attribute
>New attribute: 1.1.1.2 was added to event id 1386.


### misp-delete-event
***
Deletes an event according to the given event ID.


#### Base Command

`misp-delete-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | Event ID to delete. | Required |


#### Context Output

There is no context output for this command.

#### Command Example
```!misp-delete-event event_id=1386```

#### Human Readable Output

>Event 1386 has been deleted

### misp-remove-tag-from-event
***
Removes a tag from the given UUID event .


#### Base Command

`misp-remove-tag-from-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the event, e.g., 59575300-4be8-4ff6-8767-0037ac110032. | Required |
| tag | Tag to remove from the event. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | string | MISP event ID. |
| MISP.Event.Distribution | string | MISP event distribution. |
| MISP.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). |
| MISP.Event.PublishTimestamp | number | Timestamp of the publish time \(if published\). |
| MISP.Event.EventCreatorEmail | string | Email address of the event creator. |
| MISP.Event.Info | string | Event name. |
| MISP.Event.AttributeCount | string | Number of attributes of the event. |
| MISP.Event.OrganisationID | string | Event organization ID. |
| MISP.Event.CreationDate | date | Event creation date. |
| MISP.Event.Locked | boolean | Is the event locked. |
| MISP.Event.Organisation.ID | number | Organization ID. |
| MISP.Event.Organisation.Name | string | Organization name. |
| MISP.Event.Organisation.UUID | string | Organization UUID. |
| MISP.Event.Organisation.local | boolean | Is the organization local. |
| MISP.Event.OwnerOrganisation.ID | number | Owner organization ID. |
| MISP.Event.OwnerOrganisation.Name | string | Owner organization name. |
| MISP.Event.OwnerOrganisation.UUID | string | Owner organization UUID. |
| MISP.Event.OwnerOrganisation.local | boolean | Is the owner organization local. |
| MISP.Event.ProposalEmailLock | boolean | If email lock proposed. |
| MISP.Event.LastChanged | date | Last change event timestamp. |
| MISP.Event.Galaxy.Description | string | Event's galaxy description. |
| MISP.Event.Galaxy.Name | string | Galaxy name. |
| MISP.Event.Galaxy.Type | number | Galaxy type. |
| MISP.Event.Published | boolean | Is the event published. |
| MISP.Event.DisableCorrelation | boolean | Is correlation disabled. |
| MISP.Event.UUID | string | Event UUID. |
| MISP.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). |
| MISP.Event.SharingGroupID | string | Event sharing group ID. |
| MISP.Event.Tag.Name | string | All tag names in the event. |
| MISP.Event.Tag.is_galaxy | boolean | Is the tag is galaxy. |
| MISP.Event.Object.Name | String | Name of the object. |
| MISP.Event.Object.Description | String | Description of the object. |
| MISP.Event.Object.ID | Number | ID of the object. |
| MISP.Event.Object.UUID | String | UUID of the object. |


#### Command Example
```!misp-remove-tag-from-event tag="test" uuid="bd3adb29-4404-4b54-8f88-e87a58325ba1"```

#### Context Example
```json
{
    "MISP": {
        "Event": {
            "Analysis": "0",
            "AttributeCount": "3",
            "CreationDate": "2021-07-25",
            "DisableCorrelation": false,
            "Distribution": "0",
            "EventCreatorEmail": "admin@admin.test",
            "Galaxy": [],
            "ID": "1386",
            "Info": "New Event",
            "Locked": false,
            "Object": [],
            "Organisation": {
                "ID": "1",
                "Name": "ORGNAME",
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                "local": true
            },
            "OrganisationID": "1",
            "OwnerOrganisation": {
                "ID": "1",
                "Name": "ORGNAME",
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                "local": true
            },
            "OwnerOrganisation.ID": "1",
            "ProposalEmailLock": false,
            "PublishTimestamp": "1970-01-01 00:00:00",
            "Published": false,
            "RelatedEvent": [],
            "SharingGroupID": "0",
            "ThreatLevelID": "1",
            "LastChanged": "2021-07-25 08:40:39",
            "UUID": "bd3adb29-4404-4b54-8f88-e87a58325ba1"
        }
    }
}
```

#### Human Readable Output

>Tag test has been successfully removed from the event bd3adb29-4404-4b54-8f88-e87a58325ba1

### misp-add-tag-to-event
***
Adds a tag to the given UUID event .


#### Base Command

`misp-add-tag-to-event`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the event, e.g., 59575300-4be8-4ff6-8767-0037ac110032. | Required |
| tag | Tag to add to the event. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | string | MISP event ID. |
| MISP.Event.Distribution | string | MISP event distribution. |
| MISP.Event.ThreatLevelID | string | Threat level of the MISP event \(1 High, 2 Medium, 3 Low, 4 Undefined\). |
| MISP.Event.PublishTimestamp | number | Timestamp of the publish time \(if published\). |
| MISP.Event.EventCreatorEmail | string | Email address of the event creator. |
| MISP.Event.Info | string | Event name. |
| MISP.Event.AttributeCount | string | Number of attributes of the event. |
| MISP.Event.OrganisationID | string | Event organization ID. |
| MISP.Event.CreationDate | date | Event creation date. |
| MISP.Event.Locked | boolean | Is the event locked. |
| MISP.Event.Organisation.ID | number | Organization ID. |
| MISP.Event.Organisation.Name | string | Organization name. |
| MISP.Event.Organisation.UUID | string | Organization UUID. |
| MISP.Event.Organisation.local | boolean | Is the organization local. |
| MISP.Event.OwnerOrganisation.ID | number | Owner organization ID. |
| MISP.Event.OwnerOrganisation.Name | string | Owner organization name. |
| MISP.Event.OwnerOrganisation.UUID | string | Owner organization UUID. |
| MISP.Event.OwnerOrganisation.local | boolean | Is the owner organization local. |
| MISP.Event.ProposalEmailLock | boolean | If email lock proposed. |
| MISP.Event.LastChanged | date | Last change event timestamp. |
| MISP.Event.Galaxy.Description | string | Event's galaxy description. |
| MISP.Event.Galaxy.Name | string | Galaxy name. |
| MISP.Event.Galaxy.Type | number | Galaxy type. |
| MISP.Event.Published | boolean | Is the event published. |
| MISP.Event.DisableCorrelation | boolean | Is correlation disabled. |
| MISP.Event.UUID | string | Event UUID. |
| MISP.Event.Analysis | string | Event analysis \(0 Initial, 1 Ongoing, 2 Completed\). |
| MISP.Event.SharingGroupID | string | Event sharing group ID. |
| MISP.Event.Tag.Name | string | All tag names in the event. |
| MISP.Event.Tag.is_galaxy | boolean | Is the tag is galaxy. |
| MISP.Event.Object.Name | String | Name of the object. |
| MISP.Event.Object.Description | String | Description of the object. |
| MISP.Event.Object.ID | Number | ID of the object. |
| MISP.Event.Object.UUID | String | UUID of the object. |


#### Command Example
```!misp-add-tag-to-event uuid="bd3adb29-4404-4b54-8f88-e87a58325ba1" tag="test"```

#### Context Example
```json
{
    "MISP": {
        "Event": {
            "Analysis": "0",
            "AttributeCount": "3",
            "CreationDate": "2021-07-25",
            "DisableCorrelation": false,
            "Distribution": "0",
            "EventCreatorEmail": "admin@admin.test",
            "Galaxy": [],
            "ID": "1386",
            "Info": "New Event",
            "Locked": false,
            "Object": [],
            "Organisation": {
                "ID": "1",
                "Name": "ORGNAME",
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                "local": true
            },
            "OrganisationID": "1",
            "OwnerOrganisation": {
                "ID": "1",
                "Name": "ORGNAME",
                "UUID": "5ce29ac4-3b54-459e-a6ee-00acac110002",
                "local": true
            },
            "OwnerOrganisation.ID": "1",
            "ProposalEmailLock": false,
            "PublishTimestamp": "1970-01-01 00:00:00",
            "Published": false,
            "RelatedEvent": [],
            "SharingGroupID": "0",
            "Tag": [
                {
                    "Name": "test",
                    "is_galaxy": false
                }
            ],
            "ThreatLevelID": "1",
            "LastChanged": "2021-07-25 08:40:39",
            "UUID": "bd3adb29-4404-4b54-8f88-e87a58325ba1"
        }
    }
}
```

#### Human Readable Output

>Tag test has been successfully added to event bd3adb29-4404-4b54-8f88-e87a58325ba1

### misp-add-tag-to-attribute
***
Adds a tag to the given UUID attribute .


#### Base Command

`misp-add-tag-to-attribute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the attribute, e.g., 59575300-4be8-4ff6-8767-0037ac110032. | Required |
| tag | Tag to add to the attribute. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Attribute.Distribution | string | Attribute distribution. |
| MISP.Attribute.Value | string | Attribute value. |
| MISP.Attribute.EventID | string | Attribute event ID. |
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. |
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. |
| MISP.Attribute.LastChanged | date | Attribute creation timestamp. |
| MISP.Attribute.ObjectID | string | Attribute object id. |
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. |
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled? |
| MISP.Attribute.Type | string | Attribute type. |
| MISP.Attribute.ID | string | Attribute ID. |
| MISP.Attribute.UUID | string | Attribute UUID. |
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. |
| MISP.Attribute.Category | string | Attribute category. |
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. |
| MISP.Attribute.Comment | string | Attribute comment. |
| MISP.Attribute.Event.ID | string | MISP event ID. |
| MISP.Attribute.Event.Distribution | string | MISP event distribution. |
| MISP.Attribute.Event.Info | string | MISP event name. |
| MISP.Attribute.Event.OrganisationID | string | MISP event organisation ID. |
| MISP.Attribute.Event.OwnerOrganisation.ID | string | Event owner organization ID. |
| MISP.Attribute.Event.UUID | string | MISP event UUID. |
| MISP.Attribute.Tag.Name | string | Attribute tag name. |
| MISP.Attribute.Tag.is_galaxy | string | Is tag is galexy. |


#### Command Example
```!misp-add-tag-to-attribute tag=test uuid="ccf241a4-971f-432d-be05-ee8cb6a3c28e"```

#### Context Example
```json
{
    "MISP": {
        "Attribute": {
            "Category": "External analysis",
            "Comment": "test",
            "Deleted": false,
            "DisableCorrelation": false,
            "Distribution": "3",
            "Event": {
                "Distribution": "0",
                "ID": "1386",
                "Info": "New Event",
                "OrganisationID": "1",
                "OwnerOrganisation.ID": "1",
                "UUID": "bd3adb29-4404-4b54-8f88-e87a58325ba1"
            },
            "EventID": "1386",
            "ID": "113879",
            "ObjectID": "0",
            "ObjectRelation": null,
            "SharingGroupID": "0",
            "Tag": [
                {
                    "Name": "test",
                    "is_galaxy": null
                }
            ],
            "LastChanged": "2021-07-25 08:40:43",
            "ToIDs": true,
            "Type": "other",
            "UUID": "ccf241a4-971f-432d-be05-ee8cb6a3c28e",
            "Value": "1.1.1.3",
            "first_seen": null,
            "last_seen": null
        }
    }
}
```

#### Human Readable Output

>Tag test has been successfully added to attribute ccf241a4-971f-432d-be05-ee8cb6a3c28e

### misp-remove-tag-from-attribute
***
Removes a tag from the given UUID attribute .


#### Base Command

`misp-remove-tag-from-attribute`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| uuid | UUID of the attribute, e.g., 59575300-4be8-4ff6-8767-0037ac110032. | Required |
| tag | Tag to remove from the attribute. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Attribute.Distribution | string | Attribute distribution. |
| MISP.Attribute.Value | string | Attribute value. |
| MISP.Attribute.EventID | string | Attribute event ID. |
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. |
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. |
| MISP.Attribute.LastChanged | date | Attribute creation timestamp. |
| MISP.Attribute.ObjectID | string | Attribute object id. |
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. |
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled? |
| MISP.Attribute.Type | string | Attribute type. |
| MISP.Attribute.ID | string | Attribute ID. |
| MISP.Attribute.UUID | string | Attribute UUID. |
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. |
| MISP.Attribute.Category | string | Attribute category. |
| MISP.Attribute.SharingGroupID | string | Attribute sharing group ID. |
| MISP.Attribute.Comment | string | Attribute comment. |
| MISP.Attribute.Event.ID | string | MISP event ID. |
| MISP.Attribute.Event.Distribution | string | MISP event distribution. |
| MISP.Attribute.Event.Info | string | MISP event name. |
| MISP.Attribute.Event.OrganisationID | string | MISP event organisation ID. |
| MISP.Attribute.Event.OwnerOrganisation.ID | string | Event owner organization ID. |
| MISP.Attribute.Event.UUID | string | MISP event UUID. |
| MISP.Attribute.Tag.Name | string | Attribute tag name. |
| MISP.Attribute.Tag.is_galaxy | string | Is tag is galexy. |


#### Command Example
```!misp-remove-tag-from-attribute tag=test uuid="ccf241a4-971f-432d-be05-ee8cb6a3c28e"```

#### Context Example
```json
{
    "MISP": {
        "Attribute": {
            "Category": "External analysis",
            "Comment": "test",
            "Deleted": false,
            "DisableCorrelation": false,
            "Distribution": "3",
            "Event": {
                "Distribution": "0",
                "ID": "1386",
                "Info": "New Event",
                "OrganisationID": "1",
                "OwnerOrganisation.ID": "1",
                "UUID": "bd3adb29-4404-4b54-8f88-e87a58325ba1"
            },
            "EventID": "1386",
            "ID": "113879",
            "ObjectID": "0",
            "ObjectRelation": null,
            "SharingGroupID": "0",
            "LastChanged": "2021-07-25 08:40:43",
            "ToIDs": true,
            "Type": "other",
            "UUID": "ccf241a4-971f-432d-be05-ee8cb6a3c28e",
            "Value": "1.1.1.3",
            "first_seen": null,
            "last_seen": null
        }
    }
}
```

#### Human Readable Output

>Tag test has been successfully removed from the attribute ccf241a4-971f-432d-be05-ee8cb6a3c28e

### misp-add-sighting
***
Add sighting to an attribute.


#### Base Command

`misp-add-sighting`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | Type of sighting to add. Possible values are: sighting, false_positive, expiration. | Required |
| id | ID of attribute to add sighting to (Must be filled if UUID is empty). Can be retrieved from misp-search. | Optional |
| uuid | UUID of attribute to add sighting to (Must be filled if ID is empty). Can be retrieved from misp-search. | Optional |


#### Context Output

There is no context output for this command.

#### Command Example
```!misp-add-sighting uuid="ccf241a4-971f-432d-be05-ee8cb6a3c28e" type=false_positive```

#### Human Readable Output

>Sighting 'false_positive' has been successfully added to attribute ccf241a4-971f-432d-be05-ee8cb6a3c28e

### misp-add-events-from-feed
***
Adds an OSINT feed. Only feeds from format misp are allowed (i.e have manifest.json).


#### Base Command

`misp-add-events-from-feed`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| feed | URL of the feed to add. Possible values are: CIRCL, Botvrij.eu. | Required |
| limit | Maximum number of files to add. Default is 2. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | string | IDs of newly created events. |


#### Command Example
```!misp-add-events-from-feed limit=1 feed=Botvrij.eu```

#### Human Readable Output

>### Total of 0 events was added to MISP.
>**No entries.**


### misp-add-file-object
***
Adds an file object to the specified event ID.


#### Base Command

`misp-add-file-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of the file. | Required |
| event_id | Event ID to which add object to. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. |
| MISP.Event.Object.MetaCategory | String | Object meta category. |
| MISP.Event.Object.Distribution | Number | Distribution of object. |
| MISP.Event.Object.Name | String | Name of the object. |
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. |
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. |
| MISP.Event.Object.TemplateUUID | String | UUID of the template. |
| MISP.Event.Object.LastChanged | String | Timestamp when the object was created. |
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. |
| MISP.Event.Object.ID | Number | ID of the object. |
| MISP.Event.Object.UUID | String | UUID of the object. |
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. |
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. |
| MISP.Event.Object.Attribute.LastChanged | Date | Timestamp when the object was created. |
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted. |
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. |
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. |
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. |
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. |
| MISP.Event.Object.Attribute.Type | String | Object type. |
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. |
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. |
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. |
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. |
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. |
| MISP.Event.Object.Description | String | Description of the object. |


#### Command Example
``` !misp-add-file-object entry_id=${File.EntryID} event_id=1388 ```

#### Human Readable Output
>Object has been added to MISP event ID 1388


### misp-add-domain-object
***
Adds a domain object to MISP.


#### Base Command

`misp-add-domain-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | ID of a MISP event. | Required |
| name | The domain name, for example "google.com". | Required |
| ip | A comma separated`` list of IP addresses resolved by DNS. | Required |
| text | A description of the domain. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. |
| MISP.Event.Object.MetaCategory | String | Object meta category. |
| MISP.Event.Object.Distribution | Number | Distribution of the object. |
| MISP.Event.Object.Name | String | Name of the object. |
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. |
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. |
| MISP.Event.Object.TemplateUUID | String | UUID of the template. |
| MISP.Event.Object.LastChanged | String | Timestamp when the object was created. |
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. |
| MISP.Event.Object.ID | Number | ID of the object. |
| MISP.Event.Object.UUID | String | UUID of the object. |
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. |
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. |
| MISP.Event.Object.Attribute.LastChanged | Date | Timestamp of object creation |
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted. |
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. |
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. |
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. |
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. |
| MISP.Event.Object.Attribute.Type | String | Object type. |
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. |
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. |
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. |
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. |
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. |
| MISP.Event.Object.Description | String | Description of the object. |


#### Command Example
```!misp-add-domain-object ip="5.6.4.4" event_id=1386 name=v.com text=new```

#### Context Example
```json
{
    "MISP": {
        "Event": {
            "ID": "1386",
            "Object": {
                "Attribute": [
                    {
                        "Category": "Network activity",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": false,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113886",
                        "ObjectID": "17631",
                        "ObjectRelation": "ip",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:50",
                        "ToIDs": true,
                        "Type": "ip-dst",
                        "UUID": "ca25f831-8f91-4a1c-8a06-017269c69990",
                        "Value": "5.6.4.4",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "5.6.4.4",
                        "value2": ""
                    },
                    {
                        "Category": "Network activity",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": false,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113887",
                        "ObjectID": "17631",
                        "ObjectRelation": "domain",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:50",
                        "ToIDs": true,
                        "Type": "domain",
                        "UUID": "5ab66f03-cfcb-4540-9a0d-21f8cfad71ad",
                        "Value": "v.com",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "v.com",
                        "value2": ""
                    },
                    {
                        "Category": "Other",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": true,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113888",
                        "ObjectID": "17631",
                        "ObjectRelation": "text",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:50",
                        "ToIDs": false,
                        "Type": "text",
                        "UUID": "59dd3a7c-d6f8-464c-9f15-817309c58a2e",
                        "Value": "new",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "new",
                        "value2": ""
                    }
                ],
                "Comment": "",
                "Deleted": false,
                "Description": "A domain/hostname and IP address seen as a tuple in a specific time frame.",
                "Distribution": "5",
                "EventID": "1386",
                "ID": "17631",
                "MetaCategory": "network",
                "Name": "domain-ip",
                "SharingGroupID": "0",
                "TemplateUUID": "43b3b146-77eb-4931-b4cc-b66c60f28734",
                "TemplateVersion": "9",
                "LastChanged": "2021-07-25 08:40:50",
                "UUID": "65a87177-9366-4aa9-9287-cce28ffb3ef8",
                "first_seen": null,
                "last_seen": null
            }
        }
    }
}
```

#### Human Readable Output

>Object has been added to MISP event ID 1386

### misp-add-url-object
***
Adds a URL object to a MISP event.


#### Base Command

`misp-add-url-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | Full URL to add to the event. | Required |
| first_seen | Date that this URL was first seen, for example `2019-02-03`.'. | Optional |
| text | Description of the URL. | Optional |
| last_seen | Date that this URL was last seen, for example `2019-02-03`. | Optional |
| event_id | ID of a MISP event. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. |
| MISP.Event.Object.MetaCategory | String | Object meta category. |
| MISP.Event.Object.Distribution | Number | Distribution of the object. |
| MISP.Event.Object.Name | String | Name of the object. |
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. |
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. |
| MISP.Event.Object.TemplateUUID | String | UUID of the template. |
| MISP.Event.Object.LastChanged | String | Timestamp when the object was created. |
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. |
| MISP.Event.Object.ID | Number | ID of the object. |
| MISP.Event.Object.UUID | String | UUID of the object. |
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. |
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. |
| MISP.Event.Object.Attribute.LastChanged | Date | Timestamp when the object was created. |
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted. |
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. |
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. |
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. |
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. |
| MISP.Event.Object.Attribute.Type | String | Object type. |
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. |
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. |
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. |
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. |
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. |
| MISP.Event.Object.Description | String | Description of the object. |


#### Command Example
```!misp-add-url-object event_id=1386 url=d.com```

#### Context Example
```json
{
    "MISP": {
        "Event": {
            "ID": "1386",
            "Object": {
                "Attribute": [
                    {
                        "Category": "Network activity",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": false,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113894",
                        "ObjectID": "17633",
                        "ObjectRelation": "url",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:54",
                        "ToIDs": true,
                        "Type": "url",
                        "UUID": "9477a4ec-1d34-48e0-a549-21b1bb32590e",
                        "Value": "d.com",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "d.com",
                        "value2": ""
                    },
                    {
                        "Category": "Other",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": false,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113895",
                        "ObjectID": "17633",
                        "ObjectRelation": "resource_path",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:54",
                        "ToIDs": false,
                        "Type": "text",
                        "UUID": "6fbfe727-a739-46c9-ae83-710aa17e003c",
                        "Value": "d.com",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "d.com",
                        "value2": ""
                    }
                ],
                "Comment": "",
                "Deleted": false,
                "Description": "url object describes an url along with its normalized field (like extracted using faup parsing library) and its metadata.",
                "Distribution": "5",
                "EventID": "1386",
                "ID": "17633",
                "MetaCategory": "network",
                "Name": "url",
                "SharingGroupID": "0",
                "TemplateUUID": "60efb77b-40b5-4c46-871b-ed1ed999fce5",
                "TemplateVersion": "9",
                "LastChanged": "2021-07-25 08:40:54",
                "UUID": "f31dbe26-032c-40c7-87c9-662cb320a0d1",
                "first_seen": null,
                "last_seen": null
            }
        }
    }
}
```

#### Human Readable Output

>Object has been added to MISP event ID 1386

### misp-add-object
***
Adds any other object to MISP.


#### Base Command

`misp-add-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | ID of the event to add the object to. | Required |
| template | Template name (can be found at https://www.misp-project.org/objects.html), for example 'vehicle'. | Required |
| attributes | Attributes, for example {'description': 'Manager Ferrari', 'make': 'Ferrari', 'model': '308 GTS'}. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. |
| MISP.Event.Object.MetaCategory | String | Object meta category. |
| MISP.Event.Object.Distribution | Number | Distribution of the object. |
| MISP.Event.Object.Name | String | Name of the object. |
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. |
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. |
| MISP.Event.Object.TemplateUUID | String | UUID of the template. |
| MISP.Event.Object.LastChanged | String | Timestamp when the object was created. |
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. |
| MISP.Event.Object.ID | Number | ID of the object. |
| MISP.Event.Object.UUID | String | UUID of the object. |
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. |
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. |
| MISP.Event.Object.Attribute.LastChanged | Date | Timestamp when the object was created. |
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted? |
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. |
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. |
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. |
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. |
| MISP.Event.Object.Attribute.Type | String | Object type. |
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. |
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. |
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. |
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. |
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. |
| MISP.Event.Object.Description | String | Description of the object. |


#### Command Example
```!misp-add-object attributes="{'description':'Manager','make': 'Test', 'model': '308 GTS'}"  template=vehicle event_id=1386```

#### Context Example
```json
{
    "MISP": {
        "Event": {
            "ID": "1386",
            "Object": {
                "Attribute": [
                    {
                        "Category": "Other",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": true,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113896",
                        "ObjectID": "17634",
                        "ObjectRelation": "description",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:55",
                        "ToIDs": false,
                        "Type": "text",
                        "UUID": "ed5824e2-d512-4b11-bb52-94698fa0d467",
                        "Value": "Manager",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "Manager",
                        "value2": ""
                    },
                    {
                        "Category": "Other",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": true,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113897",
                        "ObjectID": "17634",
                        "ObjectRelation": "make",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:55",
                        "ToIDs": false,
                        "Type": "text",
                        "UUID": "b04476f3-3179-4ebd-926a-95992f803946",
                        "Value": "Test",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "Test",
                        "value2": ""
                    },
                    {
                        "Category": "Other",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": true,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113898",
                        "ObjectID": "17634",
                        "ObjectRelation": "model",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:55",
                        "ToIDs": false,
                        "Type": "text",
                        "UUID": "fd533823-8484-40d3-92b1-e9282e04bad0",
                        "Value": "308 GTS",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "308 GTS",
                        "value2": ""
                    }
                ],
                "Comment": "",
                "Deleted": false,
                "Description": "Vehicle object template to describe a vehicle information and registration",
                "Distribution": "5",
                "EventID": "1386",
                "ID": "17634",
                "MetaCategory": "misc",
                "Name": "vehicle",
                "SharingGroupID": "0",
                "TemplateUUID": "683c076c-f695-4ff2-8efa-e98a418049f4",
                "TemplateVersion": "3",
                "LastChanged": "2021-07-25 08:40:55",
                "UUID": "68e21313-43a6-450c-a830-fd5d42f6ecb2",
                "first_seen": null,
                "last_seen": null
            }
        }
    }
}
```

#### Human Readable Output

>Object has been added to MISP event ID 1386

### misp-add-ip-object
***
Adds an IP object to the MISP event. The following arguments are optional, but at least one must be supplied for the command to run successfully: "ip", "dst_port", "src_port", "domain", "hostname", "ip_src", and "ip_dst".


#### Base Command

`misp-add-ip-object`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_id | ID of a MISP event. | Required |
| ip | A comma seperated list of ip addresses. | Optional |
| dst_port | Destination port number. | Optional |
| src_port | Source port number. | Optional |
| domain | Domain name. | Optional |
| hostname | Hostname, For example 'mail123.example.com'. | Optional |
| ip_src | IP source address. | Optional |
| ip_dst | IP destination adress. | Optional |
| first_seen | Date when the ip address was first seen, for example `2019-02-03`. | Optional |
| last_seen | Date when the ip address was last seen, for example `2019-02-03`. | Optional |
| comment | Description of the object to be set as a text attribute. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Event.ID | number | MISP event ID. |
| MISP.Event.Object.MetaCategory | String | Object meta category. |
| MISP.Event.Object.Distribution | Number | Distribution of the object. |
| MISP.Event.Object.Name | String | Name of the object. |
| MISP.Event.Object.TemplateVersion | Number | Template version of the object. |
| MISP.Event.Object.EventID | Number | ID of the event in which the object was first created. |
| MISP.Event.Object.TemplateUUID | String | UUID of the template. |
| MISP.Event.Object.LastChanged | String | Timestamp when the object was created. |
| MISP.Event.Object.Deleted | Boolean | Whether the object was deleted. |
| MISP.Event.Object.ID | Number | ID of the object. |
| MISP.Event.Object.UUID | String | UUID of the object. |
| MISP.Event.Object.Attribute.Value | String | Value of the attribute. |
| MISP.Event.Object.Attribute.EventID | Number | ID of the first event from which the object originated. |
| MISP.Event.Object.Attribute.LastChanged | Date | Timestamp when the object was created. |
| MISP.Event.Object.Attribute.Deleted | Boolean | Whether the object was deleted. |
| MISP.Event.Object.Attribute.ObjectID | Number | ID of the object. |
| MISP.Event.Object.Attribute.DisableCorrelation | Boolean | Whether correlation is disabled. |
| MISP.Event.Object.Attribute.ID | Unknown | ID of the attribute. |
| MISP.Event.Object.Attribute.ObjectRelation | String | Relation of the object. |
| MISP.Event.Object.Attribute.Type | String | Object type. |
| MISP.Event.Object.Attribute.UUID | String | UUID of the attribute. |
| MISP.Event.Object.Attribute.ToIDs | Boolean | Whether the to_ids flag is on. |
| MISP.Event.Object.Attribute.Category | String | Category of the attribute. |
| MISP.Event.Object.Attribute.SharingGroupID | Number | ID of the sharing group. |
| MISP.Event.Object.Attribute.Comment | String | Comment of the attribute. |
| MISP.Event.Object.Description | String | Description of the object. |


#### Command Example
```!misp-add-ip-object event_id=1386 dst_port=4545 ip_src=1.2.4.4 ip_dst=1.5.52.1 src_port=1001 comment=nice```

#### Context Example
```json
{
    "MISP": {
        "Event": {
            "ID": "1386",
            "Object": {
                "Attribute": [
                    {
                        "Category": "Network activity",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": true,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113889",
                        "ObjectID": "17632",
                        "ObjectRelation": "dst-port",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:52",
                        "ToIDs": false,
                        "Type": "port",
                        "UUID": "70450b90-7900-418c-aef8-f21b6eae5103",
                        "Value": "4545",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "4545",
                        "value2": ""
                    },
                    {
                        "Category": "Network activity",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": false,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113890",
                        "ObjectID": "17632",
                        "ObjectRelation": "src-port",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:52",
                        "ToIDs": false,
                        "Type": "port",
                        "UUID": "dd5fcb17-9323-4eb3-9b34-fa5ba5bfa0a0",
                        "Value": "1001",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "1001",
                        "value2": ""
                    },
                    {
                        "Category": "Network activity",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": false,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113891",
                        "ObjectID": "17632",
                        "ObjectRelation": "ip-src",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:52",
                        "ToIDs": true,
                        "Type": "ip-src",
                        "UUID": "0c884a97-5211-495f-84d4-2be378140766",
                        "Value": "1.2.4.4",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "1.2.4.4",
                        "value2": ""
                    },
                    {
                        "Category": "Network activity",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": false,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113892",
                        "ObjectID": "17632",
                        "ObjectRelation": "ip-dst",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:52",
                        "ToIDs": true,
                        "Type": "ip-dst",
                        "UUID": "d2ac7a54-ad89-4ce7-9d5a-75bab87604ba",
                        "Value": "1.5.52.1",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "1.5.52.1",
                        "value2": ""
                    },
                    {
                        "Category": "Other",
                        "Comment": "",
                        "Deleted": false,
                        "DisableCorrelation": true,
                        "Distribution": "5",
                        "EventID": "1386",
                        "ID": "113893",
                        "ObjectID": "17632",
                        "ObjectRelation": "text",
                        "SharingGroupID": "0",
                        "LastChanged": "2021-07-25 08:40:52",
                        "ToIDs": false,
                        "Type": "text",
                        "UUID": "93aa78e6-fad8-4424-b41c-ecdd001ad8fe",
                        "Value": "nice",
                        "first_seen": null,
                        "last_seen": null,
                        "value1": "nice",
                        "value2": ""
                    }
                ],
                "Comment": "",
                "Deleted": false,
                "Description": "An IP address (or domain or hostname) and a port seen as a tuple (or as a triple) in a specific time frame.",
                "Distribution": "5",
                "EventID": "1386",
                "ID": "17632",
                "MetaCategory": "network",
                "Name": "ip-port",
                "SharingGroupID": "0",
                "TemplateUUID": "9f8cea74-16fe-4968-a2b4-026676949ac6",
                "TemplateVersion": "8",
                "LastChanged": "2021-07-25 08:40:52",
                "UUID": "ee93accc-b707-4788-aa90-97a747447007",
                "first_seen": null,
                "last_seen": null
            }
        }
    }
}
```

#### Human Readable Output

>Object has been added to MISP event ID 1386

### misp-search-attributes
***
Search for attributes in MISP.


#### Base Command

`misp-search-attributes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The attribute type. Use any valid MISP attribute type. | Optional |
| value | Search for the specified value in the attributes' value field. | Optional |
| category | The attribute category. Use any valid MISP attribute category. | Optional |
| uuid | Return attributes with the given UUID. Alternatively, return all the attributes that are part of the given UUID's event. E.g., 59523300-4be8-4fa6-8867-0037ac110002 . | Optional |
| to_ids | Whether to return only the attributes set with the "to_ids" flag. The default is to return all attributes without with and with out to_ids flag. Possible values are: true, false. | Optional |
| last | Search attributes of events published within the last "x" amount of time. Valid time values are days, hours, and minutes (for example "5d", "12h", "30m"). This filter uses the published timestamp of the event. | Optional |
| include_decay_score | Whether to return the decay score at the attribute level. Default is false. Possible values are: true, false. | Optional |
| org | Search by the creator organisation by supplying the organisation identifier. | Optional |
| tags | A comma-separated list of tags to include in the results. To exclude a tag, prefix the tag name with "!". Can be: "AND", "OR", and "NOT" followed by ":". To chain logical operators use ";". for example, "AND:tag1,tag2;OR:tag3". | Optional |
| from | Events with the date set to a date after the one specified. This filter will use the date of the event. | Optional |
| to | Events with the date set to a date before the one specified. This filter will use the date of the event. | Optional |
| event_id | A comma-separated list of event ids, return the attributes that are part of the given event ids. | Optional |
| include_sightings | Whether to include the the sightings of the matching attributes. Default is false. Possible values are: true, false. | Optional |
| include_correlations | Whether to include the full correlations of the matching attributes. Default is false. Possible values are: true, false. | Optional |
| page | If a limit is set, sets the page to be returned. page 3, limit 100 will return records 201-&gt;300). | Optional |
| limit | Limit the number of attributes returned. Default is 50. | Optional |
| enforceWarninglist | Whether to return only the values that are not on the warninglists. Possible values are: true, false. | Optional |
| compact | Whether return only the attribute's values that match the search query. In case you want to get the full attributes data, please set this argument to false. Possible values are: true, false. Default is false. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MISP.Attribute.Distribution | string | Attribute distribution. |
| MISP.Attribute.last_seen | string | Attribute last_seen timestamp. |
| MISP.Attribute.first_seen | string | Attribute first_seen timestamp. |
| MISP.Attribute.Value | string | Attribute value. |
| MISP.Attribute.EventID | string | Attribute event ID. |
| MISP.Attribute.LastChanged | date | Attribute creation timestamp. |
| MISP.Attribute.Deleted | boolean | Is the attribute deleted. |
| MISP.Attribute.DisableCorrelation | boolean | Is attribute correlation disabled. |
| MISP.Attribute.Type | string | Attribute type. |
| MISP.Attribute.ObjectID | string | Attribute's object ID. |
| MISP.Attribute.ID | string | Attribute ID. |
| MISP.Attribute.UUID | string | Attribute UUID. |
| MISP.Attribute.ObjectRelation | string | Attribute's object relation. |
| MISP.Attribute.ShadowAttribute | Unknown | Attribute shadow attribute. |
| MISP.Attribute.ToIDs | boolean | Is the Intrusion Detection System flag set. |
| MISP.Attribute.Category | string | Attribute category. |
| MISP.Attribute.SharingGroupID | number | Attribute sharing group ID. |
| MISP.Attribute.Comment | string | Attribute comment. |
| MISP.Attribute.Event.ID | string | MISP event ID. |
| MISP.Attribute.Event.Distribution | string | MISP event distribution. |
| MISP.Attribute.Event.Info | string | MISP event name. |
| MISP.Attribute.Event.OrganisationID | string | MISP event organisation id. |
| MISP.Attribute.Event.OwnerOrganisation.ID | string | MISP event owner organisation id. |
| MISP.Attribute.Event.UUID | string | Event UUID. |
| MISP.Attribute.Object.Distribution | Number | Distribution of object. |
| MISP.Attribute.Object.ID | Number | ID of the object. |
| MISP.Attribute.Object.SharingGroupID | String | Object sharing group id. |
| MISP.Attribute.Tag.Name | string | All tag names in the attribute. |
| MISP.Attribute.Tag.is_galaxy | Boolean | Is the tag is a galaxy. |
| MISP.Attribute.Sighting.Type | String | Sighting type. |


#### Command Example
```!misp-search-attributes tags="COVID-19"```

#### Context Example
```json
{
    "MISP": {
        "Attribute": [
            {
                "Category": "Payload delivery",
                "Comment": "",
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Distribution": "3",
                    "ID": "149",
                    "Info": "Capitalizing on Coronavirus Panic, Threat Actors Target Victims Worldwide",
                    "OrganisationID": "1",
                    "OwnerOrganisation.ID": "8",
                    "UUID": "5e6b322a-9f80-4e2f-9f2a-3cab0a3b4631"
                },
                "EventID": "149",
                "ID": "71703",
                "ObjectID": "0",
                "ObjectRelation": null,
                "SharingGroupID": "0",
                "Tag": [
                    {
                        "Name": "COVID-19",
                        "is_galaxy": null
                    }
                ],
                "LastChanged": "2021-07-19 12:44:27",
                "ToIDs": true,
                "Type": "sha256",
                "UUID": "7f78d940-c1f1-4a75-87a5-11b0fcd61e53",
                "Value": "c8466c386261facf38ce62e75a8c6414affbfaed439e91fa00e515e079702fe0",
                "first_seen": null,
                "last_seen": null
            },
            {
                "Category": "Network activity",
                "Comment": "",
                "Deleted": false,
                "DisableCorrelation": false,
                "Distribution": "5",
                "Event": {
                    "Distribution": "1",
                    "ID": "143",
                    "Info": "Recent Qakbot (Qbot) activity",
                    "OrganisationID": "1",
                    "OwnerOrganisation.ID": "7",
                    "UUID": "5fd0c599-ab6c-4ba1-a69a-df9ec0a8ab16"
                },
                "EventID": "143",
                "ID": "71740",
                "ObjectID": "0",
                "ObjectRelation": null,
                "SharingGroupID": "0",
                "Tag": [
                    {
                        "Name": "COVID-19",
                        "is_galaxy": null
                    },
                    {
                        "Name": "misp-galaxy:financial-fraud=\"Compromised Personally Identifiable Information (PII)\"",
                        "is_galaxy": null
                    }
                ],
                "LastChanged": "2021-06-21 12:35:10",
                "ToIDs": true,
                "Type": "ip-dst",
                "UUID": "de95a690-97b9-491c-bd94-1ab7ee885622",
                "Value": "1.2.3.4",
                "first_seen": null,
                "last_seen": null
            }
        ]
    }
}
```

#### Human Readable Output

>### MISP search-attributes returned 2 attributes
>|Attribute Category|Attribute ID|Attribute Tags|Attribute Type|Attribute Value|Event Distribution|Event ID|Event Info|Event Organisation ID|Event UUID|Timestamp|To IDs|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| Payload delivery | 71703 | COVID-19,<br/>misp-galaxy:financial-fraud="Cash Recovery Scam" | sha256 | c8466c386261facf38ce62e75a8c6414affbfaed439e91fa00e515e079702fe0 | 3 | 149 | Capitalizing on Coronavirus Panic, Threat Actors Target Victims Worldwide | 1 | 5e6b322a-9f80-4e2f-9f2a-3cab0a3b4631 | 2021-07-19 12:44:27 | true |
>| Network activity | 71740 | COVID-19,<br/>misp-galaxy:financial-fraud="Compromised Personally Identifiable Information (PII)" | ip-dst | 1.2.3.4 | 1 | 143 | Recent Qakbot (Qbot) activity | 1 | 5fd0c599-ab6c-4ba1-a69a-df9ec0a8ab16 | 2021-06-21 12:35:10 | true |


## Breaking changes from the previous version of this integration - MISP v3
%%Reputation commands%%
The main change in this version is that searching indicators (reputation commands) implemented with search-attributes (and not with search-events as in previous version).
Please see the new commands(ip, file, url...) context output.

### Commands
#### The following commands were removed in this version:
* *misp-add-tag* - this command was replaced by both *misp-add-tag-to-event* and *misp-add-tag-to-attribute*.
* *misp-add-email-object* - this command was replaced by *misp-add-file-object* as Email object is not supported by the new PYMISP version.
* *misp-download-sample* - this command was removed as download sample is not supported by the new PYMISP version.
* *misp-upload-sample* - this command was removed as upload sample is not supported by the new PYMISP version.


### Arguments
#### The following arguments were removed in this version:

In the *misp-create-event* command:
* *id* - this argument was replaced by *event_id*.
In the *misp-add-domain-object* command:
* *dns* - this argument was replaced by *ip*.

#### The behavior of the following arguments was changed:

In the *misp-add-events-from-feed* command:
* *feed* - is now required.
* *limit* - this argument default value was replaced from '0' to be '2'.
In the *misp-create-event* command:
* *to_ids* - this argument default value was replaced from 'false' to be 'true'.
In the *misp-create-event* command:
* *to_ids* - this argument default value was replaced from 'false' to be 'true'.


## Additional Considerations for this version
%%Indicator Scoring%%
* In MISP V3, indicator scoring calculated depending on **MISP's tags**. In case no tags were found, the score
is calculated by the event's threat level id.
* Indicators of attributes and Events that have tags which configured as malicious will be scored 3 (i.e malicious).
* Indicators of attributes and Events that have tags which configured as suspicious will be scored 2 (i.e suspicious).
* Indicators of attributes and Events that don't have any tags configured as suspicious nor malicious will be scored by their events' threat level id.
* Threat level id with value 1, 2 or 3 will be scored 3 (i.e malicious).
* Threat level id with value 4 will be scored 0 (i.e unknown).

When configure an instance you should set:
1. Malicious tag IDs with tag IDs that would be calculated as malicious.
2. Suspicious tag IDs with tag IDs that would be calculated as suspicious.

