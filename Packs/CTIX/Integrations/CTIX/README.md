This is Cyware Threat Intelligence eXhange(CTIX) integration which enriches IP/Domain/URL/File Data.
This integration was integrated and tested with version 2.4 and 2.7 of CTIX.
This integration is NOT COMPATIBLE with CTIX version 3.0 and above. Use the CTIX V3 Integration for CTIX version 3 and above. 
Supported Cortex XSOAR versions: 5.0.0 and later.

## Configure CTIX in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| base_url | Endpoint URL | True |
| access_id | Access Key | True |
| secret_key | Secret Key | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Return IP Details.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 
| enhanced | Boolean Flag which when enabled returns an enhanced response which includes the extra enhancement data from various sources. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | IP address. | 
| IP.ASN | String | The autonomous system name for the IP address. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| CTIX.IP.tenant_id | string | Tenant ID | 
| CTIX.IP.stix_object_id | string | ID of the Threat Data Object in CTIX application | 
| CTIX.IP.tlp_data | string | TLP Value of the Threat Data Object | 
| CTIX.IP.first_seen | string | Timestamp of when the IP was first seen on the CTIX application | 
| CTIX.IP.last_seen | string | Timestamp of when the IP was latest seen on the CTIX application | 
| CTIX.IP.deprecated | boolean | Shows if the Threat Data Object is deprecated on the CTIX application | 
| CTIX.IP.intel_grading | string | Intel grading | 
| CTIX.IP.criticality | number | Criticality of the Threat Data Object on the scale of 0-5 | 
| CTIX.IP.indicator_type | string | Threat Data Object type | 
| CTIX.IP.package_id | unknown | List of IDs of packages on the CTIX application through which these IPs were received | 
| CTIX.IP.source | unknown | List of sources from which the IP address was received in the CTIX application | 
| CTIX.IP.risk_severity | number | Risk Severity of the Threat Data Object on the scale of 0-5 | 
| CTIX.IP.labels | unknown | List of Tags applied on the Threat Data Object | 
| CTIX.IP.source_grading | string | Source Grading | 
| CTIX.IP.name2 | string | Value of the Threat Data Object | 
| CTIX.IP.published_collections | unknown | Published collections | 
| CTIX.IP.published_package_id | unknown | Package ID | 
| CTIX.IP.blocked | boolean | Shows if the Threat Data Object is blocked on the CTIX application | 
| CTIX.IP.blocked_time | string | Timestamp of when the Threat Data Object was blocked on the CTIX application. | 
| CTIX.IP.deprecated_time | string | Timestamp of when the Threat Data Object was deprecated on the CTIX application | 
| CTIX.IP.notification_preference | unknown | Notification preference | 
| CTIX.IP.followed_on | unknown | Followed On | 
| CTIX.IP.score | number | CTIX Confidence Score of the IP Object out of 100 | 
| CTIX.IP.type | string | Type  of object | 
| CTIX.IP.subscriber_id | unknown | List of Subscriber IDs | 
| CTIX.IP.subscriber | unknown | List of Subscribers | 
| CTIX.IP.subscriber_collection_id | unknown | List of Subscriber Collection IDs | 
| CTIX.IP.subscriber_collection | unknown | List of Subscriber Collection | 
| CTIX.IP.object_type | string | Type of object | 
| CTIX.IP.blocked_on | unknown | Name of the Application where the Threat Data Object was blocked on. | 
| CTIX.IP.follow_by | unknown | List of Cyware Users who follow the object. | 
| CTIX.IP.is_false_positive | boolean | Shows if the Threat Data Object was marked false positive in the CTIX application | 
| CTIX.IP.domain_tld | string | Top-Level Domain information about the Threat Data Object. | 
| CTIX.IP.asn | string | ASN number of the Threat Data Object | 
| CTIX.IP.registered_domain | string | Registered Domain | 
| CTIX.IP.geo_details | unknown | Geographic details of the Threat Data Object | 
| CTIX.IP.country | string | Geographic details of the Object | 
| CTIX.IP.registrar | string | Registrar | 
| CTIX.IP.file_extension | string | File Extension | 
| CTIX.IP.whitelisted | unknown | List | 
| CTIX.IP.object_description | string | Description of the Threat Data Object. | 
| CTIX.IP.custom_score | number | Custom Score of the Threat Data Object | 
| CTIX.IP.is_following | boolean | Boolean Value | 
| CTIX.IP.under_review | boolean | Shows if Threat Data Object is marked as Under Review on the CTIX application | 
| CTIX.IP.under_reviewed_time | string | Timestamp when the object was marked under review. | 
| CTIX.IP.reviewed | boolean | Shows if the Threat Data Object is Marked as Reviewed on the CTIX application | 
| CTIX.IP.reviewed_time | string | Timestamp when then object was reviewed. | 
| CTIX.IP.object_description_defang | string | Description of the object. | 
| CTIX.IP.source_data | unknown | List of sources from which CTIX received this IP. | 
| CTIX.IP.related_fields | unknown | Relationship Data about the Threat Data Object present on the CTIX application | 
| CTIX.IP.enhancement_data | unknown | Additional enhanced data about the Threat Data Object fetched by the CTIX application | 


#### Command Example
```!ip ip="8.8.8.8" enhanced=True```

#### Context Example
```json
{
    "CTIX": {
        "IP": {
            "asn": "AS3356",
            "blocked": false,
            "blocked_on": [],
            "blocked_time": 0,
            "country": "United States",
            "criticality": 0,
            "custom_score": 0,
            "deprecated": false,
            "deprecated_time": null,
            "domain_tld": null,
            "enhancement_data": {},
            "file_extension": null,
            "first_seen": 1608281585,
            "follow_by": [],
            "followed_on": null,
            "geo_details": {
                "city": {
                    "city": null,
                    "continent_code": "NA",
                    "continent_name": "North America",
                    "country_code": "US",
                    "country_name": "United States",
                    "dma_code": null,
                    "latitude": 37.751,
                    "longitude": -97.822,
                    "postal_code": null,
                    "region": null,
                    "time_zone": "America/Chicago"
                },
                "country": {
                    "country_code": "US",
                    "country_name": "United States"
                }
            },
            "indicator_type": "ipv4-addr",
            "intel_grading": null,
            "is_false_positive": false,
            "is_following": false,
            "labels": [],
            "last_seen": 1608281585,
            "name2": "8.8.8.8",
            "notification_preference": null,
            "object_description": "",
            "object_description_defang": "",
            "object_type": "indicator",
            "package_id": [
                "package-4a183313-81cb-42bf-b3ed-f163662c2fcd"
            ],
            "published_collections": [],
            "published_package_id": [],
            "registered_domain": null,
            "registrar": null,
            "related_fields": {
                "attack_pattern": [],
                "campaign": [],
                "course_of_action": [],
                "indicator": [],
                "intrusion_set": [],
                "kill_chain_phases": [],
                "malware": [],
                "threat_actor": [],
                "tool": [],
                "ttp": []
            },
            "reviewed": false,
            "reviewed_time": 0,
            "risk_severity": 0,
            "score": 62.5,
            "source": [
                "Import"
            ],
            "source_data": [
                {
                    "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                    "name": "Import"
                }
            ],
            "source_grading": null,
            "stix_object_id": "indicator--b09b6649-56ba-4acd-88fd-f84aadf85b55",
            "subscriber": [],
            "subscriber_collection": [],
            "subscriber_collection_id": [],
            "subscriber_id": [],
            "tenant_id": "0a834138-cc59-4107-aa69-46e6080f06af",
            "tlp_data": "GREEN",
            "type": "Indicator",
            "under_review": false,
            "under_reviewed_time": 0,
            "value": "8.8.8.8",
            "whitelisted": []
        }
    },
    "DBotScore": [
        {
            "Indicator": "8.8.8.8",
            "Score": 2,
            "Type": "ip",
            "Vendor": "HelloWorld"
        },
        {
            "Indicator": "8.8.8.8",
            "Score": 2,
            "Type": "ip",
            "Vendor": "CTIX"
        }
    ],
    "IP": {
        "ASN": "AS3356",
        "Address": "8.8.8.8"
    }
}
```

#### Human Readable Output

>### IP List
>|asn|blocked|blocked_time|country|criticality|custom_score|deprecated|first_seen|geo_details|indicator_type|is_false_positive|is_following|last_seen|name2|object_type|package_id|related_fields|reviewed|reviewed_time|risk_severity|score|source|source_data|stix_object_id|tenant_id|tlp_data|type|under_review|under_reviewed_time|value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| AS3356 | false | 0 | United States | 0 | 0.0 | false | | 1608281585 | country: {"country_code": "US", "country_name": "United States"}<br/>city: {"city": null, "continent_code": "NA", "continent_name": "North America", "country_code": "US", "country_name": "United States", "dma_code": null, "latitude": 37.751, "longitude": -97.822, "postal_code": null, "region": null, "time_zone": "America/Chicago"} | ipv4-addr | false | false | 1608281585 | 8.8.8.8 | indicator | package-4a183313-81cb-42bf-b3ed-f163662c2fcd | attack_pattern: <br/>campaign: <br/>intrusion_set: <br/>malware: <br/>threat_actor: <br/>tool: <br/>indicator: <br/>ttp: <br/>kill_chain_phases: <br/>course_of_action:  | false | 0 | 0 | 62.5 | Import | {'name': 'Import', 'id': 'd1d3b628-346f-43c3-a369-235661ac6277'} | indicator--b09b6649-56ba-4acd-88fd-f84aadf85b55 | 0a834138-cc59-4107-aa69-46e6080f06af | GREEN | Indicator | false | 0 | 8.8.8.8 |


### domain
***
Return Domain Details.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Required | 
| enhanced | Boolean Flag which when enabled returns an enhanced response which includes the extra enhancement data from various sources. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The domain name. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| CTIX.Domain.tenant_id | string | Tenant ID | 
| CTIX.Domain.stix_object_id | string | ID of the Threat Data Object in CTIX application | 
| CTIX.Domain.tlp_data | string | TLP Value of the Threat Data Object | 
| CTIX.Domain.first_seen | string | Timestamp of when the IP was first seen on the CTIX application | 
| CTIX.Domain.last_seen | string | Timestamp of when the IP was latest seen on the CTIX application | 
| CTIX.Domain.deprecated | boolean | Shows if the Threat Data Object is deprecated on the CTIX application | 
| CTIX.Domain.intel_grading | string | Intel grading | 
| CTIX.Domain.criticality | number | Criticality of the Threat Data Object on the scale of 0-5 | 
| CTIX.Domain.indicator_type | string | Threat Data Object type | 
| CTIX.Domain.package_id | unknown | List of IDs of packages on the CTIX application through which these IPs were received | 
| CTIX.Domain.source | unknown | List of sources from which the IP address was received in the CTIX application | 
| CTIX.Domain.risk_severity | number | Risk Severity of the Threat Data Object on the scale of 0-5 | 
| CTIX.Domain.labels | unknown | List of Tags applied on the Threat Data Object | 
| CTIX.Domain.source_grading | string | Source Grading | 
| CTIX.Domain.name2 | string | Value of the Threat Data Object | 
| CTIX.Domain.published_collections | unknown | Published collections | 
| CTIX.Domain.published_package_id | unknown | Package ID | 
| CTIX.Domain.blocked | boolean | Shows if the Threat Data Object is blocked on the CTIX application | 
| CTIX.Domain.blocked_time | string | Timestamp of when the Threat Data Object was blocked on the CTIX application. | 
| CTIX.Domain.deprecated_time | string | Timestamp of when the Threat Data Object was deprecated on the CTIX application | 
| CTIX.Domain.notification_preference | unknown | Notification preference | 
| CTIX.Domain.followed_on | unknown | Followed On | 
| CTIX.Domain.score | number | CTIX Confidence Score of the IP Object out of 100 | 
| CTIX.Domain.type | string | Type  of object | 
| CTIX.Domain.subscriber_id | unknown | List of Subscriber IDs | 
| CTIX.Domain.subscriber | unknown | List of Subscribers | 
| CTIX.Domain.subscriber_collection_id | unknown | List of Subscriber Collection IDs | 
| CTIX.Domain.subscriber_collection | unknown | List of Subscriber Collection | 
| CTIX.Domain.object_type | string | Type of object | 
| CTIX.Domain.blocked_on | unknown | Name of the Application where the Threat Data Object was blocked on. | 
| CTIX.Domain.follow_by | unknown | List of Cyware Users who follow the object. | 
| CTIX.Domain.is_false_positive | boolean | Shows if the Threat Data Object was marked false positive in the CTIX application | 
| CTIX.Domain.domain_tld | string | Top-Level Domain information about the Threat Data Object. | 
| CTIX.Domain.asn | string | ASN number of the Threat Data Object | 
| CTIX.Domain.registered_domain | string | Registered Domain | 
| CTIX.Domain.geo_details | unknown | Geographic details of the Threat Data Object | 
| CTIX.Domain.country | string | Geographic details of the Object | 
| CTIX.Domain.registrar | string | Registrar | 
| CTIX.Domain.file_extension | string | File Extension | 
| CTIX.Domain.whitelisted | unknown | List | 
| CTIX.Domain.object_description | string | Description of the Threat Data Object. | 
| CTIX.Domain.custom_score | number | Custom Score of the Threat Data Object | 
| CTIX.Domain.is_following | boolean | Boolean Value | 
| CTIX.Domain.under_review | boolean | Shows if Threat Data Object is marked as Under Review on the CTIX application | 
| CTIX.Domain.under_reviewed_time | string | Timestamp when the object was marked under review. | 
| CTIX.Domain.reviewed | boolean | Shows if the Threat Data Object is Marked as Reviewed on the CTIX application | 
| CTIX.Domain.reviewed_time | string | Timestamp when then object was reviewed. | 
| CTIX.Domain.object_description_defang | string | Description of the object. | 
| CTIX.Domain.source_data | unknown | List of sources from which CTIX received this IP. | 
| CTIX.Domain.related_fields | unknown | Relationship Data about the Threat Data Object present on the CTIX application | 
| CTIX.Domain.enhancement_data | unknown | Additional enhanced data about the Threat Data Object fetched by the CTIX application | 


#### Command Example
```!domain domain="google.com" enhanced=True```

#### Context Example
```json
{
    "CTIX": {
        "Domain": {
            "asn": null,
            "blocked": false,
            "blocked_on": [],
            "blocked_time": 0,
            "country": null,
            "criticality": 0,
            "custom_score": 0,
            "deprecated": false,
            "deprecated_time": null,
            "domain_tld": ".com",
            "enhancement_data": {},
            "file_extension": null,
            "first_seen": 1606486346,
            "follow_by": [],
            "followed_on": null,
            "geo_details": {},
            "indicator_type": "domain",
            "intel_grading": null,
            "is_false_positive": false,
            "is_following": false,
            "labels": [],
            "last_seen": 1607004096,
            "name2": "google.com",
            "notification_preference": null,
            "object_description": "",
            "object_description_defang": "",
            "object_type": "indicator",
            "package_id": [
                "package-caffb979-5a33-4787-8813-07319fa365df"
            ],
            "published_collections": [],
            "published_package_id": [],
            "registered_domain": "google.com",
            "registrar": null,
            "related_fields": {
                "attack_pattern": [],
                "campaign": [],
                "course_of_action": [],
                "indicator": [],
                "intrusion_set": [],
                "kill_chain_phases": [],
                "malware": [],
                "threat_actor": [],
                "tool": [],
                "ttp": []
            },
            "reviewed": false,
            "reviewed_time": 0,
            "risk_severity": 0,
            "score": 62.5,
            "source": [
                "pop3",
                "PoP3"
            ],
            "source_data": [
                {
                    "id": "2e29c86a-fb67-4ead-88ff-396ed3cef3e4",
                    "name": "PoP3"
                },
                {
                    "id": "da862993-bf78-4bdd-a715-83dbfb685a6c",
                    "name": "pop3"
                }
            ],
            "source_grading": null,
            "stix_object_id": "indicator--9949458d-0dd0-4f52-8d29-01f741359f58",
            "subscriber": [],
            "subscriber_collection": [],
            "subscriber_collection_id": [],
            "subscriber_id": [],
            "tenant_id": "0a834138-cc59-4107-aa69-46e6080f06af",
            "tlp_data": "GREEN",
            "type": "Indicator",
            "under_review": false,
            "under_reviewed_time": 0,
            "value": "google.com",
            "whitelisted": []
        }
    },
    "DBotScore": {
        "Indicator": "google.com",
        "Score": 2,
        "Type": "domain",
        "Vendor": "CTIX"
    },
    "Domain": {
        "Name": "google.com"
    }
}
```

#### Human Readable Output

>### Domain List
>|blocked|blocked_time|criticality|custom_score|deprecated|domain_tld|first_seen|indicator_type|is_false_positive|is_following|last_seen|name2|object_type|package_id|registered_domain|related_fields|reviewed|reviewed_time|risk_severity|score|source|source_data|stix_object_id|tenant_id|tlp_data|type|under_review|under_reviewed_time|value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 0 | 0 | 0.0 | false | .com | 1606486346 | domain | false | false | 1607004096 | google.com | indicator | package-caffb979-5a33-4787-8813-07319fa365df | google.com | attack_pattern: <br/>campaign: <br/>intrusion_set: <br/>malware: <br/>threat_actor: <br/>tool: <br/>indicator: <br/>ttp: <br/>kill_chain_phases: <br/>course_of_action:  | false | 0 | 0 | 62.5 | pop3,<br/>PoP3 | {'name': 'PoP3', 'id': '2e29c86a-fb67-4ead-88ff-396ed3cef3e4'},<br/>{'name': 'pop3', 'id': 'da862993-bf78-4bdd-a715-83dbfb685a6c'} | indicator--9949458d-0dd0-4f52-8d29-01f741359f58 | 0a834138-cc59-4107-aa69-46e6080f06af | GREEN | Indicator | false | 0 | google.com |


### url
***
Return URL Details.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Required | 
| enhanced | Boolean Flag which when enabled returns an enhanced response which includes the extra enhancement data from various sources. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| URL.Data | String | The URL. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| CTIX.URL.tenant_id | string | Tenant ID | 
| CTIX.URL.stix_object_id | string | ID of the Threat Data Object in CTIX application | 
| CTIX.URL.tlp_data | string | TLP Value of the Threat Data Object | 
| CTIX.URL.first_seen | string | Timestamp of when the IP was first seen on the CTIX application | 
| CTIX.URL.last_seen | string | Timestamp of when the IP was latest seen on the CTIX application | 
| CTIX.URL.deprecated | boolean | Shows if the Threat Data Object is deprecated on the CTIX application | 
| CTIX.URL.intel_grading | string | Intel grading | 
| CTIX.URL.criticality | number | Criticality of the Threat Data Object on the scale of 0-5 | 
| CTIX.URL.indicator_type | string | Threat Data Object type | 
| CTIX.URL.package_id | unknown | List of IDs of packages on the CTIX application through which these IPs were received | 
| CTIX.URL.source | unknown | List of sources from which the IP address was received in the CTIX application | 
| CTIX.URL.risk_severity | number | Risk Severity of the Threat Data Object on the scale of 0-5 | 
| CTIX.URL.labels | unknown | List of Tags applied on the Threat Data Object | 
| CTIX.URL.source_grading | string | Source Grading | 
| CTIX.URL.name2 | string | Value of the Threat Data Object | 
| CTIX.URL.published_collections | unknown | Published collections | 
| CTIX.URL.published_package_id | unknown | Package ID | 
| CTIX.URL.blocked | boolean | Shows if the Threat Data Object is blocked on the CTIX application | 
| CTIX.URL.blocked_time | string | Timestamp of when the Threat Data Object was blocked on the CTIX application. | 
| CTIX.URL.deprecated_time | string | Timestamp of when the Threat Data Object was deprecated on the CTIX application | 
| CTIX.URL.notification_preference | unknown | Notification preference | 
| CTIX.URL.followed_on | unknown | Followed On | 
| CTIX.URL.score | number | CTIX Confidence Score of the IP Object out of 100 | 
| CTIX.URL.type | string | Type  of object | 
| CTIX.URL.subscriber_id | unknown | List of Subscriber IDs | 
| CTIX.URL.subscriber | unknown | List of Subscribers | 
| CTIX.URL.subscriber_collection_id | unknown | List of Subscriber Collection IDs | 
| CTIX.URL.subscriber_collection | unknown | List of Subscriber Collection | 
| CTIX.URL.object_type | string | Type of object | 
| CTIX.URL.blocked_on | unknown | Name of the Application where the Threat Data Object was blocked on. | 
| CTIX.URL.follow_by | unknown | List of Cyware Users who follow the object. | 
| CTIX.URL.is_false_positive | boolean | Shows if the Threat Data Object was marked false positive in the CTIX application | 
| CTIX.URL.domain_tld | string | Top-Level Domain information about the Threat Data Object. | 
| CTIX.URL.asn | string | ASN number of the Threat Data Object | 
| CTIX.URL.registered_domain | string | Registered Domain | 
| CTIX.URL.geo_details | unknown | Geographic details of the Threat Data Object | 
| CTIX.URL.country | string | Geographic details of the Object | 
| CTIX.URL.registrar | string | Registrar | 
| CTIX.URL.file_extension | string | File Extension | 
| CTIX.URL.whitelisted | unknown | List | 
| CTIX.URL.object_description | string | Description of the Threat Data Object. | 
| CTIX.URL.custom_score | number | Custom Score of the Threat Data Object | 
| CTIX.URL.is_following | boolean | Boolean Value | 
| CTIX.URL.under_review | boolean | Shows if Threat Data Object is marked as Under Review on the CTIX application | 
| CTIX.URL.under_reviewed_time | string | Timestamp when the object was marked under review. | 
| CTIX.URL.reviewed | boolean | Shows if the Threat Data Object is Marked as Reviewed on the CTIX application | 
| CTIX.URL.reviewed_time | string | Timestamp when then object was reviewed. | 
| CTIX.URL.object_description_defang | string | Description of the object. | 
| CTIX.URL.source_data | unknown | List of sources from which CTIX received this IP. | 
| CTIX.URL.related_fields | unknown | Relationship Data about the Threat Data Object present on the CTIX application | 
| CTIX.URL.enhancement_data | unknown | Additional enhanced data about the Threat Data Object fetched by the CTIX application | 


#### Command Example
```!url url="https://www.test.com/" enhanced=True```

#### Context Example
```json
{
    "CTIX": {
        "URL": {
            "asn": null,
            "blocked": false,
            "blocked_on": [],
            "blocked_time": 0,
            "country": null,
            "criticality": 3,
            "custom_score": 0,
            "deprecated": false,
            "deprecated_time": null,
            "domain_tld": ".com",
            "enhancement_data": {},
            "file_extension": null,
            "first_seen": 1605768210,
            "follow_by": [],
            "followed_on": null,
            "geo_details": {},
            "indicator_type": "url",
            "intel_grading": null,
            "is_false_positive": false,
            "is_following": false,
            "labels": [
                {
                    "colour_code": null,
                    "created": 1605030281,
                    "created_by": "system@default.tld",
                    "id": "23ccc391-6968-4734-b93e-d4985e23dcfd",
                    "modified": 1605030281,
                    "modified_by": "system@default.tld",
                    "name": "anomalous-activity"
                }
            ],
            "last_seen": 1605894588,
            "name2": "https://www.test.com/",
            "notification_preference": null,
            "object_description": "",
            "object_description_defang": "",
            "object_type": "indicator",
            "package_id": [
                "package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe",
                "package-63f2228a-7037-4e56-a3df-23644ba3be64"
            ],
            "published_collections": [
                "inbox & polling",
                "adsa",
                "newtestcollection1 - edited"
            ],
            "published_package_id": [
                "5df96375-1e0d-494b-870f-3f029d5cc565",
                "bbb62de5-f71f-4ca9-81b7-c4e94e3640cf",
                "96c58eb5-5784-4de5-8aa7-b4292525914c"
            ],
            "registered_domain": "test.com",
            "registrar": null,
            "related_fields": {
                "attack_pattern": [],
                "campaign": [],
                "course_of_action": [],
                "indicator": [],
                "intrusion_set": [],
                "kill_chain_phases": [],
                "malware": [],
                "threat_actor": [],
                "tool": [],
                "ttp": []
            },
            "reviewed": false,
            "reviewed_time": 0,
            "risk_severity": 5,
            "score": 58.18,
            "source": [
                "customsource1.x",
                "Import"
            ],
            "source_data": [
                {
                    "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                    "name": "Import"
                },
                {
                    "id": "012072c9-1421-4960-ab01-2bb541596374",
                    "name": "customsource1.x"
                }
            ],
            "source_grading": null,
            "stix_object_id": "indicator--70414571-660b-4360-b064-f0cf58caf903",
            "subscriber": [],
            "subscriber_collection": [],
            "subscriber_collection_id": [],
            "subscriber_id": [],
            "tenant_id": "0a834138-cc59-4107-aa69-46e6080f06af",
            "tlp_data": "GREEN",
            "type": "Indicator",
            "under_review": false,
            "under_reviewed_time": 0,
            "value": "https://test.com/",
            "whitelisted": []
        }
    },
    "DBotScore": {
        "Indicator": "https://test.com/",
        "Score": 2,
        "Type": "url",
        "Vendor": "CTIX"
    },
    "URL": {
        "Data": "https://test.com/"
    }
}
```

#### Human Readable Output

>### URL List
>|blocked|blocked_time|criticality|custom_score|deprecated|domain_tld|first_seen|indicator_type|is_false_positive|is_following|labels|last_seen|name2|object_type|package_id|published_collections|published_package_id|registered_domain|related_fields|reviewed|reviewed_time|risk_severity|score|source|source_data|stix_object_id|tenant_id|tlp_data|type|under_review|under_reviewed_time|value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 0 | 3 | 0.0 | false | .com | 1605768210 | url | false | false | {'id': '23ccc391-6968-4734-b93e-d4985e23dcfd', 'name': 'anomalous-activity', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605030281, 'modified_by': 'system@default.tld', 'modified': 1605030281}<br/> | 1605894588 | https://test.com | indicator | package-fd79e1a4-db90-4748-b9cb-f72264bf3ffe,<br/>package-63f2228a-7037-4e56-a3df-23644ba3be64 | inbox & polling,<br/>adsa,<br/>newtestcollection1 - edited | 5df96375-1e0d-494b-870f-3f029d5cc565,<br/>bbb62de5-f71f-4ca9-81b7-c4e94e3640cf,<br/>96c58eb5-5784-4de5-8aa7-b4292525914c | test.com | attack_pattern: <br/>campaign: <br/>intrusion_set: <br/>malware: <br/>threat_actor: <br/>tool: <br/>indicator: <br/>ttp: <br/>kill_chain_phases: <br/>course_of_action:  | false | 0 | 5 | 58.18 | customsource1.x,<br/>Import | {'name': 'Import', 'id': 'd1d3b628-346f-43c3-a369-235661ac6277'},<br/>{'name': 'customsource1.x', 'id': '012072c9-1421-4960-ab01-2bb541596374'} | indicator--70414571-660b-4360-b064-f0cf58caf903 | 0a834138-cc59-4107-aa69-46e6080f06af | GREEN | Indicator | false | 0 | https://test.com/ |


### file
***
Return File Details.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of Files. | Required | 
| enhanced | Boolean Flag which when enabled returns an enhanced response which includes the extra enhancement data from various sources. Possible values are: true, false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Name | String | The full file name. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA256 hash of the file.| 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| CTIX.File.tenant_id | string | Tenant ID | 
| CTIX.File.stix_object_id | string | ID of the Threat Data Object in CTIX application | 
| CTIX.File.tlp_data | string | TLP Value of the Threat Data Object | 
| CTIX.File.first_seen | string | Timestamp of when the IP was first seen on the CTIX application | 
| CTIX.File.last_seen | string | Timestamp of when the IP was latest seen on the CTIX application | 
| CTIX.File.deprecated | boolean | Shows if the Threat Data Object is deprecated on the CTIX application | 
| CTIX.File.intel_grading | string | Intel grading | 
| CTIX.File.criticality | number | Criticality of the Threat Data Object on the scale of 0-5 | 
| CTIX.File.indicator_type | string | Threat Data Object type | 
| CTIX.File.package_id | unknown | List of IDs of packages on the CTIX application through which these IPs were received | 
| CTIX.File.source | unknown | List of sources from which the IP address was received in the CTIX application | 
| CTIX.File.risk_severity | number | Risk Severity of the Threat Data Object on the scale of 0-5 | 
| CTIX.File.labels | unknown | List of Tags applied on the Threat Data Object | 
| CTIX.File.source_grading | string | Source Grading | 
| CTIX.File.name2 | string | Value of the Threat Data Object | 
| CTIX.File.published_collections | unknown | Published collections | 
| CTIX.File.published_package_id | unknown | Package ID | 
| CTIX.File.blocked | boolean | Shows if the Threat Data Object is blocked on the CTIX application | 
| CTIX.File.blocked_time | string | Timestamp of when the Threat Data Object was blocked on the CTIX application. | 
| CTIX.File.deprecated_time | string | Timestamp of when the Threat Data Object was deprecated on the CTIX application | 
| CTIX.File.notification_preference | unknown | Notification preference | 
| CTIX.File.followed_on | unknown | Followed On | 
| CTIX.File.score | number | CTIX Confidence Score of the IP Object out of 100 | 
| CTIX.File.type | string | Type  of object | 
| CTIX.File.subscriber_id | unknown | List of Subscriber IDs | 
| CTIX.File.subscriber | unknown | List of Subscribers | 
| CTIX.File.subscriber_collection_id | unknown | List of Subscriber Collection IDs | 
| CTIX.File.subscriber_collection | unknown | List of Subscriber Collection | 
| CTIX.File.object_type | string | Type of object | 
| CTIX.File.blocked_on | unknown | Name of the Application where the Threat Data Object was blocked on. | 
| CTIX.File.follow_by | unknown | List of Cyware Users who follow the object. | 
| CTIX.File.is_false_positive | boolean | Shows if the Threat Data Object was marked false positive in the CTIX application | 
| CTIX.File.domain_tld | string | Top-Level Domain information about the Threat Data Object. | 
| CTIX.File.asn | string | ASN number of the Threat Data Object | 
| CTIX.File.registered_domain | string | Registered Domain | 
| CTIX.File.geo_details | unknown | Geographic details of the Threat Data Object | 
| CTIX.File.country | string | Geographic details of the Object | 
| CTIX.File.registrar | string | Registrar | 
| CTIX.File.file_extension | string | File Extension | 
| CTIX.File.whitelisted | unknown | List | 
| CTIX.File.object_description | string | Description of the Threat Data Object. | 
| CTIX.File.custom_score | number | Custom Score of the Threat Data Object | 
| CTIX.File.is_following | boolean | Boolean Value | 
| CTIX.File.under_review | boolean | Shows if Threat Data Object is marked as Under Review on the CTIX application | 
| CTIX.File.under_reviewed_time | string | Timestamp when the object was marked under review. | 
| CTIX.File.reviewed | boolean | Shows if the Threat Data Object is Marked as Reviewed on the CTIX application | 
| CTIX.File.reviewed_time | string | Timestamp when then object was reviewed. | 
| CTIX.File.object_description_defang | string | Description of the object. | 
| CTIX.File.source_data | unknown | List of sources from which CTIX received this IP. | 
| CTIX.File.related_fields | unknown | Relationship Data about the Threat Data Object present on the CTIX application | 
| CTIX.File.enhancement_data | unknown | Additional enhanced data about the Threat Data Object fetched by the CTIX application | 


#### Command Example
```!file file="4ebb2b00a11f9361cf3757e96f14ad4b" enhanced=True```

#### Context Example
```json
{
    "CTIX": {
        "File": {
            "asn": null,
            "blocked": false,
            "blocked_on": [],
            "blocked_time": 0,
            "country": null,
            "criticality": 3,
            "custom_score": 0,
            "deprecated": true,
            "deprecated_time": 1588854933,
            "domain_tld": null,
            "enhancement_data": {},
            "file_extension": null,
            "first_seen": 1586262933,
            "follow_by": [],
            "followed_on": null,
            "geo_details": {},
            "indicator_type": "MD5",
            "intel_grading": null,
            "is_false_positive": false,
            "is_following": false,
            "labels": [
                {
                    "colour_code": null,
                    "created": 1605030281,
                    "created_by": "system@default.tld",
                    "id": "23ccc391-6968-4734-b93e-d4985e23dcfd",
                    "modified": 1605030281,
                    "modified_by": "system@default.tld",
                    "name": "anomalous-activity"
                }
            ],
            "last_seen": 1605791028,
            "name2": "4ebb2b00a11f9361cf3757e96f14ad4b",
            "notification_preference": null,
            "object_description": "",
            "object_description_defang": "",
            "object_type": "indicator",
            "package_id": [
                "package-d54892d8-b495-4331-b361-17ffbeacdaed",
                "package-09be25b9-5d6b-4320-b512-4dc0e088f434",
                "bundle--87151b50-31a4-4f0a-9f5f-282b0f1d1285"
            ],
            "published_collections": [
                "adsa",
                "newtestcollection1 - edited"
            ],
            "published_package_id": [
                "1557df73-68b4-485b-9821-e3036e5fb7a4",
                "a1eb2b29-fed4-4635-8e5c-a74f4339b8ab"
            ],
            "registered_domain": null,
            "registrar": null,
            "related_fields": {
                "attack_pattern": [],
                "campaign": [],
                "course_of_action": [],
                "indicator": [],
                "intrusion_set": [],
                "kill_chain_phases": [],
                "malware": [],
                "threat_actor": [],
                "tool": [],
                "ttp": []
            },
            "reviewed": false,
            "reviewed_time": 0,
            "risk_severity": 5,
            "score": 50,
            "source": [
                "Import"
            ],
            "source_data": [
                {
                    "id": "d1d3b628-346f-43c3-a369-235661ac6277",
                    "name": "Import"
                }
            ],
            "source_grading": null,
            "stix_object_id": "indicator--2e35588f-cde1-4492-a720-ab0aee7fafaa",
            "subscriber": [],
            "subscriber_collection": [],
            "subscriber_collection_id": [],
            "subscriber_id": [],
            "tenant_id": "0a834138-cc59-4107-aa69-46e6080f06af",
            "tlp_data": null,
            "type": "Indicator",
            "under_review": false,
            "under_reviewed_time": 0,
            "value": "4ebb2b00a11f9361cf3757e96f14ad4b",
            "whitelisted": []
        }
    },
    "DBotScore": {
        "Indicator": "4ebb2b00a11f9361cf3757e96f14ad4b",
        "Score": 2,
        "Type": "file",
        "Vendor": "CTIX"
    },
    "File": [
        {
            "Name": "4ebb2b00a11f9361cf3757e96f14ad4b",
            "MD5": "4ebb2b00a11f9361cf3757e96f14ad4b"
        }
    ]
}
```

#### Human Readable Output

>### File List
>|blocked|blocked_time|criticality|custom_score|deprecated|deprecated_time|first_seen|indicator_type|is_false_positive|is_following|labels|last_seen|name2|object_type|package_id|published_collections|published_package_id|related_fields|reviewed|reviewed_time|risk_severity|score|source|source_data|stix_object_id|tenant_id|type|under_review|under_reviewed_time|value|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | 0 | 3 | 0.0 | true | 1588854933 | 1586262933 | MD5 | false | false | {'id': '23ccc391-6968-4734-b93e-d4985e23dcfd', 'name': 'anomalous-activity', 'colour_code': None, 'created_by': 'system@default.tld', 'created': 1605030281, 'modified_by': 'system@default.tld', 'modified': 1605030281}| 1605791028 | 4ebb2b00a11f9361cf3757e96f14ad4b | indicator | package-d54892d8-b495-4331-b361-17ffbeacdaed,<br/>package-09be25b9-5d6b-4320-b512-4dc0e088f434,<br/>bundle--87151b50-31a4-4f0a-9f5f-282b0f1d1285 | adsa,<br/>newtestcollection1 - edited | 1557df73-68b4-485b-9821-e3036e5fb7a4,<br/>a1eb2b29-fed4-4635-8e5c-a74f4339b8ab | attack_pattern: <br/>campaign: <br/>intrusion_set: <br/>malware: <br/>threat_actor: <br/>tool: <br/>indicator: <br/>ttp: <br/>kill_chain_phases: <br/>course_of_action:  | false | 0 | 5 | 50.0 | Import | {'name': 'Import', 'id': 'd1d3b628-346f-43c3-a369-235661ac6277'} | indicator--2e35588f-cde1-4492-a720-ab0aee7fafaa | 0a834138-cc59-4107-aa69-46e6080f06af | Indicator | false | 0 | 4ebb2b00a11f9361cf3757e96f14ad4b |

### ctix-create-intel
***
Creates Intel in CTIX platform.


#### Base Command

`ctix-create-intel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- | --- |
| title | Title of ioc | Optional |
| description | Description of ioc| Optional |
| tlp | Tlp of ioc | Optional |
| confidence | Confidence of ioc | Optional |
| ips | comma-separated list of IPs | Optional | 
| urls | comma-separated list of URLs | Optional |
| domains | comma-separated list of domains | Optional |
| files | comma-separated list of files | Optional |
| emails | comma-separated list of emails | Optional |
| malwares | comma-separated list of malwares | Optional |
| threat_actors | comma-separated list of threat actors | Optional |
| attack_patterns | comma-separated list of attack patterns | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CTIX.Intel.response | String | The response of the api | 
| CTIX.Intel.status | Number | Status code returned from the api | 


#### Command Example
```ctix-create-intel ips=1.2.3.4,3.45.56.78 urls=https://ioc_test.com,https://test_ioc.com files=8e7fad44308af9d1d60aac4fafcecdf2f66aa0315eb5f092fafa5bb03a5c2e3e emails=ioc@gmail.com,malicious@gmail.com malwares=dridex,spambot threat_actors=everest,grief attack_patterns=phishing,ddos title=title_xsoar_intel_creation description=xsoar_description tlp=green confidence=70```

#### Context Example
```json
{
    "CTIX": {
        "Intel": {
            "response": "Package is pushed in CTIX for publishing",
            "status": 201
        }
    }
}
```