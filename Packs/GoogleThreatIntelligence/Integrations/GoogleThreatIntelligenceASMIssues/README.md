# Google Threat Intelligence - ASM Issues

This integration allows the creation of incidents based on ASM Issues from Google Threat Intelligence.

## Configure Google Threat Intelligence - ASM Issues in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | See [Acquiring your API key](#acquiring-your-api-key) | True |
| Fetch incidents |  | False |
| Max Fetch | Maximum number of Issues to fetch each time. Maximum value is 200. | False |
| First Fetch Time | The date or relative timestamp from which to begin fetching Issues.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 May 2025, 01 May 2025 04:45:33, 2025-05-17T14:05:44Z. | False |
| Mirroring Direction | The mirroring direction in which to mirror the details. You can mirror "Outgoing" \(from XSOAR to GTI\) direction for ASM Issues. | False |
| Mirror tag for notes | The tag value should be used to mirror the issue note by adding the same tag in the notes. | False |
| Project ID | Provide the project ID to fetch issues for a specific project.<br/><br/>Note: The specified project ID will be used as a default value for ASM Issue commands. | False |
| Search String | Search String to filter out the ASM Issues.<br/><br/>For Example: collection:google severity:5 status_new:open scoped:true entity_type:domain<br/><br/>Note: The fields last_seen_after, last_seen_before, and first_seen_after will be ignored from the provided search string. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |

### Acquiring your API key

Your API key can be found in your GoogleThreatIntelligence account user menu, clicking on your avatar:

![How to get api key in GoogleThreatIntelligence](../../doc_files/Google_Threat_intelligence_API_key.png)

Your API key carries all your privileges, so keep it secure and don't share it with anyone.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gti-asm-issue-list

***
Search the ASM Issues with provided filter arguments.

#### Base Command

`gti-asm-issue-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | Specify the project ID for the project.<br/><br/>Note:If no value is provided for the project ID, it will be taken from the configuration parameters. | Optional |
| search_string | Specify search string for listing ASM Issues.<br/><br/>Note: If no value is provided, all issues for the project will be returned. | Optional |
| page_size | Specify the desired page size for the request. Maximum value is 1000. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleThreatIntelligenceASMIssues.Issues.id | String | Unique identifier for the issue in Google Threat Intelligence. |
| GoogleThreatIntelligenceASMIssues.Issues.uid | String | Internal UID assigned to the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.uuid | String | Universally unique identifier \(UUID\) for the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.description | String | Detailed description of the identified issue. |
| GoogleThreatIntelligenceASMIssues.Issues.dynamic_id | Number | Dynamic numerical identifier for tracking the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.name | String | Human-readable name of the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.pretty_name | String | Enhanced, formatted name for display purposes. |
| GoogleThreatIntelligenceASMIssues.Issues.upstream | String | Source or upstream system where the issue originated. |
| GoogleThreatIntelligenceASMIssues.Issues.last_seen | Date | Timestamp when the issue was last observed. |
| GoogleThreatIntelligenceASMIssues.Issues.first_seen | Date | Timestamp when the issue was first detected. |
| GoogleThreatIntelligenceASMIssues.Issues.entity_uid | String | Unique identifier of the affected entity. |
| GoogleThreatIntelligenceASMIssues.Issues.entity_type | String | Type of entity affected \(e.g., domain, IP, host\). |
| GoogleThreatIntelligenceASMIssues.Issues.entity_name | String | Name of the affected entity. |
| GoogleThreatIntelligenceASMIssues.Issues.alias_group | String | Group of related entities or aliases associated with the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.collection | String | Collection or dataset name where the issue belongs. |
| GoogleThreatIntelligenceASMIssues.Issues.collection_uuid | String | Unique UUID of the associated collection. |
| GoogleThreatIntelligenceASMIssues.Issues.collection_type | String | Type of collection where the issue is categorized. |
| GoogleThreatIntelligenceASMIssues.Issues.organization_uuid | String | UUID of the organization linked to the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.pretty_name | String | User-friendly name summarizing the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.severity | Number | Severity level assigned to the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.scoped | Boolean | Indicates if the issue is scoped to a specific context or asset. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.confidence | String | Confidence score indicating the reliability of the issue detection. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.status | String | Current status of the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.category | String | Category of the issue based on threat type. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.identifiers.name | String | Name of an identifier associated with the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.identifiers.type | String | Type of identifier linked to the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.status_new | String | Updated status of the issue based on latest assessment. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.status_new_detailed | String | Detailed description of the updated issue status. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.ticket_list | List | List of linked tickets associated with the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.tags | List | Tags associated with the issue for classification. |
| GoogleThreatIntelligenceASMIssues.Issues.cisa_known_exploited | Boolean | Indicates whether the issue is part of CISA's Known Exploited Vulnerabilities list. |
| GoogleThreatIntelligenceASMIssues.Issues.epss_v2_score_lte | Number | EPSS v2 score indicating likelihood of exploitation \(less than or equal\). |
| GoogleThreatIntelligenceASMIssues.Issues.epss_v2_percentile_gte | Number | EPSS v2 percentile indicating exploitation probability \(greater than or equal\). |

#### Command example

```!gti-asm-issue-list search_string="collection:google" page_size=2```

#### Context Example

```json
{
    "GoogleThreatIntelligenceASMIssues": {
        "Issues": [
            {
                "id": "dummy_uid_01",
                "uid": "dummy_uid_01",
                "uuid": "dummy_uuid_01",
                "description": "A cookie was found, missing the 'HttpOnly' attribute. HttpOnly is a flag included in a Set-Cookie HTTP response header.",
                "dynamic_id": 10101011,
                "name": "insecure_cookie_httponly_attribute",
                "pretty_name": "Insecure Cookie (Missing 'HttpOnly' Attribute)",
                "upstream": "intrigue",
                "last_seen": "2025-07-14T15:18:51.000Z",
                "first_seen": "2025-06-29T00:46:43.000Z",
                "entity_uid": "dummy_entity_uid_01",
                "entity_type": "Intrigue::Entity::Uri",
                "entity_name": "https://www.example_entity.com",
                "alias_group": "dummy_alias_group_01",
                "collection": "google",
                "collection_uuid": "dummy_collection_uuid_01",
                "collection_type": "pre_collection",
                "organization_uuid": "test",
                "summary": {
                    "pretty_name": "Insecure Cookie (Missing 'HttpOnly' Attribute)",
                    "severity": 5,
                    "scoped": true,
                    "confidence": "confirmed",
                    "status": "closed_benign",
                    "category": "application",
                    "identifiers": "123",
                    "status_new": "closed",
                    "status_new_detailed": "benign",
                    "ticket_list": [
                        "ticket"
                    ]
                },
                "tags": [
                    "test1"
                ]
            },
            {
                "id": "dummy_uid_02",
                "uid": "dummy_uid_02",
                "uuid": "dummy_uuid_02",
                "description": "A cookie was found, missing the 'HttpOnly' attribute.",
                "dynamic_id": 10101010,
                "name": "insecure_cookie_httponly_attribute",
                "pretty_name": "Insecure Cookie (Missing 'HttpOnly' Attribute)",
                "upstream": "intrigue",
                "last_seen": "2025-07-14T15:18:51.000Z",
                "first_seen": "2025-06-29T00:46:43.000Z",
                "entity_uid": "dummy_entity_uid_02",
                "entity_type": "Intrigue::Entity::Uri",
                "entity_name": "http://www.exmaple_2.com",
                "alias_group": "dummy_alias_group_02",
                "collection": "google",
                "collection_uuid": "dummy_collection_uuid_02",
                "collection_type": "pre_collection",
                "organization_uuid": "test",
                "summary": {
                    "pretty_name": "Insecure Cookie (Missing 'HttpOnly' Attribute)",
                    "severity": 5,
                    "scoped": true,
                    "confidence": "confirmed",
                    "status": "open_new",
                    "category": "application",
                    "identifiers": "123",
                    "status_new": "open",
                    "status_new_detailed": "new",
                    "ticket_list": [
                        "ticket"
                    ]
                },
                "tags": [
                    "Test2"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### ASM Issues
>
>|Issue ID|Issue Name|Issue Description|Status|Severity|Entity Name|Entity uid|Entity Type|Collection|Confidence|Last Seen|First Seen|Tags|
>
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| dummy_uid_01 | Insecure Cookie (Missing 'HttpOnly' Attribute) | A cookie was found, missing the 'HttpOnly' attribute. HttpOnly is a flag included in a Set-Cookie HTTP response header. | Benign | 5 | https://www.example_entity.com | dummy_entity_uid_01 | Intrigue::Entity::Uri | google | confirmed | 2025-07-14T15:18:51.000Z | 2025-06-29T00:46:43.000Z | test1 |
>| dummy_uid_02 | Insecure Cookie (Missing 'HttpOnly' Attribute) | A cookie was found, missing the 'HttpOnly' attribute. | Open | 5 | http://www.exmaple_2.com | dummy_entity_uid_02 | Intrigue::Entity::Uri | google | confirmed | 2025-07-14T15:18:51.000Z | 2025-06-29T00:46:43.000Z | Test2 |

### gti-asm-issue-get

***
Get a particular ASM Issue by ID.

#### Base Command

`gti-asm-issue-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Specify the ID of the issue.<br/><br/>Note: Use gti-asm-issue-list to retrive the Issue ID. | Required |
| project_id | Specify the project ID for the project.<br/><br/>Note:If no value is provided for the project ID, it will be taken from the configuration parameters. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleThreatIntelligenceASMIssues.Issues.uuid | String | Universally unique identifier \(UUID\) of the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.dynamic_id | Number | Dynamic numerical identifier assigned to the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.entity_uid | String | Unique identifier of the affected entity. |
| GoogleThreatIntelligenceASMIssues.Issues.alias_group | String | Group of related aliases associated with the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.category | String | Threat category associated with the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.confidence | String | Confidence score indicating the reliability of detection. |
| GoogleThreatIntelligenceASMIssues.Issues.description | String | Detailed description of the identified issue. |
| GoogleThreatIntelligenceASMIssues.Issues.details.name | String | Name associated with the issue details. |
| GoogleThreatIntelligenceASMIssues.Issues.details.source | String | Data source from which the issue details are derived. |
| GoogleThreatIntelligenceASMIssues.Issues.details.status | String | Current status of the issue details. |
| GoogleThreatIntelligenceASMIssues.Issues.details.category | String | Category of the issue details. |
| GoogleThreatIntelligenceASMIssues.Issues.details.severity | String | Severity level of the issue details. |
| GoogleThreatIntelligenceASMIssues.Issues.details.mx_records.host | String | Host name from the MX record. |
| GoogleThreatIntelligenceASMIssues.Issues.details.mx_records.priority | String | Priority value from the MX record. |
| GoogleThreatIntelligenceASMIssues.Issues.details.references.uri | String | Reference URI linked to the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.details.references.type | String | Type of reference for the provided URI. |
| GoogleThreatIntelligenceASMIssues.Issues.details.description | String | Description provided in the issue details. |
| GoogleThreatIntelligenceASMIssues.Issues.details.pretty_name | String | Readable and formatted name for the issue details. |
| GoogleThreatIntelligenceASMIssues.Issues.first_seen | Date | Timestamp when the issue was first detected. |
| GoogleThreatIntelligenceASMIssues.Issues.identifiers | List | List of identifiers associated with the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.last_seen | Date | Timestamp when the issue was last observed. |
| GoogleThreatIntelligenceASMIssues.Issues.name | String | Name assigned to the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.pretty_name | String | Human-readable formatted name of the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.scoped | Boolean | Indicates whether the issue is scoped to a specific asset or context. |
| GoogleThreatIntelligenceASMIssues.Issues.severity | Number | Severity score assigned to the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.source | String | Source from which the issue originates. |
| GoogleThreatIntelligenceASMIssues.Issues.status | String | Current status of the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.ticket_list | List | List of tickets linked to this issue. |
| GoogleThreatIntelligenceASMIssues.Issues.type | String | Type of issue detected. |
| GoogleThreatIntelligenceASMIssues.Issues.uid | String | Internal unique ID of the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.upstream | String | Upstream system or source responsible for reporting the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.created_at | Date | Timestamp when the issue was created. |
| GoogleThreatIntelligenceASMIssues.Issues.updated_at | Date | Timestamp when the issue was last updated. |
| GoogleThreatIntelligenceASMIssues.Issues.collection_id | Number | Numeric ID of the collection associated with the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.elasticsearch_mappings_hash | String | Hash value representing Elasticsearch mappings for the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.cisa_known_exploited | Boolean | Indicates if the issue is part of CISA's Known Exploited Vulnerabilities list. |
| GoogleThreatIntelligenceASMIssues.Issues.epss_v2_score_lte | Number | EPSS v2 score showing likelihood of exploitation \(less than or equal\). |
| GoogleThreatIntelligenceASMIssues.Issues.epss_v2_percentile_gte | Number | EPSS v2 percentile representing exploitation probability \(greater than or equal\). |
| GoogleThreatIntelligenceASMIssues.Issues.entity_id | Number | Numeric ID of the associated entity. |
| GoogleThreatIntelligenceASMIssues.Issues.collection | String | Name of the collection where the issue belongs. |
| GoogleThreatIntelligenceASMIssues.Issues.collection_type | String | Type of collection to which the issue is linked. |
| GoogleThreatIntelligenceASMIssues.Issues.collection_uuid | String | UUID of the associated collection. |
| GoogleThreatIntelligenceASMIssues.Issues.organization_uuid | String | UUID of the organization associated with the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.entity_name | String | Name of the affected entity. |
| GoogleThreatIntelligenceASMIssues.Issues.entity_type | String | Type of the affected entity \(e.g., domain, IP, asset\). |
| GoogleThreatIntelligenceASMIssues.Issues.summary.pretty_name | String | User-friendly summary name of the issue. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.severity | Number | Severity level defined in the issue summary. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.scoped | Boolean | Indicates whether the summary is scoped to a specific asset or context. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.confidence | String | Confidence score provided in the issue summary. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.status | String | Status value specified in the issue summary. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.category | String | Category defined in the issue summary. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.identifiers | List | Identifiers included in the issue summary. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.status_new | String | Updated status of the issue summary. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.status_new_detailed | String | Detailed description of the updated issue summary status. |
| GoogleThreatIntelligenceASMIssues.Issues.summary.ticket_list | List | List of tickets associated with the issue summary. |
| GoogleThreatIntelligenceASMIssues.Issues.tags | List | Tags assigned to the issue for categorization. |

#### Command example

```!gti-asm-issue-get issue_id=dummy_uid```

#### Context Example

```json
{
    "GoogleThreatIntelligenceASMIssues": {
        "Issues": {
            "uuid": "dummy_uuid",
        "dynamic_id": 210054431,
        "entity_uid": "dummy_entity_uid",
        "alias_group": "4898048",
        "category": "misconfiguration",
        "confidence": "confirmed",
        "description": "Any CA is able to generate a certificate for this domain, increasing the risk of exposure if that CA is compromised.",
        "details": {
            "name": "dns_caa_policy_missing",
            "task": "tasks",
            "added": "dummy_added",
            "proof": "dummy_proof",
            "status": "dummy_status",
            "category": "dummy_category",
            "severity": 5,
            "references": [
                {
                    "uri": "https://www.example.com/DNS_Certification_Authority_Authorization",
                    "type": "description"
                },
                {
                    "uri": "https://www.example.com/caa/",
                    "type": "remediation"
                }
            ],
            "description": "Any CA is able to generate a certificate for this domain, increasing the risk of exposure if that CA is compromised.",
            "pretty_name": "Domain is missing a CAA record",
            "remediation": "Add a CAA record, setting the policy for this domain."
        },
        "first_seen": "2024-12-18T15:43:48.000Z",
        "identifiers": "test",
        "last_seen": "2025-02-11T16:55:42.000Z",
        "name": "dns_caa_policy_missing",
        "pretty_name": "Domain is missing a CAA record",
        "scoped": true,
        "severity": 5,
        "source": "intrigue",
        "status": "open_new",
        "ticket_list": ["ticket"],
        "type": "standard",
        "uid": "dummy_uid",
        "upstream": "intrigue",
        "created_at": "2025-02-11T16:56:52.734Z",
        "updated_at": "2024-12-19T00:00:00.000Z",
        "collection_id": 181421,
        "elasticsearch_mappings_hash": "dummy_elasticsearch_mappings_hash",
        "cisa_known_exploited": false,
        "epss_v2_score_lte": 4,
        "epss_v2_percentile_gte": 4,
        "entity_id": -522945081,
        "collection": "testdata",
        "collection_type": "pre_collection",
        "collection_uuid": "dummy_collection_uuid",
        "organization_uuid": "dummy_organization_uuid",
        "entity_name": "testdata.ai",
        "entity_type": "Intrigue::Entity::Domain",
        "summary": {
            "pretty_name": "Domain is missing a CAA record",
            "severity": 5,
            "scoped": true,
            "confidence": "confirmed",
            "status": "open_new",
            "category": "misconfiguration",
            "identifiers": "test",
            "status_new": "open",
            "status_new_detailed": "new",
            "ticket_list": ["ticket"]
        },
        "tags": ["Test"]
        }
    }
}
```

#### Human Readable Output

>### ASM Issue
>
>|Issue ID|Issue Name|Issue Description|Status|Severity|Entity Name|Entity uid|Entity Type|Collection|Confidence|Last Seen|First Seen|Tags|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| dummy_uid | Domain is missing a CAA record | Any CA is able to generate a certificate for this domain, increasing the risk of exposure if that CA is compromised. | Open | 5 | testdata.ai | dummy_entity_uid | Intrigue::Entity::Domain | testdata | confirmed | 2025-02-11T16:55:42.000Z | 2024-12-18T15:43:48.000Z | Test |

### gti-asm-issue-status-update

***
Update the status of an ASM Issue.

#### Base Command

`gti-asm-issue-status-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_id | Specify the ID of the issue.<br/><br/>Note: Use gti-asm-issue-list to retrive the Issue ID. | Required |
| project_id | Specify the project ID for the project.<br/><br/>Note:If no value is provided for the project ID, it will be taken from the configuration parameters. | Optional |
| status | Specify status of the issues to be updated. Possible values are: Open, Triaged, In Progress, Closed, Mitigated, Resolved, Duplicate, Out of Scope, False Positive, Risk Accepted, Benign, Unable to Reproduce, Track Externally. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleThreatIntelligenceASMIssues.Issues.uid | String | Unique identifier for the issue in Google Threat Intelligence. |
| GoogleThreatIntelligenceASMIssues.Issues.success | Boolean | Indicates whether the API request to fetch issue details was successful. |
| GoogleThreatIntelligenceASMIssues.Issues.message | String | Response message returned by the API, providing additional information. |
| GoogleThreatIntelligenceASMIssues.Issues.result | String | Result status or outcome returned by the API for the issue request. |

#### Command example

```!gti-asm-issue-status-update issue_id="dummy_uid" status="resolved"```

#### Context Example

```json
{
    "GoogleThreatIntelligenceASMIssues": {
        "Issues": {
            "message": "Successfully reported status as closed_resolved",
            "result": "closed_resolved",
            "success": true,
            "uid": "dummy_uid"
        }
    }
}
```

#### Human Readable Output

>### ASM Issue Status Updated Successfully
>
>|Issue ID|Status|
>|---|---|
>| dummy_uid | Resolved |
