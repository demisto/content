The CyCognito integration fetches issues discovered by the CyCognito platform, thereby providing users with a view of their organization's internet-exposed attack surface. These issues include identification, prioritization, and recommendations for remediation of the risks faced by the organization. The integration contains commands to query assets and issues detected by the CyCognito platform, and includes a rich dashboard and layout with issue management capability.
This integration was integrated and tested with CyCognito V1 API.

## Configure CyCognito in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | The API Key required to authenticate to the service. | True |
| Incident type | Incident type to map if no classifier is provided. | False |
| Incident Mirroring Direction | The mirroring direction in which to mirror the incident. You can mirror only in \(from CyCognito to XSOAR\), out \(from XSOAR to CyCognito\), or in both directions. | False |
| Fetch incidents | Indicates whether to fetch incident from the instance. | False |
| First Fetch Time | The date or relative timestamp from which to begin fetching incidents.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z | False |
| Max Fetch | The maximum number of incidents to fetch every time. The maximum value is '1000'. | False |
| Issue Type | The type of issue to fetch. By default, all types of issues will be fetched. Multiple selection is supported. | False |
| Locations | Filters incidents according to the geographic locations in which the issue is found. Multiple selection is supported.| False |
| Severity | The severity levels of the issues to fetch from CyCognito. By default, all the severity levels will be fetched, Multiple selection is supported. | False |
| Investigation Status | The investigation status of the issues to fetch from CyCognito. By default, it fetches uninvestigated issues. | False |
| Advanced Filter | Applies a filter to the list of issues based on a JSON-specific query.<br/><br/>Format:<br/>\[\{<br/>    "field": "issue-type",<br/>    "op": "in",<br/>    "values": \[<br/>       "Unsafe Authentication",<br/>       "Vulnerable Software"<br/>    \]	<br/>\},<br/>\{<br/>    "op": "not-in",<br/>    "field": "severity-score",<br/>    "values": \[10, 9\]<br/>\}\]<br/><br/>Note: When using several filtering options \(e.g., 'Issue Type' and 'Advanced Filter'\), Advanced Filter parameters will take precedence over other parameters.<br/>For a complete reference to the CyCognito fields and operations, please refer to the CyCognito API V0 documentation at <br/>https://docs.cycognito.com/reference/query-issues | False |
| Trust any certificate (not secure) | Indicates whether to allow connections without verifying SSL certificate's validity. | False |
| Use system proxy settings | Indicates whether to use XSOAR's system proxy settings to connect to the API. | False |
| Incidents Fetch Interval | Time interval for fetching incidents. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cycognito-issue-get
***
Retrieves information about an issue associated with a particular instance based on the provided issue instance ID.


#### Base Command

`cycognito-issue-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| issue_instance_id | Unique issue ID of the instance.<br/><br/>Example: 0.0.0.0-cyc-auth-default-credentials,<br/>example.com-cyc-sql-injection, 0.0.0.0-cyc-exposed-bucket-with-data.<br/><br/>Note: Users can retrieve the list of issue instance IDs by executing the "cycognito-issues-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyCognito.Issue.id | String | Unique ID of the issue. |
| CyCognito.Issue.references | Unknown | Issue reference. | 
| CyCognito.Issue.potential_threat | String | The threat that the issue might cause. | 
| CyCognito.Issue.tags | Unknown | Tags of the issue. | 
| CyCognito.Issue.organizations | Unknown | Organizations of the instance. | 
| CyCognito.Issue.issue_id | String | Unique ID of the issue. | 
| CyCognito.Issue.summary | String | A brief description that summarizes the issue. | 
| CyCognito.Issue.resolved_at | String | Date/time when the issue was resolved. | 
| CyCognito.Issue.investigation_status | String | Investigation status of the issue. | 
| CyCognito.Issue.locations | Unknown | The geographic location of the instance. | 
| CyCognito.Issue.detection_complexity | String | Measures the difficulty at which a vulnerable asset can be detected by a potential attacker. | 
| CyCognito.Issue.title | String | Title of the issue. | 
| CyCognito.Issue.exploitation_score | Number | Exploitation score of the issue. | 
| CyCognito.Issue.issue_type | String | Type of the issue. | 
| CyCognito.Issue.comment | String | Comment associated with the issue. | 
| CyCognito.Issue.severity | String | Severity of the issue. | 
| CyCognito.Issue.remediation_steps | Unknown | A list of actions that describe how to resolve the issue. | 
| CyCognito.Issue.potential_impact | Unknown | A list of categories that describe what might happen if the issue is exploited. | 
| CyCognito.Issue.exploitation_method | String | Exploitation method of the issue. | 
| CyCognito.Issue.affected_asset | String | The unique ID of the asset with which the issue is associated. | 
| CyCognito.Issue.severity_score | Number | The numeric severity of the issue is in the range of 0 \(not severe\) through 10 \(severe\). | 
| CyCognito.Issue.last_detected | Date | The time at which the issue was last detected. | 
| CyCognito.Issue.first_detected | Date | The time at which the issue was first detected. | 
| CyCognito.Issue.issue_status | String | Status of the issue found. | 
| CyCognito.Issue.evidence | Unknown | Provides a reason or proof of why the issue was indeed detected by CyCognito. |

#### Command example
```!cycognito-issue-get issue_instance_id=127.0.0.1-cve-2019-00000```
#### Context Example
```json
{
    "CyCognito": {
        "Issue": {
            "affected_asset": "ip/127.0.0.1",
            "detection_complexity": "Service Detection",
            "exploitation_method": "Metasploit",
            "exploitation_score": 3,
            "first_detected": "2022-03-31T03:39:22.568Z",
            "id": "127.0.0.1-cve-2019-00000",
            "investigation_status": "investigating",
            "issue_id": "CVE-2019-00000",
            "issue_status": "new",
            "issue_type": "Vulnerable Software",
            "last_detected": "2022-03-31T03:39:22.568Z",
            "locations": [
                "IND"
            ],
            "organizations": [
                "Acme Interior Design",
                "Acme Corporation"
            ],
            "potential_impact": [
                "Loss of integrity",
                "Loss of confidentiality",
                "Data compromise"
            ],
            "references": [],
            "remediation_steps": [
                "Patch the Pulse Secure VPN to the latest version."
            ],
            "severity": "critical",
            "severity_score": 10,
            "summary": "| The Pulse Secure VPN has been confirmed to be vulnerable to an arbitrary file reading vulnerability. | Unauthenticated remote attackers can send the asset a specially crafted URI and thereby access arbitrary sensitive files. | Attackers can leverage the harvested information to perform further attacks.",
            "tags": [
                "Vulnerable Software",
                "Pulse Secure",
                "network vulnerabilities"
            ],
            "potential_threat": "Information Disclosure",
            "title": "Pulse Secure Arbitrary File Reading"
        }
    }
}
```

#### Human Readable Output

>### Issue detail:
>#### ID: 127.0.0.1-test
>|Title|Affected Asset|Detection Complexity|Investigation Status|Exploitation Score|First Detected|Last Detected|Organizations|Locations|Potential Threat|Severity|Issue Type|Issue Status|Remediation Steps|Potential Impact|Tags|Summary|Link to Platform|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Pulse Secure Arbitrary File Reading | ip/127.0.0.1 | Service Detection | investigating | 3 | 31 Mar 2022, 03:39 AM | 31 Mar 2022, 03:39 AM | Acme Interior Design, Acme Corporation | India | Information Disclosure | critical | Vulnerable Software | new | Patch the Pulse Secure VPN to the latest version. | Loss of integrity, Loss of confidentiality, Data compromise | Vulnerable Software, Pulse Secure, network vulnerabilities | The Pulse Secure VPN has been confirmed to be vulnerable to an arbitrary file reading vulnerability. Unauthenticated remote attackers can send the asset a specially crafted URI and thereby access arbitrary sensitive files. Attackers can leverage the harvested information to perform further attacks. | [Click Here](https://platform.cycognito.com/issues/issue/127.0.0.1-test/info)


### cycognito-asset-get
***
Retrieves information about a specific asset according to the specified asset type and asset ID.


#### Base Command

`cycognito-asset-get`
#### Input

| **Argument Name** | **Description** | **Required** |
|---|---|---|
| asset_type | The type of asset.<br/><br/>Supported values: 'ip', 'domain', 'cert', 'webapp', 'iprange'                                                                                                                                                                                                                                                                                                                                                              | Required | 
| asset_id | The unique asset identifier.<br/><br/>Note: The asset ID value can be found by executing the "cycognito-assets-list" command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
|---|---|---|
| CyCognito.Asset.alive | Boolean | Whether the port is alive or not. | 
| CyCognito.Asset.comment | String | Comment associated with the asset. | 
| CyCognito.Asset.id | String | Unique identifier of the asset. <br/>Note: The asset ID is derived from the asset_id input field. | 
| CyCognito.Asset.type | String | The type of asset. | 
| CyCognito.Asset.business_units | Unknown | The business units of the asset. | 
| CyCognito.Asset.signature | String | The identifier of the certificate. | 
| CyCognito.Asset.closed_ports.status | String | Status of the closed ports object associated with the asset. | 
| CyCognito.Asset.closed_ports.port | Number | Port of the closed ports object associated with the asset. | 
| CyCognito.Asset.closed_ports.protocol | String | Protocol associated with the asset. | 
| CyCognito.Asset.created | Date | Creation time of the asset. | 
| CyCognito.Asset.domain | String | Domain of the asset. | 
| CyCognito.Asset.domains | Unknown | List of domains associated with the asset. | 
| CyCognito.Asset.domain_names | Unknown | List of domain names associated with the asset. | 
| CyCognito.Asset.expiration | Date | The date and time at which the asset expires. | 
| CyCognito.Asset.first_seen | Date | The time and date at which the asset was first discovered. | 
| CyCognito.Asset.hosting_type | String | Hosting type of the asset. | 
| CyCognito.Asset.ip | String | IP address of the asset. | 
| CyCognito.Asset.ip_addresses | Unknown | IP name of the asset. | 
| CyCognito.Asset.issuer_alt_names | Unknown | List of alternative names of the issuers. | 
| CyCognito.Asset.issuer_common_name | String | Common name of the Issuer. | 
| CyCognito.Asset.issuer_country | String | Country of the issuer. | 
| CyCognito.Asset.issuer_locality | String | Locality of the issuer. | 
| CyCognito.Asset.issuer_organization | String | The issuer's organization. | 
| CyCognito.Asset.issuer_organization_unit | String | The issuer's organization unit. | 
| CyCognito.Asset.issuer_state | String | The state of the issuer. | 
| CyCognito.Asset.issues_count | Number | Count of the issues. | 
| CyCognito.Asset.last_seen | Date | The time and date at which the asset was last seen. | 
| CyCognito.Asset.locations | Unknown | Location of the asset. | 
| CyCognito.Asset.open_ports.status | String | Status of the open ports object associated with the asset. | 
| CyCognito.Asset.open_ports.port | Number | Port of the open ports object associated with the asset. | 
| CyCognito.Asset.open_ports.protocol | String | Protocol associated with the asset. |  
| CyCognito.Asset.organizations | Unknown | Organizations of the asset. | 
| CyCognito.Asset.status | String | Status of the asset. | 
| CyCognito.Asset.security_grade | String | Security rating of the asset. | 
| CyCognito.Asset.severe_issues | Number | The number of severe issues associated with the asset. | 
| CyCognito.Asset.signature_algorithm | String | Signature algorithm of the asset. | 
| CyCognito.Asset.sub_domains | Unknown | Subdomains of the asset. | 
| CyCognito.Asset.subject_alt_names | Unknown | List of alternate subject names. | 
| CyCognito.Asset.subject_common_name | String | Common name of the subject. | 
| CyCognito.Asset.subject_country | String | Subject's country. | 
| CyCognito.Asset.subject_locality | String | Locality of the subject. | 
| CyCognito.Asset.subject_organization | String | Subject's Organization. | 
| CyCognito.Asset.subject_organization_unit | String | The organization unit of the subject. | 
| CyCognito.Asset.subject_state | String | State of the subject. | 
| CyCognito.Asset.tags | Unknown | Tags of the asset. | 
| CyCognito.Asset.dynamically_resolved | String | Whether the asset has a rotating IP address. | 
| CyCognito.Asset.investigation_status | String | Investigation status of the asset. | 
| CyCognito.Asset.discoverability | String | Quantifies an asset's level of exposure. |

#### Command example
```!cycognito-asset-get asset_type=ip asset_id=127.0.0.1```
#### Context Example
```json
{
    "CyCognito": {
        "Asset": {
            "alive": true,
            "closed_ports": [
                {
                    "port": 8080,
                    "protocol": "tcp",
                    "status": "closed"
                },
                {
                    "port": 102,
                    "protocol": "tcp",
                    "status": "closed"
                },
                {
                    "port": 445,
                    "protocol": "tcp",
                    "status": "closed"
                },
                {
                    "port": 161,
                    "protocol": "tcp",
                    "status": "closed"
                },
                {
                    "port": 4040,
                    "protocol": "tcp",
                    "status": "closed"
                },
                {
                    "port": 7070,
                    "protocol": "tcp",
                    "status": "closed"
                },
                {
                    "port": 1723,
                    "protocol": "tcp",
                    "status": "closed"
                }
            ],
            "comment": {
                "content": "A grade",
                "last_update": "2022-05-06T05:19:05.931Z"
            },
            "dynamically_resolved": "no",
            "first_seen": "2022-01-20T03:58:36.696Z",
            "hosting_type": "owned",
            "id": "127.0.0.1",
            "investigation_status": "investigated",
            "ip": "127.0.0.1",
            "issues_count": 1,
            "last_seen": "2022-03-31T03:39:22.568Z",
            "locations": [
                "IND"
            ],
            "open_ports": [
                {
                    "port": 9999,
                    "protocol": "tcp",
                    "status": "open"
                },
                {
                    "port": 2000,
                    "protocol": "tcp",
                    "status": "open"
                }
            ],
            "organizations": [
                "Acme Interior Design",
                "Acme Corporation"
            ],
            "security_grade": "B",
            "severe_issues": 0,
            "status": "new",
            "tags": [
                "Gateways",
                "ACME"
            ],
            "type": "ip"
        }
    }
}
```

#### Human Readable Output

>### Asset Details:
>|Asset ID|Asset Type|Hosting Type|Alive|Locations|First Seen|Last Seen|Status|Security Grade|Tags|Organizations|Severe Issues|Investigation Status|Open Ports|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 127.0.0.1 | ip | owned | true | India | 20 Jan 2022, 03:58 AM | 31 Mar 2022, 03:39 AM | new | B | Gateways,<br/>ACME | Acme Interior Design, Acme Corporation | 0 | investigated | TCP - 9999, TCP - 2000 |


### cycognito-asset-investigation-status-change
***
Modifies the investigation status of the specified asset.


#### Base Command

`cycognito-asset-investigation-status-change`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_type | The type of asset.<br/><br/>Supported values: 'ip', 'domain', 'cert', 'webapp', 'iprange' | Required | 
| asset_id | The unique asset identifier.<br/><br/>Note: The asset ID value can be found by executing the "cycognito-assets-list" command. | Required | 
| investigation_status | The investigation status of the asset. <br/><br/>Supported values: 'uninvestigated', 'investigating', 'investigated'. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
|---|---|---|
| CyCognito.Asset.type | String | The type of the asset. | 
| CyCognito.Asset.id | String | Unique identifier of the asset. <br/>Note: The asset ID is derived from the asset_ID input field. | 
| CyCognito.Asset.investigation_status | String | Investigation status of the Asset. | 
| CyCognito.Asset.action_status | String | Whether the status update is successful or failed. | 

#### Command example
```!cycognito-asset-investigation-status-change asset_type=ip asset_id=127.0.0.1 investigation_status=investigated```
#### Context Example
```json
{
    "CyCognito": {
        "Asset": {
            "action_status": "Success",
            "asset_type": "ip",
            "id": "127.0.0.1",
            "investigation_status": "investigated"
        }
    }
}
```

#### Human Readable Output

>### Investigation Status has been successfully updated for 127.0.0.1
>|Asset Type|Asset ID|Investigation Status|Action Status|
>|---|---|---|---|
>| ip | 127.0.0.1 | investigated | Success |


### cycognito-issue-investigation-status-change
***
Modifies the investigation status of the specified issue.


#### Base Command

`cycognito-issue-investigation-status-change`
#### Input

| **Argument Name** | **Description** | **Required** |
|---|---|---|
| issue_instance_id | The unique issue ID of the instance whose investigation status is to be changed.<br/><br/>Example: 0.0.0.0-cyc-auth-default-credentials,<br/>example.com-cyc-sql-injection, 0.0.0.0-cyc-exposed-bucket-with-data.<br/><br/>Note: Users can retrieve the list of issue instance IDs by executing the "cycognito-issues-list" command. | Required | 
| investigation_status | The investigation status of the issue.<br/><br/>Supported values: 'uninvestigated', 'investigating', 'investigated' | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyCognito.Issue.id | String | Unique ID of the issue. | 
| CyCognito.Issue.investigation_status | String | Investigation status of the issue. | 
| CyCognito.Issue.action_status | String | Whether the update is successful or failed. | 

#### Command example
```!cycognito-issue-investigation-status-change issue_instance_id=127.0.0.1-cve-2019-00000 investigation_status=investigated```
#### Context Example
```json
{
    "CyCognito": {
        "Issue": {
            "action_status": "Success",
            "id": "127.0.0.1-cve-2019-00000",
            "investigation_status": "investigated"
        }
    }
}
```

#### Human Readable Output

>### Investigation Status has been successfully updated for 127.0.0.1-cve-2019-00000
>|Issue ID|Investigation Status|Action Status|
>|---|---|---|
>| 127.0.0.1-cve-2019-00000 | investigated | Success |


### cycognito-issues-list
***
Retrieves the list of the issues that meet the specified filter criteria.


#### Base Command

`cycognito-issues-list`
#### Input

| **Argument Name** | **Description** | **Required** |
|---|---|---|
| count | The number of results to retrieve.<br/><br/>Maximum value is '1000'. Default is 50. | Optional | 
| offset | Sets the starting index for the returned results. By specifying offset, you retrieve a subset of records starting with the offset value.<br/><br/>Note: If a negative value is provided then the default value of 0 will be used. Default is 0. | Optional | 
| search | An Advanced Search parameter to query the response.<br/><br/>Note: Retrieves all the occurrences that are included in the string. | Optional | 
| first_detected | The date and time at which CyCognito first discovered and attributed the asset to the organization.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z | Optional | 
| last_detected | The date and time at which CyCognito most recently attributed the asset to the organization.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z | Optional | 
| organizations | Filters the issues according to the provided organizations. Supports comma-separated values. | Optional | 
| locations | The geographical locations in which the issue is found. Supported values contain the three-letter ISO country code for the respective countries--e.g., IND, USA. | Optional | 
| issue_type | Filters the records according to the issue type. Supports comma-separated values.<br/><br/>Supported values: "Abandoned Asset", "Certificate Validity", "Cryptographic Vulnerability", "E-mail Security", "Exposed Asset", "Exposed Data", "Exposed Dev Environment", "Information Gathering", "Phishing Threat", "Potential Imposter Asset", "Security Hygiene", "Unmaintained Asset", "Unsafe Authentication", "Vulnerable Software", "Weak Encryption", "XSS" | Optional | 
| sort_by | The name of the field by which to sort the results. The response fields available for sorting the data are found in the following documentation:<br/>https://docs.cycognito.com/reference/reference-getting-started. | Optional | 
| sort_order | Specifies whether to sort the results in either ascending or descending order.<br/><br/>Supported values: 'asc', 'desc' | Optional | 
| advanced_filter | Applies a filter to the list of issues based on a JSON-specific query.<br/><br/>Format:<br/>\[\{<br/>    "field": "issue-type",<br/>    "op": "in",<br/>    "values": \[<br/>       "Unsafe Authentication",<br/>       "Vulnerable Software"<br/>    \]	<br/>\},<br/>\{<br/>    "op": "not-in",<br/>    "field": "severity-score",<br/>    "values": \[10, 9\]<br/>\}\]<br/><br/>Note: When using several filtering options (e.g., 'Issue Type' and 'Advanced Filter'), advance_json parameters will take precedence over other parameters. <br/>For a complete reference to the CyCognito fields and operations, please refer to the CyCognito API V0 documentation at <br/>https://docs.cycognito.com/reference/query-issues. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyCognito.Issue.id | String | Unique ID of the issue. |
| CyCognito.Issue.references | Unknown | Reference of the issue. | 
| CyCognito.Issue.potential_threat | String | The threat that the issue might cause. | 
| CyCognito.Issue.tags | Unknown | Tags of the issue. | 
| CyCognito.Issue.organizations | Unknown | Organizations of the instance. | 
| CyCognito.Issue.issue_id | String | Unique ID of the issue. | 
| CyCognito.Issue.summary | String | A brief description that summarizes the issue. | 
| CyCognito.Issue.resolved_at | String | Date/time when the issue was resolved. | 
| CyCognito.Issue.investigation_status | String | Investigation status of the issue. | 
| CyCognito.Issue.locations | Unknown | The geographic location of the instance. | 
| CyCognito.Issue.detection_complexity | String | Measures the difficulty at which a vulnerable asset can be detected by a potential attacker. | 
| CyCognito.Issue.title | String | Title of the issue. | 
| CyCognito.Issue.exploitation_score | Number | Exploitation score of the issue. | 
| CyCognito.Issue.issue_type | String | Type of the issue. | 
| CyCognito.Issue.comment | String | Comment associated with the issue. | 
| CyCognito.Issue.severity | String | Severity of the issue. | 
| CyCognito.Issue.remediation_steps | Unknown | A list of actions that describe how to resolve the issue. | 
| CyCognito.Issue.potential_impact | Unknown | A list of categories that describe what might happen if the issue is exploited. | 
| CyCognito.Issue.exploitation_method | String | Exploitation method of the issue. | 
| CyCognito.Issue.affected_asset | String | The unique ID of the asset with which the issue is associated. | 
| CyCognito.Issue.severity_score | Number | The numeric severity of the issue is in the range of 0 \(not severe\) through 10 \(severe\). | 
| CyCognito.Issue.last_detected | Date | The time at which the issue was last detected. | 
| CyCognito.Issue.first_detected | Date | The time at which the issue was first detected. | 
| CyCognito.Issue.issue_status | String | Status of the issue found. | 
| CyCognito.Issue.evidence | Unknown | Provides a reason or proof of why the issue was indeed detected by CyCognito. |

#### Command example
```!cycognito-issues-list count=2```
#### Context Example
```json
{
    "CyCognito": {
        "Issue": [
            {
                "affected_asset": "ip/127.0.0.1",
                "detection_complexity": "Service Detection",
                "exploitation_method": "Metasploit",
                "exploitation_score": 3,
                "first_detected": "2022-03-31T03:39:22.568Z",
                "id": "issue/127.0.0.1-cve-2019-00000",
                "investigation_status": "investigating",
                "issue_id": "CVE-2019-00000",
                "issue_status": "new",
                "issue_type": "Vulnerable Software",
                "last_detected": "2022-03-31T03:39:22.568Z",
                "locations": [
                    "USA"
                ],
                "organizations": [
                    "ACME Ticketing",
                    "ACME Cleantech Solutions",
                    "Acme Holdings"
                ],
                "potential_impact": [
                    "Loss of integrity",
                    "Loss of confidentiality",
                    "Loss of availability",
                    "Data compromise",
                    "Network breach"
                ],
                "references": [],
                "remediation_steps": [
                    "Patch the NetScaler to the latest version.",
                    "If a patch is not feasible, perform \"work-around\" mitigations per Citrix's instructions."
                ],
                "severity": "critical",
                "severity_score": 10,
                "summary": "| The NetScaler has been confirmed to be vulnerable to CVE-2019-00000 (first made public in December 2019). | Due to improper handling of the path names, CVE-2019-00000 enables attackers to perform directory traversal and unauthenticated, remote arbitrary code execution via specially crafted HTTP requests. | As NetScalers serve as entry-points to organization networks, attackers can exploit this vulnerability to breach organization networks and leverage the NetScaler for further attacks. | This vulnerability has been exploited \"in the wild\" by unknown attackers.",
                "tags": [
                    "Pulse Secure"
                ],
                "potential_threat": "Remote Code Execution",
                "title": "CVE-2019-00000 (Unauthenticated Remote Directory Traversal & Code Execution)"
            },
            {
                "affected_asset": "ip/127.0.0.2",
                "comment": {
                    "content": "hello",
                    "last_update": "2022-06-14T06:42:20.952Z"
                },
                "detection_complexity": "Handshake",
                "exploitation_method": "Man-in-the-Middle",
                "exploitation_score": 4,
                "first_detected": "2022-03-20T18:48:33.528Z",
                "id": "issue/127.0.0.2-cyc-tls-hsts-dummy",
                "investigation_status": "investigating",
                "issue_id": "CYC-TLS-HSTS-DUMMY",
                "issue_status": "new",
                "issue_type": "Cryptographic Vulnerability",
                "last_detected": "2022-03-20T18:48:33.528Z",
                "locations": [
                    "USA"
                ],
                "organizations": [
                    "Acme Homes"
                ],
                "potential_impact": [
                    "Loss of integrity",
                    "Loss of confidentiality"
                ],
                "remediation_steps": [
                    "Enable an HSTS policy of at least 180 days."
                ],
                "severity": "critical",
                "severity_score": 10,
                "summary": "The server's HSTS policy is either too short or non-existent. | HTTP Strict Transport Security is an optional HTTP header that instructs browsers to only communicate with the server using HTTPS (and not HTTP) for a certain period of time, thus helping prevent \"SSL-stripping\" attacks.",
                "potential_threat": "Trust",
                "title": "Insecure HSTS"
            }
        ]
    }
}
```

#### Human Readable Output

>### Issues:
>|ID|Title|Severity Score|Severity|Issue Type|Issue Status|Organizations|Investigation Status|First Detected|Last Detected|Locations|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 127.0.0.1-cve-2019-00000 | Pulse Secure Arbitrary File Reading | 10.0 | critical | Vulnerable Software | new | Acme Interior Design, Acme Corporation | investigating | 31 Mar 2022, 03:39 AM | 31 Mar 2022, 03:39 AM | India |
>| 127.0.0.2-cve-2019-00000 | CVE-2019-00000 (Unauthenticated Remote Directory Traversal & Code Execution) | 10.0 | critical | Vulnerable Software | new | ACME Ticketing, ACME Cleantech Solutions, Acme Holdings | uninvestigated | 31 Mar 2022, 03:39 AM | 31 Mar 2022, 03:39 AM | United States |


### cycognito-assets-list
***
Retrieves the list of assets that meet specified filter criteria.


#### Base Command

`cycognito-assets-list`
#### Input

| **Argument Name** | **Description** | **Required** |
|---|---|---|
| asset_type | The type of asset.<br/><br/>Supported values: 'ip', 'domain', 'cert', 'webapp', 'iprange' | Required | 
| count | The number of results to be retrieved in a response. <br/><br/>Maximum value is '1000'. Default is 50. | Optional | 
| offset | Sets the starting index for the returned results. By specifying offset, you retrieve a subset of records starting with the offset value.<br/><br/>Note: If a negative value is provided then the default value of 0 will be used. Default is 0. | Optional | 
| search | An Advanced Search parameter to query the response.<br/><br/>Note: Retrieves all the occurrences that are included in the string. | Optional | 
| status | Filters the assets according to the selected status. Supports comma-separated values.<br/><br/>Supported values: 'changed', 'new', 'normal' | Optional | 
| organizations | Filters the assets according to the provided organizations. Supports comma-separated values. | Optional | 
| security_grade | Filters the assets according to the provided security ratings. Supports comma-separated values.<br/><br/>Supported values: 'A', 'B', 'C', 'D', 'F'<br/><br/>Where:<br/>A = Very strong<br/>B = Strong<br/>C = Less vulnerable<br/>D = Vulnerable<br/>F = Highly vulnerable | Optional | 
| locations | The geographical locations in which the asset is found. Supported values contain the three-letter ISO country code for the respective countries'e.g., IND, USA.<br/>Locations are available only for IP, Domain, and Certificate asset types. | Optional | 
| first_seen | The date and time at which CyCognito first discovered and attributed the asset to the organization.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z | Optional | 
| last_seen | The date and time at which CyCognito most recently attributed the asset to the organization.<br/><br/>Supported formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ<br/><br/>For example: 01 Mar 2021, 01 Feb 2021 04:45:33, 2022-04-17T14:05:44Z | Optional | 
| sort_by | Specifies the field by which to sort.<br/><br/>Note: The response fields available for sorting the data are found in the following documentation:<br/>https://docs.cycognito.com/reference/query-assets. | Optional | 
| sort_order | Specifies whether to sort the results in either ascending or descending order.<br/><br/>Supported values: 'asc', 'desc'. Default is desc. | Optional | 
| advanced_filter | Applies a filter to the list of assets based on a JSON-specific query.<br/><br/>Format:<br/>\[\{<br/>    "field": "status",<br/>    "op": "in",<br/>    "values": \[<br/>        "new",<br/>        "changed"<br/>    \]	<br/>\},<br/>\{<br/>    "op": "not-in",<br/>    "field": "security-rating",<br/>    "values": \["A"\]<br/>\}\]<br/><br/>Note: For a complete reference to the CyCognito fields and operations, please refer to the CyCognito API V0 documentation at https://docs.cycognito.com/reference/query-assets. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CyCognito.Asset.alive | Boolean | Whether the port is alive or not. | 
| CyCognito.Asset.comment | String | Comments related to the asset. | 
| CyCognito.Asset.id | String | Unique identifier of the asset. <br/>Note: Asset ID is derived from the asset_id input field. | 
| CyCognito.Asset.type | String | Type of the asset. | 
| CyCognito.Asset.business_units | Unknown | Business units of the asset. | 
| CyCognito.Asset.signature | String | The identifier of the certificate. | 
| CyCognito.Asset.closed_ports.status | String | Status of the closed ports object associated with the asset. | 
| CyCognito.Asset.closed_ports.port | Number | Port of the closed ports object associated with the asset. | 
| CyCognito.Asset.closed_ports.protocol | String | Protocol associated with the asset. | 
| CyCognito.Asset.created | Date | Date and time at which the asset was created. | 
| CyCognito.Asset.domain | String | Domain name of the asset. | 
| CyCognito.Asset.domains | Unknown | Domain of the asset. | 
| CyCognito.Asset.domain_names | Unknown | List of domain names associated with the asset. | 
| CyCognito.Asset.expiration | Date | Date and time at which the asset is expired. | 
| CyCognito.Asset.first_seen | Date | Time at which an asset was first discovered and attributed to the organization. | 
| CyCognito.Asset.hosting_type | String | Hosting type of the asset. | 
| CyCognito.Asset.investigation_status | String | Investigation status of the asset. | 
| CyCognito.Asset.ip | String | IP of the asset. | 
| CyCognito.Asset.ip_addresses | Unknown | List of IP associated with the asset. | 
| CyCognito.Asset.issuer_alt_names | Unknown | List of alternate issuer names. | 
| CyCognito.Asset.issuer_common_name | String | Common name of the Issuer. | 
| CyCognito.Asset.issuer_country | String | Country of Issuer. | 
| CyCognito.Asset.issuer_locality | String | Locality of issuer. | 
| CyCognito.Asset.issuer_organization | String | Organization of the issuer. | 
| CyCognito.Asset.issuer_organization_unit | String | The organization unit of the issuer. | 
| CyCognito.Asset.issuer_state | String | State of the issuer. | 
| CyCognito.Asset.issues_count | Number | Count of issues associated with the asset. | 
| CyCognito.Asset.last_seen | Date | Time at which an asset was discovered and attributed to the organization. | 
| CyCognito.Asset.locations | Unknown | List of geographic locations with which an asset might be associated. | 
| CyCognito.Asset.open_ports.status | String | Status of the open ports object associated with the asset. | 
| CyCognito.Asset.open_ports.port | Number | Port of the open ports object associated with the asset. | 
| CyCognito.Asset.open_ports.protocol | String | Protocol associated with the asset. |
| CyCognito.Asset.organizations | Unknown | List of organizations associated with the asset. | 
| CyCognito.Asset.status | String | Last status of the asset. | 
| CyCognito.Asset.security_grade | String | Security rating of the asset based on the number and severity of the associated issues. | 
| CyCognito.Asset.severe_issues | Number | The number of severe issues associated with the asset. | 
| CyCognito.Asset.signature_algorithm | String | Signature algorithm associated with the asset. | 
| CyCognito.Asset.sub_domains | Unknown | List of subdomains associated with the asset. | 
| CyCognito.Asset.subject_alt_names | Unknown | List of alternate subject names. | 
| CyCognito.Asset.subject_common_name | String | Common name of the subject. | 
| CyCognito.Asset.subject_country | String | Subject's country. | 
| CyCognito.Asset.subject_locality | String | Locality of the subject. | 
| CyCognito.Asset.subject_organization | String | Subject's organization. | 
| CyCognito.Asset.subject_organization_unit | String | The organization unit of the subject. | 
| CyCognito.Asset.subject_state | String | State of the subject. | 
| CyCognito.Asset.tags | Unknown | List of tags associated with the asset. | 
| CyCognito.Asset.dynamically_resolved | String | Whether the asset has a rotating IP address. | 
| CyCognito.Asset.discoverability | String | Quantifies an asset's level of exposure. |

#### Command example
```!cycognito-assets-list asset_type=ip count=2```
#### Context Example
```json
{
    "CyCognito": {
        "Asset": [
            {
                "alive": true,
                "closed_ports": [
                    {
                        "port": 6001,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 47808,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 5900,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 111,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 9200,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 11211,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 1723,
                        "protocol": "tcp",
                        "status": "closed"
                    }
                ],
                "dynamically_resolved": "no",
                "first_seen": "2022-03-23T12:36:17.808Z",
                "hosting_type": "owned",
                "id": "ip/127.0.0.1",
                "investigation_status": "investigated",
                "ip": "127.0.0.1",
                "issues_count": 1,
                "last_seen": "2022-03-31T03:39:22.568Z",
                "locations": [
                    "MYS"
                ],
                "open_ports": [
                    {
                        "port": 465,
                        "protocol": "tcp",
                        "status": "open"
                    },
                    {
                        "port": 993,
                        "protocol": "tcp",
                        "status": "open"
                    },
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "status": "open"
                    },
                    {
                        "port": 53,
                        "protocol": "udp",
                        "status": "open"
                    }
                ],
                "organizations": [
                    "Acme Corporation"
                ],
                "security_grade": "F",
                "severe_issues": 1,
                "status": "new",
                "tags": [
                    "Vulnerable Software",
                    "Red Hat"
                ],
                "type": "ip"
            },
            {
                "alive": true,
                "closed_ports": [
                    {
                        "port": 3389,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 8888,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 110,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 548,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 23,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 11211,
                        "protocol": "tcp",
                        "status": "closed"
                    },
                    {
                        "port": 1723,
                        "protocol": "tcp",
                        "status": "closed"
                    }
                ],
                "dynamically_resolved": "no",
                "first_seen": "2022-03-23T12:27:04.354Z",
                "hosting_type": "owned",
                "id": "ip/127.0.0.2",
                "investigation_status": "investigated",
                "ip": "127.0.0.2",
                "issues_count": 2,
                "last_seen": "2022-03-31T03:39:22.568Z",
                "locations": [
                    "MYS"
                ],
                "open_ports": [
                    {
                        "port": 587,
                        "protocol": "tcp",
                        "status": "open"
                    },
                    {
                        "port": 21,
                        "protocol": "tcp",
                        "status": "open"
                    },
                    {
                        "port": 22,
                        "protocol": "tcp",
                        "status": "open"
                    },
                    {
                        "port": 465,
                        "protocol": "tcp",
                        "status": "open"
                    }
                ],
                "organizations": [
                    "Acme Corporation"
                ],
                "security_grade": "F",
                "severe_issues": 1,
                "status": "new",
                "tags": [
                    "Block Cipher"
                ],
                "type": "ip"
            }
        ]
    }
}
```

#### Human Readable Output

>### Asset List:
>### Assets Type: IP
>|Asset ID|Security Grade|Status|Organizations|Investigation Status|Severe Issues|First Seen|Last Seen|Hosting Type|Locations|
>|---|---|---|---|---|---|---|---|---|---|
>| 127.0.0.1 | F | new | Acme Corporation | investigated | 1 | 23 Mar 2022, 12:27 PM | 31 Mar 2022, 03:39 AM | owned | Malaysia |
>| 127.0.0.2 | F | new | Acme Corporation | investigated | 1 | 23 Mar 2022, 12:27 PM | 31 Mar 2022, 03:39 AM | owned | Malaysia |