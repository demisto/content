Vulnerability management solution to help reduce threat exposure.
This integration was integrated and tested with version 6.6.103 of Rapid7 Nexpose.

## Configure Rapid7 InsightVM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Rapid7 InsightVM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g., https://192.0.2.0:8080) | True |
    | Username | True |
    | Password | True |
    | 2FA Token | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### nexpose-get-asset

***
Returns the specified asset.

#### Base Command

`nexpose-get-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Asset ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Asset.Addresses | unknown | All addresses discovered on the asset. | 
| Nexpose.Asset.AssetId | number | Id of the asset. | 
| Nexpose.Asset.Hardware | string | The primary Media Access Control \(MAC\) address of the asset. The format is six groups of two hexadecimal digits separated by colons. | 
| Nexpose.Asset.Aliases | unknown | All host names or aliases discovered on the asset. | 
| Nexpose.Asset.HostType | string | The type of asset. Valid values are unknown, guest, hypervisor, physical, mobile | 
| Nexpose.Asset.Site | string | Asset site name. | 
| Nexpose.Asset.OperatingSystem | string | Operating system of the asset. | 
| Nexpose.Asset.Vulnerabilities | number | The total number of vulnerabilities on the asset. | 
| Nexpose.Asset.CPE | string | The Common Platform Enumeration \(CPE\) of the operating system. | 
| Nexpose.Asset.LastScanDate | date | Last scan date of the asset. | 
| Nexpose.Asset.LastScanId | number | ID of the asset's last scan. | 
| Nexpose.Asset.RiskScore | number | The risk score \(with criticality adjustments\) of the asset. | 
| Nexpose.Asset.Software.Software | string | The description of the software. | 
| Nexpose.Asset.Software.Version | string | The version of the software. | 
| Nexpose.Asset.Services.Name | string | The name of the service. | 
| Nexpose.Asset.Services.Port | number | The port of the service. | 
| Nexpose.Asset.Services.Product | string | The product running the service. | 
| Nexpose.Asset.Services.protocol | string | The protocol of the service, valid values are ip, icmp, igmp, ggp, tcp, pup, udp, idp, esp, nd, raw | 
| Nexpose.Asset.Users.FullName | string | The full name of the user account. | 
| Nexpose.Asset.Users.Name | string | The name of the user account. | 
| Nexpose.Asset.Users.UserId | number | The identifier of the user account. | 
| Nexpose.Asset.Vulnerability.Id | number | The identifier of the vulnerability. | 
| Nexpose.Asset.Vulnerability.Instances | number | The number of vulnerable occurrences of the vulnerability. This does not include invulnerable instances. | 
| Nexpose.Asset.Vulnerability.Title | string | The title \(summary\) of the vulnerability. | 
| Nexpose.Asset.Vulnerability.Malware | number | The malware kits that are known to be used to exploit the vulnerability. | 
| Nexpose.Asset.Vulnerability.Exploit | number | The exploits that can be used to exploit a vulnerability. | 
| Nexpose.Asset.Vulnerability.CVSS | string | The CVSS exploit score. | 
| Nexpose.Asset.Vulnerability.Risk | number | The risk score of the vulnerability, rounded to a maximum of to digits of precision. If using the default Rapid7 Real Risk™ model, this value ranges from 0-1000. | 
| Nexpose.Asset.Vulnerability.PublishedOn | date | The date the vulnerability was first published or announced. The format is an ISO 8601 date, YYYY-MM-DD. | 
| Nexpose.Asset.Vulnerability.ModifiedOn | date | The last date the vulnerability was modified. The format is an ISO 8601 date, YYYY-MM-DD. | 
| Nexpose.Asset.Vulnerability.Severity | string | The severity of the vulnerability, one of: "Moderate", "Severe", "Critical". | 
| Endpoint.IP | string | Endpoint IP address. | 
| Endpoint.HostName | string | Endpoint host name. | 
| Endpoint.OS | string | Endpoint operating system. | 
| CVE.ID | string | Common Vulnerabilities and Exposures IDs. | 

### nexpose-get-asset-tags

***
Returns the specified tags for an asset.

#### Base Command

`nexpose-get-asset-tags`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Asset ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.AssetTag.Type | string | Type of asset tag. | 
| Nexpose.AssetTag.Name | string | The value of the tag. | 
| Nexpose.AssetTag.CreatedTime | string | Timestamp of when the tag was created. | 
| Nexpose.AssetTag.RiskModifier | string | The risk modifier value associated with criticality tag type. | 

#### Command example

```!nexpose-get-asset-tags asset_id=1```

#### Context Example

```json
{
    "Nexpose":{
        "AssetTag":[
                {
                    "CreatedTime": "2023-00-00T00:00:00.000Z",
                    "Name": "Low",
                    "RiskModifier": "0.75",
                    "Type": "criticality"
                },
                {
                    "CreatedTime": "2023-00-00T00:00:00.000Z",
                    "Name": "FAKELOCATION",
                    "RiskModifier": null,
                    "Type": "location"
                },
                {
                    "CreatedTime": "2023-00-00T00:00:00.000Z",
                    "Name": "FAKEOWNER",
                    "RiskModifier": null,
                    "Type": "owner"
                },
                {
                    "CreatedTime": "2023-00-00T00:00:00.000Z",
                    "Name": "AWS",
                    "RiskModifier": null,
                    "Type": "custom"
                }
            ]
    }
}
```

#### Human Readable Output

> ### Nexpose Asset Tags for Asset 1
>
> |Type|Name|Risk Modifier|Created Time|
> |---|---|---|---|
> | criticality | Low | 0.75 | 2023-00-00T00:00:00.000Z |
> | location | FAKELOCATION |  | 2023-00-00T00:00:00.000Z |
> | owner | FAKEOWNER |  | 2023-00-00T00:00:00.000Z |
> | custom | AWS |  | 2023-00-00T00:00:00.000Z |

### nexpose-get-assets

***
Returns all assets for which you have access.

#### Base Command

`nexpose-get-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. Page indexing starts at 0. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ";". For example: "riskScore,DESC;hostName,ASC". | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Asset.AssetId | number | The identifier of the asset. | 
| Nexpose.Asset.Address | string | The primary IPv4 or IPv6 address of the asset. | 
| Nexpose.Asset.Name | string | The primary host name \(local or FQDN\) of the asset. | 
| Nexpose.Asset.Site | string | Asset site name. | 
| Nexpose.Asset.Exploits | number | The number of distinct exploits that can exploit any of the vulnerabilities on the asset. | 
| Nexpose.Asset.Malware | number | The number of distinct malware kits that vulnerabilities on the asset are susceptible to. | 
| Nexpose.Asset.OperatingSystem | string | Operating system of the asset. | 
| Nexpose.Asset.Vulnerabilities | number | The total number of vulnerabilities. | 
| Nexpose.Asset.RiskScore | number | The risk score \(with criticality adjustments\) of the asset. | 
| Nexpose.Asset.Assessed | boolean | Whether the asset has been assessed for vulnerabilities at least once. | 
| Nexpose.Asset.LastScanDate | date | Last scan date of the asset. | 
| Nexpose.Asset.LastScanId | number | Id of the asset's last scan. | 
| Endpoint.IP | string | Endpoint IP address. | 
| Endpoint.HostName | string | Endpoint host name. | 
| Endpoint.OS | string | Endpoint operating system. | 

#### Command example
```!nexpose-get-assets limit=3```
#### Context Example
```json
{
    "Endpoint": [
        {
            "Hostname": "pool-96-252-18-158.bstnma.fios.verizon.net",
            "ID": 9,
            "IPAddress": "192.0.2.1",
            "Vendor": "Rapid7 Nexpose"
        },
        {
            "Hostname": "angular.testsparker.com",
            "ID": 11,
            "IPAddress": "192.0.2.2",
            "OS": "Ubuntu Linux",
            "Vendor": "Rapid7 Nexpose"
        },
        {
            "ID": 12,
            "IPAddress": "192.0.2.3",
            "OS": "Microsoft Windows",
            "Vendor": "Rapid7 Nexpose"
        }
    ],
    "Nexpose": {
        "Asset": [
            {
                "Address": "192.0.2.1",
                "Assessed": true,
                "AssetId": 9,
                "Exploits": 0,
                "LastScanDate": "2020-10-01T22:37:33.710Z",
                "LastScanId": 650,
                "Malware": 0,
                "Name": "pool-96-252-18-158.bstnma.fios.verizon.net",
                "OperatingSystem": null,
                "RiskScore": 0,
                "Site": "PANW",
                "Vulnerabilities": 0
            },
            {
                "Address": "192.0.2.2",
                "Assessed": true,
                "AssetId": 11,
                "Exploits": 2,
                "LastScanDate": "2022-11-02T14:54:19.055Z",
                "LastScanId": "-",
                "Malware": 0,
                "Name": "angular.testsparker.com",
                "OperatingSystem": "Ubuntu Linux",
                "RiskScore": 7718.4091796875,
                "Site": "PANW",
                "Vulnerabilities": 26
            },
            {
                "Address": "192.0.2.3",
                "Assessed": true,
                "AssetId": 12,
                "Exploits": 4,
                "LastScanDate": "2049-03-01T04:31:56Z",
                "LastScanId": "-",
                "Malware": 0,
                "Name": null,
                "OperatingSystem": "Microsoft Windows",
                "RiskScore": 18819.919921875,
                "Site": "PANW",
                "Vulnerabilities": 45
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Asset 12
>|AssetId|Address|Site|Exploits|Malware|OperatingSystem|Vulnerabilities|RiskScore|Assessed|LastScanDate|LastScanId|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 12 | 192.0.2.3 | PANW | 4 | 0 | Microsoft Windows | 45 | 18819.919921875 | true | 2049-03-01T04:31:56Z | - |


### nexpose-search-assets

***
Search and return all assets matching specific filters. Returns only assets the user has access to.

#### Base Command

`nexpose-search-assets`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Queries to use as a filter, according to the Search Criteria API standard. Multiple queries can be specified, separated by a ";" separator. For example: "ip-address in-range 192.0.2.0,192.0.2.1;host-name is myhost". For more information regarding Search Criteria, refer to https://help.rapid7.com/insightvm/en-us/api/index.html#section/Overview/Responses. | Optional | 
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. Page indexing starts at 0. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ";" separator. For example: "riskScore,DESC;hostName,ASC". | Optional | 
| ipAddressIs | A specific IP address to search. | Optional | 
| hostNameIs | A specific host name to search. | Optional | 
| riskScoreHigherThan | A minimum risk score to use as a filter. | Optional | 
| vulnerabilityTitleContains | A string to search for in vulnerabilities titles. | Optional | 
| siteIdIn | Site IDs to filter for. Can be a comma-separated list. | Optional | 
| siteNameIn | Site names to filter for. Can be a comma-separated list. | Optional | 
| match | Operator to determine how to match filters. "all" requires that all filters match for an asset to be included. "any" requires only one filter to match for an asset to be included. Possible values are: all, any. Default is all. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Asset.AssetId | number | The identifier of the asset. | 
| Nexpose.Asset.Address | string | The primary IPv4 or IPv6 address of the asset. | 
| Nexpose.Asset.Name | string | The primary host name \(local or FQDN\) of the asset. | 
| Nexpose.Asset.Site | string | Asset site name. | 
| Nexpose.Asset.Exploits | number | The number of distinct exploits that can exploit any of the vulnerabilities on the asset. | 
| Nexpose.Asset.Malware | number | The number of distinct malware kits that vulnerabilities on the asset are susceptible to. | 
| Nexpose.Asset.OperatingSystem | string | Operating system of the asset. | 
| Nexpose.Asset.Vulnerabilities | number | The total number of vulnerabilities. | 
| Nexpose.Asset.RiskScore | number | The risk score \(with criticality adjustments\) of the asset. | 
| Nexpose.Asset.Assessed | boolean | Whether the asset has been assessed for vulnerabilities at least once. | 
| Nexpose.Asset.LastScanDate | date | Last scan date of the asset. | 
| Nexpose.Asset.LastScanId | number | Id of the asset's last scan. | 
| Endpoint.IP | string | Endpoint IP address. | 
| Endpoint.HostName | string | Endpoint host name. | 
| Endpoint.OS | string | Endpoint operating system. | 

#### Command example
```!nexpose-search-assets match=all riskScoreHigherThan=1000 limit=3```
#### Context Example
```json
{
    "Endpoint": [
        {
            "Hostname": "angular.testsparker.com",
            "ID": 11,
            "IPAddress": "192.0.2.2",
            "OS": "Ubuntu Linux",
            "Vendor": "Rapid7 Nexpose"
        },
        {
            "ID": 12,
            "IPAddress": "192.0.2.3",
            "OS": "Microsoft Windows",
            "Vendor": "Rapid7 Nexpose"
        },
        {
            "Hostname": "57.27.185.35.bc.googleusercontent.com",
            "ID": 13,
            "IPAddress": "192.0.2.4",
            "OS": "Linux 2.6.18",
            "Vendor": "Rapid7 Nexpose"
        }
    ],
    "Nexpose": {
        "Asset": [
            {
                "Address": "192.0.2.2",
                "Assessed": true,
                "AssetId": 11,
                "Exploits": 2,
                "LastScanDate": "2022-11-02T14:54:19.055Z",
                "LastScanId": "-",
                "Malware": 0,
                "Name": "angular.testsparker.com",
                "OperatingSystem": "Ubuntu Linux",
                "RiskScore": 7718.4091796875,
                "Site": "PANW",
                "Vulnerabilities": 26
            },
            {
                "Address": "192.0.2.3",
                "Assessed": true,
                "AssetId": 12,
                "Exploits": 4,
                "LastScanDate": "2049-03-01T04:31:56Z",
                "LastScanId": "-",
                "Malware": 0,
                "Name": null,
                "OperatingSystem": "Microsoft Windows",
                "RiskScore": 18819.919921875,
                "Site": "PANW",
                "Vulnerabilities": 45
            },
            {
                "Address": "192.0.2.4",
                "Assessed": true,
                "AssetId": 13,
                "Exploits": 0,
                "LastScanDate": "2022-11-15T11:53:25.281Z",
                "LastScanId": "-",
                "Malware": 0,
                "Name": "57.27.185.35.bc.googleusercontent.com",
                "OperatingSystem": "Linux 2.6.18",
                "RiskScore": 1323.0916748046875,
                "Site": "PANW",
                "Vulnerabilities": 2
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Asset 13
>|AssetId|Address|Name|Site|Exploits|Malware|OperatingSystem|RiskScore|Assessed|LastScanDate|LastScanId|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 13 | 192.0.2.4 | 57.27.185.35.bc.googleusercontent.com | PANW | 0 | 0 | Linux 2.6.18 | 1323.0916748046875 | true | 2022-11-15T11:53:25.281Z | - |


### nexpose-get-scan

***
Get a specific scan.

#### Base Command

`nexpose-get-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a specific scan to retrieve. Can be a comma-separated list. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | string | The name of the user who started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Vulnerabilities.Critical | number | The number of critical vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Moderate | number | The number of moderate vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Severe | number | The number of severe vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Total | number | The total number of vulnerabilities. | 

#### Command example
```!nexpose-get-scan id=1```
#### Context Example
```json
{
    "Nexpose": {
        "Scan": {
            "Assets": 0,
            "Completed": "2019-12-03T20:48:01.368Z",
            "Id": 1,
            "Message": null,
            "ScanName": "Tue 03 Dec 2019 10:47 PM",
            "ScanType": "Manual",
            "StartedBy": null,
            "Status": "finished",
            "TotalTime": "51.316 seconds",
            "Vulnerabilities": {
                "Critical": 0,
                "Moderate": 0,
                "Severe": 0,
                "Total": 0
            }
        }
    }
}
```

#### Human Readable Output

>### Nexpose Scan ID 1
>|Id|ScanType|ScanName|Assets|TotalTime|Completed|Status|
>|---|---|---|---|---|---|---|
>| 1 | Manual | Tue 03 Dec 2019 10:47 PM | 0 | 51.316 seconds | 2019-12-03T20:48:01.368Z | finished |
>### Vulnerabilities
>|Critical|Severe|Moderate|Total|
>|---|---|---|---|
>| 0 | 0 | 0 | 0 |


### nexpose-get-asset-vulnerability

***
Returns details and possible remediations for an asset's vulnerability.

#### Base Command

`nexpose-get-asset-vulnerability`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of an asset to search for the vulnerability. | Required | 
| vulnerabilityId | ID of a vulnerability to search for. Example: 7-zip-cve-2008-6536. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Asset.AssetId | number | Identifier of the asset. | 
| Nexpose.Asset.Vulnerability.Id | number | The identifier of the vulnerability. | 
| Nexpose.Asset.Vulnerability.Title | string | The title \(summary\) of the vulnerability. | 
| Nexpose.Asset.Vulnerability.Severity | string | The severity of the vulnerability, one of: "Moderate", "Severe", "Critical". | 
| Nexpose.Asset.Vulnerability.RiskScore | number | The risk score of the vulnerability, rounded to a maximum of to digits of precision. If using the default Rapid7 Real Risk™ model, this value ranges from 0-1000. | 
| Nexpose.Asset.Vulnerability.CVSS | string | The CVSS vector\(s\) for the vulnerability. | 
| Nexpose.Asset.Vulnerability.CVSSV3 | string | The CVSS v3 vector. | 
| Nexpose.Asset.Vulnerability.Published | date | The date the vulnerability was first published or announced. The format is an ISO 8601 date, YYYY-MM-DD. | 
| Nexpose.Asset.Vulnerability.Added | date | The date the vulnerability coverage was added. The format is an ISO 8601 date, YYYY-MM-DD. | 
| Nexpose.Asset.Vulnerability.Modified | date | The last date the vulnerability was modified. The format is an ISO 8601 date, YYYY-MM-DD. | 
| Nexpose.Asset.Vulnerability.CVSSScore | number | The CVSS score \(ranges from 0-10\). | 
| Nexpose.Asset.Vulnerability.CVSSV3Score | number | The CVSS3 score, which ranges from 0-10. | 
| Nexpose.Asset.Vulnerability.Categories | unknown | All vulnerability categories assigned to this vulnerability. | 
| Nexpose.Asset.Vulnerability.CVES | unknown | All CVEs assigned to this vulnerability. | 
| Nexpose.Asset.Vulnerability.Check.Port | number | The port of the service the result was discovered on. | 
| Nexpose.Asset.Vulnerability.Check.Protocol | string | The protocol of the service the result was discovered on, valid values ip, icmp, igmp, ggp, tcp, pup, udp, idp, esp, nd, raw | 
| Nexpose.Asset.Vulnerability.Check.Since | date | The date and time the result was first recorded, in the ISO8601 format. If the result changes status this value is the date and time of the status change. | 
| Nexpose.Asset.Vulnerability.Check.Proof | string | The proof explaining why the result was found vulnerable. | 
| Nexpose.Asset.Vulnerability.Check.Status | string | The status of the vulnerability check result. Valid values are, unknown, not-vulnerable, vulnerable, vulnerable-version, vulnerable-potential, vulnerable-with-exception-applied, vulnerable-version-with-exception-applied, vulnerable-potential-with-exception-applied | 
| Nexpose.Asset.Vulnerability.Solution.Type | string | The type of the solution. One of: "Configuration", "Rollup patch", "Patch". | 
| Nexpose.Asset.Vulnerability.Solution.Summary | string | The summary of the solution. | 
| Nexpose.Asset.Vulnerability.Solution.Steps | string | The steps required to remediate the vulnerability. | 
| Nexpose.Asset.Vulnerability.Solution.Estimate | string | The estimated duration to apply the solution, in minutes. | 
| Nexpose.Asset.Vulnerability.Solution.AdditionalInformation | string | Additional information or resources that can assist in applying the remediation | 
| CVE.ID | string | Common Vulnerabilities and Exposures IDs. | 

#### Command example
```!nexpose-get-asset-vulnerability id=1 vulnerabilityId=apache-httpd-cve-2017-15710```
#### Context Example
```json
{
    "CVE": {
        "CVSS": {
            "Score": 7.5,
            "Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "Version": "3"
        },
        "Description": "The affected asset is vulnerable to this vulnerability ONLY if it is running one of the following modules: mod_authnz_ldap. Review your web server configuration for validation. mod_authnz_ldap, if configured with AuthLDAPCharsetConfig, uses the Accept-Language header value to lookup the right charset encoding when verifying the user's credentials. If the header value is not present in the charset conversion table, a fallback mechanism is used to truncate it to a two characters value to allow a quick retry (for example, 'en-US' is truncated to 'en'). A header value of less than two characters forces an out of bound write of one NUL byte to a memory location that is not part of the string. In the worst case, quite unlikely, the process would crash which could be used as a Denial of Service attack. In the more likely case, this memory is already reserved for future use and the issue has no effect at all.",
        "ID": "CVE-2017-15710",
        "Modified": "2020-01-30",
        "Published": "2018-03-26"
    },
    "DBotScore": {
        "Indicator": "CVE-2017-15710",
        "Score": 0,
        "Type": "cve",
        "Vendor": "Rapid7 Nexpose"
    },
    "Nexpose": {
        "Asset": {
            "AssetId": "1",
            "Vulnerability": [
                {
                    "Added": "2018-03-26",
                    "CVES": [
                        "CVE-2017-15710"
                    ],
                    "CVSS": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                    "CVSSScore": 5,
                    "CVSSV3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    "CVSSV3Score": 7.5,
                    "Categories": [
                        "Apache",
                        "Apache HTTP Server",
                        "Denial of Service",
                        "LDAP",
                        "Web"
                    ],
                    "Check": [
                        {
                            "Port": 80,
                            "Proof": "Running HTTP serviceProduct HTTPD exists -- Apache HTTPD 2.4.29Vulnerable version of product HTTPD found -- Apache HTTPD 2.4.29",
                            "Protocol": "tcp",
                            "Since": "2020-10-01T22:40:08.844Z",
                            "Status": "vulnerable-version"
                        },
                        {
                            "Port": 8000,
                            "Proof": "Running HTTP serviceProduct HTTPD exists -- Apache HTTPD 2.4.29Vulnerable version of product HTTPD found -- Apache HTTPD 2.4.29",
                            "Protocol": "tcp",
                            "Since": "2020-10-01T22:40:08.844Z",
                            "Status": "vulnerable-version"
                        }
                    ],
                    "Id": "apache-httpd-cve-2017-15710",
                    "Modified": "2020-01-30",
                    "Published": "2018-03-26",
                    "RiskScore": 175.22,
                    "Severity": "Severe",
                    "Solution": [
                        {
                            "AdditionalInformation": "The latest version of Apache HTTPD is 2.4.48.\n\nMany platforms and distributions provide pre-built binary packages for Apache HTTP server. These pre-built packages are usually customized and optimized for a particular distribution, therefore we recommend that you use the packages if they are available for your operating system.",
                            "Estimate": "2 hours",
                            "Steps": "Download and apply the upgrade from: http://archive.apache.org/dist/httpd/httpd-2.4.48.tar.gz (http://archive.apache.org/dist/httpd/httpd-2.4.48.tar.gz)",
                            "Summary": "Upgrade to the latest version of Apache HTTPD",
                            "Type": "rollup-patch"
                        }
                    ],
                    "Title": "Apache HTTPD: Out of bound write in mod_authnz_ldap when using too small Accept-Language values (CVE-2017-15710)"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Vulnerability apache-httpd-cve-2017-15710
>|Id|Title|Severity|RiskScore|CVSS|CVSSV3|Published|Added|Modified|CVSSScore|CVSSV3Score|Categories|CVES|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| apache-httpd-cve-2017-15710 | Apache HTTPD: Out of bound write in mod_authnz_ldap when using too small Accept-Language values (CVE-2017-15710) | Severe | 175.22 | AV:N/AC:L/Au:N/C:N/I:N/A:P | CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | 2018-03-26 | 2018-03-26 | 2020-01-30 | 5.0 | 7.5 | Apache,<br/>Apache HTTP Server,<br/>Denial of Service,<br/>LDAP,<br/>Web | CVE-2017-15710 |
>### Checks
>|Port|Protocol|Since|Proof|Status|
>|---|---|---|---|---|
>| 80 | tcp | 2020-10-01T22:40:08.844Z | Running HTTP serviceProduct HTTPD exists -- Apache HTTPD 2.4.29Vulnerable version of product HTTPD found -- Apache HTTPD 2.4.29 | vulnerable-version |
>| 8000 | tcp | 2020-10-01T22:40:08.844Z | Running HTTP serviceProduct HTTPD exists -- Apache HTTPD 2.4.29Vulnerable version of product HTTPD found -- Apache HTTPD 2.4.29 | vulnerable-version |
>### Solutions
>|Type|Summary|Steps|Estimate|AdditionalInformation|
>|---|---|---|---|---|
>| rollup-patch | Upgrade to the latest version of Apache HTTPD | Download and apply the upgrade from: http:<span>//</span>archive.apache.org/dist/httpd/httpd-2.4.48.tar.gz (http:<span>//</span>archive.apache.org/dist/httpd/httpd-2.4.48.tar.gz) | 2 hours | The latest version of Apache HTTPD is 2.4.48.<br/><br/>Many platforms and distributions provide pre-built binary packages for Apache HTTP server. These pre-built packages are usually customized and optimized for a particular distribution, therefore we recommend that you use the packages if they are available for your operating system. |


### nexpose-create-shared-credential

***
Create a new shared credential. For detailed explanation of all parameters of this command, see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSharedCredential

#### Base Command

`nexpose-create-shared-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the credential. | Required | 
| site_assignment | Site assignment configuration for the credential. Assign the shared scan credential either to be available to all sites, or a specific list of sites. Possible values are: All-Sites, Specific-Sites. | Required | 
| service | Credential service type. Possible values are: AS400, CIFS, CIFSHash, CVS, DB2, FTP, HTTP, MS-SQL, MySQL, Notes, Oracle, POP, PostgresSQL, Remote-Exec, SNMP, SNMPv3, SSH, SSH-Key, Sybase, Telnet. | Required | 
| database | Database name. | Optional | 
| description | Description for the credential. | Optional | 
| domain | Domain address. | Optional | 
| host_restriction | Hostname or IP address to restrict the credentials to. | Optional | 
| http_realm | HTTP realm. | Optional | 
| notes_id_password | Password for the notes account that will be used for authenticating. | Optional | 
| ntlm_hash | NTLM password hash. | Optional | 
| oracle_enumerate_sids | Whether the scan engine should attempt to enumerate SIDs from the environment. Possible values are: true, false. | Optional | 
| oracle_listener_password | Oracle Net Listener password. Used to enumerate SIDs from your environment. | Optional | 
| oracle_sid | Oracle database name. | Optional | 
| password | Password for the credential. | Optional | 
| port_restriction | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if `host_restriction` is used. | Optional | 
| sites | List of site IDs for the shared credential that are explicitly assigned access to the shared scan credential, allowing it to use the credential during a scan. | Optional | 
| community_name | SNMP community for authentication. | Optional | 
| authentication_type | SNMPv3 authentication type for the credential. Possible values are: No-Authentication, MD5, SHA. | Optional | 
| privacy_password | SNMPv3 privacy password to use. | Optional | 
| privacy_type | SNMPv3 Privacy protocol to use. Possible values are: No-Privacy, DES, AES-128, AES-192, AES-192-With-3-DES-Key-Extension, AES-256, AES-256-With-3-DES-Key-Extension. | Optional | 
| ssh_key_pem | PEM formatted private key. | Optional | 
| ssh_permission_elevation | Elevation type to use for scans. Possible values are: None, sudo, sudosu, su, pbrun, Privileged-Exec. | Optional | 
| ssh_permission_elevation_password | Password to use for elevation. | Optional | 
| ssh_permission_elevation_username | Username to use for elevation. | Optional | 
| ssh_private_key_password | Password for the private key. | Optional | 
| use_windows_authentication | Whether to use Windows authentication. Possible values are: true, false. | Optional | 
| username | Username for the credential. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.SharedCredential.id | number | ID of the generated credential. | 

### nexpose-create-site

***
Creates a new site with the specified configuration.

#### Base Command

`nexpose-create-site`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Site name. Must be unique. | Required | 
| description | Site's description. | Optional | 
| assets | Addresses of assets to include in site scans. Can be a comma-separated list. | Required | 
| scanTemplateId | ID of a scan template to use. If not specified, the default scan template will be used. Use `nexpose-get-report-templates` to get a list of all available templates. | Optional | 
| importance | Site importance. Defaults to "normal" if not specified. Possible values are: very_low, low, normal, high, very_high. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Site.Id | number | ID of the created site. | 

### nexpose-create-vulnerability-exception

***
Create a new vulnerability exception.

#### Base Command

`nexpose-create-vulnerability-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| expires | The date and time the vulnerability exception is set to expire in ISO 8601 date format. | Optional | 
| vulnerability_id | ID of the vulnerability to create the exception for. Example: 7-zip-cve-2008-6536. | Required | 
| scope_type | The type of the exception scope. If set to anything other than `Global`, `scope_id` parameter is required. Possible values are: Global, Site, Asset, Asset Group. | Required | 
| state | State of the vulnerability exception. Possible values are: Expired, Approved, Rejected, Under Review. | Required | 
| comment | A comment from the submitter as to why the exception was submitted. | Optional | 
| reason | Reason why the vulnerability exception was submitted. Possible values are: False Positive, Compensating Control, Acceptable Use, Acceptable Risk, Other. | Required | 
| scope_id | ID of the chosen `scope_type` (site ID, asset ID, etc.). Required if `scope_type` is anything other than `Global`. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.VulnerabilityException.id | number | ID of the generated vulnerability exception. | 

### nexpose-delete-asset

***
Delete an asset.

#### Base Command

`nexpose-delete-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the asset to delete. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!nexpose-delete-asset id=1```
#### Human Readable Output

>Asset 1 has been deleted.

### nexpose-delete-scan-schedule

***
Delete a scheduled scan.

#### Base Command

`nexpose-delete-scan-schedule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site to delete. | Optional | 
| site_name | Name of the site to delete (can be used instead of `site_id`). | Optional | 
| schedule_id | ID of the scheduled scan to delete. | Required | 

#### Context Output

There is no context output for this command.
### nexpose-delete-shared-credential

***
> **Note:**
> This command couldn't have been tested on our side, and therefore could have issues. Please let us know if you encounter any bugs or issues.

Delete a shared credential.

#### Base Command

`nexpose-delete-shared-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the shared credential to delete. | Required | 

#### Context Output

There is no context output for this command.
### nexpose-delete-site-scan-credential

***
> **Note:**
> This command couldn't have been tested on our side, and therefore could have issues. Please let us know if you encounter any bugs or issues.

Delete a site scan credential.

#### Base Command

`nexpose-delete-site-scan-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| credential_id | ID of the site scan credential to delete. | Required | 

#### Context Output

There is no context output for this command.
### nexpose-delete-site

***
Deletes a site.

#### Base Command

`nexpose-delete-site`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a site to delete. | Optional | 
| site_name | Name of the site to delete (can be used instead of `site_id`). | Optional | 

#### Context Output

There is no context output for this command.
### nexpose-delete-vulnerability-exception

***
Delete a vulnerability exception.

#### Base Command

`nexpose-delete-vulnerability-exception`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the vulnerability exception to delete. | Required | 


#### Command example
```!nexpose-delete-vulnerability-exception id=1```
#### Human Readable Output

>Vulnerability exception with ID 1 has been deleted.

### nexpose-get-sites

***
Retrieves accessible sites.

#### Base Command

`nexpose-get-sites`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. Page indexing starts at 0. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ";". For example: "riskScore,DESC;hostName,ASC". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Site.Id | number | The identifier of the site. | 
| Nexpose.Site.Name | string | The site name. | 
| Nexpose.Site.Assets | number | The number of assets that belong to the site. | 
| Nexpose.Site.Type | string | The type of the site. Valid values are agent, dynamic, static | 
| Nexpose.Site.Vulnerabilities | number | The total number of vulnerabilities. | 
| Nexpose.Site.Risk | number | The risk score \(with criticality adjustments\) of the site. | 
| Nexpose.Site.LastScan | date | The date and time of the site's last scan. | 

#### Command example
```!nexpose-get-sites limit=5```
#### Context Example
```json
{
    "Nexpose": {
        "Site": [
            {
                "Assets": 4,
                "Id": 1,
                "LastScan": "2021-08-03T14:09:15.321Z",
                "Name": "Authenticated-Assets",
                "Risk": 20416,
                "Type": "static",
                "Vulnerabilities": 41
            },
            {
                "Assets": 18,
                "Id": 2,
                "LastScan": "2021-06-29T07:06:54.733Z",
                "Name": "PANW",
                "Risk": 213245,
                "Type": "static",
                "Vulnerabilities": 455
            },
            {
                "Assets": 10,
                "Id": 3,
                "LastScan": "2020-11-26T17:13:54.117Z",
                "Name": "Test",
                "Risk": 18820,
                "Type": "static",
                "Vulnerabilities": 45
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Sites
>| Id  |Name|Assets|Vulnerabilities|Risk|Type|LastScan|
-----|---|---|---|---|---|---|---|
>| 1   | Authenticated-Assets | 4 | 41 | 20416.0 | static | 2021-08-03T14:09:15.321Z |
>| 2 | PANW | 18 | 455 | 213245.0 | static | 2021-06-29T07:06:54.733Z |
>| 3   | Test | 10 | 45 | 18820.0 | static | 2020-11-26T17:13:54.117Z |


### nexpose-get-report-templates

***
Returns all available report templates.

#### Base Command

`nexpose-get-report-templates`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Template.Id | number | The identifier of the report template. | 
| Nexpose.Template.Name | string | The name of the report template. | 
| Nexpose.Template.Description | string | The description of the report template. | 
| Nexpose.Template.Type | string | The type of the report template. document is a templatized, typically printable, report that has various sections of content. export is data-oriented output, typically CSV. file is a printable report template using a report template file. | 

#### Command example
```!nexpose-get-report-templates```
#### Context Example
```json
{
    "Nexpose": {
        "Template": [
            {
                "Description": "Provides comprehensive details about discovered assets, vulnerabilities, and users.",
                "Id": "audit-report",
                "Name": "Audit Report",
                "Type": "document"
            },
            {
                "Description": "Compares current scan results to those of an earlier baseline scan.",
                "Id": "baseline-comparison",
                "Name": "Baseline Comparison",
                "Type": "document"
            },
            {
                "Description": "Provides a high-level view of security data, including general results information and statistical charts.",
                "Id": "executive-overview",
                "Name": "Executive Overview",
                "Type": "document"
            },
            {
                "Description": "Provides information and metrics about 10 discovered vulnerabilities with the highest risk scores.",
                "Id": "highest-risk-vulns",
                "Name": "Highest Risk Vulnerabilities",
                "Type": "document"
            },
            {
                "Description": "Lists results for standard policy scans (AS/400, Oracle, Domino, Windows Group, CIFS/SMB account). Does not include Policy Manager results.",
                "Id": "policy-eval",
                "Name": "Policy Evaluation",
                "Type": "document"
            },
            {
                "Description": "Provides detailed remediation instructions for each discovered vulnerability.",
                "Id": "remediation-plan",
                "Name": "Remediation Plan",
                "Type": "document"
            },
            {
                "Description": "Lists test results for each discovered vulnerability, including how it was verified.",
                "Id": "report-card",
                "Name": "Report Card",
                "Type": "document"
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Templates
>|Id|Name|Description|Type|
>|---|---|---|---|
>| audit-report | Audit Report | Provides comprehensive details about discovered assets, vulnerabilities, and users. | document |
>| baseline-comparison | Baseline Comparison | Compares current scan results to those of an earlier baseline scan. | document |
>| executive-overview | Executive Overview | Provides a high-level view of security data, including general results information and statistical charts. | document |
>| highest-risk-vulns | Highest Risk Vulnerabilities | Provides information and metrics about 10 discovered vulnerabilities with the highest risk scores. | document |
>| policy-eval | Policy Evaluation | Lists results for standard policy scans (AS/400, Oracle, Domino, Windows Group, CIFS/SMB account). Does not include Policy Manager results. | document |
>| remediation-plan | Remediation Plan | Provides detailed remediation instructions for each discovered vulnerability. | document |
>| report-card | Report Card | Lists test results for each discovered vulnerability, including how it was verified. | document |


### nexpose-create-asset

***
Create a new asset.

#### Base Command

`nexpose-create-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| date | The date the data was collected on the asset in ISO 8601 format. | Required | 
| ip | Primary IPv4 or IPv6 address of the asset. | Required | 
| host_name | Hostname of the asset. | Optional | 
| host_name_source | The source used to detect the host name. "User" indicates the host name source is user-supplied. Possible values are: User, DNS, NetBIOS, DCE, EPSEC, LDAP, Other. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Asset.id | string | ID of the newly created asset. | 

#### Command example
```!nexpose-create-asset site_id="1" date="2022-01-01T10:00:00Z" ip="192.0.2.0"```
#### Context Example
```json
{
    "Nexpose": {
        "Asset": {
            "id": 1
        }
    }
}
```

#### Human Readable Output

>New asset has been created with ID 1.

### nexpose-create-assets-report

***
Generates a new report on given assets according to a template and arguments.

#### Base Command

`nexpose-create-assets-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assets | Asset IDs to create the report on. Can be a comma-separated list. | Required | 
| template | Report template ID to create the report with. If not provided, the first available template will be used. | Optional | 
| name | Report name. | Optional | 
| format | Report format (uses PDF by default). Possible values are: pdf, rtf, xml, html, text. | Optional | 
| download_immediately | Whether to download the report immediately after the report is generated. Defaults to "true". If the report takes longer than 10 seconds to generate, set to "false". Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry ID of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Extension | string | File extension of the report file. | 
| InfoFile.Info | string | Information about the report file. | 
| InfoFile.Size | number | Size of the report file \(in bytes\). | 
| InfoFile.Type | string | Type of the report file. | 
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Name | string | The report name. | 
| Nexpose.Report.Format | string | The report format. | 

### nexpose-create-sites-report

***
Generates a new report on given sites according to a template and arguments.

#### Base Command

`nexpose-create-sites-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sites | Site IDs to create the report on. Can be a comma-separated list. | Optional | 
| site_names | Names of sites to create the report on. Can be a comma-separated list. | Optional | 
| template | Report template ID to use for report's creation. If not provided, the first available template will be used. | Optional | 
| name | Report name. | Optional | 
| format | Report format (uses PDF by default). Possible values are: pdf, rtf, xml, html, text. | Optional | 
| download_immediately | If true, downloads the report immediately after the report is generated. The default is "true". If the report takes longer than 10 seconds to generate, set to "false". Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry ID of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Extension | string | File extension of the report file. | 
| InfoFile.Info | string | Info about the report file. | 
| InfoFile.Size | number | Size of the report file. | 
| InfoFile.Type | string | Type of the report file. | 
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Name | string | The report name. | 
| Nexpose.Report.Format | string | The report format. | 

### nexpose-create-site-scan-credential

***
> **Note:**
> This command couldn't have been tested on our side, and therefore could have issues. Please let us know if you encounter any bugs or issues.

Create a new site scan credential. For detailed explanation of all parameters of this command, see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/createSiteCredential

#### Base Command

`nexpose-create-site-scan-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| name | Name of the credential. | Required | 
| service | Credential service type. Possible values are: AS400, CIFS, CIFSHash, CVS, DB2, FTP, HTTP, MS-SQL, MySQL, Notes, Oracle, POP, PostgresSQL, Remote-Exec, SNMP, SNMPv3, SSH, SSH-Key, Sybase, Telnet. | Required | 
| database | Database name. | Optional | 
| description | Description for the credential. | Optional | 
| domain | Domain address. | Optional | 
| host_restriction | Hostname or IP address to restrict the credentials to. | Optional | 
| http_realm | HTTP realm. | Optional | 
| notes_id_password | Password for the notes account that will be used for authenticating. | Optional | 
| ntlm_hash | NTLM password hash. | Optional | 
| oracle_enumerate_sids | Whether the scan engine should attempt to enumerate SIDs from the environment. Possible values are: true, false. | Optional | 
| oracle_listener_password | Oracle Net Listener password. Used to enumerate SIDs from your environment. | Optional | 
| oracle_sid | Oracle database name. | Optional | 
| password | Password for the credential. | Optional | 
| port_restriction | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if `host_restriction` is used. | Optional | 
| community_name | SNMP community for authentication. | Optional | 
| authentication_type | SNMPv3 authentication type for the credential. Possible values are: No-Authentication, MD5, SHA. | Optional | 
| privacy_password | SNMPv3 privacy password to use. | Optional | 
| privacy_type | SNMPv3 privacy protocol to use. Possible values are: No-Privacy, DES, AES-128, AES-192, AES-192-With-3-DES-Key-Extension, AES-256, AES-256-With-3-DES-Key-Extension. | Optional | 
| ssh_key_pem | PEM formatted private key. | Optional | 
| ssh_permission_elevation | Elevation type to use for scans. Possible values are: None, sudo, sudosu, su, pbrun, Privileged-Exec. | Optional | 
| ssh_permission_elevation_password | Password to use for elevation. | Optional | 
| ssh_permission_elevation_username | Username to use for elevation. | Optional | 
| ssh_private_key_password | Password for the private key. | Optional | 
| use_windows_authentication | Whether to use Windows authentication. Possible values are: true, false. | Optional | 
| username | Username for the credential. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.SiteScanCredential.id | number | ID of the generated credential. | 

### nexpose-create-scan-report

***
Generates a new report for a specified scan.

#### Base Command

`nexpose-create-scan-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan | ID of the scan to create a report about. | Required | 
| template | Report template ID to use for creation. If not provided, the first available template will be used. | Optional | 
| name | Report name. | Optional | 
| format | Report format (uses PDF by default). Possible values are: pdf, rtf, xml, html, text. | Optional | 
| download_immediately | If true, downloads the report immediately after the report is generated. The default is "true". If the report takes longer than 10 seconds to generate, set to "false". Possible values are: true, false. Default is true. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry ID of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Extension | string | File extension of the report file. | 
| InfoFile.Info | string | Info about the report file. | 
| InfoFile.Size | number | Size of the report file. | 
| InfoFile.Type | string | Type of the report file. | 
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Name | string | The report name. | 
| Nexpose.Report.Format | string | The report format. | 

#### Command example
```!nexpose-create-scan-report scan=1 download_immediately=false```
#### Context Example
```json
{
    "Nexpose": {
        "Report": {
            "Format": "pdf",
            "ID": 3241,
            "InstanceID": 3212,
            "Name": "report 2022-11-30 09:25:36.359529"
        }
    }
}
```

#### Human Readable Output

>### Report Information
>|Format|ID|InstanceID|Name|
>|---|---|---|---|
>| pdf | 3241 | 3212 | report 2022-11-30 09:25:36.359529 |


### nexpose-create-scan-schedule

***
> **Note:**
> This command couldn't have been tested on our side, and therefore could have issues. Please let us know if you encounter any bugs or issues.

Create a new site scan schedule.

#### Base Command

`nexpose-create-scan-schedule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| enabled | Whether to enable the scheduled scan after creation. Possible values are: True, False. Default is True. | Optional | 
| on_scan_repeat | The desired behavior of a repeating scheduled scan when the previous scan was paused due to reaching its maximum duration. Possible values are: Restart-Scan, Resume-Scan. | Required | 
| start | The scheduled start date and time formatted in ISO 8601 format. Repeating schedules will determine the next schedule to begin based on this date and time. | Required | 
| excluded_asset_group_ids | A list of IDs for asset groups to exclude from the scan. | Optional | 
| excluded_addresses | A list of addresses to exclude from the scan. | Optional | 
| included_asset_group_ids | A list of IDs for asset groups to include in the scan. | Optional | 
| included_addresses | A list of addresses to include in the scan. | Optional | 
| duration_days | Maximum duration of the scan in days. | Optional | 
| duration_hours | Maximum duration of the scan in hours. | Optional | 
| duration_minutes | Maximum duration of the scan in minutes. | Optional | 
| frequency | How frequently the schedule should repeat (Every...). Possible values are: Hour, Day, Week, Date-of-month. | Optional | 
| interval_time | The interval time the schedule should repeat. This depends on the value set in `frequency`. For example, if the value of `frequency` is set to "Day" and `interval` is set to 2, then the schedule will repeat every 2 days. Required only if frequency is used. | Optional | 
| date_of_month | Specifies the schedule repeat day of the interval month. For example, if `date_of_month` is 17 and `interval` is set to 2, then the schedule will repeat every 2 months on the 17th day of the month. Required and used only if frequency is set to `Date of month`. | Optional | 
| scan_name | A unique user-defined name for the scan launched by the schedule. If not explicitly set in the schedule, the scan name will be generated prior to the scan launching. | Optional | 
| scan_template | ID of the scan template to use. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.ScanSchedule.id | int | ID of the newly created scan schedule. | 

### nexpose-list-assigned-shared-credential

***
Retrieve information about shared credentials for a specific site.

#### Base Command

`nexpose-list-assigned-shared-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| limit | The number of records to limit the response to. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.AssignedSharedCredential.enabled | string | Flag indicating whether the shared credential is enabled for the site's scans. | 
| Nexpose.AssignedSharedCredential.id | string | ID of the shared credential. | 
| Nexpose.AssignedSharedCredential.name | string | The name of the shared credential. | 
| Nexpose.AssignedSharedCredential.service | string | Credential service type. | 

#### Command example
```!nexpose-list-assigned-shared-credential site_id=1 limit=3```
#### Context Example
```json
{
    "Nexpose": {
        "AssignedSharedCredential": [
            {
                "enabled": true,
                "id": 1,
                "name": "Test 1",
                "service": "ftp"
            },
            {
                "enabled": true,
                "id": 2,
                "name": "Test 2",
                "service": "ftp"
            },
            {
                "enabled": true,
                "id": 3,
                "name": "Test 3",
                "service": "ftp"
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Assigned Shared Credentials
>| Id  |Name|Service|Enabled|
-----|---|---|---|---|
>| 1   | Test 1 | ftp | true |
>| 2  | Test 2 | ftp | true |
>| 3  | Test 3 | ftp | true |


### nexpose-list-vulnerability

***
Retrieve information about all or a specific vulnerability.

#### Base Command

`nexpose-list-vulnerability`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a specific vulnerability to retrieve. | Optional | 
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. Page indexing starts at 0. | Optional | 
| limit | The number of records to limit the response to. Default is 10. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ";". For example: "riskScore,DESC;hostName,ASC". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Vulnerability.added | string | The date the vulnerability coverage was added in ISO 8601 format. | 
| Nexpose.Vulnerability.categories | array | All vulnerability categories assigned to this vulnerability. | 
| Nexpose.Vulnerability.cves | array | All CVEs assigned to this vulnerability. | 
| Nexpose.Vulnerability.cvss.v2.accessComplexity | string | Access Complexity \(AC\) component that measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system. | 
| Nexpose.Vulnerability.cvss.v2.accessVector | string | Access Vector \(Av\) component that reflects how the vulnerability is exploited. | 
| Nexpose.Vulnerability.cvss.v2.authentication | string | Authentication \(Au\) component that measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. | 
| Nexpose.Vulnerability.cvss.v2.availabilityImpact | string | Availability Impact \(A\) component that measures the impact to availability of a successfully exploited vulnerability. | 
| Nexpose.Vulnerability.cvss.v2.confidentialityImpact | string | Confidentiality Impact \(C\) component that measures the impact on confidentiality of a successfully exploited vulnerability. | 
| Nexpose.Vulnerability.cvss.v2.exploitScore | number | The CVSS exploit score. | 
| Nexpose.Vulnerability.cvss.v2.impactScore | number | The CVSS impact score. | 
| Nexpose.Vulnerability.cvss.v2.integrityImpact | string | Integrity Impact \(I\) component that measures the impact to integrity of a successfully exploited vulnerability. | 
| Nexpose.Vulnerability.cvss.v2.score | number | The CVSS score \(ranges from 0-10\). | 
| Nexpose.Vulnerability.cvss.v2.vector | string | The CVSS v2 vector. | 
| Nexpose.Vulnerability.cvss.v3.attackComplexity | string | Access Complexity \(AC\) component that measures the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. | 
| Nexpose.Vulnerability.cvss.v3.attackVector | string | Attack Vector \(AV\) component that measures context by which vulnerability exploitation is possible. | 
| Nexpose.Vulnerability.cvss.v3.availabilityImpact | string | Availability Impact \(A\) that measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. | 
| Nexpose.Vulnerability.cvss.v3.confidentialityImpact | string | Confidentiality Impact \(C\) component that measures the impact on confidentiality of a successfully exploited vulnerability. | 
| Nexpose.Vulnerability.cvss.v3.exploitScore | number | The CVSS impact score. | 
| Nexpose.Vulnerability.cvss.v3.impactScore | number | The CVSS exploit score. | 
| Nexpose.Vulnerability.cvss.v3.integrityImpact | string | Integrity Impact \(I\) that measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. | 
| Nexpose.Vulnerability.cvss.v3.privilegeRequired | string | Privileges Required \(PR\) that measures the level of privileges an attacker must possess before successfully exploiting the vulnerability. | 
| Nexpose.Vulnerability.cvss.v3.scope | string | Scope \(S\) that measures the collection of privileges defined by a computing authority \(e.g., an application, an operating system, or a sandbox environment\) when granting access to computing resources \(e.g., files, CPU, memory, etc.\). These privileges are assigned based on some method of identification and authorization. | 
| Nexpose.Vulnerability.cvss.v3.score | number | The CVSS score \(ranges from 0-10\). | 
| Nexpose.Vulnerability.cvss.v3.userInteraction | string | User Interaction \(UI\) that measures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component. | 
| Nexpose.Vulnerability.cvss.v3.vector | string | The CVSS v3 vector. | 
| Nexpose.Vulnerability.denialOfService | boolean | Whether the vulnerability can lead to Denial of Service \(DoS\). | 
| Nexpose.Vulnerability.description.html | string | Hypertext Markup Language \(HTML\) representation of the content. | 
| Nexpose.Vulnerability.description.text | string | Textual representation of the content. | 
| Nexpose.Vulnerability.exploits | number | The exploits that can be used to exploit a vulnerability. | 
| Nexpose.Vulnerability.id | string | The identifier of the vulnerability. | 
| Nexpose.Vulnerability.malwareKits | number | The malware kits that are known to be used to exploit the vulnerability. | 
| Nexpose.Vulnerability.modified | string | The last date the vulnerability was modified in ISO 8601 format. | 
| Nexpose.Vulnerability.pci.adjustedCVSSScore | number | The CVSS score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10. | 
| Nexpose.Vulnerability.pci.adjustedSeverityScore | number | The severity score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10. | 
| Nexpose.Vulnerability.pci.fail | boolean | Whether, if present on a host, this vulnerability would cause a PCI failure. True if "status" is "Fail", false otherwise. | 
| Nexpose.Vulnerability.pci.specialNotes | string | Any special notes or remarks about the vulnerability that pertain to PCI compliance. | 
| Nexpose.Vulnerability.pci.status | string | The PCI compliance status of the vulnerability. Can be either "Pass", or "Fail". | 
| Nexpose.Vulnerability.published | string | The date the vulnerability was first published or announced in ISO 8601 format. | 
| Nexpose.Vulnerability.riskScore | number | The risk score of the vulnerability, rounded to a maximum of two digits of precision. If using the default Rapid7 Real Risk model, this value ranges from 0-1000. | 
| Nexpose.Vulnerability.severity | string | The severity of the vulnerability, can be either "Moderate", "Severe", or "Critical". | 
| Nexpose.Vulnerability.severityScore | number | The severity score of the vulnerability, on a scale of 0-10. | 
| Nexpose.Vulnerability.title | string | The title \(summary\) of the vulnerability. | 

#### Command example
```!nexpose-list-vulnerability limit=3```
#### Context Example
```json
{
    "Nexpose": {
        "Vulnerability": [
            {
                "added": "2018-05-16",
                "categories": [
                    "7-Zip"
                ],
                "cves": [
                    "CVE-2008-6536"
                ],
                "cvss": {
                    "v2": {
                        "accessComplexity": "L",
                        "accessVector": "N",
                        "authentication": "N",
                        "availabilityImpact": "C",
                        "confidentialityImpact": "C",
                        "exploitScore": 9.9968,
                        "impactScore": 10.0008,
                        "integrityImpact": "C",
                        "score": 10,
                        "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C"
                    }
                },
                "denialOfService": false,
                "description": {
                    "html": "<p>Unspecified vulnerability in 7-zip before 4.5.7 has unknown impact and remote attack vectors, as demonstrated by the PROTOS GENOME test suite for Archive Formats (c10).</p>",
                    "text": "Unspecified vulnerability in 7-zip before 4.5.7 has unknown impact and remote attack vectors, as demonstrated by the PROTOS GENOME test suite for Archive Formats (c10)."
                },
                "exploits": 0,
                "id": "7-zip-cve-2008-6536",
                "malwareKits": 0,
                "modified": "2018-06-08",
                "pci": {
                    "adjustedCVSSScore": 10,
                    "adjustedSeverityScore": 5,
                    "fail": true,
                    "status": "Fail"
                },
                "published": "2009-03-29",
                "riskScore": 898.63,
                "severity": "Critical",
                "severityScore": 10,
                "title": "7-Zip: CVE-2008-6536: Unspecified vulnerability in 7-zip before 4.5.7"
            },
            {
                "added": "2018-05-16",
                "categories": [
                    "7-Zip",
                    "Remote Execution"
                ],
                "cves": [
                    "CVE-2016-2334"
                ],
                "cvss": {
                    "v2": {
                        "accessComplexity": "M",
                        "accessVector": "N",
                        "authentication": "N",
                        "availabilityImpact": "C",
                        "confidentialityImpact": "C",
                        "exploitScore": 8.5888,
                        "impactScore": 10.0008,
                        "integrityImpact": "C",
                        "score": 9.3,
                        "vector": "AV:N/AC:M/Au:N/C:C/I:C/A:C"
                    },
                    "v3": {
                        "attackComplexity": "L",
                        "attackVector": "L",
                        "availabilityImpact": "H",
                        "confidentialityImpact": "H",
                        "exploitScore": 1.8346,
                        "impactScore": 5.8731,
                        "integrityImpact": "H",
                        "privilegeRequired": "N",
                        "scope": "U",
                        "score": 7.8,
                        "userInteraction": "R",
                        "vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
                    }
                },
                "denialOfService": false,
                "description": {
                    "html": "<p>Heap-based buffer overflow in the NArchive::NHfs::CHandler::ExtractZlibFile method in 7zip before 16.00 and p7zip allows remote attackers to execute arbitrary code via a crafted HFS+ image.</p>",
                    "text": "Heap-based buffer overflow in the NArchive::NHfs::CHandler::ExtractZlibFile method in 7zip before 16.00 and p7zip allows remote attackers to execute arbitrary code via a crafted HFS+ image."
                },
                "exploits": 0,
                "id": "7-zip-cve-2016-2334",
                "malwareKits": 0,
                "modified": "2018-06-08",
                "pci": {
                    "adjustedCVSSScore": 9,
                    "adjustedSeverityScore": 5,
                    "fail": true,
                    "status": "Fail"
                },
                "published": "2016-12-13",
                "riskScore": 717.53,
                "severity": "Critical",
                "severityScore": 9,
                "title": "7-Zip: CVE-2016-2334: Heap-based buffer overflow vulnerability"
            },
            {
                "added": "2018-05-16",
                "categories": [
                    "7-Zip",
                    "Trojan"
                ],
                "cves": [
                    "CVE-2016-7804"
                ],
                "cvss": {
                    "v2": {
                        "accessComplexity": "M",
                        "accessVector": "N",
                        "authentication": "N",
                        "availabilityImpact": "P",
                        "confidentialityImpact": "P",
                        "exploitScore": 8.5888,
                        "impactScore": 6.443,
                        "integrityImpact": "P",
                        "score": 6.8,
                        "vector": "AV:N/AC:M/Au:N/C:P/I:P/A:P"
                    },
                    "v3": {
                        "attackComplexity": "L",
                        "attackVector": "L",
                        "availabilityImpact": "H",
                        "confidentialityImpact": "H",
                        "exploitScore": 1.8346,
                        "impactScore": 5.8731,
                        "integrityImpact": "H",
                        "privilegeRequired": "N",
                        "scope": "U",
                        "score": 7.8,
                        "userInteraction": "R",
                        "vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
                    }
                },
                "denialOfService": false,
                "description": {
                    "html": "<p>Untrusted search path vulnerability in 7 Zip for Windows 16.02 and earlier allows remote attackers to gain privileges via a Trojan horse DLL in an unspecified directory.</p>",
                    "text": "Untrusted search path vulnerability in 7 Zip for Windows 16.02 and earlier allows remote attackers to gain privileges via a Trojan horse DLL in an unspecified directory."
                },
                "exploits": 0,
                "id": "7-zip-cve-2016-7804",
                "malwareKits": 0,
                "modified": "2018-06-08",
                "pci": {
                    "adjustedCVSSScore": 6,
                    "adjustedSeverityScore": 4,
                    "fail": true,
                    "specialNotes": "The presence of malware, including rootkits, backdoors, or trojan horse programs are a violation of PCI DSS, and result in an automatic failure. ",
                    "status": "Fail"
                },
                "published": "2017-05-22",
                "riskScore": 578.88,
                "severity": "Severe",
                "severityScore": 7,
                "title": "7-Zip: CVE-2016-7804: Untrusted search path vulnerability"
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Vulnerabilities
>|Title|MalwareKits|Exploits|CVSS|CVSSv3|Risk|PublishedOn|ModifiedOn|Severity|
>|---|---|---|---|---|---|---|---|---|
>| 7-Zip: CVE-2008-6536: Unspecified vulnerability in 7-zip before 4.5.7 | 0 | 0 | 10.0 |  | 898.63 | 2009-03-29 | 2018-06-08 | Critical |
>| 7-Zip: CVE-2016-2334: Heap-based buffer overflow vulnerability | 0 | 0 | 9.3 | 7.8 | 717.53 | 2016-12-13 | 2018-06-08 | Critical |
>| 7-Zip: CVE-2016-7804: Untrusted search path vulnerability | 0 | 0 | 6.8 | 7.8 | 578.88 | 2017-05-22 | 2018-06-08 | Severe |


### nexpose-list-scan-schedule

***
> **Note:**
> This command couldn't have been tested on our side, and therefore could have issues. Please let us know if you encounter any bugs or issues.

Retrieve information about scan schedules for a specific site or a specific scan schedule.

#### Base Command

`nexpose-list-scan-schedule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| schedule_id | ID of the scheduled scan (optional, will return a single specific scan if used). | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.ScanSchedule.assets.excludedAssetGroups.assetGroupIDs | array | List of asset group identifiers that will be excluded from scans. | 
| Nexpose.ScanSchedule.assets.excludedTargets.addresses | array | List of addresses that will be excluded from scans. | 
| Nexpose.ScanSchedule.assets.includedAssetGroups.assetGroupIDs | array | List of asset group identifiers that will be included in scans. | 
| Nexpose.ScanSchedule.assets.includedTargets.addresses | array | List of addresses that will be included in scans. | 
| Nexpose.ScanSchedule.duration | string | Specifies in ISO 8601 duration format the maximum duration the scheduled scan is allowed to run. | 
| Nexpose.ScanSchedule.enabled | string | Flag indicating whether the scan schedule is enabled. | 
| Nexpose.ScanSchedule.id | int | The identifier of the scan schedule. | 
| Nexpose.ScanSchedule.nextRuntimes | array | List the next 10 dates when the schedule will launch. | 
| Nexpose.ScanSchedule.onScanRepeat | string | Specifies the desired behavior of a repeating scheduled scan when the previous scan was paused due to reaching is maximum duration. | 
| Nexpose.ScanSchedule.repeat.dayOfWeek | unknown | Specifies the desired behavior of a repeating scheduled scan when the previous scan was paused due to reaching is maximum duration. | 
| Nexpose.ScanSchedule.repeat.every | unknown | The frequency in which the schedule repeats. Each value represents a different unit of time and is used in conjunction with the property interval. | 
| Nexpose.ScanSchedule.repeat.interval | unknown | The interval time the schedule should repeat. This depends on the value set in every. | 
| Nexpose.ScanSchedule.repeat.weekOfMonth | unknown | This property only applies to schedules with an every value of "day-of-month". The week of the month the scheduled task should repeat. | 
| Nexpose.ScanSchedule.repeat.scanEngineId | unknown | The identifier of the scan engine to be used for this scan schedule. If not set, the site's assigned scan engine will be used. | 
| Nexpose.ScanSchedule.repeat.scanName | unknown | A user-defined name for the scan launched by the schedule. | 
| Nexpose.ScanSchedule.repeat.scanTemplateId | unknown | The identifier of the scan template to be used for this scan schedule. If not set, the site's assigned scan template will be used. | 
| Nexpose.ScanSchedule.repeat.start | unknown | The scheduled start date and time. Repeating schedules will determine the next schedule to begin based on this date and time. | 

### nexpose-list-shared-credential

***
Retrieve information about all or a specific shared credential.

#### Base Command

`nexpose-list-shared-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a specific shared credential to retrieve. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.SharedCredential.account.authenticationType | string | SNMPv3 authentication type for the credential. | 
| Nexpose.SharedCredential.account.communityName | string | SNMP community for authentication. | 
| Nexpose.SharedCredential.account.database | string | Database name. | 
| Nexpose.SharedCredential.account.domain | string | Domain address. | 
| Nexpose.SharedCredential.account.enumerateSids | boolean | Whether the scan engine should attempt to enumerate SIDs from the environment. | 
| Nexpose.SharedCredential.account.notesIDPassword | string | Password for the notes account that will be used for authenticating. | 
| Nexpose.SharedCredential.account.ntlmHash | string | NTLM password hash. | 
| Nexpose.SharedCredential.account.oracleListenerPassword | string | The Oracle Net Listener password. Used to enumerate SIDs from the environment. | 
| Nexpose.SharedCredential.account.password | string | Password for the credential. | 
| Nexpose.SharedCredential.account.pemKey | string | PEM formatted private key. | 
| Nexpose.SharedCredential.account.permissionElevation | string | Elevation type to use for scans. | 
| Nexpose.SharedCredential.account.permissionElevationPassword | string | Password to use for elevation. | 
| Nexpose.SharedCredential.account.permissionElevationUserName | string | Username to use for elevation. | 
| Nexpose.SharedCredential.account.privacyPassword | string | SNMPv3 privacy password to use. | 
| Nexpose.SharedCredential.account.privacyType | string | SNMPv3 privacy protocol to use. | 
| Nexpose.SharedCredential.account.privateKeyPassword | string | Password for the private key. | 
| Nexpose.SharedCredential.account.realm | string | HTTP realm. | 
| Nexpose.SharedCredential.account.service | string | Credential service type. | 
| Nexpose.SharedCredential.account.sid | string | Oracle database name. | 
| Nexpose.SharedCredential.account.useWindowsAuthentication | boolean | Whether to use Windows authentication. | 
| Nexpose.SharedCredential.account.username | string | Username for the credential. | 
| Nexpose.SharedCredential.description | string | Description for the credential. | 
| Nexpose.SharedCredential.hostRestriction | string | Hostname or IP address to restrict the credentials to. | 
| Nexpose.SharedCredential.id | number | ID of the shared credential. | 
| Nexpose.SharedCredential.name | string | Name of the credential. | 
| Nexpose.SharedCredential.portRestriction | number | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if \`hostRestriction\` is used. | 
| Nexpose.SharedCredential.siteAssignment | string | Site assignment configuration for the credential. | 
| Nexpose.SharedCredential.sites | array | List of site IDs for the shared credential that are explicitly assigned access to the shared scan credential, allowing it to use the credential during a scan. | 

#### Command example
```!nexpose-list-shared-credential limit=3```
#### Context Example
```json
{
    "Nexpose": {
        "SharedCredential": [
            {
                "account": {
                    "authenticationType": "md5",
                    "privacyType": "no-privacy",
                    "service": "snmpv3",
                    "username": "test"
                },
                "id": 1,
                "name": "shared credentials",
                "siteAssignment": "specific-sites",
                "sites": [
                    1
                ]
            },
            {
                "account": {
                    "service": "as400",
                    "username": "test"
                },
                "id": 2,
                "name": "shared credentials",
                "siteAssignment": "specific-sites",
                "sites": [
                    1
                ]
            },
            {
                "account": {
                    "permissionElevation": "sudosu",
                    "permissionElevationUsername": "test",
                    "service": "ssh",
                    "username": "test"
                },
                "id": 3,
                "name": "shared credentials",
                "siteAssignment": "specific-sites",
                "sites": [
                    1
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Shared Credentials
>| Id  |Name|Service|UserName|
-----|---|---|---|---|
>| 1   | shared credentials | snmpv3 | test |
>| 2   | shared credentials | as400 | test |
>| 3   | shared credentials | ssh | test |


### nexpose-list-site-scan-credential

***
> **Note:**
> This command couldn't have been tested on our side, and therefore could have issues. Please let us know if you encounter any bugs or issues.

Retrieve information about all or a specific sca credential.

#### Base Command

`nexpose-list-site-scan-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| credential_id | ID of a specific scan credential to retrieve. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.SiteScanCredential.account.authenticationType | string | SNMPv3 authentication type for the credential. | 
| Nexpose.SiteScanCredential.account.communityName | string | SNMP community for authentication. | 
| Nexpose.SiteScanCredential.account.database | string | Database name. | 
| Nexpose.SiteScanCredential.account.domain | string | Domain address. | 
| Nexpose.SiteScanCredential.account.enumerateSids | boolean | Whether the scan engine should attempt to enumerate SIDs from the environment. | 
| Nexpose.SiteScanCredential.account.notesIDPassword | string | Password for the notes account that will be used for authenticating. | 
| Nexpose.SiteScanCredential.account.ntlmHash | string | NTLM password hash. | 
| Nexpose.SiteScanCredential.account.oracleListenerPassword | string | The Oracle Net Listener password. Used to enumerate SIDs from the environment. | 
| Nexpose.SiteScanCredential.account.password | string | Password for the credential. | 
| Nexpose.SiteScanCredential.account.pemKey | string | PEM formatted private key. | 
| Nexpose.SiteScanCredential.account.permissionElevation | string | Elevation type to use for scans. | 
| Nexpose.SiteScanCredential.account.permissionElevationPassword | string | Password to use for elevation. | 
| Nexpose.SiteScanCredential.account.permissionElevationUserName | string | Username to use for elevation. | 
| Nexpose.SiteScanCredential.account.privacyPassword | string | SNMPv3 privacy password to use. | 
| Nexpose.SiteScanCredential.account.privacyType | string | SNMPv3 privacy protocol to use. | 
| Nexpose.SiteScanCredential.account.privateKeyPassword | string | Password for the private key. | 
| Nexpose.SiteScanCredential.account.realm | string | HTTP realm. | 
| Nexpose.SiteScanCredential.account.service | string | Credential service type. | 
| Nexpose.SiteScanCredential.account.sid | string | Oracle database name. | 
| Nexpose.SiteScanCredential.account.useWindowsAuthentication | boolean | Whether to use Windows authentication. | 
| Nexpose.SiteScanCredential.account.username | string | Username for the credential. | 
| Nexpose.SiteScanCredential.description | string | Description for the credential. | 
| Nexpose.SiteScanCredential.hostRestriction | string | Hostname or IP address to restrict the credentials to. | 
| Nexpose.SiteScanCredential.id | number | ID of the credential. | 
| Nexpose.SiteScanCredential.name | string | Name of the credential. | 
| Nexpose.SiteScanCredential.portRestriction | number | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if \`hostRestriction\` is used. | 

### nexpose-list-vulnerability-exceptions

***
Retrieve information about scan schedules for a specific site or a specific scan schedule.

#### Base Command

`nexpose-list-vulnerability-exceptions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the vulnerability exception to retrieve. If not set, retrieve all vulnerability exceptions. | Optional | 
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. Page indexing starts at 0. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ";". For example: "riskScore,DESC;hostName,ASC". Default is submit.date,ASC. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.VulnerabilityException.expires | string | The date and time the vulnerability exception is set to expire. | 
| Nexpose.VulnerabilityException.id | int | The The identifier of the vulnerability exception. | 
| Nexpose.VulnerabilityException.scope.id | int | The identifier of the vulnerability to which the exception applies. | 
| Nexpose.VulnerabilityException.scope.key | string | If the scope type is "Instance", an optional key to discriminate the instance the exception applies to. | 
| Nexpose.VulnerabilityException.scope.port | int | If the scope type is "Instance" and the vulnerability is detected on a service, the port on which the exception applies. | 
| Nexpose.VulnerabilityException.scope.type | string | The type of the exception scope. One of: "Global", "Site", "Asset", "Asset Group", "Instance". | 
| Nexpose.VulnerabilityException.scope.vulnerability | string | The identifier of the vulnerability to which the exception applies. | 
| Nexpose.VulnerabilityException.state | string | The state of the vulnerability exception. One of: "Deleted", "Expired", "Approved", "Rejected", \`"Under Review". | 
| Nexpose.VulnerabilityException.submit.comment | string | A comment from the submitter as to why the exception was submitted. | 
| Nexpose.VulnerabilityException.submit.date | string | The date and time the vulnerability exception was submitted. | 
| Nexpose.VulnerabilityException.submit.name | string | The login name of the user who submitted the vulnerability exception. | 
| Nexpose.VulnerabilityException.submit.reason | string | The reason the vulnerability exception was submitted. One of: "False Positive", "Compensating Control", "Acceptable Use", "Acceptable Risk", "Other" | 
| Nexpose.VulnerabilityException.submit.user | int | The identifier of the user who submitted the vulnerability exception. | 

#### Command example
```!nexpose-list-vulnerability-exceptions sort="submit.date,ASC" limit=3```
#### Context Example
```json
{
    "Nexpose": {
        "VulnerabilityException": [
            {
                "expires": "2028-03-01T04:31:56Z",
                "id": 1,
                "review": {
                    "comment": "Auto approved by submitter.",
                    "date": "2022-10-31T14:39:15.736Z",
                    "name": "admin",
                    "user": 1
                },
                "scope": {
                    "type": "global",
                    "vulnerability": "tlsv1_0-enabled"
                },
                "state": "approved",
                "submit": {
                    "date": "2022-06-29T16:10:06.616880Z",
                    "name": "admin",
                    "reason": "false positive",
                    "user": 1
                }
            },
            {
                "id": 2,
                "review": {
                    "date": "2022-10-30T13:54:31.084Z",
                    "name": "admin",
                    "user": 1
                },
                "scope": {
                    "type": "global",
                    "vulnerability": "php-cve-2018-10545"
                },
                "state": "rejected",
                "submit": {
                    "date": "2022-07-13T13:27:31.647402Z",
                    "name": "admin",
                    "reason": "acceptable use",
                    "user": 1
                }
            },
            {
                "id": 3,
                "scope": {
                    "type": "global",
                    "vulnerability": "cifs-smb-signing-disabled"
                },
                "state": "under review",
                "submit": {
                    "date": "2022-10-27T11:40:34.109268Z",
                    "name": "admin",
                    "reason": "acceptable use",
                    "user": 1
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Vulnerability Exceptions
>| Id  |Vulnerability|ExceptionScope|Reason|ReportedBy|ReviewStatus|ReviewedOn|ExpiresOn|
-----|---|---|---|---|---|---|---|---|
>| 1   | tlsv1_0-enabled | global | false positive | admin | approved | 2022-10-31T14:39:15.736Z | 2028-03-01T04:31:56Z |
>| 2   | php-cve-2018-10545 | global | acceptable use | admin | rejected | 2022-10-30T13:54:31.084Z |  |
>| 3   | cifs-smb-signing-disabled | global | acceptable use | admin | under review |  |  |


### nexpose-start-site-scan

***
Starts a scan for the specified site.

#### Base Command

`nexpose-start-site-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site`). | Optional | 
| hosts | Specific host(s) on the site to run the scan on. Can be an IP address or a hostname. Can be a comma-separated list. | Optional | 
| name | Scan name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | date | The name of the user who started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan. | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating. | 
| Nexpose.Scan.Vulnerabilities.Critical | number | The number of critical vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Moderate | number | The number of moderate vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Severe | number | The number of severe vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Total | number | The total number of vulnerabilities. | 

### nexpose-stop-scan

***
Stop a running scan.

#### Base Command

`nexpose-stop-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a running scan. | Required | 


### nexpose-pause-scan

***
Pause a running scan.

#### Base Command

`nexpose-pause-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a running scan. | Required | 


### nexpose-resume-scan

***
Resume a paused scan.

#### Base Command

`nexpose-resume-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of a paused scan. | Required | 


### nexpose-get-scans

***
Return a list of scans. Returns only active scans by default (active=true).

#### Base Command

`nexpose-get-scans`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| active | Whether to return only active scans. Possible values are: true, false. Default is true. | Optional | 
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. Page indexing starts at 0. | Optional | 
| limit | A number of records to limit the response to. Default is 10. | Optional | 
| sort | Criteria to sort the records by, in the format: property[,ASC\|DESC]. If not specified, default sort order is ascending. Multiple sort criteria can be specified, separated by a ";". For example: "riskScore,DESC;hostName,ASC". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | date | The name of the user who started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating. | 

#### Command example
```!nexpose-get-scans active=false limit=3```
#### Context Example
```json
{
    "Nexpose": {
        "Scan": [
            {
                "Assets": 0,
                "Completed": "2019-12-03T20:48:01.368Z",
                "Id": 1,
                "Message": null,
                "ScanName": "Tue 03 Dec 2019 10:47 PM",
                "ScanType": "Manual",
                "StartedBy": null,
                "Status": "finished",
                "TotalTime": "51.316 seconds"
            },
            {
                "Assets": 0,
                "Completed": "2019-12-03T20:53:09.453Z",
                "Id": 2,
                "Message": null,
                "ScanName": "Tue 03 Dec 2019 10:52 PM",
                "ScanType": "Manual",
                "StartedBy": null,
                "Status": "finished",
                "TotalTime": "29.91 seconds"
            },
            {
                "Assets": 0,
                "Completed": "2019-12-03T21:01:33.970Z",
                "Id": 3,
                "Message": null,
                "ScanName": "scan 2019-12-03 19:58:25.961787",
                "ScanType": "Manual",
                "StartedBy": null,
                "Status": "finished",
                "TotalTime": "28.904 seconds"
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose Scans
>|Id|ScanType|ScanName|Assets|TotalTime|Completed|Status|
>|---|---|---|---|---|---|---|
>| 1 | Manual | Tue 03 Dec 2019 10:47 PM | 0 | 51.316 seconds | 2019-12-03T20:48:01.368Z | finished |
>| 2 | Manual | Tue 03 Dec 2019 10:52 PM | 0 | 29.91 seconds | 2019-12-03T20:53:09.453Z | finished |
>| 3 | Manual | scan 2019-12-03 19:58:25.961787 | 0 | 28.904 seconds | 2019-12-03T21:01:33.970Z | finished |


### nexpose-disable-shared-credential

***
> **Note:**
> This command couldn't have been tested on our side, and therefore could have issues. Please let us know if you encounter any bugs or issues.

Disable an assigned shared credential.

#### Base Command

`nexpose-disable-shared-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| credential_id | ID of the scan schedule to update. | Required | 


### nexpose-download-report

***
Returns the generated report.

#### Base Command

`nexpose-download-report`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | ID of the report. | Required | 
| instance_id | ID of the report instance. Supports a "latest" value. | Required | 
| name | Report name. | Optional | 
| format | Report format (uses PDF by default). Possible values are: pdf, rtf, xml, html, text, nexpose-simple-xml. Default is pdf. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry ID of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Extension | string | File extension of the report file. | 
| InfoFile.Info | string | Information about the report file. | 
| InfoFile.Size | number | Size of the report file \(in bytes\). | 
| InfoFile.Type | string | Type of the report file. | 

#### Command example
```!nexpose-download-report report_id=1 instance_id=latest```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "4127@403762e2-be4e-4f12-8a17-26cdb21b129e",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "report 2022-11-30 09:25:43.835638.pdf",
        "Size": 76699,
        "Type": "PDF document, version 1.4"
    }
}
```

### nexpose-enable-shared-credential

***
> **Note:**
> This command couldn't have been tested on our side, and therefore could have issues. Please let us know if you encounter any bugs or issues.

Enable an assigned shared credential.

#### Base Command

`nexpose-enable-shared-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| credential_id | ID of the scan schedule to update. | Required | 


### nexpose-get-report-status

***
Returns the status of a report generation process.

#### Base Command

`nexpose-get-report-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | ID of the report. | Required | 
| instance_id | ID of the report instance. Supports a "latest" value. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Status | string | The status of the report generation process. Valid values: "aborted", "failed", "complete", "running", "unknown". | 

#### Command example
```!nexpose-get-report-status report_id=1 instance_id=latest```
#### Context Example
```json
{
    "Nexpose": {
        "Report": {
            "ID": "1",
            "InstanceID": "latest",
            "Status": "complete"
        }
    }
}
```

#### Human Readable Output

>### Report Generation Status
>|ID|InstanceID|Status|
>|---|---|---|
>| 1 | latest | complete |


### nexpose-update-scan-schedule

***
> **Note:**
> This command couldn't have been tested on our side, and therefore could have issues. Please let us know if you encounter any bugs or issues.

Update an existing site scan schedule.

#### Base Command

`nexpose-update-scan-schedule`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| schedule_id | ID of the scan schedule to update. | Optional | 
| enabled | A flag indicating whether the scheduled scan is enabled. Possible values are: True, False. Default is True. | Optional | 
| on_scan_repeat | The desired behavior of a repeating scheduled scan when the previous scan was paused due to reaching its maximum duration. Possible values are: Restart-Scan, Resume-Scan. | Required | 
| start | The scheduled start date and time formatted in ISO 8601 format. Repeating schedules will determine the next schedule to begin based on this date and time. | Required | 
| excluded_asset_group_ids | A list of IDs for asset groups to exclude from the scan. | Optional | 
| excluded_addresses | A list of addresses to exclude from the scan. | Optional | 
| included_asset_group_ids | A list of IDs for asset groups to include in the scan. | Optional | 
| included_addresses | A list of addresses to include in the scan. | Optional | 
| duration_days | Maximum duration of the scan in days. | Optional | 
| duration_hours | Maximum duration of the scan in hours. | Optional | 
| duration_minutes | Maximum duration of the scan in minutes. | Optional | 
| frequency | How frequently should the schedule repeat (Every...). Possible values are: Hour, Day, Week, Date-of-month. | Optional | 
| interval_time | The interval time the schedule should repeat. This depends on the value set in `frequency`. For example, if the value of `frequency` is set to "Day" and `interval` is set to 2, then the schedule will repeat every 2 days. Required only if frequency is used. | Optional | 
| date_of_month | Specifies the schedule repeat day of the interval month. For example, if `date_of_month` is 17 and `interval` is set to 2, then the schedule will repeat every 2 months on the 17th day of the month. Required and used only if frequency is set to `Date of month`. | Optional | 
| scan_name | A unique user-defined name for the scan launched by the schedule. If not explicitly set in the schedule, the scan name will be generated prior to the scan launching. | Optional | 
| scan_template | ID of the scan template to use. | Optional | 

#### Context Output

There is no context output for this command.
### nexpose-update-site-scan-credential

***
> **Note:**
> This command couldn't have been tested on our side, and therefore could have issues. Please let us know if you encounter any bugs or issues.

Update an existing site scan credential. For detailed explanation of all parameters of this command, see: https://help.rapid7.com/insightvm/en-us/api/index.html#operation/setSiteCredentials.

#### Base Command

`nexpose-update-site-scan-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | ID of the site. | Optional | 
| site_name | Name of the site (can be used instead of `site_id`). | Optional | 
| credential_id | ID of the site scan credential to update. | Required | 
| name | Name of the credential. | Required | 
| service | Credential service type. Possible values are: AS400, CIFS, CIFSHash, CVS, DB2, FTP, HTTP, MS-SQL, MySQL, Notes, Oracle, POP, PostgresSQL, Remote-Exec, SNMP, SNMPv3, SSH, SSH-Key, Sybase, Telnet. | Required | 
| database | Database name. | Optional | 
| description | Description for the credential. | Optional | 
| domain | Domain address. | Optional | 
| host_restriction | Hostname or IP address to restrict the credentials to. | Optional | 
| http_realm | HTTP realm. | Optional | 
| notes_id_password | Password for the notes account that will be used for authenticating. | Optional | 
| ntlm_hash | NTLM password hash. | Optional | 
| oracle_enumerate_sids | Whether the scan engine should attempt to enumerate SIDs from the environment. Possible values are: true, false. | Optional | 
| oracle_listener_password | Oracle Net Listener password. Used to enumerate SIDs from your environment. | Optional | 
| oracle_sid | Oracle database name. | Optional | 
| password | Password for the credential. | Optional | 
| port_restriction | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if `host_restriction` is used. | Optional | 
| community_name | SNMP community for authentication. | Optional | 
| authentication_type | SNMPv3 authentication type for the credential. Possible values are: No-Authentication, MD5, SHA. | Optional | 
| privacy_password | SNMPv3 privacy password to use. | Optional | 
| privacy_type | SNMPv3 Privacy protocol to use. Possible values are: No-Privacy, DES, AES-128, AES-192, AES-192-With-3-DES-Key-Extension, AES-256, AES-256-With-3-DES-Key-Extension. | Optional | 
| ssh_key_pem | PEM formatted private key. | Optional | 
| ssh_permission_elevation | Elevation type to use for scans. Possible values are: None, sudo, sudosu, su, pbrun, Privileged Exec. | Optional | 
| ssh_permission_elevation_password | Password to use for elevation. | Optional | 
| ssh_permission_elevation_username | Username to use for elevation. | Optional | 
| ssh_private_key_password | Password for the private key. | Optional | 
| use_windows_authentication | Whether to use Windows authentication. Possible values are: true, false. | Optional | 
| username | Username for the credential. | Optional | 

#### Context Output

There is no context output for this command.
### nexpose-update-vulnerability-exception-expiration

***
Update an existing vulnerability exception.

#### Base Command

`nexpose-update-vulnerability-exception-expiration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the vulnerability exception to update. | Required | 
| expiration | An expiration date for the vulnerability exception formatted in ISO 8601 format. Must be a date in the future. | Required | 


#### Command example
```!nexpose-update-vulnerability-exception-expiration id=1 expiration=2024-10-10T10:00:00Z```
#### Human Readable Output

>Successfully updated expiration date of vulnerability exception 1.

### nexpose-update-vulnerability-exception-status

***
Update an existing vulnerability exception.

#### Base Command

`nexpose-update-vulnerability-exception-status`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the vulnerability exception to update. | Required | 
| status | A status to update the vulnerability exception to. Possible values are: Recall, Approve, Reject. | Required | 


#### Command example
```!nexpose-update-vulnerability-exception-status id=1 status=Approve```
#### Human Readable Output

>Successfully updated status of vulnerability exception 1.

### nexpose-update-shared-credential

***
Update an existing shared credential.

#### Base Command

`nexpose-update-shared-credential`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the shared credential to update. | Required | 
| name | Name of the credential. | Required | 
| site_assignment | Site assignment configuration for the credential. Assign the shared scan credential either to be available to all sites, or a specific list of sites. Possible values are: All-Sites, Specific-Sites. | Required | 
| service | Credential service type. Possible values are: AS400, CIFS, CIFSHash, CVS, DB2, FTP, HTTP, MS-SQL, MySQL, Notes, Oracle, POP, PostgresSQL, Remote-Exec, SNMP, SNMPv3, SSH, SSH-Key, Sybase, Telnet. | Required | 
| database | Database name. | Optional | 
| description | Description for the credential. | Optional | 
| domain | Domain address. | Optional | 
| host_restriction | Hostname or IP address to restrict the credentials to. | Optional | 
| http_realm | HTTP realm. | Optional | 
| notes_id_password | Password for the notes account that will be used for authenticating. | Optional | 
| ntlm_hash | NTLM password hash. | Optional | 
| oracle_enumerate_sids | Whether the scan engine should attempt to enumerate SIDs from the environment. Possible values are: true, false. | Optional | 
| oracle_listener_password | Oracle Net Listener password. Used to enumerate SIDs from your environment. | Optional | 
| oracle_sid | Oracle database name. | Optional | 
| password | Password for the credential. | Optional | 
| port_restriction | Further restricts the credential to attempt to authenticate on a specific port. Can be used only if `host_restriction` is used. | Optional | 
| sites | List of site IDs for the shared credential that are explicitly assigned access to the shared scan credential, allowing it to use the credential during a scan. | Optional | 
| community_name | SNMP community for authentication. | Optional | 
| authentication_type | SNMPv3 authentication type for the credential. Possible values are: No-Authentication, MD5, SHA. | Optional | 
| privacy_password | SNMPv3 privacy password to use. | Optional | 
| privacy_type | SNMPv3 Privacy protocol to use. Possible values are: No-Privacy, DES, AES-128, AES-192, AES-192-With-3-DES-Key-Extension, AES-256, AES-256-With-3-DES-Key-Extension. | Optional | 
| ssh_key_pem | PEM formatted private key. | Optional | 
| ssh_permission_elevation | Elevation type to use for scans. Possible values are: None, sudo, sudosu, su, pbrun, Privileged-Exec. | Optional | 
| ssh_permission_elevation_password | Password to use for elevation. | Optional | 
| ssh_permission_elevation_username | Username to use for elevation. | Optional | 
| ssh_private_key_password | Password for the private key. | Optional | 
| use_windows_authentication | Whether to use Windows authentication. Possible values are: true, false. | Optional | 
| username | Username for the credential. | Optional | 

#### Context Output

There is no context output for this command.

### nexpose-add-site-included-asset

***

#### Base Command

`nexpose-add-site-included-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | A URL parameter. | Required | 
| assets | List of addresses to add to the site's included scan assets. Each address is a string that can represent either a hostname, IPv4 address, IPv4 address range, IPv6 address, or CIDR notation. | Optional | 
| asset_group_ids | List of asset group identifiers. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!nexpose-add-site-included-asset site_id=848 assets=8.8.8.8```

#### Human Readable Output

>Added assets 8.8.8.8 to site with ID 848

### nexpose-remove-tag-asset

***
Remove an asset from a tag. Note that the asset must be added through the asset or tag. If the asset is added using a site, asset group, or search criteria, this action will not remove the asset from the tag.

#### Base Command

`nexpose-remove-tag-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | The tag ID. | Required | 
| asset_id | The asset ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!nexpose-remove-tag-asset asset_id=25 tag_id=61```

#### Human Readable Output

>Asset 25 was removed from tag 61 successfully

### nexpose-list-tag-asset

***
Return a list of assets for a tag.

#### Base Command

`nexpose-list-tag-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | The tag ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.TagAsset.id | int | Asset ID. | 
| Nexpose.TagAsset.sources | string | The asset sources. | 

#### Command example
```!nexpose-list-tag-asset tag_id=33```
#### Context Example
```json
{
    "Nexpose": {
        "TagAsset": [
            {
                "id": 18,
                "sources": [
                    "tag"
                ]
            },
            {
                "id": 25,
                "sources": [
                    "tag"
                ]
            },
            {
                "id": 28,
                "sources": [
                    "tag"
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Tag 33 assets
>|Id|Sources|
>|---|---|
>| 18 | tag |
>| 25 | tag |
>| 28 | tag |


### nexpose-delete-tag

***
Delete a tag.

#### Base Command

`nexpose-delete-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The tag ID. | Required | 

#### Context Output

There is no context output for this command.
### nexpose-list-site-included-asset

***
Return a list of included assets for a site.

#### Base Command

`nexpose-list-site-included-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | A URL parameter. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.IncludedAsset.site_id | int | The site ID. | 
| Nexpose.IncludedAsset.addresses | string | A list of addresses of the included assets for the specified site. | 

#### Command example
```!nexpose-list-site-included-asset site_id=848```
#### Context Example
```json
{
    "Nexpose": {
        "IncludedAsset": {
            "addresses": [
                "8.8.8.8",
                "1.1.1.1"
            ],
            "site_id": 848
        }
    }
}
```

#### Human Readable Output

>### Asset list for site ID 848
>|Addresses|
>|---|
>| 8.8.8.8 |
>| 1.1.1.1 |


### nexpose-list-site-excluded-asset-group

***
Return a list of excluded asset groups for a site.

#### Base Command

`nexpose-list-site-excluded-asset-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | A URL parameter. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.ExcludedAssetGroup.site_id | int | The site ID. | 
| Nexpose.ExcludedAssetGroup.resources | int | The asset group ID. | 

#### Command example
```!nexpose-list-site-excluded-asset-group site_id=848```
#### Context Example
```json
{
    "Nexpose": {
        "ExcludedAssetGroup": {
            "resources": [],
            "site_id": 848
        }
    }
}
```


### nexpose-list-site-included-asset-group

***
Return a list of included asset groups for a site.

#### Base Command

`nexpose-list-site-included-asset-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | A URL parameter. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.IncludedAssetGroup.site_id | int | The site ID. | 
| Nexpose.IncludedAssetGroup.resources | int | The asset group ID. | 

#### Command example
```!nexpose-list-site-included-asset-group site_id=848```
#### Context Example
```json
{
    "Nexpose": {
        "IncludedAssetGroup": {
            "resources": [],
            "site_id": 848
        }
    }
}
```

#### Human Readable Output

>### Asset group list for site ID 848
>**No entries.**


### nexpose-remove-tag-asset-group

***
Remove an asset group from a tag.

#### Base Command

`nexpose-remove-tag-asset-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | The tag ID. | Required | 
| asset_group_id | The asset group ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!nexpose-remove-tag-asset-group asset_group_id=1 tag_id=61```

#### Human Readable Output

>Asset group 1 was removed from tag 61 successfully

### nexpose-create-tag

***
Create a tag.

#### Base Command

`nexpose-create-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The tag name. | Required | 
| type | The tag type. Possible values are: Owner, Location, Custom. | Required | 
| color | The tag color - relevant only for "Custom" type. Possible values are: Blue, Green, Orange, Red, Purple, Default. Default is Default. | Optional | 
| ip_address_is | A specific IP address to search for. | Optional | 
| host_name_is | A specific host name to search for. | Optional | 
| risk_score_higher_than | A minimum risk score to use as a filter. | Optional | 
| vulnerability_title_contains | A string to search for in vulnerability titles. | Optional | 
| site_id_in | Site IDs to filter for. Can be a comma-separated list. | Optional | 
| site_name_in | Site names to filter for. Can be a comma-separated list. | Optional | 
| match | Operator to determine how to match filters. "All" requires that all filters match for an asset to be included. "Any" requires only one filter to match for an asset to be included. Possible values are: All, Any. Default is Any. | Optional | 
| query | Additional queries to use as a filter, following the Search Criteria API standard. The structure is {field} {operator} {value}. Multiple queries can be specified, separated by a ";" separator. For example, 'ip-address in-range 192.0.2.0,192.0.2.1;host-name is myhost'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Tag.id | int | The tag ID. | 

### nexpose-add-tag-asset

***
Add an existing asset to an existing tag.

#### Base Command

`nexpose-add-tag-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | The tag ID. | Required | 
| asset_id | The asset ID. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!nexpose-add-tag-asset asset_id=25 tag_id=61```

#### Human Readable Output

>Asset 25 was added in tag 61 successfully

### nexpose-remove-site-excluded-asset

***
Remove excluded assets from a site.

#### Base Command

`nexpose-remove-site-excluded-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | A URL parameter. | Required | 
| assets | List of addresses to remove from the site's excluded scan assets. Each address is a string that can represent either a hostname, IPv4 address, IPv4 address range, IPv6 address, or CIDR notation. | Optional | 
| asset_group_ids | List of asset group IDs to remove from the site's exclusion list. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!nexpose-remove-site-excluded-asset site_id=848 assets=8.8.8.8```

#### Human Readable Output

>Removed assets 8.8.8.8 from site with ID 848

### nexpose-remove-site-included-asset

***

#### Base Command

`nexpose-remove-site-included-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | A URL parameter. | Required | 
| assets | List of addresses to remove from the site's included scan assets. Each address is a string that can represent either a hostname, IPv4 address, IPv4 address range, IPv6 address, or CIDR notation. | Optional | 
| asset_group_ids | List of asset group identifiers. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!nexpose-remove-site-included-asset site_id=848 assets=8.8.8.8```

#### Human Readable Output

>Removed assets 8.8.8.8 from site with ID 848

### nexpose-update-tag-search-criteria

***
Update tag search criteria.

#### Base Command

`nexpose-update-tag-search-criteria`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | The tag ID. | Required | 
| ip_address_is | A specific IP address to search for. | Optional | 
| host_name_is | A specific host name to search for. | Optional | 
| risk_score_higher_than | A minimum risk score to use as a filter. | Optional | 
| vulnerability_title_contains | A string to search for in vulnerability titles. | Optional | 
| site_id_in | Site IDs to filter for. Can be a comma-separated list. | Optional | 
| site_name_in | Site names to filter for. Can be a comma-separated list. | Optional | 
| match | Operator to determine how to match filters. "All" requires that all filters match for an asset to be included. "Any" requires only one filter to match for an asset to be included. Possible values are: All, Any. Default is Any. | Optional | 
| query | Additional queries to use as a filter, following the Search Criteria API standard. The structure is {field} {operator} {value}. Multiple queries can be specified, separated by a ";" separator. For example, 'ip-address in-range 192.0.2.0,192.0.2.1;host-name is myhost'. | Optional | 
| overwrite | Whether to overwrite the original search values or append new conditions to the existing search. Possible values are: yes, no. Default is no. | Optional | 

#### Context Output

There is no context output for this command.
### nexpose-add-tag-asset-group

***
Add existing asset groups to an existing tag.()

#### Base Command

`nexpose-add-tag-asset-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | The tag ID. | Required | 
| asset_group_ids | The asset group IDs to add. Can be a comma-separated list. | Required | 

#### Context Output

There is no context output for this command.
### nexpose-list-site-excluded-asset

***
Return a list of excluded assets for a site.

#### Base Command

`nexpose-list-site-excluded-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | A URL parameter. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.ExcludedAsset.site_id | int | The site ID. | 
| Nexpose.ExcludedAsset.addresses | string | A list of addresses of the excluded assets for the specified site. | 

#### Command example
```!nexpose-list-site-excluded-asset site_id=848```
#### Context Example
```json
{
    "Nexpose": {
        "ExcludedAsset": {
            "site_id": 848
        }
    }
}
```

#### Human Readable Output

>### Asset list for site ID 848
>**No entries.**


### nexpose-list-tag-asset-group

***
Return a list of asset groups for a tag.

#### Base Command

`nexpose-list-tag-asset-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_id | The tag ID. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.TagAssetGroup.id | int | Asset group ID. | 

#### Command example
```!nexpose-list-tag-asset-group tag_id=2```
#### Context Example
```json
{
    "Nexpose": {
        "TagAssetGroup": [
            3
        ]
    }
}
```

#### Human Readable Output

>### Tag 2 asset groups.
>|Asset groups IDs|
>|---|
>| 3 |


### nexpose-list-tag

***
Return a list of tags.

#### Base Command

`nexpose-list-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Get tag by ID. | Optional | 
| name | Filters the returned tags to only those containing the value within their name. | Optional | 
| type | Filters the returned tags to only those of this type. | Optional | 
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. Page indexing starts at 0. | Optional | 
| limit | A number of records to limit the response to. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Tag.color | String | The color associated with the tag. | 
| Nexpose.Tag.created | Date | The date when the tag was created. | 
| Nexpose.Tag.id | Number | The unique identifier of the tag. | 
| Nexpose.Tag.name | String | The name of the tag. | 
| Nexpose.Tag.searchCriteria.match | String | The match criteria used for the tag search \(e.g., "all" or "any"\). | 
| Nexpose.Tag.searchCriteria.filters.field | String | The field name used in the tag search filter. | 
| Nexpose.Tag.searchCriteria.filters.operator | String | The operator used in the tag search filter \(e.g., "is", "contains", "is-greater-than"\). | 
| Nexpose.Tag.searchCriteria.filters.lower | String | The lower bound of the range used in the tag search filter. | 
| Nexpose.Tag.searchCriteria.filters.upper | String | The upper bound of the range used in the tag search filter. | 
| Nexpose.Tag.source | String | The source of the tag. | 
| Nexpose.Tag.type | String | The type of the tag. | 
| Nexpose.Tag.searchCriteria.filters.value | String | The value used in the tag search filter. | 
| Nexpose.Tag.page.number | Number | The current page number in the paginated response. | 
| Nexpose.Tag.page.size | Number | The number of items per page in the paginated response. | 
| Nexpose.Tag.page.totalResources | Number | The total number of resources available. | 
| Nexpose.Tag.page.totalPages | Number | The total number of pages available. | 


#### Command example
```!nexpose-list-tag limit=2 name=test```

#### Context Example
```json
{
    "resources": [
        {
            "color": "default",
            "created": "2024-05-06T13:32:58.454Z",
            "id": 45,
            "name": "test",
            "searchCriteria": {
                "match": "all",
                "filters": [
                    {
                        "field": "risk-score",
                        "operator": "in-range",
                        "lower": "193.841",
                        "upper": "187.841"
                    }
                ]
            },
            "source": "custom",
            "type": "Owner"
        },
        {
            "color": "default",
            "created": "2024-05-06T13:43:52.874Z",
            "id": 46,
            "name": "new_test2",
            "searchCriteria": {
                "match": "any",
                "filters": [
                    {
                        "field": "ip-address",
                        "operator":"is",
                        "value":"3.3.3.3"
                    }
                ]
            },
            "source": "custom",
            "type": "Owner"
        }
    ],
    "page": {
        "number": 0,
        "size": 2,
        "totalResources": 8,
        "totalPages": 4
    }
}
```


### nexpose-add-site-excluded-asset

***
Add excluded assets to a site.

#### Base Command

`nexpose-add-site-excluded-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site_id | A URL parameter. | Required | 
| assets | List of addresses to add to the site's excluded scan assets. Each address is a string that can represent either a hostname, IPv4 address, IPv4 address range, IPv6 address, or CIDR notation. | Optional | 
| asset_group_ids | List of asset group IDs to exclude. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!nexpose-add-site-excluded-asset site_id=848 assets=8.8.8.8```

#### Human Readable Output

>Added assets 8.8.8.8 to site with ID 848

### nexpose-list-asset-group

***
Return a list of asset groups.

#### Base Command

`nexpose-list-asset-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Get asset group by ID. | Optional | 
| group_name | Filters the returned asset groups to only those containing the value within their name. | Optional | 
| type | Filters the returned asset groups to only those of this type. Possible values are: static, dynamic. | Optional | 
| page_size | Number of records to retrieve in each API call when pagination is used. | Optional | 
| page | A specific page to retrieve when pagination is used. Page indexing starts at 0. | Optional | 
| limit | A number of records to limit the response to. | Optional | 
| sort | The criteria to sort the records by, in the format property[,ASC\|DESC]. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.AssetGroup.assets | Number | The number of assets in the asset group. | 
| Nexpose.AssetGroup.id | Number | The unique identifier of the asset group. | 
| Nexpose.AssetGroup.name | String | The name of the asset group. | 
| Nexpose.AssetGroup.riskScore | Number | The cumulative risk score of the asset group. | 
| Nexpose.AssetGroup.type | String | The type of the asset group. | 
| Nexpose.AssetGroup.vulnerabilities.critical | Number | The number of critical vulnerabilities in the asset group. | 
| Nexpose.AssetGroup.vulnerabilities.moderate | Number | The number of moderate vulnerabilities in the asset group. | 
| Nexpose.AssetGroup.vulnerabilities.severe | Number | The number of severe vulnerabilities in the asset group. | 
| Nexpose.AssetGroup.vulnerabilities.total | Number | The total number of vulnerabilities in the asset group. | 
| Nexpose.AssetGroup.description | String | The description of the asset group. | 
#### Command example
```!nexpose-list-asset-group limit=2```
### nexpose-create-asset-group

***
Create an asset group.

#### Base Command

`nexpose-create-asset-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The asset group name. | Required | 
| type | The asset group type. Possible values are: static, dynamic. | Required | 
| description | The description of the asset group. | Required | 
| ip_address_is | A specific IP address to search for. | Optional | 
| host_name_is | A specific host name to search for. | Optional | 
| risk_score_higher_than | A minimum risk score to use as a filter. | Optional | 
| vulnerability_title_contains | A string to search for in vulnerability titles. | Optional | 
| site_id_in | Site IDs to filter for. Can be a comma-separated list. | Optional | 
| site_name_in | Site names to filter for. Can be a comma-separated list. | Optional | 
| match | Operator to determine how to match filters. "All" requires that all filters match for an asset to be included. "Any" requires only one filter to match for an asset to be included. Possible values are: All, Any. Default is Any. | Optional | 
| query | Additional queries to use as a filter, following the Search Criteria API standard. The structure is {field} {operator} {value}. Multiple queries can be specified, separated by a ";" separator. For example, 'ip-address in-range 192.0.2.0,192.0.2.1;host-name is myhost'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.AssetGroup.id | int | The asset group ID. | 

#### Command example
```!nexpose-create-asset-group name=test3 type=dynamic ip_address_is=1.1.1.1 query=`risk-score is-greater-than 8000` escription=test```