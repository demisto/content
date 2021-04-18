Rapid7's on-premise vulnerability management solution, Nexpose, helps you reduce your threat exposure by enabling you to assess and respond to changes in your environment real time and prioritizing risk across vulnerabilities, configurations, and controls.
This integration was integrated and tested with version 3 of Rapid7 Nexpose
## Configure Rapid7 Nexpose on Cortex XSOAR
To use Nexpose on XSOAR, you need user credentials for Nexpose. You
can also use a two-factor authentication token.

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Rapid7 Nexpose.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://192.168.0.1:8080) | True |
    | Username | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | The 2FA token | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

When using the `sort` parameter, you need to specify the fields to sort
as they are in the API, for example, `riskScore`. All the available
fields for any type of response can be found in the [API Documentation.](https://help.rapid7.com/insightvm/en-us/api/index.html#tag/Asset)

1.  [Get a single asset: nexpose-get-asset](#nexpose-get-asset)
2.  [Get all assets: nexpose-get-assets](#nexpose-get-assets)
3.  [Get all assets that match the filters: nexpose-search-assets](#nexpose-search-assets)
4.  [Get a specified scan: nexpose-get-scan](#nexpose-get-scan)
5.  [Get an asset's details: nexpose-get-asset-vulnerability](#nexpose-get-asset-vulnerability)
6.  [Create a site: nexpose-create-site](#nexpose-create-site)
7.  [Delete a site: nexpose-delete-site](#nexpose-delete-site)
8.  [Retrieve sites: nexpose-get-sites](#expose-get-sites)
9.  [Get report templates: nexpose-get-report-templates](#nexpose-get-report-templates)
10. [Create an assets report: nexpose-create-assets-report](#nexpose-create-assets-report)
11. [Create a sites report: nexpose-create-sites-report](#nexpose-create-sites-report)
12. [Create a scan report: nexpose-create-scan-report](#nexpose-create-scan-report)
13. [Start a site scan: nexpose-start-site-scan](#nexpose-start-site-scan)
14. [Start an assets scan: nexpose-start-assets-scan](#nexpose-start-assets-scan)
15. [Stop a scan: nexpose-stop-scan](#nexpose-stop-scan)
16. [Pause a scan: nexpose-pause-scan](#nexpose-pause-scan)
17. [Resume a scan: nexpose-resume-scan](#nexpose-resume-scan)
18. [Get a list of scans: nexpose-get-scans](#nexpose-get-scans)
19. [Get the status of a report generation process: nexpose-get-report-status](#nexpose-get-report-status)
20. [Get the content of a generated report: nexpose-download-report](#nexpose-download-report)

### nexpose-get-asset
***
Returns the specified asset.


#### Base Command

`nexpose-get-asset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | integer &lt;int64&gt; The identifier of the asset. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Asset.Addresses | unknown | All addresses discovered on the asset. | 
| Nexpose.Asset.AssetId | number | Id of the asset. | 
| Nexpose.Asset.Hardware | string | The primary Media Access Control \(MAC\) address of the asset. The format is six groups of two hexadecimal digits separated by colons. | 
| Nexpose.Asset.Aliases | unknown | All host names or aliases discovered on the asset. | 
| Nexpose.Asset.HostType | string | The type of asset, Valid values are unknown, guest, hypervisor, physical, mobile | 
| Nexpose.Asset.Site | string | Asset site name. | 
| Nexpose.Asset.OperatingSystem | string | Operating system of the asset. | 
| Nexpose.Asset.Vulnerabilities | number | The total number of vulnerabilities on the asset. | 
| Nexpose.Asset.CPE | string | The Common Platform Enumeration \(CPE\) of the operating system. | 
| Nexpose.Asset.LastScanDate | date | Last scan date of the asset. | 
| Nexpose.Asset.LastScanId | number | Id of the asset's last scan. | 
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
| CVE.ID | string | Common Vulnerabilities and Exposures ids | 


#### Command Example
```!nexpose-get-asset id=2```

#### Context Example
```json
{
    "CVE": [
        {
            "ID": "CVE-1999-0524"
        },
        {
            "ID": "CVE-2015-4000"
        },
        {
            "ID": "CVE-2016-2183"
        }
    ],
    "Endpoint": {
        "HostName": null,
        "IP": [
            "192.168.1.1"
        ],
        "MAC": [
            "00:0C:29:9B:D2:3A"
        ],
        "OS": "Linux 3.10"
    },
    "Nexpose": {
        "Asset": {
            "Addresses": [
                "192.168.1.1"
            ],
            "Aliases": null,
            "AssetId": 2,
            "CPE": null,
            "Hardware": [
                "00:0C:29:9B:D2:3A"
            ],
            "HostType": null,
            "LastScanDate": "2020-11-26T17:13:44.124Z",
            "LastScanId": 761,
            "OperatingSystem": "Linux 3.10",
            "RiskScore": 1605.670654296875,
            "Service": [
                {
                    "Name": "SSH",
                    "Port": 22,
                    "Product": "OpenSSH",
                    "Protocol": "tcp"
                }
            ],
            "Site": "Test",
            "Software": null,
            "User": null,
            "Vulnerabilities": 7,
            "Vulnerability": [
                {
                    "CVSS": 0,
                    "Exploit": 0,
                    "Id": "generic-icmp-timestamp",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2019-06-11",
                    "PublishedOn": "1997-08-01",
                    "Risk": 0,
                    "Severity": "Moderate",
                    "Title": "ICMP timestamp response"
                },
                {
                    "CVSS": 0,
                    "Exploit": 0,
                    "Id": "generic-tcp-timestamp",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2018-03-21",
                    "PublishedOn": "1997-08-01",
                    "Risk": 0,
                    "Severity": "Moderate",
                    "Title": "TCP timestamp response"
                },
                {
                    "CVSS": 0,
                    "Exploit": 0,
                    "Id": "ssh-3des-ciphers",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2020-03-31",
                    "PublishedOn": "2009-02-01",
                    "Risk": 0,
                    "Severity": "Moderate",
                    "Title": "SSH Server Supports 3DES Cipher Suite"
                },
                {
                    "CVSS": 2.6,
                    "Exploit": 0,
                    "Id": "ssh-cbc-ciphers",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2020-03-31",
                    "PublishedOn": "2013-02-08",
                    "Risk": 490.23,
                    "Severity": "Moderate",
                    "Title": "SSH CBC vulnerability"
                },
                {
                    "CVSS": 4.3,
                    "Exploit": 0,
                    "Id": "ssh-cve-2015-4000",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2020-07-13",
                    "PublishedOn": "2015-05-20",
                    "Risk": 192.46,
                    "Severity": "Severe",
                    "Title": "SSH Server Supports diffie-hellman-group1-sha1"
                },
                {
                    "CVSS": 5,
                    "Exploit": 1,
                    "Id": "ssh-cve-2016-2183-sweet32",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2020-04-01",
                    "PublishedOn": "2016-08-24",
                    "Risk": 531.96,
                    "Severity": "Severe",
                    "Title": "SSH Birthday attacks on 64-bit block ciphers (SWEET32)"
                },
                {
                    "CVSS": 4.3,
                    "Exploit": 0,
                    "Id": "ssh-weak-kex-algorithms",
                    "Instances": 1,
                    "Malware": 0,
                    "ModifiedOn": "2020-04-07",
                    "PublishedOn": "2017-07-13",
                    "Risk": 391.02,
                    "Severity": "Severe",
                    "Title": "SSH Server Supports Weak Key Exchange Algorithms"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Nexpose asset 2
>|AssetId|Addresses|Hardware|Site|OperatingSystem|LastScanDate|LastScanId|RiskScore|
>|---|---|---|---|---|---|---|---|
>| 2 | 192.168.1.1 | 00:0C:29:9B:D2:3A | Test | Linux 3.10 | 2020-11-26T17:13:44.124Z | 761 | 1605.670654296875 |
>### Vulnerabilities
>|Id|Title|Malware|Exploit|CVSS|Risk|PublishedOn|ModifiedOn|Severity|Instances|
>|---|---|---|---|---|---|---|---|---|---|
>| generic-icmp-timestamp | ICMP timestamp response | 0 | 0 | 0.0 | 0.0 | 1997-08-01 | 2019-06-11 | Moderate | 1 |
>| generic-tcp-timestamp | TCP timestamp response | 0 | 0 | 0.0 | 0.0 | 1997-08-01 | 2018-03-21 | Moderate | 1 |
>| ssh-3des-ciphers | SSH Server Supports 3DES Cipher Suite | 0 | 0 | 0.0 | 0.0 | 2009-02-01 | 2020-03-31 | Moderate | 1 |
>| ssh-cbc-ciphers | SSH CBC vulnerability | 0 | 0 | 2.6 | 490.23 | 2013-02-08 | 2020-03-31 | Moderate | 1 |
>| ssh-cve-2015-4000 | SSH Server Supports diffie-hellman-group1-sha1 | 0 | 0 | 4.3 | 192.46 | 2015-05-20 | 2020-07-13 | Severe | 1 |
>| ssh-cve-2016-2183-sweet32 | SSH Birthday attacks on 64-bit block ciphers (SWEET32) | 0 | 1 | 5.0 | 531.96 | 2016-08-24 | 2020-04-01 | Severe | 1 |
>| ssh-weak-kex-algorithms | SSH Server Supports Weak Key Exchange Algorithms | 0 | 0 | 4.3 | 391.02 | 2017-07-13 | 2020-04-07 | Severe | 1 |
>### Services
>|Name|Port|Product|Protocol|
>|---|---|---|---|
>| SSH | 22 | OpenSSH | tcp |


### nexpose-get-assets
***
Returns all assets for which you have access.


#### Base Command

`nexpose-get-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sort | Multiple criteria of &lt;string&gt; The criteria to sort the records by, in the format: property[,ASC\|DESC]. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'. | Optional | 
| limit | integer &lt;int32&gt; The number of records retrieve. | Optional | 


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


#### Command Example
```!nexpose-get-assets```

#### Context Example
```json
{
    "Endpoint": [
        {
            "HostName": null,
            "IP": "192.168.1.1",
            "OS": "Linux 3.10"
        },
        {
            "HostName": "angular.testsparker.com",
            "IP": "20.20.20.20",
            "OS": "Ubuntu Linux"
        },
        {
            "HostName": "rest.testsparker.com",
            "IP": "192.168.1.1",
            "OS": "Debian Linux"
        }

    ],
    "Nexpose": {
        "Asset": [
            {
                "Address": "192.168.1.1",
                "Assessed": true,
                "AssetId": 2,
                "Exploits": 1,
                "LastScanDate": "2020-11-26T17:13:44.124Z",
                "LastScanId": 761,
                "Malware": 0,
                "Name": null,
                "OperatingSystem": "Linux 3.10",
                "RiskScore": 1605.670654296875,
                "Site": "Test",
                "Vulnerabilities": 7
            },
            {
                "Address": "10.0.0.2",
                "Assessed": true,
                "AssetId": 3,
                "Exploits": 0,
                "LastScanDate": "2020-07-27T12:40:34.550Z",
                "LastScanId": 402,
                "Malware": 0,
                "Name": null,
                "OperatingSystem": null,
                "RiskScore": 0,
                "Site": "Test",
                "Vulnerabilities": 0
            },
            {
                "Address": "8.8.8.8",
                "Assessed": false,
                "AssetId": 4,
                "Exploits": 0,
                "LastScanDate": "2020-07-29T11:11:57.552Z",
                "LastScanId": "-",
                "Malware": 0,
                "Name": null,
                "OperatingSystem": null,
                "RiskScore": 0,
                "Site": "",
                "Vulnerabilities": 0
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose assets
>|AssetId|Address|Name|Site|Exploits|Malware|OperatingSystem|Vulnerabilities|RiskScore|Assessed|LastScanDate|LastScanId|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 2 | 192.168.1.1 |  | Test | 1 | 0 | Linux 3.10 | 7 | 1605.670654296875 | true | 2020-11-26T17:13:44.124Z | 761 |
>| 3 | 10.0.0.2 |  | Test | 0 | 0 |  | 0 | 0.0 | true | 2020-07-27T12:40:34.550Z | 402 |
>| 4 | 8.8.8.8 |  |  | 0 | 0 |  | 0 | 0.0 | false | 2020-07-29T11:11:57.552Z | - |


### nexpose-search-assets
***
Returns all assets for which you have access that match the given search criteria.


#### Base Command

`nexpose-search-assets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Multiple criteria of &lt;string&gt; Filter to match assets, according to the Search Criteria API standard. multiple filters can be provided using ';' separator. For example: 'ip-address in range 1.2.3.4,1.2.3.8;host-name is myhost'. For more information regarding Search Criteria, refer to https://help.rapid7.com/insightvm/en-us/api/index.html#section/Overview/Responses. | Optional | 
| limit | integer &lt;int32&gt; The number of records retrieve. | Optional | 
| sort | Multiple criteria of &lt;string&gt; The criteria to sort the records by, in the format: property[,ASC\|DESC]. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'. | Optional | 
| ipAddressIs | &lt;string&gt; Search by a specific IP address. | Optional | 
| hostNameIs | &lt;string&gt; Search by a specific host name. | Optional | 
| riskScoreHigherThan | &lt;float&gt; Get all assets whose risk score is higher. | Optional | 
| vulnerabilityTitleContains | &lt;string&gt; Search by vulnerability title. | Optional | 
| siteIdIn | Multiple criteria of integer&lt;int32&gt; Search by site ids. | Optional | 
| match | &lt;string&gt; Operator to determine how to match filters. all requires that all filters match for an asset to be included. any requires only one filter to match for an asset to be included. Possible values are: all, any. Default is all. | Optional | 


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


#### Command Example
```!nexpose-search-assets ipAddressIs=192.168.1.1```

#### Context Example
```json
{
    "Endpoint": {
        "HostName": null,
        "IP": "192.168.1.1",
        "OS": "Linux 3.10"
    },
    "Nexpose": {
        "Asset": {
            "Address": "192.168.1.1",
            "Assessed": true,
            "AssetId": 2,
            "Exploits": 1,
            "LastScanDate": "2020-11-26T17:13:44.124Z",
            "LastScanId": 761,
            "Malware": 0,
            "Name": null,
            "OperatingSystem": "Linux 3.10",
            "RiskScore": 1605.670654296875,
            "Site": "XSOAR Site",
            "Vulnerabilities": 7
        }
    }
}
```

#### Human Readable Output

>### Nexpose assets
>|AssetId|Address|Site|Exploits|Malware|OperatingSystem|RiskScore|Assessed|LastScanDate|LastScanId|
>|---|---|---|---|---|---|---|---|---|---|
>| 2 | 192.168.1.1 | XSOAR Site | 1 | 0 | Linux 3.10 | 1605.670654296875 | true | 2020-11-26T17:13:44.124Z | 761 |


### nexpose-get-scan
***
Returns the specified scan.


#### Base Command

`nexpose-get-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Multiple criteria of integer &lt;int64&gt; Identifiers of scans. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | string | The name of the user that started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Vulnerabilities.Critical | number | The number of critical vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Moderate | number | The number of moderate vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Severe | number | The number of severe vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Total | number | The total number of vulnerabilities. | 


#### Command Example
``` !nexpose-get-scan id=15 ```

#### Context Example
```json
{
    "Nexpose": {
        "Scan": {
                "Assets": 32,
                "Completed": "2018-04-29T11:24:58.721Z",
                "Id": 15,
                "Message": null,
                "ScanName": "Sun 29 Apr 2018 11:17 AM",
                "ScanType": "Manual",
                "StartedBy": null,
                "Status": "finished",
                "TotalTime": "9.76666666667 minutes",
                "Vulnerabilities": {
                    "Critical": 0,
                    "Moderate": 48,
                    "Severe": 61,
                    "Total": 109
                }
            }
        }
    }
```

#### Human Readable Output

[![image](https://user-images.githubusercontent.com/35098543/44337970-24cfbd80-a485-11e8-97d5-5a0cd3d87260.png)](https://user-images.githubusercontent.com/35098543/44337970-24cfbd80-a485-11e8-97d5-5a0cd3d87260.png)


### nexpose-get-asset-vulnerability
***
Returns the details and possible remediations for an asset's given vulnerability.


#### Base Command

`nexpose-get-asset-vulnerability`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | integer &lt;int64&gt; The identifier of the asset. | Required | 
| vulnerabilityId | &lt;string&gt; The identifier of the vulnerability. | Required | 


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
| Nexpose.Asset.Vulnerability.CVSSScore | number | The CVSS score, which ranges from 0-10. | 
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
| CVE.ID | string | Common Vulnerabilities and Exposures ids | 


#### Command Example
``` !nexpose-get-asset-vulnerability id=37 vulnerabilityId=apache-httpd-cve-2017-3169 ```

#### Context Example
```json
{
        "CVE": {
            "ID": "CVE-2017-3169"
        },
        "Nexpose": {
            "Asset": {
                "AssetId": "37",
                "Vulnerability": [
                    {
                        "Added": "2017-06-20",
                        "CVES": [
                            "CVE-2017-3169"
                        ],
                        "CVSS": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        "CVSSScore": 7.5,
                        "CVSSV3": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "CVSSV3Score": 9.8,
                        "Categories": [
                            "Apache",
                            "Apache HTTP Server",
                            "Web"
                        ],
                        "Check": [
                            {
                                "Port": 8080,
                                "Proof": "Running HTTP serviceProduct HTTPD exists -- Apache HTTPD 2.4.6Vulnerable version of product HTTPD found -- Apache HTTPD 2.4.6",
                                "Protocol": "tcp",
                                "Since": "2018-04-29T11:36:54.597Z",
                                "Status": "vulnerable-version"
                            },
                            {
                                "Port": 443,
                                "Proof": "Running HTTPS serviceProduct HTTPD exists -- Apache HTTPD 2.4.6Vulnerable version of product HTTPD found -- Apache HTTPD 2.4.6",
                                "Protocol": "tcp",
                                "Since": "2018-04-29T11:36:54.597Z",
                                "Status": "vulnerable-version"
                            }
                        ],
                        "Id": "2017-3169",
                        "Modified": "2018-01-08",
                        "Published": "2017-06-20",
                        "RiskScore": 574.63,
                        "Severity": "Critical",
                        "Solution": [
                            {
                                "AdditionalInformation": "The latest version of Apache HTTPD is 2.4.34.\n\nMany platforms and distributions provide pre-built binary packages for Apache HTTP server. These pre-built packages are usually customized and optimized for a particular distribution, therefore we recommend that you use the packages if they are available for your operating system.",
                                "Estimate": "120.0 minutes",
                                "Steps": "Download and apply the upgrade from: http://archive.apache.org/dist/httpd/httpd-2.4.34.tar.gz (http://archive.apache.org/dist/httpd/httpd-2.4.34.tar.gz)",
                                "Summary": "Upgrade to the latest version of Apache HTTPD",
                                "Type": "rollup-patch"
                            }
                        ],
                        "Title": "Apache HTTPD: mod_ssl Null Pointer Dereference (CVE-2017-3169)"
                    }
                ]
            }
        }
    }
```

#### Human Readable Output

[![image](https://user-images.githubusercontent.com/35098543/44338298-31084a80-a486-11e8-881c-99dccae4d854.png)](https://user-images.githubusercontent.com/35098543/44338298-31084a80-a486-11e8-881c-99dccae4d854.png)


### nexpose-create-site
***
Creates a new site with the specified configuration.


#### Base Command

`nexpose-create-site`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | &lt;string&gt; The site name. Name must be unique. | Required | 
| description | &lt;string&gt; The site's description. | Optional | 
| assets | Multiple criteria of &lt;string&gt; Specify asset addresses to be included in site scans. | Required | 
| scanTemplateId | &lt;string&gt; The identifier of a scan template. Use nexpose-get-report-templates to get all templates,  default scan template is selected when not specified. . | Optional | 
| importance | &lt;string&gt; The site importance. Defaults to "normal" if not specified. Possible values are: very_low, low, normal, high, very_high. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Site.Id | number | The created site Id | 


#### Command Example
``` !nexpose-create-site name="site_test" assets="127.0.0.1" ```

#### Context Example
```json
{
    "Nexpose": {
        "Site": {
            "Id": 11
        }
    }
}

```
#### Human Readable Output
>### New site created
>|Id|
>|---|
>| 2 | 

### nexpose-delete-site
***
Deletes a site.


#### Base Command

`nexpose-delete-site`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Id of the site to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !nexpose-delete-site id=1258 ```

#### Human Readable Output
> Site 1258 deleted


### nexpose-get-sites
***
Retrieves accessible sites.


#### Base Command

`nexpose-get-sites`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | integer &lt;int32&gt; The number of records retrieve. | Optional | 
| sort | Multiple criteria of &lt;string&gt; The criteria to sort the records by, in the format: property[,ASC\|DESC]. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'. | Optional | 


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


#### Command Example
```!nexpose-get-sites```

#### Context Example
```json
{
    "Nexpose": {
        "Site": [
            {
                "Assets": 8,
                "Id": 1,
                "LastScan": "2020-10-01T22:43:17.717Z",
                "Name": "XSOAR",
                "Risk": 213967,
                "Type": "static",
                "Vulnerabilities": 484
            },
            {
                "Assets": 3,
                "Id": 1,
                "LastScan": "2020-11-26T17:13:54.117Z",
                "Name": "XSOAR Site",
                "Risk": 1606,
                "Type": "static",
                "Vulnerabilities": 7
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose sites
>|Id|Name|Assets|Vulnerabilities|Risk|Type|LastScan|
>|---|---|---|---|---|---|---|
>| 1 | XSOAR | 8 | 484 | 213967.0 | static | 2020-10-01T22:43:17.717Z |
>| 1 | XSOAR Site | 3 | 7 | 1606.0 | static | 2020-11-26T17:13:54.117Z |


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


#### Command Example
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
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose templates
>|Id|Name|Description|Type|
>|---|---|---|---|
>| audit-report | Audit Report | Provides comprehensive details about discovered assets, vulnerabilities, and users. | document |
>| baseline-comparison | Baseline Comparison | Compares current scan results to those of an earlier baseline scan. | document |


### nexpose-create-assets-report
***
Generates a new report on given assets according to a template and arguments.


#### Base Command

`nexpose-create-assets-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| assets | Multiple criteria of integer&lt;int64&gt; Asset ids to create the report on, comma separated. | Required | 
| template | &lt;string&gt; Report template id to create the report with. If none is provided, the first template available will be used. | Optional | 
| name | &lt;string&gt; The report name. | Optional | 
| format | &lt;string&gt; The report format, default is PDF. Possible values are: pdf, rtf, xml, html, text. | Optional | 
| download_immediately | If true, downloads the report immediately after the report is generated. The default is "true". If the report takes longer than 10 seconds to generate, set to "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry Id of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Extension | string | File extension of the report file. | 
| InfoFile.Info | string | Information about the report file. | 
| InfoFile.Size | number | Size of the report file (in bytes). | 
| InfoFile.Type | string | Type of the report file. | 
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Name | string | The report name. | 
| Nexpose.Report.Format | string | The report format. | 


#### Command Example
``` !nexpose-create-assets-report assets="1,2,3,4 ```

#### Context Example
```json
    {
        "InfoFile": {
            "EntryID": "759@cc00e449-9e7b-4609-8a68-1c8c01114562",
            "Extension": "pdf",
            "Info": "application/pdf",
            "Name": "report 2018-08-20 11:41:54.343571.pdf",
            "Size": 143959,
            "Type": "PDF document, version 1.4\n"
        }
    }
```

#### Human Readable Output
> Returned file: report 2018-08-20 11:41:54.343571.pdf [Download]()


### nexpose-create-sites-report
***
Generates a new report on given sites according to a template and arguments.


#### Base Command

`nexpose-create-sites-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sites | Multiple criteria of integer&lt;int32&gt; Site ids to create the report on, comma separated. | Required | 
| template | &lt;string&gt; Report template id to create the report with. If none is provided, the first template available will be used. | Optional | 
| name | &lt;string&gt; The report name. | Optional | 
| format | &lt;string&gt; The report format, default is PDF. Possible values are: pdf, rtf, xml, html, text. | Optional | 
| download_immediately | If true, downloads the report immediately after the report is generated. The default is "true". If the report takes longer than 10 seconds to generate, set to "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry Id of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Extension | string | File extension of the report file. | 
| InfoFile.Info | string | Information about the report file. | 
| InfoFile.Size | number | Size of the report file (in bytes). | 
| InfoFile.Type | string | Type of the report file. | 
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Name | string | The report name. | 
| Nexpose.Report.Format | string | The report format. | 

#### Command Example
```!nexpose-create-sites-report sites=1 name="XSOAR Report1"```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "2486@51c113de-6213-4aea-8beb-d4b88551f7f8",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "XSOAR Report.pdf",
        "Size": 212723,
        "Type": "PDF document, version 1.4"
    }
}
```
#### Human Readable Output
> Returned file: XSOAR Report.pdf [Download]()

### nexpose-create-scan-report
***
Generates a new report for a specified scan.


#### Base Command

`nexpose-create-scan-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan | integer &lt;int64&gt; The identifier of the scan. | Required | 
| template | &lt;string&gt; Report template id to create the report with. If none is provided, the first template available will be used. | Optional | 
| name | &lt;string&gt; The report name. | Optional | 
| format | &lt;string&gt; The report format, default is PDF. Possible values are: pdf, rtf, xml, html, text. | Optional | 
| download_immediately | If true, downloads the report immediately after the report is generated. The default is "true". If the report takes longer than 10 seconds to generate, set to "false". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry Id of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Extension | string | File extension of the report file. | 
| InfoFile.Info | string | Information about the report file. | 
| InfoFile.Size | number | Size of the report file (in bytes). | 
| InfoFile.Type | string | Type of the report file. | 
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Name | string | The report name. | 
| Nexpose.Report.Format | string | The report format. | 


#### Command Example
```!nexpose-create-scan-report scan=245 name="XSOAR test" download_immediately=false```

#### Context Example
```json
{
    "Nexpose": {
        "Report": {
            "Format": "pdf",
            "ID": "1987",
            "InstanceID": "1980",
            "Name": "XSOAR test"
        }
    }
}
```

#### Human Readable Output

>### Report Information
>|Format|ID|InstanceID|Name|
>|---|---|---|---|
>| pdf | 1987 | 1980 | XSOAR test |



### nexpose-start-site-scan
***
Starts a scan for the specified site.


#### Base Command

`nexpose-start-site-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| site | integer &lt;int32&gt; The identifier of the site. | Required | 
| hosts | Multiple criteria of &lt;string&gt; The hosts that should be included as a part of the scan. This should be a mixture of IP Addresses and host names as a comma separated string array. | Optional | 
| name | &lt;string&gt; The user-driven scan name for the scan. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | date | The name of the user that started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating | 
| Nexpose.Scan.Vulnerabilities.Critical | number | The number of critical vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Moderate | number | The number of moderate vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Severe | number | The number of severe vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Total | number | The total number of vulnerabilities. | 


#### Command Example
``` !nexpose-start-site-scan site=2 hosts=127.0.0.1 ```

#### Context Example
```json
{
    "Nexpose": {
        "Scan": {
            "Assets": 0,
            "Completed": null,
            "Id": 89391,
            "Message": null,
            "ScanName": "scan 2018-08-20 11:54:59.673365",
            "ScanType": "Manual",
            "StartedBy": null,
            "Status": "running",
            "TotalTime": "0 minutes",
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
[![image](https://user-images.githubusercontent.com/35098543/44340427-7ed48100-a48d-11e8-89ec-dbe8b8958f8c.png)](https://user-images.githubusercontent.com/35098543/44340427-7ed48100-a48d-11e8-89ec-dbe8b8958f8c.png)


### nexpose-start-assets-scan
***
Starts a scan for specified asset IP addresses and host names.


#### Base Command

`nexpose-start-assets-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| IPs | Multiple criteria of &lt;string&gt; IP addresses of assets, comma separated. | Optional | 
| hostNames | Multiple criteria of &lt;string&gt; Host names of assets, comma separated. | Optional | 
| name | &lt;string&gt; The user-driven scan name for the scan. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | date | The name of the user that started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating | 
| Nexpose.Scan.Vulnerabilities.Critical | number | The number of critical vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Moderate | number | The number of moderate vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Severe | number | The number of severe vulnerabilities. | 
| Nexpose.Scan.Vulnerabilities.Total | numberFF | The total number of vulnerabilities. | 


#### Command Example
```!nexpose-start-assets-scan IPs=127.0.0.1```

##### Context Example
```json
{
    "Nexpose": {
        "Scan": {
            "Assets": 0,
            "Completed": null,
            "Id": 89410,
            "Message": null,
            "ScanName": "scan 2018-08-20 12:31:52.951818",
            "ScanType": "Manual",
            "StartedBy": null,
            "Status": "running",
            "TotalTime": "0 minutes",
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

##### Human Readable Output

[![image](https://user-images.githubusercontent.com/35098543/44340807-b68ff880-a48e-11e8-827d-50ed6dff3798.png)](https://user-images.githubusercontent.com/35098543/44340807-b68ff880-a48e-11e8-827d-50ed6dff3798.png)


### nexpose-stop-scan
***
Stop the specified scan


#### Base Command

`nexpose-stop-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | integer &lt;int64&gt; ID of the scan to stop. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !nexpose-stop-scan id=143200 ```

#### Human Readable Output
> Successfully stopped the scan


### nexpose-pause-scan
***
Pause the specified scan


#### Base Command

`nexpose-pause-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | integer &lt;int64&gt; ID of the scan to pause. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !nexpose-pause-scan id=143200 ```

#### Human Readable Output
> Successfully paused the scan



### nexpose-resume-scan
***
Resume the specified scan


#### Base Command

`nexpose-resume-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | integer &lt;int64&gt; ID of the scan to resume. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !nexpose-resume-scan id=143200 ```

#### Human Readable Output
> Successfully resumed the scan


### nexpose-get-scans
***
Returns a list of scans.


#### Base Command

`nexpose-get-scans`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| active | &lt;boolean&gt; Return active or past scans. Possible values are: true, false. Default is true. | Optional | 
| limit | integer &lt;int32&gt; The number of records retrieve. Default is 10. | Optional | 
| sort | Multiple criteria of &lt;string&gt; The criteria to sort the records by, in the format: property[,ASC\|DESC]. The default sort order is ascending. Multiple sort criteria can be specified using multiple sort query parameters separated by a ';'. For example: 'riskScore,DESC;hostName,ASC'. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Scan.Id | number | The identifier of the scan. | 
| Nexpose.Scan.ScanType | string | The scan type \(automated, manual, scheduled\). | 
| Nexpose.Scan.StartedBy | date | The name of the user that started the scan. | 
| Nexpose.Scan.Assets | number | The number of assets found in the scan | 
| Nexpose.Scan.TotalTime | string | The duration of the scan in minutes. | 
| Nexpose.Scan.Completed | date | The end time of the scan in ISO8601 format. | 
| Nexpose.Scan.Status | string | The scan status. Valid values are aborted, unknown, running, finished, stopped, error, paused, dispatched, integrating | 


#### Command Example
```!nexpose-get-scans active=false```

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
                "TotalTime": "5.26666666667 minutes"
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
                "TotalTime": "1.51666666667 minutes"
            },
            {
                "Assets": 1,
                "Completed": "2020-04-20T13:57:00.647Z",
                "Id": 3,
                "Message": null,
                "ScanName": "Test scan",
                "ScanType": "Manual",
                "StartedBy": null,
                "Status": "finished",
                "TotalTime": "10.7833333333 minutes"
            }
        ]
    }
}
```

#### Human Readable Output

>### Nexpose scans
>|Id|ScanType|ScanName|Assets|TotalTime|Completed|Status|
>|---|---|---|---|---|---|---|
>| 1 | Manual | Tue 03 Dec 2019 10:47 PM | 0 | 5.26666666667 minutes | 2019-12-03T20:48:01.368Z | finished |
>| 2 | Manual | Tue 03 Dec 2019 10:52 PM | 0 | 1.51666666667 minutes | 2019-12-03T20:53:09.453Z | finished |
>| 3 | Manual | Test scan | 1 | 10.7833333333 minutes | 2020-04-20T13:57:00.647Z | finished |


### nexpose-download-report
***
Returns the generated report.


#### Base Command

`nexpose-download-report`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The identifier of the report. | Required | 
| instance_id | The identifier of the report instance. Also supports the "latest" keyword. | Required | 
| name | The report name. | Optional | 
| format | The report format, default is pdf. Possible values are: pdf, rtf, xml, html, text. Default is pdf. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.EntryId | string | Entry Id of the report file. | 
| InfoFile.Name | string | Name of the report file. | 
| InfoFile.Extension | string | File extension of the report file. | 
| InfoFile.Info | string | Information about the report file. | 
| InfoFile.Size | number | Size of the report file (in bytes). | 
| InfoFile.Type | string | Type of the report file. | 

#### Command Example
```!nexpose-download-report report_id=1983 instance_id=1976```

#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "2498@51c113de-6213-4aea-8beb-d4b88551f7f8",
        "Extension": "pdf",
        "Info": "application/pdf",
        "Name": "report 2021-02-01 08:31:58.023348.pdf",
        "Size": 212722,
        "Type": "PDF document, version 1.4"
    }
}
```

### nexpose-get-report-status
***
Returns the status of a report generation process.


#### Base Command

`nexpose-get-report-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The identifier of the report. | Required | 
| instance_id | The identifier of the report instance. Also supports the "latest" keyword. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Nexpose.Report.ID | string | The identifier of the report. | 
| Nexpose.Report.InstanceID | string | The identifier of the report instance. | 
| Nexpose.Report.Status | string | The status of the report generation process. Valid values: "aborted", "failed", "complete", "running", "unknown" | 

#### Command Example
```!nexpose-get-report-status report_id=1983 instance_id=1976```

#### Context Example
```json
{
    "Nexpose": {
        "Report": {
            "ID": "1983",
            "InstanceID": "1976",
            "Status": "complete"
        }
    }
}
```

#### Human Readable Output

>### Report Generation Status
>|ID|InstanceID|Status|
>|---|---|---|
>| 1983 | 1976 | complete |


Troubleshooting
-

-   In case of a timeout error, the API server address or port may be incorrect.
-   In case of a `400 Bad Request` error, incorrect values were provided to an API resource, e.g incorrect search fields.
-   In case of a `401 Unauthorized` error, incorrect credentials were provided or there are insufficient privileges for a specific resource.
-   In case of a `404 Not Found` error, a specified resource was not found, e.g a vulnerability that doesn't exist in an asset.
