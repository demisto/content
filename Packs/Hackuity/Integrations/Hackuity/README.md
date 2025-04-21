From a war-room, query your Hackuity cockpit in order to seamlessly retrieve information related to your vulnerability stock.
This integration was integrated and tested with version 1.25.0 of Hackuity

## Configure Hackuity in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Corporate server URL | True |
| Namespace | True |
| Api key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### hackuity-search-findings
***
Search for findings in Hackuity.


#### Base Command

`hackuity-search-findings`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_name | The name of the asset. | Optional | 
| asset_type | The type of the asset if the asset name is specified (by default, restricts to IPs &amp; domains). | Optional | 
| attribute | An attribute value. | Optional | 
| cvss_min | The minimum CVSS (included). | Optional | 
| cvss_max | The maximum CVSS (excluded). | Optional | 
| limit | The maximum number of items to return. Default is 20. | Optional | 
| trs_min | The minimum TRS (included). | Optional | 
| trs_max | The maximum TRS (excluded). | Optional | 
| vuln_type | The vulnerability type (ID). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hackuity.Findings.Asset.ID | String | The ID of the asset | 
| Hackuity.Findings.Asset.Name | String | The name of the asset | 
| Hackuity.Findings.Asset.Type | String | The type of the asset | 
| Hackuity.Findings.Attributes | Unknown | The attributes of the finding | 
| Hackuity.Findings.Score.CVSS | Number | The CVSS of the finding | 
| Hackuity.Findings.Score.TRS | Number | The TRS of the finding | 
| Hackuity.Findings.ID | String | The ID of the finding | 
| Hackuity.Findings.Status.Ignored | Boolean | Whether the finding is ignored | 
| Hackuity.Findings.Status.State | String | The state of the finding | 
| Hackuity.Findings.Status.SubState | String | The sub-state of the finding | 
| Hackuity.Findings.Status.LastClosedAt | Date | The date of the last time the finding was closed |
| Hackuity.Findings.VulnType.ID | String | The ID of the vulnerability type | 
| Hackuity.Findings.VulnType.Name | String | The name of the vulnerability type | 

#### Command example
```!hackuity-search-findings asset_name=example.com```
#### Context Example
```json
{
    "Hackuity": {
        "Findings": [
            {
                "Asset": {
                    "ID": "NKTVm2RU4606",
                    "Name": "example.com",
                    "Type": "DOMAIN"
                },
                "Attributes": {
                    "cve_id": "CVE-2015-6550"
                },
                "ID": "j6SMpiorqFi1",
                "Score": {
                    "CVSS": 10,
                    "TRS": 693
                },
                "Status": {
                    "Ignored": false,
                    "State": "CLOSED",
                    "SubState": "FIXED"
                },
                "VulnType": {
                    "ID": "common-vulnerability-exposure",
                    "Name": "Common Vulnerability and Exposure (CVE)"
                }
            },
            {
                "Asset": {
                    "ID": "NKTVm2RU4606",
                    "Name": "example.com",
                    "Type": "DOMAIN"
                },
                "Attributes": {
                    "cve_id": "CVE-2015-6551"
                },
                "ID": "ag8FkNpubY7N",
                "Score": {
                    "CVSS": 10,
                    "TRS": 693
                },
                "Status": {
                    "Ignored": false,
                    "State": "CLOSED",
                    "SubState": "FIXED"
                },
                "VulnType": {
                    "ID": "common-vulnerability-exposure",
                    "Name": "Common Vulnerability and Exposure (CVE)"
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Findings
>|Asset|VulnType|Attributes|Score|Status|
>|---|---|---|---|---|
>| ID: NKTVm2RU4606<br/>Name: example.com<br/>Type: DOMAIN | ID: common-vulnerability-exposure<br/>Name: Common Vulnerability and Exposure (CVE) | cve_id: CVE-2015-6550 | CVSS: 10.0<br/>TRS: 693 | Ignored: false<br/>State: CLOSED<br/>SubState: FIXED |
>| ID: NKTVm2RU4606<br/>Name: example.com<br/>Type: DOMAIN | ID: common-vulnerability-exposure<br/>Name: Common Vulnerability and Exposure (CVE) | cve_id: CVE-2015-6551 | CVSS: 10.0<br/>TRS: 693 | Ignored: false<br/>State: CLOSED<br/>SubState: FIXED |


### hackuity-search-vulndb-vulnerabilities
***
Search for vulndb vulnerabilities in Hackuity.


#### Base Command

`hackuity-search-vulndb-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_name | The name of the asset. | Optional | 
| asset_type | The type of the asset if the asset name is specified (by default, restricts to IPs &amp; domains). | Optional | 
| attribute | An attribute value. | Optional | 
| cvss_min | The minimum CVSS (included). | Optional | 
| cvss_max | The maximum CVSS (excluded). | Optional | 
| limit | The maximum number of items to return. Default is 20. | Optional | 
| trs_min | The minimum TRS (included). | Optional | 
| trs_max | The maximum TRS (excluded). | Optional | 
| vuln_type | The vulnerability type (ID). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hackuity.Vulnerabilities.Attributes | String | The attributes of the vulnerability | 
| Hackuity.Vulnerabilities.Score.CVSS | String | The CVSS of the vulnerability | 
| Hackuity.Vulnerabilities.Score.TRS | String | The TRS of the vulnerability | 
| Hackuity.Vulnerabilities.Description | String | The description of the vulnerability | 
| Hackuity.Vulnerabilities.ID | String | The ID of the vulnerability | 
| Hackuity.Vulnerabilities.Seen.First | Date | The date of the first time the vulnerability has been seen | 
| Hackuity.Vulnerabilities.Findings.Total | String | The total number of findings on this vulnerability | 
| Hackuity.Vulnerabilities.Findings.Open | String | The number of open findings on this vulnerability | 
| Hackuity.Vulnerabilities.Findings.Closed | String | The number of closed findings on this vulnerability | 
| Hackuity.Vulnerabilities.Findings.Ignored | String | The number of ignored findings on this vulnerability | 
| Hackuity.Vulnerabilities.VulnType.ID | String | The ID of the vulnerability type | 
| Hackuity.Vulnerabilities.VulnType.Name | String | The name of the vulnerability type | 

#### Command example
```!hackuity-search-vulndb-vulnerabilities asset_name=example.com```
#### Context Example
```json
{
    "Hackuity": {
        "Vulnerabilities": [
            {
                "Attributes": [
                    {
                        "key": "cve_id",
                        "value": "CVE-2020-0705"
                    }
                ],
                "Description": "An information disclosure vulnerability exists when the Windows Network Driver Interface Specification (NDIS) improperly handles memory.To exploit this vulnerability, an attacker would first have to gain execution on the victim system, aka 'Windows Network Driver Interface Specification (NDIS) Information Disclosure Vulnerability'.",
                "Findings": {
                    "Closed": 0,
                    "Ignored": 0,
                    "Open": 1,
                    "Total": 1
                },
                "ID": "hy#asset/NKTVm2RU4606:LWxh4Y7UpCUw",
                "Score": {
                    "CVSS": 9,
                    "TRS": 636
                },
                "Seen": {
                    "First": "2021-03-03T07:56:07Z"
                },
                "VulnTypes": [
                    {
                        "ID": "common-vulnerability-exposure",
                        "Name": "Common Vulnerability and Exposure (CVE)"
                    }
                ]
            },
            {
                "Attributes": [
                    {
                        "key": "cve_id",
                        "value": "CVE-2020-0958"
                    }
                ],
                "Description": "An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0956, CVE-2020-0957.",
                "Findings": {
                    "Closed": 0,
                    "Ignored": 0,
                    "Open": 1,
                    "Total": 1
                },
                "ID": "hy#asset/NKTVm2RU4606:mTYugfvOy9yt",
                "Score": {
                    "CVSS": 9,
                    "TRS": 636
                },
                "Seen": {
                    "First": "2021-03-03T07:56:07Z"
                },
                "VulnTypes": [
                    {
                        "ID": "common-vulnerability-exposure",
                        "Name": "Common Vulnerability and Exposure (CVE)"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### VulnDB vulnerabilities
>|VulnTypes|Description|Attributes|Score|Findings|Seen|
>|---|---|---|---|---|---|
>| {'ID': 'common-vulnerability-exposure', 'Name': 'Common Vulnerability and Exposure (CVE)'} | An information disclosure vulnerability exists when the Windows Network Driver Interface Specification (NDIS) improperly handles memory.To exploit this vulnerability, an attacker would first have to gain execution on the victim system, aka 'Windows Network Driver Interface Specification (NDIS) Information Disclosure Vulnerability'. | {'key': 'cve_id', 'value': 'CVE-2020-0705'} | CVSS: 9.0<br/>TRS: 636 | Total: 1<br/>Open: 1<br/>Closed: 0<br/>Ignored: 0 | First: 2021-03-03T07:56:07Z |
>| {'ID': 'common-vulnerability-exposure', 'Name': 'Common Vulnerability and Exposure (CVE)'} | An elevation of privilege vulnerability exists in Windows when the Windows kernel-mode driver fails to properly handle objects in memory, aka 'Win32k Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-0956, CVE-2020-0957. | {'key': 'cve_id', 'value': 'CVE-2020-0958'} | CVSS: 9.0<br/>TRS: 636 | Total: 1<br/>Open: 1<br/>Closed: 0<br/>Ignored: 0 | First: 2021-03-03T07:56:07Z |


### hackuity-search-provider-vulnerabilities
***
Search for provider vulnerabilities in Hackuity.


#### Base Command

`hackuity-search-provider-vulnerabilities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_name | The name of the asset. | Optional | 
| asset_type | The type of the asset if the asset name is specified (by default, restricts to IPs &amp; domains). | Optional | 
| attribute | An attribute value. | Optional | 
| cvss_min | The minimum CVSS (included). | Optional | 
| cvss_max | The maximum CVSS (excluded). | Optional | 
| limit | The maximum number of items to return. Default is 20. | Optional | 
| trs_min | The minimum TRS (included). | Optional | 
| trs_max | The maximum TRS (excluded). | Optional | 
| vuln_type | The vulnerability type (ID). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hackuity.Vulnerabilities.Attributes | String | The attributes of the vulnerability | 
| Hackuity.Vulnerabilities.Score.CVSS | String | The CVSS of the vulnerability | 
| Hackuity.Vulnerabilities.Score.TRS | String | The TRS of the vulnerability | 
| Hackuity.Vulnerabilities.Description | String | The description of the vulnerability | 
| Hackuity.Vulnerabilities.ID | String | The ID of the vulnerability | 
| Hackuity.Vulnerabilities.Seen.First | Date | The date of the first time the vulnerability has been seen | 
| Hackuity.Vulnerabilities.Findings.Total | String | The total number of findings on this vulnerability | 
| Hackuity.Vulnerabilities.Findings.Open | String | The number of open findings on this vulnerability | 
| Hackuity.Vulnerabilities.Findings.Closed | String | The number of closed findings on this vulnerability | 
| Hackuity.Vulnerabilities.Findings.Ignored | String | The number of ignored findings on this vulnerability | 
| Hackuity.Vulnerabilities.VulnType.ID | String | The ID of the vulnerability type | 
| Hackuity.Vulnerabilities.VulnType.Name | String | The name of the vulnerability type | 

#### Command example
```!hackuity-search-provider-vulnerabilities asset_name=example.com```
#### Context Example
```json
{
    "Hackuity": {
        "Vulnerabilities": [
            {
                "Attributes": [],
                "Description": "KB4561669: Windows 7 and Windows Server 2008 R2 June 2020 Security Update",
                "Findings": {
                    "Closed": 2,
                    "Ignored": 0,
                    "Open": 8,
                    "Total": 10
                },
                "ID": "hy#asset/NKTVm2RU4606:QHBzm5XEkjIp",
                "Score": {
                    "CVSS": 9,
                    "TRS": 636
                },
                "Seen": {
                    "First": "2021-03-03T07:56:07Z"
                },
                "VulnTypes": [
                    {
                        "ID": "common-vulnerability-exposure",
                        "Name": "Common Vulnerability and Exposure (CVE)"
                    }
                ]
            },
            {
                "Attributes": [],
                "Description": "KB4541500: Windows 7 and Windows Server 2008 R2 March 2020 Security Update",
                "Findings": {
                    "Closed": 1,
                    "Ignored": 0,
                    "Open": 15,
                    "Total": 16
                },
                "ID": "hy#asset/NKTVm2RU4606:rX8JQJaETpoq",
                "Score": {
                    "CVSS": 9,
                    "TRS": 636
                },
                "Seen": {
                    "First": "2021-03-03T07:56:07Z"
                },
                "VulnTypes": [
                    {
                        "ID": "common-vulnerability-exposure",
                        "Name": "Common Vulnerability and Exposure (CVE)"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>### Provider vulnerabilities
>|VulnTypes|Description|Attributes|Score|Findings|Seen|
>|---|---|---|---|---|---|
>| {'ID': 'common-vulnerability-exposure', 'Name': 'Common Vulnerability and Exposure (CVE)'} | KB4561669: Windows 7 and Windows Server 2008 R2 June 2020 Security Update |  | CVSS: 9.0<br/>TRS: 636 | Total: 10<br/>Open: 8<br/>Closed: 2<br/>Ignored: 0 | First: 2021-03-03T07:56:07Z |
>| {'ID': 'common-vulnerability-exposure', 'Name': 'Common Vulnerability and Exposure (CVE)'} | KB4541500: Windows 7 and Windows Server 2008 R2 March 2020 Security Update |  | CVSS: 9.0<br/>TRS: 636 | Total: 16<br/>Open: 15<br/>Closed: 1<br/>Ignored: 0 | First: 2021-03-03T07:56:07Z |


### hackuity-dashboard-widgets
***
List the widgets in the default dashboard of the user.


#### Base Command

`hackuity-dashboard-widgets`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hackuity.Dashboard.Widgets.ID | String | The ID of the widget | 
| Hackuity.Dashboard.Widgets.Params | Unknown | The configuration of the widget | 
| Hackuity.Dashboard.Widgets.Type | String | The type of the widget | 

#### Command example
```!hackuity-dashboard-widgets```
#### Context Example
```json
{
    "Hackuity": {
        "Dashboard": {
            "Widgets": [
                {
                    "ID": "abcd3fgh1jklmn0pqrstuv",
                    "Params": {
                        "nbDaysToCompare": 28,
                        "withTotal": true
                    },
                    "Type": "ASSETS_OVERVIEW"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Dashboard widgets
>|ID|Type|Params|
>|---|---|---|
>| abcd3fgh1jklmn0pqrstuv | ASSETS_OVERVIEW | nbDaysToCompare: 28<br/>withTotal: true |


### hackuity-dashboard-data
***
Get the data of a dashboard widget


#### Base Command

`hackuity-dashboard-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| widget_id | The ID of the widget. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hackuity.Dashboard.Data | Unknown | The data of the widget | 

#### Command example
```!hackuity-dashboard-data widget_id=abcd3fgh1jklmn0pqrstuv```
#### Context Example
```json
{
    "Hackuity": {
        "Dashboard": {
            "Data": {
                "abcd3fgh1jklmn0pqrstuv": {
                    "currentNbAssets": 456,
                    "previousNbAssets": 123
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Dashboard widget data (abcd3fgh1jklmn0pqrstuv)
>|currentNbAssets|previousNbAssets|
>|---|---|
>| 456 | 123 |
