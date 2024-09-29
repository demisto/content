Searches for CVE information using [circl.lu](https://www.circl.lu/services/cve-search/).

## Configure CIRCL CVE Search in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cve-latest

***
Returns the latest updated CVEs.

#### Base Command

`cve-latest`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of CVEs to display. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- |----------| --- |
| CVE.ID | String   | The ID of the CVE. |
| CVE.CVSS | Number   | The CVSS score of the CVE. |
| CVE.Published | Date     | The date the CVE was published. |
| CVE.Modified | Date     | The date that the CVE was last modified. |
| CVE.Description | String   | The description of the CVE. |
| DBotScore.Indicator | String   | The indicator value. |
| DBotScore.Score | Number   | The indicator score. |
| DBotScore.Type | String   | The indicator type. |
| DBotScore.Vendor | String   | The vendor reporting the score of the indicator. |

##### Human Readable Output

|  |  |
| --- | --- |
| CVSS | The CVE CVSS Score |
| Description | CVE Description |
| ID | CVE ID |
| Modified | The date the CVE was modified |
| Published | The date the CVE was published |

### cve

***
Returns CVE information by CVE ID.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | A comma-separated list of CVE IDs to search | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. |
| CVE.CVSS.Score | Number | The CVSS score of the CVE. |
| CVE.CVSS.Vector | String | The CVSS vector of the CVE. |
| CVE.CVSS.Table | Dict | The CVSS table of the CVE. |
| CVE.Published | Date | The date the CVE was published. |
| CVE.Modified | Date | The date that the CVE was last modified. |
| CVE.Description | String | The description of the CVE. |
| CVE.vulnerableconfigurations | Dict | Vulnerable configurations in CPE format |
| CVE.vulnerableproduct | Dict | Vulnerable products in CPE format |
| CVE.Tags | List | A list of tags |
| CVE.Relationships | List | List of relationships for the CVE |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |


##### Command Example

`!cve cve=CVE-2014-1234`

##### Context Example

```python
{
    "CVE": [
        {
            "ID": "CVE-2014-1234",
            "Published": "2014-01-10T12:02:00",
            "CVSS": 2.1,
            "Modified": "2014-01-10T17:57:00",
            "Description": "The paratrooper-newrelic gem 1.0.1 for Ruby allows local users to obtain the X-Api-Key value by listing the curl process."
        }
    ]
}
```

##### Human Readable Output

|  |  |
| --- | --- |
| CVSS | 4.3 |
| Description | XSS in livehelperchat in GitHub repository livehelperchat/livehelperchat prior to 3.97. This vulnerability has the potential to deface websites, result in compromised user accounts, and can run malicious code on web pages, which can lead to a compromise of the userâ€™s device. |
| ID | CVE-2022-1234 |
| Modified | 2022-04-13T15:03:00 |
| Published |2022-04-06T04:15:00 |