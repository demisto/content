Searches for CVE information using circl.lu.
This integration was integrated and tested with version xx of CVE Search v2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-cve-search-v2).

## Configure CVE Search v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CVE Search v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL | True |
    | Use system proxy settings | False |
    | Trust any certificate (not secure) | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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

### cve

***
Returns CVE information by CVE ID.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | The CVE ID. For example: CVE-2014-1234. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | number | The CVSS score of the CVE. | 
| CVE.Published | Date | The date the CVE was published. | 
| CVE.Modified | Date | The date that the CVE was last modified. | 
| CVE.Description | String | The description of the CVE. | 
| DBotScore.Indicator | String | The indicator value. | 
| DBotScore.Score | Number | The indicator score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor reporting the score of the indicator. | 


##### Command Example
```!cve cve_id=CVE-2014-1234```

##### Context Example
```
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