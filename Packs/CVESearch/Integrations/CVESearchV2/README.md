## Overview
---

Search CVE Information - powered by circl.lu
This integration was integrated and tested with CVE Search (Version 2.1).

## Use Cases
1. Getting information about a specific cve
2. Getting the latest published cve's 
---

## Configure CVE Search on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for CVE Search v2.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Server URL__
4. Click __Test__ to validate the URLs and connection.

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. cve-latest
2. cve

### 1. cve-latest
---
Retruns the latest updated CVEs.

##### Base Command

`cve-latest`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | String | The CVSS score of the CVE. | 
| CVE.Published | Date | The date the CVE was published. | 
| CVE.Modified | Date | When CVE was last modified. | 
| CVE.Description | String | The description of the CVE. | 


##### Command Example
```!cve-latest limit=2```

##### Context Example
```
{
    "CVE": [
        {
            "ID": "CVE-2020-7998", 
            "Published": "2020-01-28T05:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T05:15:00", 
            "Description": "An arbitrary file upload vulnerability has been discovered in the Super File Explorer app 1.0.1 for iOS. The vulnerability is located in the developer path that is accessible and hidden next to the root path. By default, there is no password set for the FTP or Web UI service."
        }, 
        {
            "ID": "CVE-2020-7997", 
            "Published": "2020-01-28T05:15:00", 
            "CVSS": 5, 
            "Modified": "2020-01-28T05:15:00", 
            "Description": "ASUS WRT-AC66U 3 RT 3.0.0.4.372_67 devices allow XSS via the Client Name field to the Parental Control feature."
        }, 
    ]
}
```

##### Human Readable Output
Integration log: {'CVE(val.ID === obj.ID)': [{'ID': 'CVE-2020-7998', 'CVSS': 5.0, 'Published': '2020-01-28T05:15:00', 'Modified': '2020-01-28T05:15:00', 'Description': 'An arbitrary file upload vulnerability has been discovered in the Super File Explorer app 1.0.1 for iOS. The vulnerability is located in the developer path that is accessible and hidden next to the root path. By default, there is no password set for the FTP or Web UI service.'}, {'ID': 'CVE-2020-7997', 'CVSS': 5.0, 'Published': '2020-01-28T05:15:00', 'Modified': '2020-01-28T05:15:00', 'Description': 'ASUS WRT-AC66U 3 RT 3.0.0.4.372_67 devices allow XSS via the Client Name field to the Parental Control feature.'}]}
### cicle.lu Latest CVEs
|CVSS|Description|ID|Modified|Published|
|---|---|---|---|---|
| 5.0 | An arbitrary file upload vulnerability has been discovered in the Super File Explorer app 1.0.1 for iOS. The vulnerability is located in the developer path that is accessible and hidden next to the root path. By default, there is no password set for the FTP or Web UI service. | CVE-2020-7998 | 2020-01-28T05:15:00 | 2020-01-28T05:15:00 |
| 5.0 | ASUS WRT-AC66U 3 RT 3.0.0.4.372_67 devices allow XSS via the Client Name field to the Parental Control feature. | CVE-2020-7997 | 2020-01-28T05:15:00 | 2020-01-28T05:15:00 |

### 2. cve
---
Search CVE by ID

##### Base Command

`cve`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | A comma separated list of CVE IDs to search. | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | String | The CVSS score of the CVE. | 
| CVE.Published | Date | The date the CVE was published. | 
| CVE.Modified | Date | The date the CVE was last modified. | 
| CVE.Description | String | The description of the CVE. | 


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

##### Human Readable Output
Integration log: {'CVE(val.ID === obj.ID)': [{'ID': 'CVE-2014-1234', 'CVSS': 2.1, 'Published': '2014-01-10T12:02:00', 'Modified': '2014-01-10T17:57:00', 'Description': 'The paratrooper-newrelic gem 1.0.1 for Ruby allows local users to obtain the X-Api-Key value by listing the curl process.'}]}
### CVE Search results
|CVSS|Description|ID|Modified|Published|
|---|---|---|---|---|
| 2.1 | The paratrooper-newrelic gem 1.0.1 for Ruby allows local users to obtain the X-Api-Key value by listing the curl process. | CVE-2014-1234 | 2014-01-10T17:57:00 | 2014-01-10T12:02:00 |
