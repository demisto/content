Qintel’s Patch Management Intelligence (PMI) product simplifies the vulnerability management process by providing vital context around reported Common Vulnerabilities and Exposures. With this integration, users can query PMI to surface CVEs that are known by Qintel to be leveraged by eCrime and Nation State adversaries.
This integration was integrated and tested with version 0.16.0 of PMI

## Configure QintelPMI in Cortex


| **Parameter** | **Required** |
| --- | --- |
| PMI API URL (optional) | False |
| Qintel Credentials | True |
| Password | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cve

***
Queries Qintel for CVE intelligence


#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | List of CVEs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE, for example: CVE-2015-1653 | 
| CVE.CVSS | String | The CVSS of the CVE, for example: 10.0 | 
| CVE.Published | Date | The timestamp of when the CVE was published. | 
| CVE.Modified | Date | The timestamp of when the CVE was last modified. | 
| CVE.Description | String | A description of the CVE. | 
| Qintel.CVE.ID | string | The ID of the CVE | 
| Qintel.CVE.AffectedSystem | string | Systems affected by the CVE | 
| Qintel.CVE.AffectedVersions | string | Systems affected by the CVE | 
| Qintel.CVE.LastObserved | string | Last threat actor observation time | 
| Qintel.CVE.Observations | array | List of observations | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 


#### Command Example

```!cve cve=CVE-2021-0123```

#### Context Example

```json
{
    "CVE": {
        "CVSS": "None",
        "Description": "None",
        "ID": "CVE-2021-0123",
        "Modified": "None",
        "Published": "None"
    },
    "DBotScore": {
        "Indicator": "CVE-2021-0123",
        "Score": 0,
        "Type": "cve",
        "Vendor": null
    },
    "Qintel": {
        "CVE": {
            "AffectedSystem": "Example System",
            "AffectedVersions": "1.0, 1.1",
            "LastObserved": "2021-04-20 04:00:00",
            "Observations": [
                {
                    "actor": "Unattributed Threat Actor",
                    "actor_type": "other",
                    "date_observed": "2021-04-20 04:00:00",
                    "exploit_notes": null,
                    "exploit_type": "cve"
                }
            ],
            "id": "CVE-2021-0123"
        }
    }
}
```

#### Human Readable Output

>### Qintel vulnerability results for: CVE-2021-0123

>**Vulnerability in Example System affecting versions: 1.0, 1.1**
>**Last observed: 2021-04-20 04:00:00**
>|actor|actor_type|exploit_type|exploit_notes|date_observed|
>|---|---|---|---|---|
>| Unattributed Threat Actor | other | cve |  | 2021-04-20 04:00:00 |
