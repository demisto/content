Queries the public repository of PAN-OS CVEs.
This integration was integrated and tested with the [beta](https://security.paloaltonetworks.com/api) version 1 of the Palo Alto Networks Security Advisories API.

The Palo Alto Networks Security Advisories API is a representation of the GUI; https://security.paloaltonetworks.com/


## Configure Palo Alto Networks Security Advisories in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Default URL for PAN-OS advisories website | False |
| Fetch indicator product name | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pan-advisories-get-advisories
***
Gets all the advisories for the given product.


#### Base Command

`pan-advisories-get-advisories`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product | Product name to search for advisories. | Required | 
| sort | Sort returned advisories by this value, can be date, cvss, etc. Leading hyphpen (-) indicates reverse search. Default is -date. | Optional | 
| severity | Filter advisories to this severity level only. Possible values are: HIGH, CRITICAL, MEDIUM, LOW, NONE. | Optional | 
| q | Text search query. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PANSecurityAdvisory.Advisory.data_type | Unknown | The type of advisory this is | 
| PANSecurityAdvisory.Advisory.data_format | Unknown | The format of the advisory, such as MITRE | 
| PANSecurityAdvisory.Advisory.cve_id | Unknown | The ID of the CVE described by this advisory | 
| PANSecurityAdvisory.Advisory.cve_date_public | Unknown | The date this CVE was released | 
| PANSecurityAdvisory.Advisory.cve_title | Unknown | The name of this CVE | 
| PANSecurityAdvisory.Advisory.description | Unknown | Human readable description of Advisory | 
| PANSecurityAdvisory.Advisory.cvss_score | Unknown | The CVSS Score | 
| PANSecurityAdvisory.Advisory.cvss_severity | Unknown | The CVSS Severity | 
| PANSecurityAdvisory.Advisory.cvss_vector_string | Unknown | The CVSS Vector string | 
| PANSecurityAdvisory.Advisory.affected_version_list | Unknown | List of affected versions strings | 

#### Command example
```!pan-advisories-get-advisories product="PAN-OS" q=CVE-2022-0778```
#### Context Example
```json
{
    "PANSecurityAdvisory": {
        "Advisory": [
            {
                "affected_version_list": [
                    "Prisma Access 3.0",
                    "Prisma Access 2.2",
                    "Prisma Access 2.1",
                    "PAN-OS 10.2.0",
                    "PAN-OS 10.2",
                    "PAN-OS 10.1.5",
                    "PAN-OS 10.1.4-h4",
                    "PAN-OS 10.1.4-h3",
                    "PAN-OS 10.1.4-h2",
                    "PAN-OS 10.1.4-h1",
                    "PAN-OS 10.1.4",
                    "PAN-OS 10.1.3",
                    "PAN-OS 10.1.2",
                    "PAN-OS 10.1.1",
                    "PAN-OS 10.1.0",
                    "PAN-OS 10.1",
                    "PAN-OS 10.0.9",
                    "PAN-OS 10.0.8-h8",
                    "PAN-OS 10.0.8-h7",
                    "PAN-OS 10.0.8-h6",
                    "PAN-OS 10.0.8-h5",
                    "PAN-OS 10.0.8-h4",
                    "PAN-OS 10.0.8-h3",
                    "PAN-OS 10.0.8-h2",
                    "PAN-OS 10.0.8-h1",
                    "PAN-OS 10.0.8",
                    "PAN-OS 10.0.7",
                    "PAN-OS 10.0.6",
                    "PAN-OS 10.0.5",
                    "PAN-OS 10.0.4",
                    "PAN-OS 10.0.3",
                    "PAN-OS 10.0.2",
                    "PAN-OS 10.0.1",
                    "PAN-OS 10.0.0",
                    "PAN-OS 10.0",
                    "PAN-OS 9.1.13",
                    "PAN-OS 9.1.12-h3",
                    "PAN-OS 9.1.12-h2",
                    "PAN-OS 9.1.12-h1",
                    "PAN-OS 9.1.12",
                    "PAN-OS 9.1.11-h3",
                    "PAN-OS 9.1.11-h2",
                    "PAN-OS 9.1.11-h1",
                    "PAN-OS 9.1.11",
                    "PAN-OS 9.1.10",
                    "PAN-OS 9.1.9",
                    "PAN-OS 9.1.8",
                    "PAN-OS 9.1.7",
                    "PAN-OS 9.1.6",
                    "PAN-OS 9.1.5",
                    "PAN-OS 9.1.4",
                    "PAN-OS 9.1.3-h1",
                    "PAN-OS 9.1.3",
                    "PAN-OS 9.1.2-h1",
                    "PAN-OS 9.1.2",
                    "PAN-OS 9.1.1",
                    "PAN-OS 9.1.0-h3",
                    "PAN-OS 9.1.0-h2",
                    "PAN-OS 9.1.0-h1",
                    "PAN-OS 9.1.0",
                    "PAN-OS 9.1",
                    "PAN-OS 9.0.16",
                    "PAN-OS 9.0.15",
                    "PAN-OS 9.0.14-h4",
                    "PAN-OS 9.0.14-h3",
                    "PAN-OS 9.0.14-h2",
                    "PAN-OS 9.0.14-h1",
                    "PAN-OS 9.0.14",
                    "PAN-OS 9.0.13",
                    "PAN-OS 9.0.12",
                    "PAN-OS 9.0.11",
                    "PAN-OS 9.0.10",
                    "PAN-OS 9.0.9-h1",
                    "PAN-OS 9.0.9",
                    "PAN-OS 9.0.8",
                    "PAN-OS 9.0.7",
                    "PAN-OS 9.0.6",
                    "PAN-OS 9.0.5",
                    "PAN-OS 9.0.4",
                    "PAN-OS 9.0.3-h3",
                    "PAN-OS 9.0.3-h2",
                    "PAN-OS 9.0.3-h1",
                    "PAN-OS 9.0.3",
                    "PAN-OS 9.0.2-h4",
                    "PAN-OS 9.0.2-h3",
                    "PAN-OS 9.0.2-h2",
                    "PAN-OS 9.0.2-h1",
                    "PAN-OS 9.0.2",
                    "PAN-OS 9.0.1",
                    "PAN-OS 9.0.0",
                    "PAN-OS 9.0",
                    "PAN-OS 8.1.22",
                    "PAN-OS 8.1.21-h1",
                    "PAN-OS 8.1.21",
                    "PAN-OS 8.1.20-h1",
                    "PAN-OS 8.1.20",
                    "PAN-OS 8.1.19",
                    "PAN-OS 8.1.18",
                    "PAN-OS 8.1.17",
                    "PAN-OS 8.1.16",
                    "PAN-OS 8.1.15-h3",
                    "PAN-OS 8.1.15-h2",
                    "PAN-OS 8.1.15-h1",
                    "PAN-OS 8.1.15",
                    "PAN-OS 8.1.14-h2",
                    "PAN-OS 8.1.14-h1",
                    "PAN-OS 8.1.14",
                    "PAN-OS 8.1.13",
                    "PAN-OS 8.1.12",
                    "PAN-OS 8.1.11",
                    "PAN-OS 8.1.10",
                    "PAN-OS 8.1.9-h4",
                    "PAN-OS 8.1.9-h3",
                    "PAN-OS 8.1.9-h2",
                    "PAN-OS 8.1.9-h1",
                    "PAN-OS 8.1.9",
                    "PAN-OS 8.1.8-h5",
                    "PAN-OS 8.1.8-h4",
                    "PAN-OS 8.1.8-h3",
                    "PAN-OS 8.1.8-h2",
                    "PAN-OS 8.1.8-h1",
                    "PAN-OS 8.1.8",
                    "PAN-OS 8.1.7",
                    "PAN-OS 8.1.6-h2",
                    "PAN-OS 8.1.6-h1",
                    "PAN-OS 8.1.6",
                    "PAN-OS 8.1.5",
                    "PAN-OS 8.1.4",
                    "PAN-OS 8.1.3",
                    "PAN-OS 8.1.2",
                    "PAN-OS 8.1.1",
                    "PAN-OS 8.1.0",
                    "PAN-OS 8.1",
                    "GlobalProtect App",
                    "Cortex XDR Agent"
                ],
                "cve_date_public": "2022-03-31T02:30:00.000Z",
                "cve_id": "CVE-2022-0778",
                "cve_title": "Impact of the OpenSSL Infinite Loop Vulnerability CVE-2022-0778",
                "cvss_score": 7.5,
                "cvss_severity": "HIGH",
                "cvss_vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "data_format": "MITRE",
                "data_type": "CVE",
                "description": "The Palo Alto Networks Product Security Assurance team is evaluating the OpenSSL infinite loop vulnerability (CVE-2022-0778) as it relates to our products.\n\nThis vulnerability causes the OpenSSL library to enter an infinite loop when parsing an invalid certificate and can result in a Denial-of-Service (DoS) to the application. An attacker does not need a verified certificate to exploit this vulnerability because parsing a bad certificate triggers the infinite loop before the verification process is completed.\n\nThe Cortex XSOAR product is not impacted by this vulnerability. However, PAN-OS, GlobalProtect app, and Cortex XDR agent software contain a vulnerable version of the OpenSSL library and product availability is impacted by this vulnerability. For PAN-OS software, this includes both hardware and virtual firewalls and Panorama appliances as well as Prisma Access customers. This vulnerability has reduced severity on Cortex XDR agent and Global Protect app as successful exploitation requires an attacker-in-the-middle attack (MITM): 5.9 Medium (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H).\n\nWe are working diligently on fixes to remove the vulnerable code from our PAN-OS, GlobalProtect app, and Cortex XDR agent software. The fixed versions for hotfixes and other product upgrades will be updated in this advisory as soon as possible."
            }
        ]
    }
}
```

#### Human Readable Output

>### Palo Alto Networks Security Advisories
>|affected_version_list|affects_vendor_name|cve_date_public|cve_id|cve_title|cvss_score|cvss_severity|cvss_vector_string|data_format|data_type|description|
>|---|---|---|---|---|---|---|---|---|---|---|
>| Prisma Access 3.0,<br/>Prisma Access 2.2,<br/>Prisma Access 2.1,<br/>PAN-OS 10.2.0,<br/>PAN-OS 10.2,<br/>PAN-OS 10.1.5,<br/>PAN-OS 10.1.4-h4,<br/>PAN-OS 10.1.4-h3,<br/>PAN-OS 10.1.4-h2,<br/>PAN-OS 10.1.4-h1,<br/>PAN-OS 10.1.4,<br/>PAN-OS 10.1.3,<br/>PAN-OS 10.1.2,<br/>PAN-OS 10.1.1,<br/>PAN-OS 10.1.0,<br/>PAN-OS 10.1,<br/>PAN-OS 10.0.9,<br/>PAN-OS 10.0.8-h8,<br/>PAN-OS 10.0.8-h7,<br/>PAN-OS 10.0.8-h6,<br/>PAN-OS 10.0.8-h5,<br/>PAN-OS 10.0.8-h4,<br/>PAN-OS 10.0.8-h3,<br/>PAN-OS 10.0.8-h2,<br/>PAN-OS 10.0.8-h1,<br/>PAN-OS 10.0.8,<br/>PAN-OS 10.0.7,<br/>PAN-OS 10.0.6,<br/>PAN-OS 10.0.5,<br/>PAN-OS 10.0.4,<br/>PAN-OS 10.0.3,<br/>PAN-OS 10.0.2,<br/>PAN-OS 10.0.1,<br/>PAN-OS 10.0.0,<br/>PAN-OS 10.0,<br/>PAN-OS 9.1.13,<br/>PAN-OS 9.1.12-h3,<br/>PAN-OS 9.1.12-h2,<br/>PAN-OS 9.1.12-h1,<br/>PAN-OS 9.1.12,<br/>PAN-OS 9.1.11-h3,<br/>PAN-OS 9.1.11-h2,<br/>PAN-OS 9.1.11-h1,<br/>PAN-OS 9.1.11,<br/>PAN-OS 9.1.10,<br/>PAN-OS 9.1.9,<br/>PAN-OS 9.1.8,<br/>PAN-OS 9.1.7,<br/>PAN-OS 9.1.6,<br/>PAN-OS 9.1.5,<br/>PAN-OS 9.1.4,<br/>PAN-OS 9.1.3-h1,<br/>PAN-OS 9.1.3,<br/>PAN-OS 9.1.2-h1,<br/>PAN-OS 9.1.2,<br/>PAN-OS 9.1.1,<br/>PAN-OS 9.1.0-h3,<br/>PAN-OS 9.1.0-h2,<br/>PAN-OS 9.1.0-h1,<br/>PAN-OS 9.1.0,<br/>PAN-OS 9.1,<br/>PAN-OS 9.0.16,<br/>PAN-OS 9.0.15,<br/>PAN-OS 9.0.14-h4,<br/>PAN-OS 9.0.14-h3,<br/>PAN-OS 9.0.14-h2,<br/>PAN-OS 9.0.14-h1,<br/>PAN-OS 9.0.14,<br/>PAN-OS 9.0.13,<br/>PAN-OS 9.0.12,<br/>PAN-OS 9.0.11,<br/>PAN-OS 9.0.10,<br/>PAN-OS 9.0.9-h1,<br/>PAN-OS 9.0.9,<br/>PAN-OS 9.0.8,<br/>PAN-OS 9.0.7,<br/>PAN-OS 9.0.6,<br/>PAN-OS 9.0.5,<br/>PAN-OS 9.0.4,<br/>PAN-OS 9.0.3-h3,<br/>PAN-OS 9.0.3-h2,<br/>PAN-OS 9.0.3-h1,<br/>PAN-OS 9.0.3,<br/>PAN-OS 9.0.2-h4,<br/>PAN-OS 9.0.2-h3,<br/>PAN-OS 9.0.2-h2,<br/>PAN-OS 9.0.2-h1,<br/>PAN-OS 9.0.2,<br/>PAN-OS 9.0.1,<br/>PAN-OS 9.0.0,<br/>PAN-OS 9.0,<br/>PAN-OS 8.1.22,<br/>PAN-OS 8.1.21-h1,<br/>PAN-OS 8.1.21,<br/>PAN-OS 8.1.20-h1,<br/>PAN-OS 8.1.20,<br/>PAN-OS 8.1.19,<br/>PAN-OS 8.1.18,<br/>PAN-OS 8.1.17,<br/>PAN-OS 8.1.16,<br/>PAN-OS 8.1.15-h3,<br/>PAN-OS 8.1.15-h2,<br/>PAN-OS 8.1.15-h1,<br/>PAN-OS 8.1.15,<br/>PAN-OS 8.1.14-h2,<br/>PAN-OS 8.1.14-h1,<br/>PAN-OS 8.1.14,<br/>PAN-OS 8.1.13,<br/>PAN-OS 8.1.12,<br/>PAN-OS 8.1.11,<br/>PAN-OS 8.1.10,<br/>PAN-OS 8.1.9-h4,<br/>PAN-OS 8.1.9-h3,<br/>PAN-OS 8.1.9-h2,<br/>PAN-OS 8.1.9-h1,<br/>PAN-OS 8.1.9,<br/>PAN-OS 8.1.8-h5,<br/>PAN-OS 8.1.8-h4,<br/>PAN-OS 8.1.8-h3,<br/>PAN-OS 8.1.8-h2,<br/>PAN-OS 8.1.8-h1,<br/>PAN-OS 8.1.8,<br/>PAN-OS 8.1.7,<br/>PAN-OS 8.1.6-h2,<br/>PAN-OS 8.1.6-h1,<br/>PAN-OS 8.1.6,<br/>PAN-OS 8.1.5,<br/>PAN-OS 8.1.4,<br/>PAN-OS 8.1.3,<br/>PAN-OS 8.1.2,<br/>PAN-OS 8.1.1,<br/>PAN-OS 8.1.0,<br/>PAN-OS 8.1,<br/>GlobalProtect App,<br/>Cortex XDR Agent | Palo Alto Networks | 2022-03-31T02:30:00.000Z | CVE-2022-0778 | Impact of the OpenSSL Infinite Loop Vulnerability CVE-2022-0778 | 7.5 | HIGH | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H | MITRE | CVE | The Palo Alto Networks Product Security Assurance team is evaluating the OpenSSL infinite loop vulnerability (CVE-2022-0778) as it relates to our products.<br/><br/>This vulnerability causes the OpenSSL library to enter an infinite loop when parsing an invalid certificate and can result in a Denial-of-Service (DoS) to the application. An attacker does not need a verified certificate to exploit this vulnerability because parsing a bad certificate triggers the infinite loop before the verification process is completed.<br/><br/>The Cortex XSOAR product is not impacted by this vulnerability. However, PAN-OS, GlobalProtect app, and Cortex XDR agent software contain a vulnerable version of the OpenSSL library and product availability is impacted by this vulnerability. For PAN-OS software, this includes both hardware and virtual firewalls and Panorama appliances as well as Prisma Access customers. This vulnerability has reduced severity on Cortex XDR agent and Global Protect app as successful exploitation requires an attacker-in-the-middle attack (MITM): 5.9 Medium (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H).<br/><br/>We are working diligently on fixes to remove the vulnerable code from our PAN-OS, GlobalProtect app, and Cortex XDR agent software. The fixed versions for hotfixes and other product upgrades will be updated in this advisory as soon as possible. |
