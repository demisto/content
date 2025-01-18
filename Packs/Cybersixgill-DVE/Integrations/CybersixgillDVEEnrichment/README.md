Powered by the broadest automated collection from the deep and dark web, Cybersixgill’s Dynamic Vulnerability Exploit (DVE) Score is a feed of common known vulnerabilities, scored by their probability of getting exploited. The DVE Score feed enables Cortex XSOAR users to track threats from vulnerabilities that others define as irrelevant, but have a higher probability of being exploited. It is the only solution that predicts the immediate risks of a vulnerability based on threat actors’ intent. 

DVE Score is also the most comprehensive CVE enrichment solution on the market: Cortex XSOAR users gain unparalleled context and can accelerate threat response and decision making, effectively giving security teams a head start on vulnerability management. 

·    Anticipate the exploitation of a vulnerability up to 90 days in advance
·    Track threats from CVEs that most others define as irrelevant or obsolete, but a higher probability of being exploited by active cyber threat actors.
·    Gain visibility as well as the ability to prioritize and articulate the remediation process across the organization - straight from Cortex XSOAR

To obtain access to Cybersixgill DVE Score feed via Cortex XSOAR, please contact Cybersixgill at getstarted@cybersixgill.com.

## Configure Sixgill_Darkfeed_Enrichment in Cortex



| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Sixgill API client ID | Sixgill API client ID | True |
| Sixgill API client secret | Sixgill API client secret | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cybersixgill-cve-enrich
***
Returns information for each CVE in the input list


#### Base Command

`cybersixgill-cve-enrich`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | A comma-separated list of CVEs to check. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- | 
| Sixgill.CVE.value | String | The value of the CVE. | 
| Sixgill.CVE.Description | String | Description of the given DVE ID. | 
| Sixgill.CVE.Created | Date | The creation date of the CVE. | 
| Sixgill.CVE.Modified | Date | The modified date of the CVE. | 
| Sixgill.CVE.Cybersixgill_DVE_score_current | String | The current Cybersixgill DVE Score. | 
| Sixgill.CVE.Cybersixgill_DVE_score_highest_ever_date | String | The date on which Sixgill's highest DVE score ever reported. | 
| Sixgill.CVE.Cybersixgill_DVE_score_highest_ever | String | Sixgill's highest DVE score ever reported. | 
| Sixgill.CVE.Cybersixgill_Previously_exploited_probability | String | Sixgill's score of previously exploited probability. | 
| Sixgill.CVE.Previous_Level | String | Previous level of the CVE ID. | 
| Sixgill.CVE.CVSS_3_1_score | String | CVSS 3.1 score. | 
| Sixgill.CVE.CVSS_3_1_severity | String | CVSS 3.1 severity. | 
| Sixgill.CVE.NVD_Link | String | NVD link. | 
| Sixgill.CVE.NVD_last_modified_date | Date | NVD last modified date. | 
| Sixgill.CVE.NVD_publication_date | Date | NVD publication date. | 
| Sixgill.CVE.CVSS_2_0_score | String | CVSS 2.0 score. | 
| Sixgill.CVE.CVSS_2_0_severity | String | CVSS 2.0 severity. | 
| Sixgill.CVE.NVD_Vector_V2_0 | String | NVD vector v2.0. | 
| Sixgill.CVE.NVD_Vector_V3_1 | String | NVD vector v3.1. | 
| Sixgill.CVE.rawJSON | String | The raw JSON of the CVE entich information. | 


#### Command Example
``` ```

#### Human Readable Output
