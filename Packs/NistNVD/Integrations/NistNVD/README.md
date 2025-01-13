National Vulnerability Database

## Configure Nist NVD in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Nist NVD CVES URL | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### nvd-get-vulnerability

***
You can get latest vulnerabilities with given time from National Vulnerability Database.

#### Base Command

`nvd-get-vulnerability`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time | Get vulnerability within this time frame (in days - max range is 120 days). Example: time=30. Default is 30. | Required | 
| resultsPerPage | Default: 20. Default is 20. | Optional | 
| startIndex | Using for paging. Default: 0. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### nvd-search-keyword

***
The keyword parameter allows your application to retrieve records where a word or phrase is found in the vulnerability description or reference links.

#### Base Command

`nvd-search-keyword`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keyword | Example: keyword=apple. | Required | 
| isExactMatch | If the keyword is a phrase, i.e., contains more than one term, then the isExactMatch parameter may be used to influence the response. Use isExactMatch=true to retrieve records matching the exact phrase. Otherwise, the results contain any record having any of the terms. Possible values are: true, false. Default is true. | Required | 
| time | Get vulnerability within this time frame (in days - max range is 120 days). Example: time=30. Default is 30. | Optional | 
| resultsPerPage | Default: 20. Default is 20. | Optional | 
| startIndex | Using for paging. Default: 0. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### nvd-search-cvss

***
CVSS refers to the scoring system used by NIST to assess the severity of vulnerabilities, https://www.first.org/cvss/. NVD provides base scores using the CVSS version 2 and, more recently, version 3.x.

#### Base Command

`nvd-search-cvss`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cvssType | cvssV4, cvssV3 or cvssV2. Possible values are: cvssV2, csvsV3, cvssV4. Default is cvssV4. | Required | 
| key | Search parameter that use with CVSS. Example: cvssV3Metrics \| cvssV4Severity. Possible values are: Severity, Metrics. Default is Severity. | Required | 
| value | Two pairs of parameters allow you to filter vulnerabilities based on CVSS base scores. Use either the cvssV2Severity or cvssV3Severity parameter to find vulnerabilities having a LOW, MEDIUM, or HIGH version 2 or 3.x score, respectively. For CVSS V3.x, cvssV3Severity=CRITICAL is also supported. Example: cvssV2Severity=HIGH \| cvssV3Metrics=C:H/A:N \| cvssV3Metrics=AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N. | Required | 
| time | Get vulnerability within this time frame (in days - max range is 120 days). Example: time=30. Default is 30. | Optional | 
| resultsPerPage | Default: 20. Default is 20. | Optional | 
| startIndex | Using for paging. Default: 0. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### nvd-search-cwe

***
CWE refers to the classification of vulnerabilities at https://cwe.mitre.org/. NIST staff associate one or more CWE to each vulnerability during the analysis process. In the following example, CWE-20 means vulnerabilities caused by Improper Input Validation. To filter search results based on CWE, use the cweId parameter. Example: cweId=CWE-20

#### Base Command

`nvd-search-cwe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cweId | Example: cweId=CWE-20. | Required | 
| time | Get vulnerability within this time frame (in days - max range is 120 days). Example: time=30. Default is 30. | Optional | 
| resultsPerPage | Default: 20. Default is 20. | Optional | 
| startIndex | Using for paging. Default: 0. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### nvd-search-cpe

***
NVD analysts identify which product or products are affected by each vulnerability. The set of associated products is known as the applicability statement of the CVE. NVD uses the Common Platform Enumeration (CPE), version 2.3, to convey product vendors, names, versions, etc. For more information, see https://cpe.mitre.org/.

#### Base Command

`nvd-search-cpe`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cpe | Example: cpe:2.3:o:microsoft:windows_10 \| cpe:2.3:o:microsoft:windows_10:1511 \| cpe:2.3:*:microsoft. | Required | 
| time | Get vulnerability within this time frame (in days - max range is 120 days). Example: time=30. Default is 30. | Optional | 
| resultsPerPage | Default: 20. Default is 20. | Optional | 
| startIndex | Using for paging. Default: 0. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.
### nvd-search-cve

***
Search specific CVE

#### Base Command

`nvd-search-cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | CVEID. Example: CVE-2020-1000. | Required | 

#### Context Output

There is no context output for this command.