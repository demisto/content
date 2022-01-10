OSV (Open Source Vulnerability) is a vulnerability database for open source projects. For each vulnerability, it perform bisects to figure out the exact commit that introduces the bug, as well the exact commit that fixes it. This is cross referenced against upstream repositories to figure out the affected tags and commit ranges 
This integration was integrated and tested with version xx of OSV

## Configure OSV on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OSV.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://api.osv.dev) | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### osv-get-vuln-by-id
***
Return a `Vulnerability` object for a given OSV ID. All list of vulnerabilities can be found at https://osv.dev/list


#### Base Command

`osv-get-vuln-by-id`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id_ | The `id` field is a unique identifier for the vulnerability entry. For example: OSV-2020-111. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OSV.Vulnerability.id | String | The \`id\` field is a unique identifier for the vulnerability entry | 
| OSV.Vulnerability.published | String | The RFC3339 timestamp indicating when this entry was published. | 
| OSV.Vulnerability.modified | String | The RFC3339 timestamp indicating when this entry was last modified. | 
| OSV.Vulnerability.withdrawn | String | Optional. The RFC3339 timestamp indicating when this entry is considered to be withdrawn. | 
| OSV.Vulnerability.summary | String | Required. One line human readable summary for the vulnerability. It is recommended to keep this under 120 characters. | 
| OSV.Vulnerability.details | String | Required. Any additional human readable details for the vulnerability. | 
| OSV.Vulnerability.affected.ranges.repo | String | Required if type is GIT. The publicly accessible URL of the repo that can be directly passed to clone commands. | 
| OSV.Vulnerability.affected.ranges.events.introduced | String | The earliest version/commit where this vulnerability was introduced in. | 
| OSV.Vulnerability.affected.ranges.events.fixed | String | The version/commit that this vulnerability was fixed in. | 
| OSV.Vulnerability.affected.ranges.events.limit | String | The limit to apply to the range. | 
| OSV.Vulnerability.references.url | String | Required. The URL. | 
| OSV.Vulnerability.code | Number |  | 
| OSV.Vulnerability.message | String |  | 
| OSV.Vulnerability.details.typeUrl | String |  | 
| OSV.Vulnerability.details.value | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### osv-query-affected-by-commit
***
Query vulnerabilities for a particular project at a given commit


#### Base Command

`osv-query-affected-by-commit`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| commit | The commit hash to query for. E.g 6879efc2c1596d11a6a6ad296f80063b558d5e0f. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OSV.VulnerabilityList.vulns.id | String | The \`id\` field is a unique identifier for the vulnerability entry. | 
| OSV.VulnerabilityList.vulns.published | String | The RFC3339 timestamp indicating when this entry was published. | 
| OSV.VulnerabilityList.vulns.modified | String | The RFC3339 timestamp indicating when this entry was last modified. | 
| OSV.VulnerabilityList.vulns.withdrawn | String | Optional. The RFC3339 timestamp indicating when this entry is considered to be withdrawn. | 
| OSV.VulnerabilityList.vulns.summary | String | Required. One line human readable summary for the vulnerability. It is recommended to keep this under 120 characters. | 
| OSV.VulnerabilityList.vulns.details | String | Required. Any additional human readable details for the vulnerability. | 
| OSV.VulnerabilityList.vulns.affected.ranges.repo | String | Required if type is GIT. The publicly accessible URL of the repo that can be directly passed to clone commands. | 
| OSV.VulnerabilityList.vulns.affected.ranges.events.introduced | String | The earliest version/commit where this vulnerability was introduced in. | 
| OSV.VulnerabilityList.vulns.affected.ranges.events.fixed | String | The version/commit that this vulnerability was fixed in. | 
| OSV.VulnerabilityList.vulns.affected.ranges.events.limit | String | The limit to apply to the range. | 
| OSV.VulnerabilityList.vulns.references.url | String | Required. The URL. | 
| OSV.VulnerabilityList.code | Number |  | 
| OSV.VulnerabilityList.message | String |  | 
| OSV.VulnerabilityList.details.typeUrl | String |  | 
| OSV.VulnerabilityList.details.value | String |  | 


#### Command Example
``` ```

#### Human Readable Output



### osv-query-affected-by-package
***
Query vulnerabilities for a particular project based on package name and verion


#### Base Command

`osv-query-affected-by-package`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| version |  The version string to query for. A fuzzy match is done against upstream versions. Eg. 3.3.0. | Required | 
| packageName | The name of the package/project to query for. Eg. django-tinymce. | Required | 
| ecosystem | The ecosystem of the package. Eg. PyPI. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OSV.VulnerabilityList.vulns.id | string | The \`id\` field is a unique identifier for the vulnerability entry. | 
| OSV.VulnerabilityList.vulns.published | string | The RFC3339 timestamp indicating when this entry was published. | 
| OSV.VulnerabilityList.vulns.modified | string | The RFC3339 timestamp indicating when this entry was last modified. | 
| OSV.VulnerabilityList.vulns.withdrawn | string | Optional. The RFC3339 timestamp indicating when this entry is considered to be withdrawn. | 
| OSV.VulnerabilityList.vulns.summary | string | Required. One line human readable summary for the vulnerability. It is recommended to keep this under 120 characters. | 
| OSV.VulnerabilityList.vulns.details | string | Required. Any additional human readable details for the vulnerability. | 
| OSV.VulnerabilityList.vulns.affected.ranges.repo | string | Required if type is GIT. The publicly accessible URL of the repo that can be directly passed to clone commands. | 
| OSV.VulnerabilityList.vulns.affected.ranges.events.introduced | string | The earliest version/commit where this vulnerability was introduced in. | 
| OSV.VulnerabilityList.vulns.affected.ranges.events.fixed | string | The version/commit that this vulnerability was fixed in. | 
| OSV.VulnerabilityList.vulns.affected.ranges.events.limit | string | The limit to apply to the range. | 
| OSV.VulnerabilityList.vulns.references.url | string | Required. The URL. | 
| OSV.VulnerabilityList.code | number |  | 
| OSV.VulnerabilityList.message | string |  | 
| OSV.VulnerabilityList.details.typeUrl | string |  | 
| OSV.VulnerabilityList.details.value | string |  | 


#### Command Example
``` ```

#### Human Readable Output


