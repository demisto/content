Query Symantec Endpoint Security Threat Intel data.
This integration was integrated and tested with Symantec Threat Intel.

## Configure Symantec Threat Intel on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Symantec Threat Intel.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Tennant URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Ignore Domains (e.g. domain.local) | Comma-separated list of domains that shall be ignored for Urls and \(Sub-\)Domains reputation lookup | False |
    | Ignore Private IPs (e.g. 192.168.0.1) |  | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### file

***
Get file reputation for given SHA256.

#### Base Command

`file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of files. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| File.SHA256 | String | The SHA256 hash of the file. | 

### ip

***
Get ip reputation.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| IP.Address | String | IP address. | 

### url

***
Get reputation for given url.

#### Base Command

`url`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| URL.Data | String | The URL. | 

### domain

***
Get reputation for given domain.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domains. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| Domain.Name | String | The domain name. | 

### symantec-protection-file

***
Get information whether a given file has been blocked by any Symantec technologies.

#### Base Command

`symantec-protection-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | Comma-separated list of file Sha256 hashes. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Symantec.Protection.file | String | input file sha256. | 
| Symantec.Protection.state.technology | String | Symantec technology providing protection. | 
| Symantec.Protection.state.firstDefsetVersion | String | The first definition version with protection. | 
| Symantec.Protection.state.threatName | String | The name of the threat the file is detected as. | 

### symantec-protection-network

***
Get  information whether given domain or ip has been blocked by any Symantec technologies.

#### Base Command

`symantec-protection-network`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| network | Comma-separated list of domains or IPs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Symantec.Protection.network | String | input domain or ip. | 
| Symantec.Protection.state.technology | String | Symantec technology providing protection. | 
| Symantec.Protection.state.firstDefsetVersion | String | The first definition version with protections. | 
| Symantec.Protection.state.threatName | String | The name of the threat the domain or is detected as. | 

### symantec-protection-cve

***
Get returns information whether a given CVE has been blocked by any Symantec technologies.

#### Base Command

`symantec-protection-cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | Comma-separated list of CVEs. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Symantec.Protection.file | String | input CVE. | 
| Symantec.Protection.state.technology | String | Symantec technology providing protection. | 
| Symantec.Protection.state.firstDefsetVersion | String | The first definition version with protections. | 
| Symantec.Protection.state.threatName | String | The name of the threat the domain or is detected as. | 
