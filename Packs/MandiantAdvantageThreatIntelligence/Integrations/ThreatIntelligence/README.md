Integrate with Mandiant Advantage
This integration was integrated and tested with version 4 of the Mandiant Advantage Threat Intelligence API

## Configure Mandiant Advantage Threat Intelligence on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Mandiant Advantage Threat Intelligence.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Base URL | Leave as 'api.intelligence.mandiant.com' if unsure | False |
    | API Key | Your API Key from Mandiant Advantage Threat Intelligence | True |
    | Secret Key | Your Secret Key from Mandiant Advantage Threat Intelligence | True |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
    | Feed Expiration Policy |  | False |
    | Feed Expiration Interval |  | False |
    | Feed Fetch Interval |  | False |
    | Feed Minimum Confidence Score | The minimum MScore value to import as part of the feed | True |
    | Feed Exclude Open Source Intelligence | Whether to exclude Open Source Intelligence as part of the feed | True |
    | Mandiant indicator type | The type of indicators to fetch. Indicator type might include the following: Domains, IPs, Files and URLs. | False |
    | First fetch time | The maximum value allowed is 90 days. | False |
    | Maximum number of indicators per fetch | Maximum value of 1000.  Any values higher will be capped to 1000 | False |
    | Tags | Supports CSV values. | False |
    | Timeout | API calls timeout. | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Retrieve indicator metadata | Retrieve additional information for each indicator. Note that this requires additional API calls. | False |
    | Create relationships | Note that this requires additional API calls. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### threat-intelligence-get-indicators
***
Get Mandiant indicators


#### Base Command

`threat-intelligence-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| update_context | Update context. | Optional | 
| limit | The maximum number of indicators to fetch. | Optional | 
| indicatorMetadata | Whether to retrieve additional data for each indicator. Possible values are: true, false. Default is false. | Optional | 
| indicatorRelationships | Whether to create indicator relationships. Possible values are: true, false. Default is false. | Optional | 
| type | The type of indicators to fetch. Possible values are: Malware, Indicators, Actors. Default is Malware,Indicators,Actors. | Required | 


#### Context Output

There is no context output for this command.
### get-indicator
***
Get information about a single Indicator of Compromise from Mandiant


#### Base Command

`get-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| indicator_value | Value of the indicator to look up.  Can be URL, domain name, IP address, or file hash. | Required | 


#### Context Output

There is no context output for this command.
### get-actor
***
Get information about a Threat Actor from Mandiant


#### Base Command

`get-actor`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| actor_name | Name of the actor to look up. | Required | 


#### Context Output

There is no context output for this command.
### get-malware
***
Get information about a Malware Family from Mandiant


#### Base Command

`get-malware`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| malware_name | Name of the malware family to look up. | Required | 


#### Context Output

There is no context output for this command.
### file
***
Retrieve information about a File Hash from Mandiant


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of files. | Optional | 


#### Context Output

There is no context output for this command.
### ip
***
Retrieve information about an IP Address from Mandiant


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Optional | 


#### Context Output

There is no context output for this command.
### url
***
Retrieve information about a URL from Mandiant


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Optional | 


#### Context Output

There is no context output for this command.
### domain
***
Retrieve information about an FQDN from Mandiant


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domains. | Optional | 


#### Context Output

There is no context output for this command.
### cve
***
Retrieve information about a Vulnerability (by CVE) from Mandiant


#### Base Command

`cve`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | List of CVEs. | Optional | 


#### Context Output

There is no context output for this command.
### get-campaign
***
Retrieve information about a Campaign from Mandiant


#### Base Command

`get-campaign`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| campaign_id | ID of the campaign to lookup. | Required | 


#### Context Output

There is no context output for this command.