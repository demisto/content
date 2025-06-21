Threat Intelligence Feeds provide data on the known indicators of compromise: malicious IPs, URLs, Domains

## Configure ANY.RUN Feeds in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ANYRUN.
3. Click **Add instance** to create and configure a new integration instance.
4. Click **Test** to validate the connection to ANY.RUN Cloud Sandbox.


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Username | ANY.RUN username | True |
| Password | ANY.RUN password | True |
| Server's FQDN | Go to Settings &amp; Info → Settings → Integrations → API Keys. Click Copy API URL. Your FQDN is saved in the clipboard. | True |
| XSOAR API-KEY ID | In the API Keys table, locate the ID field. Note your corresponding ID number | True |
| XSOAR API-KEY |  | True |

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
The commands allow you to launch and download only your own tasks, public submissions are not available at this point.

### anyrun-get-indicators

***
Receive ANY.RUN Indicators

#### Base Command

`anyrun-get-indicators`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collection | ANY.RUN indicator collection type. Supports: full, ip, url, domain. Possible values are: full, ip, url, domain. | Optional | 
| match_type | Filter results based on the STIX object types. | Optional | 
| match_id | IOC identifier. | Optional | 
| match_revoked | Enable or disable receiving revoked feeds in report. Default is False. | Optional | 
| match_version | Filter STIX objects by their object version. Default is last. | Optional | 
| added_after | Receive IOCs after specified date. Format: YYYY-MM-DD. | Optional | 
| modified_after | Receive IOCs after specified date. Format: YYYY-MM-DD. | Required | 
| limit | Number of tasks on a page. Default, all IOCs are included. Default is 100. | Optional | 

#### Context Output

There is no context output for this command.
