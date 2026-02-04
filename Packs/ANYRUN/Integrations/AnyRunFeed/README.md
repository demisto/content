Threat Intelligence Feed provide data on the known indicators of compromise: malicious IPs, URLs, Domains

## Generate your API key 

Please contact your ANY.RUN account manager to get your API key.
> **Warning**
> 
> Prefixed API keys and Basic Authentication for TI Feeds will not be supported in future releases.

## Configure ANY.RUN Feed in Cortex

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ANY.RUN.
3. Click **Add instance** to create and configure a new integration instance.
4. Insert ANY.RUN TI Feeds API key into the **Password** parameter.
5. Please use "ANY.RUN" as username.
6. Click **Test** to validate the URLs, token, and connection.

| **Parameter**    | **Description**                  | **Required** |
|------------------|----------------------------------| --- |
| Password         | Example: WmNfqnpo...2Sjon7mtvm8e | True |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

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
