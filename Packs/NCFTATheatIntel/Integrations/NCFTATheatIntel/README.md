This integration is for fetching MISP IOC's and threat intel report
## Configure NCFTA Theat Intel in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g., https://misp.ncfta.net) | True |
| api_key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ncfta-get-iocs

***
Get IOC's from MISP API

#### Base Command

`ncfta-get-iocs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| sharing_groups | Available MISP Sharing Groups. Possible values are: tnt, raolf, mti, dga, tor, vpn, tnt_ransomware, proxy. | Optional | 
| timestamped | Example: “7d", "24h", "6h" (default 7d). Default is 7d. | Optional | 
| limit | Limit the number of IOC's in response. Default is 100. | Optional | 

#### Context Output

There is no context output for this command.
