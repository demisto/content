ReliaQuest GreyMatter DR monitors and manages an organization's digital risk across the widest range of data sources within the open, deep, and dark web.
This integration was integrated and tested with version v1 of ReliaQuest GreyMatter DRP Incidents.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure ReliaQuest GreyMatter DRP Incidents in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch incidents | Start fetching incidents | False |
| DS SearchLight API URL | Enter the Digital Shadows SearchLight API URL | True |
| Account ID | Account ID associated with this account. | True |
| API Key | Enter the API Key for this account. | True |
| API Secret | Enter the API Secret for this account. | True |
| Trust any certificate (not secure) | Verify certificate | False |
| Risk Types | Remove all if you don't want to select  all risk types, and then select specifically | True |
| Risk Level | Remove all if you don't want to select  all risk types, and then select specifically | False |
| Ingest Closed / Auto-rejected Alerts | If you don't want to ingest rejected/resolved/closed incidents then set it to False. Otherwise incidents will ingested with auto-closed=True | False |
| Fetch Limit | The maximum number of incidents to fetch | True |
| Incidents Fetch Interval | This controls how often the integration will perform a fetch_incidents command | False |
| Start date | Since when want to fetch the data with given format\(%Y-%m-%dT%H:%M:%SZ\) | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ds-search

***
Perform a general search against incidents, threats closed sources, etc.

#### Base Command

`ds-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | No description provided. | Required | 

#### Context Output

There is no context output for this command.