[Get Declaration of Compromises from Stamus Security Platform and build Incidents. Then get related artifacts, events and Host Insight information]
This integration was integrated and tested with version 39.0.0 of Stamus

## Configure Stamus on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Stamus.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Stamus Central Server |  | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |
    | Maximum number of incidents per fetch |  | False |
    | First fetch time |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### Stamus-Check-IOC

***
[Get events with IOC key/value filter]

#### Base Command

`Stamus-Check-IOC`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | [Indicator of Compromise key]. | Required |
| value | [Indicator of Compromise value]. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| StamusIntegration.IOC | String | \[Fetch events matching an IOC.\] |

### Stamus-Get-Host-Insight

***
[Get Host Insights information]

#### Base Command

`Stamus-Get-Host-Insight`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | [IP to get Host Insights information]. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| StamusIntegration.HostInsights | String | \[Fetch information about a host known by Host Insight module\] |

### Stamus-Get-DoC-Events

***
[Get events for a Declaration of Compromise using the Stamus ID]

#### Base Command

`Stamus-Get-DoC-Events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | [Stamus ID used to get related information]. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| StamusIntegration.RelatedEvents | String | \[Get events for a Declaration of Compromise.\] |
