In today’s complex security landscape, resource-constrained teams struggle to efficiently mitigate exposure risks across large infrastructures. The Zafran Integration with Palo XSOAR helps you implement **Automated, High Impact Mitigations at scale**. With this integration, teams can prioritize mitigation actions, trigger playbooks with a single click, and streamline their response efforts, all from within the Palo XSOAR environment.

## Configure Zafran API on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Zafran API.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. api.zafran.io) | True |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### zafran-mitigation-performed

***
Update on mitigations performed

#### Base Command

`zafran-mitigation-performed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| external_ticket_id | External service ticket ID. | Optional | 
| external_ticket_url | External service ticket link. | Optional | 
| id | Mitigation ID. | Required | 
| state | Mitigation status     new - New mitigation     pending_approval - Waiting for mitigation approval     rejected - Mitigative action was rejected.     in_progress - Mitigation approved and in progress.     completed - Mitigation applied successfully. Possible values are: new, pending_approval, rejected, in_progress, completed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zafran.MitigationsPerformedResponse.internal_status_code | Number | Internal status code. | 
| Zafran.MitigationsPerformedResponse.message | String | Error message. | 

### zafran-mitigations-export

***
Export recommended mitigations

#### Base Command

`zafran-mitigations-export`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filter | ZQL filter. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zafran.UpstreamMitigation.assets_count | Number | Assets count. | 
| Zafran.UpstreamMitigation.control_product | String | Control Product. | 
| Zafran.UpstreamMitigation.exposure | Number | Exposure in days. | 
| Zafran.UpstreamMitigation.id | String | Zafran mitigation unique id. | 
| Zafran.UpstreamMitigation.mitigation_type | String | Mitigation type. | 
| Zafran.UpstreamMitigation.recommendation | String | Recommendation. | 
| Zafran.UpstreamMitigation.title | String | Title. | 
| Zafran.UpstreamMitigation.vulnerabilities_count | Number | Vulnerabilities count. | 
| Zafran.UpstreamMitigation.internal_status_code | Number | Internal status code. | 
| Zafran.UpstreamMitigation.message | String | Error message | 

### zafran-mitigations-performed

***
Update on mitigations performed

#### Base Command

`zafran-mitigations-performed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mitigation_id | Mitigation ID. | Optional | 
| mitigation_ids | Mitigation IDs. | Optional | 
| state | Mitigation status     new - New mitigation     pending_approval - Waiting for mitigation approval     rejected - Mitigative action was rejected.     in_progress - Mitigation approved and in progress.     completed - Mitigation applied successfully. Possible values are: new, pending_approval, rejected, in_progress, completed. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Zafran.MitigationsPerformedResponse.internal_status_code | Number | Internal status code. | 
| Zafran.MitigationsPerformedResponse.message | String | Error message. | 
