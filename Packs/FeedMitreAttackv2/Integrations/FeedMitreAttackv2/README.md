Use the MITRE ATT&CK® feed to fetch MITRE’s Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK®) content. MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.
This integration was integrated and tested with version xx of MITRE ATT&CK v2 test

## Configure MITRE ATT&CK Feed v2 test on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MITRE ATT&CK Feed v2 test.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fetch indicators |  | False |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | False |
    | Source Reliability | Reliability of the source providing the intelligence data. | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
    |  |  | False |
    |  |  | False |
    | Feed Fetch Interval |  | False |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. | False |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) |  | False |
    | Tags | Supports CSV values. | False |
    | Create relationships |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### mitre-get-indicators
***
Retrieves a limited number of indicators.


#### Base Command

`mitre-get-indicators`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of indicators to return. Default is 10. | Required | 
| raw | Output in raw JSON format. Can be "True" or "False". Possible values are: False, True. Default is False. | Optional | 


#### Context Output

There is no context output for this command.
### mitre-show-feeds
***
Shows the feed names and IDs from TAXII.


#### Base Command

`mitre-show-feeds`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### attack-pattern
***
Looks up the reputation of the indicator.


#### Base Command

`attack-pattern`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack_pattern | Indicator to look up. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| AttackPattern.STIXID | string | The STIX ID of the Attack Pattern. | 
| AttackPattern.KillChainPhases | string | The kill chain phases of the Attack Pattern. | 
| AttackPattern.FirstSeenBySource | string | The first seen by source of the Attack Pattern. | 
| AttackPattern.Description | string | The description of the Attack Pattern. | 
| AttackPattern.OperatingSystemRefs | string | The operating system references of the Attack Pattern. | 
| AttackPattern.Publications | string | The publications of the Attack Pattern. | 
| AttackPattern.MITREID | string | The MITRE ID of the Attack Pattern. | 
| AttackPattern.Tags | string | The tags of the Attack Pattern. | 

### mitre-get-indicator-name
***
Gets the Attack Pattern value from the Attack Pattern ID.


#### Base Command

`mitre-get-indicator-name`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| attack_ids | The Attack Pattern IDs list. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MITREATTACK.id | String | MITRE ATTACK Attack Pattern ID. | 
| MITREATTACK.value | String | MITRE ATTACK Attack Pattern value. | 
