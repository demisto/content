Integrate with Mandiant Advantage Attack Surface Management to import "issues" as Incidents.
This integration was integrated and tested with version 1 of AttackSurfaceManagement

## Configure Mandiant Attack Surface Management in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your server URL | The ASM API URL.  Leave as \`https://asm-api.advantage.mandiant.com/\` if you're unsure | True |
| Access Key | The Access and Secret Keys used for authentication | True |
| Secret Key |  | True |
| Project ID | The ASM Project ID to retrieve issues from | False |
| Collection IDs | A list of Collection IDs, separated by commas \(\`,\`\) | False |
| Initial Lookback Days | The number of days to look back when first retrieving issues. | True |
| Maximum Issues To Fetch | The maximum number of issues to pull during a single fetch-incidents command. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Mirror incoming incidents |  | False |

Test of mirroring! 1. 2. 3. 4.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### attacksurfacemanagement-get-projects

***
Retrieve a list of all accessible ASM projects.

#### Base Command

`attacksurfacemanagement-get-projects`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MandiantAdvantageASM.Projects.Name | String | The name of the project | 
| MandiantAdvantageASM.Projects.ID | Number | The ID of the project | 
| MandiantAdvantageASM.Projects.Owner | unknown | The E-Mail of the project owner | 

#### Command example

```!attacksurfacemanagement-get-projects```

#### Context Example

```json
{
  "MandiantAdvantageASM": {
    "Projects": [
      {
        "ID": 6797,
        "Name": "ASMQA_AttackSurfaceAPP",
        "Owner": "name@attacksurface.app"
      }
    ]
  }
}
```

#### Human Readable Output

>### Results

>|ID|Name|Owner|
>|---|---|---|
>| 6797 | ASMQA_AttackSurfaceAPP | name@attacksurface.app |


### attacksurfacemanagement-get-collections

***
Retrieve a list of collections for a specified project

#### Base Command

`attacksurfacemanagement-get-collections`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project_id | The ID of the project to query collections for. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MandiantAdvantageASM.Collections.Name | String | The name of the collection | 
| MandiantAdvantageASM.Collections.ID | String | The ID of the collection | 
| MandiantAdvantageASM.Collections.Owner | unknown | The owner of the collection | 

#### Command example

```!attacksurfacemanagement-get-collections```

#### Context Example

```json
{
    "MandiantAdvantageASM": {
        "Collections": [
            {
                "ID": "attacksurface_mw3tdwq",
                "Name": "Attacksurface_APP_QA",
                "Owner": "ASMQA_AttackSurfaceAPP"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results

>|ID|Name|Owner|
>|---|---|---|
>| attacksurface_mw3tdwq | Attacksurface_APP_QA | ASMQA_AttackSurfaceAPP |


### fetch-incidents

***
Fetch Incidents

#### Base Command

`fetch-incidents`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### get-remote-data

***
Update a specific incident

#### Base Command

`get-remote-data`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ASM Incident ID. | Required | 
| lastUpdate | Retrieve entries that were created after lastUpdate. Default is 0. | Optional | 

#### Context Output

There is no context output for this command.

### update-remote-system

***
Update issue in Mandiant Advantage ASM

#### Base Command

`update-remote-system`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

## Incident Mirroring

You can enable incident mirroring between Cortex XSOAR incidents and Mandiant Attack Surface Management corresponding events (available from Cortex XSOAR version 6.0.0).
To set up the mirroring:

1. Enable *Fetching incidents* in your instance configuration.

Newly fetched incidents will be mirrored in the chosen direction. However, this selection does not affect existing incidents.
**Important Note:** To ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Mandiant Attack Surface Management.