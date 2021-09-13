Submit Password Protected ZIP File.

Use "Picard-2399" as your zip password.
This integration was integrated and tested with version xx of Hatching Triage Sandbox

## Configure Hatching Triage Sandbox on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Hatching Triage Sandbox.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Hatching Triage API URL | True |
    |  | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### HatchingSubmitFile
***
Submit File To SandBox


#### Base Command

`HatchingSubmitFile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| FileEntryID | File EntryID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### HatchingGetReport
***
Get Report From SandBox


#### Base Command

`HatchingGetReport`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| SampleID | Sample ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


