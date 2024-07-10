CreateIncidents fetches incident created manually.

## Configure Create Test Incidents on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Instances**.
2. Search for Create Test Incidents.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Source URL | The base url of the source you wish to upload/ downlowd files from. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Incident type |  | False |
    | Fetch incidents |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### create-test-incident-from-file
***
Creates incidents from json files provided, and stores it in the instance context.


#### Base Command

`create-test-incident-from-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incidents_path | The path of json file containing incidents. Can contain one incident or a list of incidents. For example: Packs/somePack/TestPlaybooks/examples.json. | Required | 
| attachment_paths | The paths of the files to be added to incidents as attachment. Would be added to all incidents provided in the incident_path file. For example: Packs/somePack/TestPlaybooks/attach.eml. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!create-test-incident-from-file incidents_path=Packs/DeveloperTools/Integrations/CreateIncidents/test_data/incidents.json attachment_path="Packs/DeveloperTools/Integrations/CreateIncidents/test_data/YOU HAVE WON 10000$.eml"```
#### Human Readable Output

>Loaded 1 incidents from file.


### create-test-incident-from-raw-json
***
Creates incidents from json file, and stores it in the instance context.

#### Base Command

`create-test-incident-from-raw-json`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | - |----------|
| incident_raw_json | The json object that represents the incident. | Optional  | 
| incident_entry_id | The enry ID of the json file that represents the incidents. | Optional  | 
| attachment_paths | The paths of the files to be added to incidents as attachment. Would be added to all incidents provided in the incident_path file. For example: Packs/somePack/TestPlaybooks/attach.eml. | Optional | 
| attachment_entry_ids | The enry IDs of the incident attachments. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!create-test-incident-from-raw-json incident_entry_id="12@12"```
#### Human Readable Output

>Loaded 1 incidents from file.

```!create-test-incident-from-raw-json incident_raw_json="{'name': 'test_incident'}"```
#### Human Readable Output

>Loaded 1 incidents from file.
