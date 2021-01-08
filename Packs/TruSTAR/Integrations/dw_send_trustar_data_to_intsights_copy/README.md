This integration downloads TruSTAR IOC data and sends it to IntSights.

/docker_image_create name=trustar dependencies=trustar
This integration was integrated and tested with version 01 of dw_send_trustar_data_to_intsights_copy
## Configure dw_send_trustar_data_to_intsights_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for dw_send_trustar_data_to_intsights_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | intsights | Intsights Credentials \(ID/Key\) | False |
    | trustar | TruSTAR Credentials \(API Key/Secret\) | False |
    | sleep_setting | Time between sending documents | False |
    | ConfidenceLevel | Confidence Level of the documents | False |
    | enclave_ids | The list of enclave ids. separated by commas | False |
    | client_metatag | The email for the user. | False |
    | user_api_key |  | False |
    | user_api_secret |  | False |
    | longRunning | Long running instance | False |
    | incidentType | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### trustar-get-IOC-data
***
 


#### Base Command

`trustar-get-IOC-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trustar-clean-IOC-data
***
 


#### Base Command

`trustar-clean-IOC-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trustar-send-IOC-data-to-intsights
***
 


#### Base Command

`trustar-send-IOC-data-to-intsights`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### trustar-length-IOC-data
***
Get the length of IOC Indicators Obtained


#### Base Command

`trustar-length-IOC-data`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IndicatorValues.Length | unknown | Number of Indicators | 


#### Command Example
``` ```

#### Human Readable Output


