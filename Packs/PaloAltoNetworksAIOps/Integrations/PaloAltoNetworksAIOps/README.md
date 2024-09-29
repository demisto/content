Palo Alto Networks Best Practice Assessment (BPA) analyzes NGFW and Panorama configurations and compares them to the best practices.
This integration was integrated and tested with version from March 2024 of PaloAltoNetworksAIOps.

## Configure Palo Alto Networks AIOps in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Pan-OS/Panorama Server URL | True |
| Pan-OS/Panorama API Key | True |
| TSG ID | True |
| Client ID | True |
| Client Secret | True |
| Trust any certificate (not secure) | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aiops-bpa-report-generate

***
Generates a bpa report. Steps - 
- Get information about Pan-OS/Panorama device.
- Get configuration file of Pan-OS/Panorama. If the user provided an entry_id to a config file this step is skipped.
- Use the information retrieved above to generate a BPA report.
- During this process the API also generates a report_id for internal use.

#### Base Command

`aiops-bpa-report-generate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | - Optional: Use this argument if you prefer to upload a configuration file instead of generating the report from Panorama/PAN-OS.<br/>- Entry_id from Cortex XSOAR War Room after uploading a file - should be a config file in xml format.<br/>- If you used this argument and the process failed or reached a timeout, make sure the config file is in xml format. | Optional | 
| requester_email | Requester email. | Required | 
| requester_name | Requester name. | Required | 
| interval_in_seconds | Interval for polling mechanism. Default is 30. | Optional | 
| timeout | Timeout for downloading the file. Default is 600. | Optional | 
| export_as_file | Whether to export the generated report as a file. Possible values are: true, false. Default is True. | Optional | 
| show_in_context | Whether to show the report data inside the context. Possible values are: true, false. Default is False. | Optional | 

#### Context Output

By default, there is no context output for this command.
When using show_in_context = True flag the generated report will be inserted to the context data.

#### Command example
```!aiops-bpa-report-generate requester_email=testl@gmail.com requester_name=test```
#### Human Readable Output

#### - Initiated

>The report with id 7fec3669-c7bc-4113-b8b9-cae6a2aeb066 was sent successfully. Download in progress...

#### - If generation was successful

> Generated a file with the relevant data and insert into context data if requested.

#### - If generation was unsuccessful

>The report with id 7fec3669-c7bc-4113-b8b9-cae6a2aeb066 could not be generated- finished with an error.

#### - If timed out

> Scheduled entry timed out.
#####  This indicates that the configuration file is not in the correct format or that the timeout period is insufficient for generating the report.