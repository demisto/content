Image processing with Google Vision API

## Configure Google Vision AI in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Google service account JSON (a credentials JSON generated from Google API Manager or from GCP console) | True |
| Use system proxy settings | False |
| Trust any certificate (not secure) | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### google-vision-detect-logos
***
Detects brand logos in the given image.


#### Base Command

`google-vision-detect-logos`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The entry ID of the image to process. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleVisionAPI.Logo.Description | Unknown | The logo description provided by the Google Vision API. | 
| GoogleVisionAPI.Logo.MID | Unknown | The unique logo MID provided by the Google Vision API. | 
| GoogleVisionAPI.Logo.Score | Unknown | The certainty score provided by the Google Vision API. | 