Cyble Threat Intel is an integration which will help Existing Cyble Vision users. This integration would allow users to
access the TAXII feed avaialable as part of Vision Licensing and integrate the data into XSOAR.

## Configure Cyble Threat Intel on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cyble Threat Intel.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Required** |
       | --- | --- |
   | Server URL | True |
   | Trust any certificate (not secure) | False |
   | Use system proxy settings | False |
   | Access Token | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBot message appears in the War Room with the command details.

This integration provides following command(s) which can be used to access the Threat Intelligence

### cyble-vision-fetch-taxii

***
Fetch the indicators based on the taxii service

#### Base Command

`cyble-vision-fetch-taxii`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | Returns paginated records of the provided page considering the limits. Default is 1. | Required | 
| limit | Number of records to return per page(max 20). Using a smaller limit will get faster responses. Default is 10. | Optional | 
| start_date | Returns records starting with given date value. (Format: YYYY-mm-dd). | Required | 
| end_date | Returns records till the end date value. (Format: YYYY-mm-dd). | Required | 
| start_time | Returns records starting with given time value (Format: HH:mm:ss). Default is 00:00:00. | Optional | 
| end_time | Returns records till given time value (Format: HH:mm:ss). Default is 00:00:00. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CybleIntel.Threat.details | String | Returns the Threat Intel details from the Taxii service  | 
