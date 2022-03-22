Cyble Threat Intel is an integration which will help Existing Cyble Vision users. This integration would allow users to access the API avaialable as part of Vision Licensing and integrate the data into XSOAR. 

## Configure Cyble Intel on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Cyble Threat Intel.
3. Click **Add instance** to create and configure a new integration instance.


# Commands
    
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

This integration provides following command(s) which can be used to access the Threat Intelligence

**!cyble-vision-fetch-taxii**
| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| page | Returns paginated records of the provided page considering the limits | True |
| limit | Number of records to return per page(max 20). Using a smaller limit will get faster responses. | False |
| start_date | Returns records starting with given date value. (Format: YYYY-mm-dd) | True |
| end_date | Returns records till the end date value. (Format: YYYY-mm-dd) | True |
| start_time | Returns records starting with given time value (Format: HH:mm:ss) | False |
| end_time | Returns records till given time value (Format: HH:mm:ss) | False |
