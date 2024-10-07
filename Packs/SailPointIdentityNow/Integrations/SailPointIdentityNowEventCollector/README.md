This is the SailPoint IdentityNow event collector integration for Cortex XSIAM.
This integration was integrated and tested with version 3 of SailPoint API.

## Configure SailPoint IdentityNow Event Collector in Cortex


| **Parameter** | **Required** |
| --- | --- |
| IdentityNow Server URL (e.g., https://{tenant}.api.identitynow.com)  <br /> In order to get the tenant name, follow this [link](https://developer.sailpoint.com/docs/api/getting-started/#find-your-tenant-name).| True |
| Client ID <br /> In order to generate the Client ID and Client Secret, follow this [link](https://developer.sailpoint.com/docs/api/authentication/#generate-a-personal-access-token).  | True |
| Client Secret | True |
| Max number of events per fetch | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


Note: After generating client credentials, it is required to allow the following scopes: sp, search, read.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### identitynow-get-events

***
Gets events from SailPoint IdentityNow. This command is used for developing/debugging and is to be used with caution, as it can create events, leading to event duplication and exceeding API request limitations.

#### Base Command

`identitynow-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | If true, the command will create events, otherwise it will only display them. Possible values are: true, false. Default is false. | Optional | 
| limit | Maximum number of results to return. Default is 50. | Optional | 
| from_date | Date from which to get events in the format of %Y-%m-%dT%H:%M:%S. | Optional |
| from_id | An ID of the event to retrieve events from.| Optional |

#### Context Output

There is no context output for this command.