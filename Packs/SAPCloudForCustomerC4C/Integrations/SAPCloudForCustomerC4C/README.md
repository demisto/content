The SAP Cloud for Customer solution helps you manage day-to-day sales and service interactions efficiently by sending and receiving signals between front- and back-office solutions and providing a single view of the customer.
This integration was integrated and tested with version xx of SAPCloudForCustomerC4C.

## Configure SAP Cloud For Customer C4C in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Your server URL | True |
| Username | True |
| Password | True |
| Report ID | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Maximum number of audit events per fetch | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### sap-cloud-get-events

***
Retrieves events from the SAP Cloud for Customer API based on specified filters.

#### Base Command

`sap-cloud-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | The **start date** for filtering events. Events newer than or equal to this date will be retrieved.<br/>Must be in `DD-MM-YYYY HH:MM:SS` format (e.g., `10-07-2025 14:17:46`).<br/>. | Required |
| days_from_start | The **number of days** to include events after the `start_date`. For example, if `start_date` is <br/>'10-07-2025 10:00:00' and `days_from_start` is '2', events will be retrieved up to '12-07-2025 10:00:00'.<br/>It's recommended to keep this value no more than 5 days to avoid very large result sets.<br/>. Default is 2. | Optional |
| should_push_events | Set to **true** to create events in your system from the retrieved data. <br/>If **false** (default), the command will only display the events without creating them.<br/>. Possible values are: true, false. Default is false. | Optional |
| limit | The **maximum number of events** to retrieve. If more events match the criteria, only this<br/>specified amount will be returned.<br/>. Default is 10. | Optional |

#### Context Output

There is no context output for this command.
