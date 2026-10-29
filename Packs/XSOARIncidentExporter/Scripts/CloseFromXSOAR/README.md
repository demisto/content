Extracts Close Reason and Close Notes from a pushed Cortex XSOAR incident alert and closes the Cortex XSIAM case if the Cortex XSOAR incident was closed.

This script is intended to run inside a Cortex XSIAM trigger playbook for Cortex XSOAR-sourced alerts. It reads the alert description to determine whether the source Cortex XSOAR incident is closed, then calls `closeInvestigation` with the mapped close reason.

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | xsoar, xsiam, close |

## Outputs

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XSOARExporter.Close.XSOARIncidentID | String | The Cortex XSOAR incident ID from the alert. |
| XSOARExporter.Close.XSOARCloseReason | String | The close reason from Cortex XSOAR. |
| XSOARExporter.Close.XSIAMCloseReason | String | The mapped Cortex XSIAM close reason. |
| XSOARExporter.Close.CloseNotes | String | The close notes from Cortex XSOAR. |
| XSOARExporter.Close.Action | String | Whether the case was closed or no action was taken. |
