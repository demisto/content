Extracts Close Reason and Close Notes from a pushed XSOAR incident alert and closes the Cortex XSIAM case if the XSOAR incident was closed.

This script is intended to run inside a Cortex XSIAM trigger playbook for XSOAR-sourced alerts. It reads the alert description to determine whether the source XSOAR incident is closed, then calls `closeInvestigation` with the mapped close reason.

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | xsoar, xsiam, close |

## Outputs

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| XSOARExporter.Close.XSOARIncidentID | String | The XSOAR incident ID from the alert. |
| XSOARExporter.Close.XSOARCloseReason | String | The close reason from XSOAR. |
| XSOARExporter.Close.XSIAMCloseReason | String | The mapped XSIAM close reason. |
| XSOARExporter.Close.CloseNotes | String | The close notes from XSOAR. |
| XSOARExporter.Close.Action | String | Whether the case was closed or no action was taken. |
