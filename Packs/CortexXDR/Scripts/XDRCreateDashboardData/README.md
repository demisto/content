The script creates lists with statistic data for the widgets inside Cortex XDR dashboard.
It used the **GetIncidentsByQuery** script to get all the open XDR incidents, to get also the closed incidents - jsut set the input **includeClosedIncidents** to True.
In order to collect the data, the script read the context key from each incident according to the widget type and add it to demisto list. 
The widget **Cortex XDR Top 10 Alerts** for example gets its data from the list **xdrIncidents_Alerts**,
The values inside the list comes from the context `PaloAltoNetworksXDR.Incident.alerts.name` inside the incidents.
We recommended to use the playbook **Job - Cortex XDR dashboard** that used this script to keep the dashboard update.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Demisto Version | 6.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Job - Cortex XDR dashboard

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| includeClosedIncidents | Set True to collect data for open and closed XDR incidents. |

## Outputs
---
There are no outputs for this script.
