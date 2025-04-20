Automate your privacy Incident Response workflow through the BreachRx platform.
This integration was integrated and tested with version 1.20 of BreachRx

## Configure BreachRx in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Your BreachRx URL |  | True |
| GraphQL API URL |  | True |
| API Key | The API Key to use for connection | True |
| Secret Key | The API Key to use for connection | True |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### breachrx-incident-create
***
Create a privacy Incident on the BreachRx platform.


#### Base Command

`breachrx-incident-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_name | The name to use when creating the privacy Incident on the BreachRx platform. | Optional |
| description | A brief description to explain the privacy Incident on the BreachRx platform. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BreachRx.Incident.id | string | The ID of the privacy Incident on the BreachRx platform. |
| BreachRx.Incident.name | string | The name of the privacy Incident on the BreachRx platform. |
| BreachRx.Incident.description | string | The description of the privacy Incident on the BreachRx platform. |
| BreachRx.Incident.identifier | string | The unique identifier of the privacy Incident on the BreachRx platform. |

### breachrx-incident-actions-get
***
Fetch all actions for a BreachRx privacy Incident.


#### Base Command

`breachrx-incident-actions-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_name | The name of the BreachRx incident to associate with this incident. | Optional |
| incident_identifier | The unique identifier of the BreachRx incident to associate with this incident. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BreachRx.Incident.Actions.id | string | The ID of an Action on a BreachRx privacy Incident. |
| BreachRx.Incident.Actions.name | string | The name of an Action on a BreachRx privacy Incident. |
| BreachRx.Incident.Actions.description | string | The description of an Action on a BreachRx privacy Incident. |
| BreachRx.Incident.Actions.user.email | string | The email of the assigned user of an Action on a BreachRx privacy Incident, if that Action is assigned to a user \(null otherwise\). |

### breachrx-incident-import
***
Link a BreachRx privacy Incident with an XSOAR Incident.


#### Base Command

`breachrx-incident-import`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_name | The name of the BreachRx incident to associate with this incident. | Optional |
| incident_identifier | The unique identifier of the BreachRx incident to associate with this incident. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BreachRx.Incident.id | string | The ID of the privacy Incident on the BreachRx platform. |
| BreachRx.Incident.name | string | The name of the privacy Incident on the BreachRx platform. |
| BreachRx.Incident.identifier | string | The unique identifier of the privacy Incident on the BreachRx platform. |

### breachrx-incident-get
***
Find a BreachRx privacy Incident on the connected BreachRx platform.


#### Base Command

`breachrx-incident-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_name | The name of the BreachRx incident to associate with this incident. | Optional |
| incident_identifier | The unique identifier of the BreachRx incident to associate with this incident. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BreachRx.Incident.id | string | The ID of the privacy Incident on the BreachRx platform. |
| BreachRx.Incident.name | string | The name of the privacy Incident on the BreachRx platform. |
| BreachRx.Incident.identifier | string | The unique identifier of the privacy Incident on the BreachRx platform. |