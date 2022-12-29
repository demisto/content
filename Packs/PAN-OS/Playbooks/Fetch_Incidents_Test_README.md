

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
* VerifyEnoughIncidents
* Set
* VerifyObjectFieldsList
* VerifyIntegrationHealth
* GetInstanceName
* DeleteContext
* SearchIncidentsV2

### Commands
* demisto-api-get

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| sourcebrand | Id of Integration that we want to test. | Panorama | Optional |
| searchfield | Comma separated list of fields to confirm that exists in all incidents. | CustomFields.destinationport | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Fetch Incidents Test](../doc_files/Fetch_Incidents_Test.png)