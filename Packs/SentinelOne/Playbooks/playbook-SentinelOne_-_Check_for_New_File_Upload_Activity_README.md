Manages a polling loop to check for the results of a submitted file fetch request to an endpoint by SentinelOne.

Input:
* StartTimestamp 
* AgentId
* Timeout 

**Note:** This playbook does not use GenericPolling. This is because the SentinelOne API returns no results when searching for activities, until it has a result. This does not fit into the GenericPolling model of being able to construct a DT query that returns results *until* the condition has been met, and then returning no results from the DT query

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts

### Sub-playbooks
* SentinelOne - Check for New File Upload Activity - Inner Loop

### Integrations
This playbook does not utilize any integrations

### Scripts

### Commands
* DeleteContext
* Set

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** |  **Required** |
| --- | --- | --- | --- |  
| StartTimestamp | The hostname of the device to run on. |  | Required |
| AgentId | The agent_id to check for new activities on |  | Required |
| Timeout | Timeout in minutes | | Required

## Playbook Outputs
---

 **Path** | **Description** | **Type** | 
| --- | --- | --- | --- | 
| SentinelOne.Activity | Found Activity | Unknown

## Playbook Image
---
This image section will be updated when the image it references has been committed to git
