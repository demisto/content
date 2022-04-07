Inner loop called by the `SentinelOne - Check for New File Upload Activity`

Input:
* StartTimestamp (Default: ${StartTimestamp})
* agent_id
* Counter
* MaxCounter

Output:
* SentinelOne.Activity
* Counter

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts

### Sub-playbooks


### Integrations
* SentinelOne v2

### Scripts
* DeleteContext
* Set
* Sleep

### Commands
* sentinelone-get-activities

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** |  **Required** |
| --- | --- | --- | --- |  
| StartTimestamp | The hostname of the device to run on. | ${Endpoint.Hostname} | Required |
| AgentId | The agent_id to check for new activities on |  | Required |
| Counter | Current iteration of loop counter | | Required |
| MaxCounter | Place at which to stop the inner loop | | Required | 

## Playbook Outputs
---

 **Path** | **Description** | **Type** | 
| --- | --- | --- | --- | 
| SentinelOne.Activity | Found Activity | Unknown
| Counter | Counter of number of times inner loop executed | number

## Playbook Image
---
This image section will be updated when the image it references has been committed to git
