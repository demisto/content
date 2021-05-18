Trigger the `xMatters - Trigger and Wait` playbook to fire an event to xMatters targeting the recipients, then branch based on the chosen response. 

## Dependencies
* xMatters

### Sub-playbooks
* xMatters - Wait for Response

### Integrations
* xMatters

### Scripts
This playbook does not use any scripts.

### Commands
* xm-trigger-workflow

## Playbook Inputs

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| recipients | A comma separated list of Groups or Users to target for a notification |  | Optional |
| subject | A brief summary of the reason to notify |  | Optional |
| body | Detailed description of the reason to notify |  | Optional |
| incident_id | The related incident_id | | Optional | 

## Playbook Outputs

| **Name** | **Description** |
| --- | --- | 
| xMatters.UserResponse | The user's response | 

## Playbook Image

![xMatters - Example Conditional Actions](xMatters_-_Example_Conditional_Actions.png)
