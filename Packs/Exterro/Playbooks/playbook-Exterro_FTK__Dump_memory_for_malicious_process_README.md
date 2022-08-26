Dumps memory of the processes running on AD agent.

## Dependencies

This playbook uses the following integration.

## Integrations

* Exterro FTK

## Commands

* exterro-ftk-trigger-workflow

## Playbook Inputs

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| Automation ID | FTK Connect Automation workflow Id | Required |
| Target IPs | IP address of the Agent | Optional | 

## Playbook Outputs

|**Path** | **Description** | **Type** |
| --- | --- | --- |
| ExterroFTK.Workflow.Status | Indicates response of the API used to trigger FTK Connect automation job | boolean |

## Playbook Image

![Exterro_FTK__Dump_Memory_using_FTK_Connect_Automation_Mon_Aug_22_2022](https://user-images.githubusercontent.com/32624966/185980427-e70310c7-58a0-4002-ade2-3534560779e7.png)

 

<img width="858" alt="Exterro_FTK__Dump_Memory_using_FTK_Connect_Automation_Mon_Aug_22_2022_1" src="https://user-images.githubusercontent.com/32624966/185980484-e0a1235d-edc8-4aaa-a386-eaeb05803500.png">