Use the Exterro package to integrate with the Exterro FTK platform enabling the automation of case/evidence management and endpoint collection.

Documentation for the integration was provided by FTK Connect.

## Configure Exterro in Cortex


| **Parameter** | **Description** | **Example** |
| --------- | ----------- | ------- |
| Name | A meaningful name for the integration instance. | FTKC Instance |
| Web Protocol | Protocol used in the FTKC server | https (or) https |
| Service URL | The URL to the FTKC server, including the scheme. | FQDN or IP address in X.X.X.X format with scheme specified. |
| Service Listening Port | The Port to the FTKC server. | 4443 |
| The API authentication key | A piece of data that servers use to verify for authenticity | eea810f5-a6f6 |
| The path to the public certificate required to authenticate | When selected, certificates are not checked. | N/A |
    

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.


### Trigger Automation Workflow in FTK Connect 

* * *

Triggers the automation job and returns a string.

##### Base Command

`exterro-ftk-trigger-workflow`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| automation_id | The Id of the automation workflow. | Required |
| case_name | The name of the case. | Optional |
| case_ids | Value of caseids. | Optional |
| evidence_path | The filepath of the evidence. | Optional |
| target_ips |  Targetips for the collection. | Optional |
| search_tag_path | The filepath of the search and tag. | Optional |
| export_path | The path to export files. | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExterroFTK.Workflow.Status | string | The Status of the automation workflow trigger. |


##### Command Example
If automation workflow Id 232 is designed for Agent Memory collection in FTK Connect, then below command can be used to trigger the automation job from cortex xsoar.
```
exterro-ftk-trigger-workflow automation_id=232 target_ips=X.X.X.X
```
##### Command Example
If automation workflow Id 233 is designed to create new case, add and process the evidence from provided path in FTK Connect, then below command can be used to trigger the automation job from cortex xsoar.
```
exterro-ftk-trigger-workflow automation_id=233 case_name="Test case_name" evidence_path="\\X.X.X.X\ProjectData\Evidences\AR"
```

##### Context Example
```
{
    ExterroFTK.Workflow
    {
        'Status': True
    }
}
```

##### Human Readable Output

True