Use the Exterro package to integrate with the Exterro FTK platform enabling the automation of case/evidence management and endpoint collection.

Documentation for the integration was provided by FTK Connect.

## Configure Exterro on Cortex XSOAR

1.  Navigate to **Settings** > **Integrations** > **Servers & Services**.
2.  Search for Exterro FTK.
3.  Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Example** |
    | --------- | ----------- | ------- |
    | Name | A meaningful name for the integration instance. | FTKC Instance |
    | Web Protocol | Protocol used in the FTKC server | https (or) https |
    | Service URL | The URL to the FTKC server, including the scheme. | FQDN or IP address in X.X.X.X format with scheme specified. |
    | Service Listening Port | The Port to the FTKC server. | 4443 |
    | APIKEY | A piece of data that servers use to verify for authenticity | eea810f5-a6f6 |
    | PUBLIC_CERT | When selected, certificates are not checked. | N/A |
    
4.  Click **Test** to validate the URLs, API Key, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.


### Trigger Automation Workflow in FTK Connect 

* * *

Triggers the automation job and returns a string.

##### Base Command

`exterro-ftk-trigger-workflow`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| Automation ID | The Id of the automation workflow. | Required |
| Case Name | The name of the case. | Optional |
| Case IDs | Value of caseids. | Optional |
| Evidence Path | The filepath of the evidence. | Optional |
| Target IPs |  Targetips for the collection. | Optional |
| SearchandTag Path | The filepath of the search and tag. | Optional |
| Export Path | The path to export files. | Optional |


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ExterroFTK.Workflow.Status | string | The Status of the automation workflow trigger. |


##### Command Example
If automation workflow Id 232 is designed for Agent Memory collection in FTK Connect, then below command can be used to trigger the automation job from cortex xsoar.
```
exterro-ftk-trigger-workflow Automation ID=232 Target IPs=X.X.X.X
```
##### Command Example
If automation workflow Id 233 is designed to create new case, add and process the evidence from provided path in FTK Connect, then below command can be used to trigger the automation job from cortex xsoar.
```
exterro-ftk-trigger-workflow Automation ID=233 Case Name="Test case_name" Evidence Path="\\X.X.X.X\ProjectData\Evidences\AR"
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