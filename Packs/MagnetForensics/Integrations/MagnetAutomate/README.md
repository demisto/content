Magnet Automate is an orchestration and automation platform that accelerates your digital forensics investigations by automating workflows and integrating with various forensic tools.
This integration was integrated and tested with version 0.2.0 of Magnet Automate API.

## Configure Magnet Automate in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Your server URL | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ma-forensics-custom-fields-list

***
Retrieves a list of custom fields for cases and evidence sources.

#### Base Command

`ma-forensics-custom-fields-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default value is 50. Default is 50. | Optional |
| all_results | Whether to return all of the results. Overrides the limit argument if used. Default value is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetForensics.CustomFields.id | Number | The unique identifier of the custom field. |
| MagnetForensics.CustomFields.name | String | The name of the custom field. |
| MagnetForensics.CustomFields.type | String | The data type of the custom field. |
| MagnetForensics.CustomFields.elementType | Unknown | The element type of the custom field. |
| MagnetForensics.CustomFields.description | String | A description of the custom field. |
| MagnetForensics.CustomFields.required | Boolean | Whether the custom field is required. |
| MagnetForensics.CustomFields.exposeInWorkflow | Boolean | Whether the custom field is exposed in workflows. |
| MagnetForensics.CustomFields.variableName | String | The variable name associated with the custom field. |

### ma-forensic-case-create

***
Creates a new case in Magnet Automate. Use ma-forensics-custom-fields-list to get all available custom fields.

#### Base Command

`ma-forensic-case-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_number | The unique case number to assign to the new case. | Required |
| custom_field_values | A JSON object containing custom field values for the case. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetForensics.Case.id | Number | The unique identifier of the created case. |
| MagnetForensics.Case.caseNumber | String | The case number assigned to the case. |
| MagnetForensics.Case.customFieldValues | Unknown | The custom field values associated with the case. |

### ma-forensics-cases-list

***
Retrieves a list of all cases or information about a specific case.

#### Base Command

`ma-forensics-cases-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case to retrieve. | Optional |
| limit | The maximum number of results to return. Default value is 50. Default is 50. | Optional |
| all_results | Whether to return all of the results. Overrides the limit argument if used. Default value is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetForensics.Case.id | Number | The unique identifier of the case. |
| MagnetForensics.Case.caseNumber | String | The case number. |

### ma-forensics-case-delete

***
Deletes a specific case from Magnet Automate.

#### Base Command

`ma-forensics-case-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case to delete. | Required |

#### Context Output

There is no context output for this command.

### ma-forensics-case-cancel

***
Cancels an ongoing case in Magnet Automate.

#### Base Command

`ma-forensics-case-cancel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case to cancel. | Required |

#### Context Output

There is no context output for this command.

### ma-forensics-workflow-run-start

***
Starts a new workflow run and associates it with a specific case.

#### Base Command

`ma-forensics-workflow-run-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case to associate the workflow run with. | Required |
| evidence_number | An evidence number to apply to the evidence source. | Required |
| type | A JSON object defining the evidence type and its parameters (e.g., ImageSource path). | Required |
| workflow_id | The unique identifier of the workflow to run. | Required |
| output_path | The directory path where the workflow output will be stored. | Optional |
| platform | The platform associated with the evidence. | Optional |
| decryption_type | The type of decryption to use (e.g., Password, RecoveryKey). | Optional |
| decryption_value | The decryption key or password. | Optional |
| continue_on_decryption_fail | Whether to continue the workflow if decryption fails. | Optional |
| custom_field_values | A JSON object containing custom field values for the workflow run. | Optional |
| assigned_node_name | The name of the specific node to assign the workflow run to. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetForensics.WorkflowRun.id | Number | The unique identifier of the started workflow run. |
| MagnetForensics.WorkflowRun.path | String | The path to the workflow run data. |
| MagnetForensics.WorkflowRun.version | Number | The version of the workflow run. |
| MagnetForensics.WorkflowRun.caseId | Number | The identifier of the associated case. |
| MagnetForensics.WorkflowRun.caseTypeId | Number | The identifier of the case type. |
| MagnetForensics.WorkflowRun.basePath | String | The base path for the workflow run. |
| MagnetForensics.WorkflowRun.automateVersion | String | The version of Magnet Automate used for the run. |

### ma-forensics-workflow-run-list

***
Retrieves a list of all workflow runs for a specific case or details of a specific run.

#### Base Command

`ma-forensics-workflow-run-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case to retrieve workflow runs for. | Required |
| run_id | The unique identifier of a specific workflow run to retrieve. | Optional |
| limit | The maximum number of results to return. Default value is 50. Default is 50. | Optional |
| all_results | Whether to return all of the results. Overrides the limit argument if used. Default value is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetForensics.WorkflowRun.id | Number | The unique identifier of the workflow run. |
| MagnetForensics.WorkflowRun.evidence | Unknown | Details about the evidence associated with the run. |
| MagnetForensics.WorkflowRun.status | String | The current status of the workflow run. |
| MagnetForensics.WorkflowRun.workflowId | Number | The identifier of the workflow being run. |
| MagnetForensics.WorkflowRun.currentStage | Unknown | Information about the current stage of the workflow run. |
| MagnetForensics.WorkflowRun.outputPath | String | The output path for the workflow run. |
| MagnetForensics.WorkflowRun.startDateTime | Date | The date and time when the workflow run started. |
| MagnetForensics.WorkflowRun.endDateTime | Date | The date and time when the workflow run ended. |
| MagnetForensics.WorkflowRun.automateVersion | String | The version of Magnet Automate used. |
| MagnetForensics.WorkflowRun.createdBy | Unknown | Information about the user who created the workflow run. |
| MagnetForensics.WorkflowRun.duration | Number | The duration of the workflow run in seconds. |
| MagnetForensics.WorkflowRun.completedStages | Unknown | A list of completed stages in the workflow run. |

### ma-forensics-workflow-run-delete

***
Deletes a specific workflow run from a case.

#### Base Command

`ma-forensics-workflow-run-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case. | Required |
| run_id | The unique identifier of the workflow run to delete. | Required |

#### Context Output

There is no context output for this command.

### ma-forensics-workflow-run-cancel

***
Cancels a specific workflow run.

#### Base Command

`ma-forensics-workflow-run-cancel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case. | Required |
| run_id | The unique identifier of the workflow run to cancel. | Required |

#### Context Output

There is no context output for this command.

### ma-forensics-merge-workflow-run-start

***
Starts a merge workflow run for multiple existing workflow runs.

#### Base Command

`ma-forensics-merge-workflow-run-start`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case. | Required |
| run_ids | A list of workflow run identifiers to merge. | Required |
| workflow_id | The unique identifier of the merge workflow to run. | Required |
| output_path | The directory path where the merged output will be stored. | Optional |
| assigned_node_name | The name of the specific node to assign the merge workflow run to. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetForensics.WorkflowRun.id | Number | The unique identifier of the started merge workflow run. |
| MagnetForensics.WorkflowRun.path | String | The path to the merge workflow run data. |
| MagnetForensics.WorkflowRun.version | Number | The version of the workflow run. |
| MagnetForensics.WorkflowRun.caseId | Number | The identifier of the associated case. |
| MagnetForensics.WorkflowRun.caseTypeId | Number | The identifier of the case type. |
| MagnetForensics.WorkflowRun.basePath | String | The base path for the workflow run. |
| MagnetForensics.WorkflowRun.automateVersion | String | The version of Magnet Automate used. |

### ma-forensics-workflow-list

***
Retrieves a list of all available workflows.

#### Base Command

`ma-forensics-workflow-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default value is 50. Default is 50. | Optional |
| all_results | Whether to return all of the results. Overrides the limit argument if used. Default value is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetForensics.Workflow.id | Number | The unique identifier of the workflow. |
| MagnetForensics.Workflow.name | String | The name of the workflow. |
| MagnetForensics.Workflow.type.name | String | The name of the workflow type. |
| MagnetForensics.Workflow.description | String | A description of the workflow. |
| MagnetForensics.Workflow.outputPath | String | The default output path for the workflow. |

### ma-forensics-workflow-delete

***
Deletes a specific workflow from Magnet Automate.

#### Base Command

`ma-forensics-workflow-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workflow_id | The unique identifier of the workflow to delete. | Required |

#### Context Output

There is no context output for this command.

### ma-forensics-workflow-get

***
Retrieves detailed information and export data for a specific workflow. Use ma-forensics-workflow-list to get all available workflows.

#### Base Command

`ma-forensics-workflow-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workflow_id | The unique identifier of the workflow to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetForensics.Workflow.id | Number | The unique identifier of the workflow. |
| MagnetForensics.Workflow.automateVersion | String | The version of Magnet Automate the workflow was created in. |
| MagnetForensics.Workflow.name | String | The name of the workflow. |
| MagnetForensics.Workflow.description | String | A description of the workflow. |
| MagnetForensics.Workflow.sourceType | String | The type of evidence source the workflow accepts. |
| MagnetForensics.Workflow.sourceConfig | Unknown | Configuration details for the evidence source. |
| MagnetForensics.Workflow.outputPath | String | The output path for the workflow. |
| MagnetForensics.Workflow.keylistPath | String | The path to the keylist used by the workflow. |
| MagnetForensics.Workflow.passwordListPath | String | The path to the password list used by the workflow. |
| MagnetForensics.Workflow.continueOnDecryptionFail | String | Whether the workflow continues if decryption fails. |
| MagnetForensics.Workflow.distribution | String | The distribution settings for the workflow. |
| MagnetForensics.Workflow.localMode | Boolean | Whether the workflow runs in local mode. |
| MagnetForensics.Workflow.timeExported | Date | The date and time when the workflow was exported. |

### ma-forensics-node-create

***
Creates a new node (agent) in Magnet Automate.

#### Base Command

`ma-forensics-node-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name of the node. | Optional |
| address | The network address or hostname of the node. | Optional |
| working_directory | The working directory for the node. | Optional |
| applications_json | A JSON array of applications installed on the node. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetForensics.Node.id | Number | The unique identifier of the created node. |
| MagnetForensics.Node.name | String | The name of the node. |
| MagnetForensics.Node.status | String | The current status of the node. |
| MagnetForensics.Node.workingDirectory | String | The working directory of the node. |
| MagnetForensics.Node.address | String | The network address of the node. |
| MagnetForensics.Node.applications | Unknown | A list of applications installed on the node. |

### ma-forensics-nodes-list

***
Retrieves a list of all available nodes (agents).

#### Base Command

`ma-forensics-nodes-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default value is 50. Default is 50. | Optional |
| all_results | Whether to return all of the results. Overrides the limit argument if used. Default value is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetForensics.Node.id | Number | The unique identifier of the node. |
| MagnetForensics.Node.name | String | The name of the node. |
| MagnetForensics.Node.status | String | The current status of the node. |
| MagnetForensics.Node.workingDirectory | String | The working directory of the node. |
| MagnetForensics.Node.address | String | The network address of the node. |
| MagnetForensics.Node.applications | Unknown | A list of applications installed on the node. |

### ma-forensics-node-update

***
Updates the configuration of an existing node.

#### Base Command

`ma-forensics-node-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| node_id | The unique identifier of the node to update. | Required |
| address | The new network address or hostname of the node. | Optional |
| working_directory | The new working directory for the node. | Optional |
| applications_json | A JSON array of applications installed on the node. | Optional |

#### Context Output

There is no context output for this command.

### ma-forensics-node-delete

***
Deletes a specific node from Magnet Automate.

#### Base Command

`ma-forensics-node-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| node_id | The unique identifier of the node to delete. | Required |

#### Context Output

There is no context output for this command.
