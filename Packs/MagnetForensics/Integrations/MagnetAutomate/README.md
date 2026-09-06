Magnet Automate is an orchestration and automation platform that accelerates your digital forensics investigations by automating workflows and integrating with various forensic tools.
This integration was integrated and tested with version 0.2.0 of Magnet Automate API.

## Configure Magnet Automate in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### mf-automate-custom-fields-list

***
Retrieves a list of custom fields for cases and evidence sources.

#### Base Command

`mf-automate-custom-fields-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default value is 50. Default is 50. | Optional |
| all_results | Whether to return all of the results. Overrides the limit argument if used. Default value is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetAutomate.CustomFields.id | Number | The unique identifier of the custom field. |
| MagnetAutomate.CustomFields.name | String | The name of the custom field. |
| MagnetAutomate.CustomFields.type | String | The data type of the custom field. |
| MagnetAutomate.CustomFields.elementType | Unknown | The element type of the custom field. |
| MagnetAutomate.CustomFields.description | String | A description of the custom field. |
| MagnetAutomate.CustomFields.required | Boolean | Whether the custom field is required. |
| MagnetAutomate.CustomFields.exposeInWorkflow | Boolean | Whether the custom field is exposed in workflows. |
| MagnetAutomate.CustomFields.variableName | String | The variable name associated with the custom field. |

#### Command Example

`!mf-automate-custom-fields-list limit=10`

### mf-automate-case-create

***
Creates a new case in Magnet Automate. Use mf-automate-custom-fields-list to get all available custom fields.

#### Base Command

`mf-automate-case-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_number | The unique case number to assign to the new case. | Required |
| custom_field_values | A JSON object containing custom field values for the case. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetAutomate.Case.id | Number | The unique identifier of the created case. |
| MagnetAutomate.Case.caseNumber | String | The case number assigned to the case. |
| MagnetAutomate.Case.customFieldValues | Unknown | The custom field values associated with the case. |

#### Command Example

`!mf-automate-case-create case_number="CASE-2024-001" custom_field_values="{\"2\": \"Civil\", \"3\": \"Magnet Forensics\"}"`

### mf-automate-cases-list

***
Retrieves a list of all cases or information about a specific case.

#### Base Command

`mf-automate-cases-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case to retrieve. | Optional |
| limit | The maximum number of results to return. Default value is 50. Default is 50. | Optional |
| all_results | Whether to return all of the results. Overrides the limit argument if used. Default value is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetAutomate.Case.id | Number | The unique identifier of the case. |
| MagnetAutomate.Case.caseNumber | String | The case number. |

#### Command Example

`!mf-automate-cases-list limit=5`

#### Command Example

`!mf-automate-cases-list case_id=10`

### mf-automate-case-delete

***
Deletes a specific case from Magnet Automate.

#### Base Command

`mf-automate-case-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

`!mf-automate-case-delete case_id=10`

### mf-automate-case-cancel

***
Cancels an ongoing case in Magnet Automate.

#### Base Command

`mf-automate-case-cancel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case to cancel. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

`!mf-automate-case-cancel case_id=10`

### mf-automate-workflow-run-start

***
Starts a new workflow run and associates it with a specific case.

#### Base Command

`mf-automate-workflow-run-start`

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
| MagnetAutomate.WorkflowRun.id | Number | The unique identifier of the started workflow run. |
| MagnetAutomate.WorkflowRun.path | String | The path to the workflow run data. |
| MagnetAutomate.WorkflowRun.version | Number | The version of the workflow run. |
| MagnetAutomate.WorkflowRun.caseId | Number | The identifier of the associated case. |
| MagnetAutomate.WorkflowRun.caseTypeId | Number | The identifier of the case type. |
| MagnetAutomate.WorkflowRun.basePath | String | The base path for the workflow run. |
| MagnetAutomate.WorkflowRun.automateVersion | String | The version of Magnet Automate used for the run. |

#### Command Example

`!mf-automate-workflow-run-start case_id=10 evidence_number="ExhibitA" type="{\"ImageSource\": {\"path\": \"C:\\\\testdata\\\\image\\\\image123.001\"}}" workflow_id=3 output_path="C:\\testdata\\output" platform="windows" decryption_type="password" decryption_value="MySecretPassword" continue_on_decryption_fail=false custom_field_values="{\"5\": \"Evidence Value A\", \"7\": \"Evidence Value B\"}" assigned_node_name="AGENT1"`

### mf-automate-workflow-run-list

***
Retrieves a list of all workflow runs for a specific case or details of a specific run.

#### Base Command

`mf-automate-workflow-run-list`

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
| MagnetAutomate.WorkflowRun.id | Number | The unique identifier of the workflow run. |
| MagnetAutomate.WorkflowRun.evidence | Unknown | Details about the evidence associated with the run. |
| MagnetAutomate.WorkflowRun.status | String | The current status of the workflow run. |
| MagnetAutomate.WorkflowRun.workflowId | Number | The identifier of the workflow being run. |
| MagnetAutomate.WorkflowRun.currentStage | Unknown | Information about the current stage of the workflow run. |
| MagnetAutomate.WorkflowRun.outputPath | String | The output path for the workflow run. |
| MagnetAutomate.WorkflowRun.startDateTime | Date | The date and time when the workflow run started. |
| MagnetAutomate.WorkflowRun.endDateTime | Date | The date and time when the workflow run ended. |
| MagnetAutomate.WorkflowRun.automateVersion | String | The version of Magnet Automate used. |
| MagnetAutomate.WorkflowRun.createdBy | Unknown | Information about the user who created the workflow run. |
| MagnetAutomate.WorkflowRun.duration | Number | The duration of the workflow run in seconds. |
| MagnetAutomate.WorkflowRun.completedStages | Unknown | A list of completed stages in the workflow run. |

#### Command Example

`!mf-automate-workflow-run-list case_id=10`

#### Command Example

`!mf-automate-workflow-run-list case_id=10 run_id=11`

### mf-automate-workflow-run-delete

***
Deletes a specific workflow run from a case.

#### Base Command

`mf-automate-workflow-run-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case. | Required |
| run_id | The unique identifier of the workflow run to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

`!mf-automate-workflow-run-delete case_id=10 run_id=11`

### mf-automate-workflow-run-cancel

***
Cancels a specific workflow run.

#### Base Command

`mf-automate-workflow-run-cancel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| case_id | The unique identifier of the case. | Required |
| run_id | The unique identifier of the workflow run to cancel. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

`!mf-automate-workflow-run-cancel case_id=10 run_id=11`

### mf-automate-merge-workflow-run-start

***
Starts a merge workflow run for multiple existing workflow runs.

#### Base Command

`mf-automate-merge-workflow-run-start`

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
| MagnetAutomate.WorkflowRun.id | Number | The unique identifier of the started merge workflow run. |
| MagnetAutomate.WorkflowRun.path | String | The path to the merge workflow run data. |
| MagnetAutomate.WorkflowRun.version | Number | The version of the workflow run. |
| MagnetAutomate.WorkflowRun.caseId | Number | The identifier of the associated case. |
| MagnetAutomate.WorkflowRun.caseTypeId | Number | The identifier of the case type. |
| MagnetAutomate.WorkflowRun.basePath | String | The base path for the workflow run. |
| MagnetAutomate.WorkflowRun.automateVersion | String | The version of Magnet Automate used. |

#### Command Example

`!mf-automate-merge-workflow-run-start case_id=10 run_ids="1,2,3" workflow_id=3 output_path="C:\\testdata\\output" assigned_node_name="AGENT1"`

### mf-automate-workflow-list

***
Retrieves a list of all available workflows.

#### Base Command

`mf-automate-workflow-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default value is 50. Default is 50. | Optional |
| all_results | Whether to return all of the results. Overrides the limit argument if used. Default value is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetAutomate.Workflow.id | Number | The unique identifier of the workflow. |
| MagnetAutomate.Workflow.name | String | The name of the workflow. |
| MagnetAutomate.Workflow.type.name | String | The name of the workflow type. |
| MagnetAutomate.Workflow.description | String | A description of the workflow. |
| MagnetAutomate.Workflow.outputPath | String | The default output path for the workflow. |

#### Command Example

`!mf-automate-workflow-list limit=10`

### mf-automate-workflow-delete

***
Deletes a specific workflow from Magnet Automate.

#### Base Command

`mf-automate-workflow-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workflow_id | The unique identifier of the workflow to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

`!mf-automate-workflow-delete workflow_id=5`

### mf-automate-workflow-get

***
Retrieves detailed information and export data for a specific workflow. Use mf-automate-workflow-list to get all available workflows.

#### Base Command

`mf-automate-workflow-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workflow_id | The unique identifier of the workflow to retrieve. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetAutomate.Workflow.id | Number | The unique identifier of the workflow. |
| MagnetAutomate.Workflow.automateVersion | String | The version of Magnet Automate the workflow was created in. |
| MagnetAutomate.Workflow.name | String | The name of the workflow. |
| MagnetAutomate.Workflow.description | String | A description of the workflow. |
| MagnetAutomate.Workflow.sourceType | String | The type of evidence source the workflow accepts. |
| MagnetAutomate.Workflow.sourceConfig | Unknown | Configuration details for the evidence source. |
| MagnetAutomate.Workflow.outputPath | String | The output path for the workflow. |
| MagnetAutomate.Workflow.keylistPath | String | The path to the keylist used by the workflow. |
| MagnetAutomate.Workflow.passwordListPath | String | The path to the password list used by the workflow. |
| MagnetAutomate.Workflow.continueOnDecryptionFail | String | Whether the workflow continues if decryption fails. |
| MagnetAutomate.Workflow.distribution | String | The distribution settings for the workflow. |
| MagnetAutomate.Workflow.localMode | Boolean | Whether the workflow runs in local mode. |
| MagnetAutomate.Workflow.timeExported | Date | The date and time when the workflow was exported. |

#### Command Example

`!mf-automate-workflow-get workflow_id=5`

### mf-automate-node-create

***
Creates a new node (agent) in Magnet Automate.

#### Base Command

`mf-automate-node-create`

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
| MagnetAutomate.Node.id | Number | The unique identifier of the created node. |
| MagnetAutomate.Node.name | String | The name of the node. |
| MagnetAutomate.Node.status | String | The current status of the node. |
| MagnetAutomate.Node.workingDirectory | String | The working directory of the node. |
| MagnetAutomate.Node.address | String | The network address of the node. |
| MagnetAutomate.Node.applications | Unknown | A list of applications installed on the node. |

#### Command Example

`!mf-automate-node-create name="NODE-002" address="automate-node-2" working_directory="C:\\automate\\temp" applications_json="[{\"applicationName\": \"AXIOM Process\", \"applicationVersion\": \"7.0.0\", \"applicationPath\": \"C:\\\\Program Files\\\\Magnet Forensics\\\\Magnet AUTOMATE\\\\agent\\\\AXIOM Process\\\\AXIOMProcess.CLI.exe\"}]"`

### mf-automate-nodes-list

***
Retrieves a list of all available nodes (agents).

#### Base Command

`mf-automate-nodes-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of results to return. Default value is 50. Default is 50. | Optional |
| all_results | Whether to return all of the results. Overrides the limit argument if used. Default value is False. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MagnetAutomate.Node.id | Number | The unique identifier of the node. |
| MagnetAutomate.Node.name | String | The name of the node. |
| MagnetAutomate.Node.status | String | The current status of the node. |
| MagnetAutomate.Node.workingDirectory | String | The working directory of the node. |
| MagnetAutomate.Node.address | String | The network address of the node. |
| MagnetAutomate.Node.applications | Unknown | A list of applications installed on the node. |

#### Command Example

`!mf-automate-nodes-list limit=10`

### mf-automate-node-update

***
Updates the configuration of an existing node.

#### Base Command

`mf-automate-node-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| node_id | The unique identifier of the node to update. | Required |
| address | The new network address or hostname of the node. | Optional |
| working_directory | The new working directory for the node. | Optional |
| applications_json | A JSON array of applications installed on the node. | Optional |

#### Context Output

There is no context output for this command.

#### Command Example

`!mf-automate-node-update node_id=1 address="automate-node-updated" working_directory="C:\\automate\\updatedTemp" applications_json="[{\"applicationName\": \"AXIOM Process\", \"applicationVersion\": \"7.1.0\"}]"`

### mf-automate-node-delete

***
Deletes a specific node from Magnet Automate.

#### Base Command

`mf-automate-node-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| node_id | The unique identifier of the node to delete. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

`!mf-automate-node-delete node_id=1`
