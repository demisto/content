Hashicorp Terraform provide infrastructure automation to provision and manage resources in any cloud or data center with Terraform.
This integration was integrated and tested with version v1.4.4 of HashicorpTerraform.

## Configure HashiCorp Terraform in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Token | The API Key to use for connection. | True |
| Default Organization Name | There is an option to override with a command input parameter. If not provided, policy commands should require the organization name. | False |
| Default Workspace ID | There is an option to override with an input parameter. If not provided, some commands should require the workspace ID. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### terraform-runs-list

***
List runs in a workspace.

#### Base Command

`terraform-runs-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| workspace_id | The workspace ID to list runs for. | Optional | 
| run_id | The run ID to get a specific run. | Optional | 
| filter_status | The run status to filter by. Possible values are: pending, fetching, fetching_completed, pre_plan_running, pre_plan_completed, queuing, plan_queued, planning, planned, cost_estimating, cost_estimated, policy_checking, policy_override, policy_soft_failed, policy_checked, confirmed, post_plan_running, post_plan_completed, planned_and_finished, planned_and_saved, apply_queued, applying, applied, discarded, errored, canceled, force_canceled. | Optional | 
| page_number | The page number of the results to return. Default is 1. | Optional | 
| page_size | The number of results to return per page. Default is 20, maximum is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Terraform.Run.data.id | String | The run ID. | 
| Terraform.Run.data.attributes.status | String | The run status. | 
| Terraform.Run.data.relationships.plan.data.id | String | The plan ID. | 
| Terraform.Run.data.attributes.status-timestamps.planned-at | Date | The datetime the plan was planned. | 
| Terraform.Run.data.type | String | THe run type. | 
| Terraform.Run.data.attributes.actions.is-cancelable | Boolean | Flag indicating whether the Terraform run can be canceled. | 
| Terraform.Run.data.attributes.actions.is-confirmable | Boolean | Flag indicating whether the Terraform run can be confirmed. | 
| Terraform.Run.data.attributes.actions.is-discardable | Boolean | Flag indicating whether the Terraform run can be discarded. | 
| Terraform.Run.data.attributes.actions.is-force-cancelable | Boolean | Flag indicating whether the Terraform run can be force-canceled. | 
| Terraform.Run.data.attributes.canceled-at | Unknown | Timestamp indicating when the Terraform run was canceled. | 
| Terraform.Run.data.attributes.created-at | Date | Timestamp indicating when the Terraform run was created. | 
| Terraform.Run.data.attributes.has-changes | Boolean | Flag indicating whether there are changes in the Terraform run. | 
| Terraform.Run.data.attributes.auto-apply | Boolean | Flag indicating whether auto-apply is enabled for the Terraform run. | 
| Terraform.Run.data.attributes.allow-empty-apply | Boolean | Flag indicating whether empty apply is allowed for the Terraform run. | 
| Terraform.Run.data.attributes.allow-config-generation | Boolean | Flag indicating whether configuration generation is allowed for the Terraform run. | 
| Terraform.Run.data.attributes.is-destroy | Boolean | Flag indicating whether the Terraform run is a destroy operation. | 
| Terraform.Run.data.attributes.message | String | Text message associated with the Terraform run. | 
| Terraform.Run.data.attributes.plan-only | Boolean | Flag indicating whether the Terraform run is for planning only. | 
| Terraform.Run.data.attributes.source | String | Source of the Terraform run. | 
| Terraform.Run.data.attributes.status-timestamps.plan-queueable-at | Date | Timestamp indicating when the Terraform run is queueable in the plan stage. | 
| Terraform.Run.data.attributes.trigger-reason | String | Reason for triggering the Terraform run. | 
| Terraform.Run.data.attributes.target-addrs | Unknown | Target addresses associated with the Terraform run. | 
| Terraform.Run.data.attributes.permissions.can-apply | Boolean | Flag indicating whether the user has permission to apply changes. | 
| Terraform.Run.data.attributes.permissions.can-cancel | Boolean | Flag indicating whether the user has permission to cancel the Terraform run. | 
| Terraform.Run.data.attributes.permissions.can-comment | Boolean | Flag indicating whether the user has permission to add comments. | 
| Terraform.Run.data.attributes.permissions.can-discard | Boolean | Flag indicating whether the user has permission to discard the Terraform run. | 
| Terraform.Run.data.attributes.permissions.can-force-execute | Boolean | Flag indicating whether the user has permission to force execute the Terraform run. | 
| Terraform.Run.data.attributes.permissions.can-force-cancel | Boolean | Flag indicating whether the user has permission to force cancel the Terraform run. | 
| Terraform.Run.data.attributes.permissions.can-override-policy-check | Boolean | Flag indicating whether the user has permission to override policy checks. | 
| Terraform.Run.data.attributes.refresh | Boolean | Flag indicating whether the Terraform run should perform a refresh. | 
| Terraform.Run.data.attributes.refresh-only | Boolean | Flag indicating whether the Terraform run is for refresh only. | 
| Terraform.Run.data.attributes.replace-addrs | Unknown | Replacement addresses associated with the Terraform run. | 
| Terraform.Run.data.attributes.save-plan | Boolean | Flag indicating whether the Terraform run plan should be saved. | 
| Terraform.Run.data.attributes.variables | Unknown | Variables associated with the Terraform run. | 
| Terraform.Run.data.relationships.apply.data.id | String | The apply ID of the run. | 
| Terraform.Run.data.relationships.comments | String | Relationship information for comments associated with the Terraform run. | 
| Terraform.Run.data.relationships.configuration-version | String | Relationship information for the Terraform configuration version associated with the run. | 
| Terraform.Run.data.relationships.cost-estimate | String | Relationship information for cost estimates associated with the Terraform run. | 
| Terraform.Run.data.relationships.created-by | String | Relationship information for the user who created the Terraform run. | 
| Terraform.Run.data.relationships.input-state-version | String | Relationship information for the input state version associated with the Terraform run. | 
| Terraform.Run.data.relationships.run-events | String | Relationship information for events associated with the Terraform run. | 
| Terraform.Run.data.relationships.policy-checks | String | Relationship information for policy checks associated with the Terraform run. | 
| Terraform.Run.data.relationships.workspace | String | Relationship information for the Terraform workspace associated with the run. | 
| Terraform.Run.data.relationships.workspace-run-alerts | String | Relationship information for alerts associated with the Terraform workspace run. | 
| Terraform.Run.data.links.self | String | Link to the Terraform run data. | 

#### Command example
```!terraform-runs-list```
#### Context Example
```json
{
    "Terraform": {
        "Run": {
            "data": [
                {
                    "attributes": {
                        "actions": {
                            "is-cancelable": false,
                            "is-confirmable": true,
                            "is-discardable": true,
                            "is-force-cancelable": false
                        },
                        "allow-config-generation": false,
                        "allow-empty-apply": false,
                        "auto-apply": false,
                        "canceled-at": null,
                        "created-at": "2023-12-17T10:23:43.258Z",
                        "has-changes": true,
                        "is-destroy": false,
                        "message": "Triggered via UI",
                        "permissions": {
                            "can-apply": true,
                            "can-cancel": true,
                            "can-comment": true,
                            "can-discard": true,
                            "can-force-cancel": true,
                            "can-force-execute": true,
                            "can-override-policy-check": true
                        },
                        "plan-only": false,
                        "refresh": true,
                        "refresh-only": false,
                        "replace-addrs": [
                            "fakewebservices_load_balancer.primary_lb"
                        ],
                        "save-plan": false,
                        "source": "tfe-ui",
                        "status": "planned",
                        "status-timestamps": {
                            "plan-queueable-at": "2023-12-17T10:23:43+00:00",
                            "plan-queued-at": "2023-12-17T10:23:43+00:00",
                            "planned-at": "2023-12-17T10:23:52+00:00",
                            "planning-at": "2023-12-17T10:23:48+00:00",
                            "queuing-at": "2023-12-17T10:23:43+00:00"
                        },
                        "target-addrs": null,
                        "terraform-version": "1.4.4",
                        "trigger-reason": "manual",
                        "variables": []
                    },
                    "id": "run-8wpCneWr4TLSzfat",
                    "links": {
                        "self": "/api/v2/runs/run-8wpCneWr4TLSzfat"
                    },
                    "relationships": {
                        "apply": {
                            "data": {
                                "id": "apply-uEYtCmrtg5MvjgTr",
                                "type": "applies"
                            },
                            "links": {
                                "related": "/api/v2/runs/run-8wpCneWr4TLSzfat/apply"
                            }
                        },
                        "comments": {
                            "data": [],
                            "links": {
                                "related": "/api/v2/runs/run-8wpCneWr4TLSzfat/comments"
                            }
                        },
                        "configuration-version": {
                            "data": {
                                "id": "cv-YDcZaBNiRbrdy1w1",
                                "type": "configuration-versions"
                            },
                            "links": {
                                "related": "/api/v2/runs/run-8wpCneWr4TLSzfat/configuration-version"
                            }
                        },
                        "created-by": {
                            "data": {
                                "id": "user-LR5kedWrdZXBWF71",
                                "type": "users"
                            },
                            "links": {
                                "related": "/api/v2/runs/run-8wpCneWr4TLSzfat/created-by"
                            }
                        },
                        "plan": {
                            "data": {
                                "id": "plan-T7zpGYFEioRfWEAq",
                                "type": "plans"
                            },
                            "links": {
                                "related": "/api/v2/runs/run-8wpCneWr4TLSzfat/plan"
                            }
                        },
                        "policy-checks": {
                            "data": [],
                            "links": {
                                "related": "/api/v2/runs/run-8wpCneWr4TLSzfat/policy-checks"
                            }
                        },
                        "run-events": {
                            "data": [
                                {
                                    "id": "re-ga2h6eu41RqrmZRn",
                                    "type": "run-events"
                                },
                                {
                                    "id": "re-ciqzHkW3bDooRzcn",
                                    "type": "run-events"
                                },
                                {
                                    "id": "re-ENvbqnmE72YFj7Wq",
                                    "type": "run-events"
                                },
                                {
                                    "id": "re-xkz1fSTKM25GxkMk",
                                    "type": "run-events"
                                }
                            ],
                            "links": {
                                "related": "/api/v2/runs/run-8wpCneWr4TLSzfat/run-events"
                            }
                        },
                        "task-stages": {
                            "data": [],
                            "links": {
                                "related": "/api/v2/runs/run-8wpCneWr4TLSzfat/task-stages"
                            }
                        },
                        "workspace": {
                            "data": {
                                "id": "ws-ZTbNWsfXHRWRVNmE",
                                "type": "workspaces"
                            }
                        }
                    },
                    "type": "runs"
                }
            ],
            "links": {
                "first": "https://app.terraform.io/api/v2/workspaces/ws-ZTbNWsfXHRWRVNmE/runs?page%5Bnumber%5D=1&page%5Bsize%5D=20",
                "last": "https://app.terraform.io/api/v2/workspaces/ws-ZTbNWsfXHRWRVNmE/runs?page%5Bnumber%5D=1&page%5Bsize%5D=20",
                "next": null,
                "prev": null,
                "self": "https://app.terraform.io/api/v2/workspaces/ws-ZTbNWsfXHRWRVNmE/runs?page%5Bnumber%5D=1&page%5Bsize%5D=20"
            },
            "meta": {
                "pagination": {
                    "current-page": 1,
                    "next-page": null,
                    "page-size": 20,
                    "prev-page": null,
                    "total-count": 9,
                    "total-pages": 1
                },
                "status-counts": {
                    "applied": 1,
                    "apply-queued": 0,
                    "applying": 0,
                    "assessed": 0,
                    "assessing": 0,
                    "canceled": 2,
                    "confirmed": 0,
                    "cost-estimated": 0,
                    "cost-estimating": 0,
                    "discarded": 4,
                    "errored": 0,
                    "fetching": 0,
                    "fetching-completed": 0,
                    "pending": 0,
                    "plan-queued": 0,
                    "planned": 1,
                    "planned-and-finished": 4,
                    "planned-and-saved": 0,
                    "planning": 0,
                    "policy-checked": 0,
                    "policy-checking": 0,
                    "policy-override": 0,
                    "policy-soft-failed": 0,
                    "post-apply-completed": 0,
                    "post-apply-running": 0,
                    "post-plan-awaiting-decision": 0,
                    "post-plan-completed": 0,
                    "post-plan-running": 0,
                    "pre-apply-awaiting-decision": 0,
                    "pre-apply-completed": 0,
                    "pre-apply-running": 0,
                    "pre-plan-awaiting-decision": 0,
                    "pre-plan-completed": 0,
                    "pre-plan-running": 0,
                    "queuing": 0,
                    "queuing-apply": 0,
                    "total": 12
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Terraform Runs
>|Plan id|Planned at|Run id|Status|
>|---|---|---|---|
>| plan-T7zpGYFEioRfWEAq | 2023-12-17T10:23:52+00:00 | run-8wpCneWr4TLSzfat | planned |
>| plan-1JUTBdedobs1Absf | 2023-12-11T11:35:35+00:00 | run-kMNQfAmoDr1k8eaT | discarded |
>| plan-21bfTFiDJ6Rz1VTZ |  | run-jb2j5r3gBievUPfR | canceled |
>| plan-twBdAcLwiGwuE7kt | 2023-12-11T11:29:38+00:00 | run-g7ihSa71hCV9yZt7 | discarded |
>| plan-JEgrv5aBeNUDDRaA | 2023-12-11T11:12:04+00:00 | run-yCYvcx1ZEmmKGXnB | discarded |
>| plan-kJLmtoaywxkXM54P | 2023-12-11T09:11:48+00:00 | run-akCRvcJ6L5cQtAhc | discarded |
>| plan-ZunKDF28KpCyiZAn | 2023-12-10T07:10:08+00:00 | run-rpSjBkbhiKAfMuwX | planned_and_finished |
>| plan-V4fvpvCzGQrsZikD | 2023-11-30T09:21:42+00:00 | run-Q2kS54r6pJjdyYfk | planned_and_finished |
>| plan-ZYYZD69ESo16jENX | 2023-10-25T10:33:11+00:00 | run-wBdFQ6egn91GGRne | applied |


### terraform-run-action

***
Perform an action on a Terraform run. The available actions are: apply, cancel, discard, force-cancel, force-execute.

#### Base Command

`terraform-run-action`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| run_id | The Terraform run ID to execute the action on. | Required | 
| action | The action to execute on the Terraform run. Possible values are: apply, cancel, discard, force-cancel, force-execute. | Required | 
| comment | An optional comment to associate with the action. Not available for the action "force-execute". | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!terraform-run-action run_id=run-8wpCneWr4TLSzfat action="discard" comment="test comment"```
#### Human Readable Output

>Successfully queued an discard request for run id run-8wpCneWr4TLSzfat

### terraform-plan-get

***
Get the plan JSON file or the plan meta data.

#### Base Command

`terraform-plan-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| plan_id | The ID of the Terraform plan to retrieve. | Required | 
| json_output | Whether to return the plan as a JSON fileResult. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Terraform.Plan.id | String | The plan ID. | 
| Terraform.Plan.attributes.status | String | The plan status. | 
| Terraform.Plan.type | String | Type of the Terraform plan data. | 
| Terraform.Plan.attributes.has-changes | Boolean | Flag indicating whether the Terraform plan has changes. | 
| Terraform.Plan.attributes.status-timestamps.started-at | Date | Timestamp indicating when the Terraform plan started. | 
| Terraform.Plan.attributes.status-timestamps.finished-at | Date | Timestamp indicating when the Terraform plan finished. | 
| Terraform.Plan.attributes.status-timestamps.agent-queued-at | Date | Timestamp indicating when the Terraform plan was queued for an agent. | 
| Terraform.Plan.attributes.log-read-url | String | URL for reading the Terraform plan log. | 
| Terraform.Plan.attributes.resource-additions | Number | Number of resource additions in the Terraform plan. | 
| Terraform.Plan.attributes.resource-changes | Number | Number of resource changes in the Terraform plan. | 
| Terraform.Plan.attributes.resource-destructions | Number | Number of resource destructions in the Terraform plan. | 
| Terraform.Plan.attributes.resource-imports | Number | Number of resource imports in the Terraform plan. | 
| Terraform.Plan.attributes.structured-run-output-enabled | Boolean | Flag indicating whether structured run output is enabled in the Terraform plan. | 
| Terraform.Plan.attributes.generated-configuration | Boolean | Flag indicating whether the Terraform plan has generated configuration. | 
| Terraform.Plan.attributes.actions.is-exportable | Boolean | Flag indicating whether the Terraform plan is exportable. | 
| Terraform.Plan.attributes.execution-details.mode | String | Execution mode details for the Terraform plan. | 
| Terraform.Plan.attributes.permissions.can-export | Boolean | Flag indicating whether the user has permission to export the Terraform plan. | 
| Terraform.Plan.relationships.state-versions.data | Unknown | Relationship information for state versions associated with the Terraform plan. | 
| Terraform.Plan.relationships.exports.data | Unknown | Relationship information for exports associated with the Terraform plan. | 
| Terraform.Plan.links.self | String | Link to the Terraform plan data. | 
| Terraform.Plan.links.json-output | String | Link to the JSON output of the Terraform plan. | 
| Terraform.Plan.links.json-output-redacted | String | Link to the redacted JSON output of the Terraform plan. | 
| Terraform.Plan.links.json-schema | String | Link to the JSON schema of the Terraform plan. | 

#### Command example
```!terraform-plan-get plan_id=plan-V4fvpvCzGQrsZikD```
#### Context Example
```json
{
    "Terraform": {
        "Plan": {
            "attributes": {
                "actions": {
                    "is-exportable": true
                },
                "execution-details": {
                    "mode": "remote"
                },
                "generated-configuration": false,
                "has-changes": false,
                "log-read-url": "url",
                "permissions": {
                    "can-export": true
                },
                "resource-additions": 0,
                "resource-changes": 0,
                "resource-destructions": 0,
                "resource-imports": 0,
                "status": "finished",
                "status-timestamps": {
                    "agent-queued-at": "2023-11-30T09:21:33+00:00",
                    "finished-at": "2023-11-30T09:21:41+00:00",
                    "started-at": "2023-11-30T09:21:37+00:00"
                },
                "structured-run-output-enabled": true
            },
            "id": "plan-V4fvpvCzGQrsZikD",
            "links": {
                "json-output": "/api/v2/plans/plan-V4fvpvCzGQrsZikD/json-output",
                "json-output-redacted": "/api/v2/plans/plan-V4fvpvCzGQrsZikD/json-output-redacted",
                "json-schema": "/api/v2/plans/plan-V4fvpvCzGQrsZikD/json-schema",
                "self": "/api/v2/plans/plan-V4fvpvCzGQrsZikD"
            },
            "relationships": {
                "exports": {
                    "data": []
                },
                "state-versions": {
                    "data": []
                }
            },
            "type": "plans"
        }
    }
}
```

#### Human Readable Output

>### Terraform Plan
>|Agent Queued at|Plan id|Status|
>|---|---|---|
>| 2023-11-30T09:21:33+00:00 | plan-V4fvpvCzGQrsZikD | finished |


#### Command example
```!terraform-plan-get plan_id=plan-V4fvpvCzGQrsZikD json_output="true"```
#### Context Example
```json
{
    "InfoFile": {
        "EntryID": "375@03d8b507-a516-4959-8133-979b2d80a807",
        "Extension": "json",
        "Info": "application/json",
        "Name": "plan-V4fvpvCzGQrsZikD.json",
        "Size": 3686,
        "Type": "JSON data"
    }
}
```

#### Human Readable Output



### terraform-policies-list

***
List the policies for an organization or get a specific policy.

#### Base Command

`terraform-policies-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the organization. | Optional | 
| policy_kind | If specified, restricts results to those with the matching policy kind value. Possible values are: sentinel, opa. | Optional | 
| policy_name | If specified, search the organization's policies by name. | Optional | 
| policy_id | If specified, get the specific policy. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Terraform.Policy.id | String | The policy ID. | 
| Terraform.Policy.type | String | The policy type. | 
| Terraform.Policy.attributes.name | String | Name of the Terraform policy. | 
| Terraform.Policy.attributes.description | Unknown | Description of the Terraform policy. | 
| Terraform.Policy.attributes.enforce.path | String | Path for enforcing the Terraform policy. | 
| Terraform.Policy.attributes.enforce.mode | String | Enforcement mode for the Terraform policy. | 
| Terraform.Policy.attributes.policy-set-count | Number | Count of policy sets associated with the Terraform policy. | 
| Terraform.Policy.attributes.updated-at | Date | Timestamp indicating when the Terraform policy was last updated. | 
| Terraform.Policy.attributes.kind | String | Kind of the Terraform policy. | 
| Terraform.Policy.attributes.enforcement-level | String | Enforcement level for the Terraform policy. | 
| Terraform.Policy.relationships.organization.data.id | String | Unique identifier for the organization associated with the Terraform policy. | 
| Terraform.Policy.relationships.organization.data.type | String | Type of the organization associated with the Terraform policy. | 
| Terraform.Policy.relationships.policy-sets.data.id | String | The IDs of the policy sets that contain this policy. | 
| Terraform.Policy.relationships.policy-sets.data.type | String | Type of the policy sets associated with the Terraform policy. | 
| Terraform.Policy.links.self | String | Link to the Terraform policy data. | 
| Terraform.Policy.links.upload | String | Link for uploading the Terraform policy. | 
| Terraform.Policy.links.download | String | Link for downloading the Terraform policy. | 
| Terraform.Policy.links.self | String | Link to the Terraform policy. | 
| Terraform.Policy.links.first | String | Link to the first page of Terraform policies. | 
| Terraform.Policy.links.prev | Unknown | Link to the previous page of Terraform policies. | 
| Terraform.Policy.links.next | Unknown | Link to the next page of Terraform policies. | 
| Terraform.Policy.links.last | String | Link to the last page of Terraform policies. | 
| Terraform.Policy.meta.pagination.current-page | Number | Current page number in the pagination of Terraform policies. | 
| Terraform.Policy.meta.pagination.page-size | Number | Number of policies displayed per page in pagination. | 
| Terraform.Policy.meta.pagination.prev-page | Unknown | Previous page number in the pagination of Terraform policies. | 
| Terraform.Policy.meta.pagination.next-page | Unknown | Next page number in the pagination of Terraform policies. | 
| Terraform.Policy.meta.pagination.total-pages | Number | Total number of pages in the pagination of Terraform policies. | 
| Terraform.Policy.meta.pagination.total-count | Number | Total count of Terraform policies. | 

#### Command example
```!terraform-policies-list```
#### Context Example
```json
{
    "Terraform": {
        "Policy": {
            "attributes": {
                "description": null,
                "enforce": [
                    {
                        "mode": "hard-mandatory",
                        "path": "nat-policies.sentinel"
                    }
                ],
                "enforcement-level": "hard-mandatory",
                "kind": "sentinel",
                "name": "nat-policies",
                "policy-set-count": 1,
                "updated-at": "2023-11-14T18:12:36.702Z"
            },
            "id": "pol-ycCqXorxsFjaH5aK",
            "links": {
                "download": "/api/v2/policies/pol-ycCqXorxsFjaH5aK/download",
                "self": "/api/v2/policies/pol-ycCqXorxsFjaH5aK",
                "upload": "/api/v2/policies/pol-ycCqXorxsFjaH5aK/upload"
            },
            "relationships": {
                "organization": {
                    "data": {
                        "id": "example-org-40dc3b",
                        "type": "organizations"
                    }
                },
                "policy-sets": {
                    "data": [
                        {
                            "id": "polset-hc2bvqDW8YRgHEt8",
                            "type": "policy-sets"
                        }
                    ]
                }
            },
            "type": "policies"
        }
    }
}
```

#### Human Readable Output

>### Terraform Policies
>|Kind|Organization id|Policy Set ids|Policy id|Policy name|
>|---|---|---|---|---|
>| sentinel | example-org-40dc3b | polset-hc2bvqDW8YRgHEt8 | pol-ycCqXorxsFjaH5aK | nat-policies |


### terraform-policy-set-list

***
List the policy sets for an organization or get a specific policy set.

#### Base Command

`terraform-policy-set-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| organization_name | The name of the organization. | Optional | 
| policy_set_id | If specified, get the specific policy set. | Optional | 
| versioned | Allows filtering policy sets based on whether they are versioned, or use individual policy relationships. A true value returns versioned sets, and a false value returns sets with individual policy relationships. If omitted, all policy sets are returned. Possible values are: true, false. | Optional | 
| policy_set_kind | If specified, restricts results to those with the matching policy kind value. Possible values are: sentinel, opa. | Optional | 
| include | Enables you to include related resource data. Value must be a comma-separated list containing one or more projects, workspaces, workspace-exclusions, policies, newest_version, or current_version. | Optional | 
| policy_set_name | Allows searching the organization's policy sets by name. | Optional | 
| page_number | The page number of the results to return. Default is 1. | Optional | 
| page_size | The number of results to return per page. Default is 20, maximum is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Terraform.PolicySet.id | String | The policy set ID. | 
| Terraform.PolicySet.type | String | The policy set type. | 
| Terraform.PolicySet.attributes.name | String | Name of the Terraform policy set. | 
| Terraform.PolicySet.attributes.description | Unknown | Description of the Terraform policy set. | 
| Terraform.PolicySet.attributes.global | Boolean | Flag indicating whether the Terraform policy set is global. | 
| Terraform.PolicySet.attributes.workspace-count | Number | Number of workspaces associated with the Terraform policy set. | 
| Terraform.PolicySet.attributes.project-count | Number | Number of projects associated with the Terraform policy set. | 
| Terraform.PolicySet.attributes.created-at | Date | Timestamp indicating when the Terraform policy set was created. | 
| Terraform.PolicySet.attributes.updated-at | Date | Timestamp indicating when the Terraform policy set was last updated. | 
| Terraform.PolicySet.attributes.kind | String | Kind of the Terraform policy set. | 
| Terraform.PolicySet.attributes.agent-enabled | Boolean | Flag indicating whether the Terraform policy set has agents enabled. | 
| Terraform.PolicySet.attributes.policy-count | Number | Number of policies associated with the Terraform policy set. | 
| Terraform.PolicySet.attributes.versioned | Boolean | Flag indicating whether the Terraform policy set is versioned. | 
| Terraform.PolicySet.relationships.organization.data.id | String | ID of the organization associated with the Terraform policy set. | 
| Terraform.PolicySet.relationships.organization.data.type | String | Type of the organization associated with the Terraform policy set. | 
| Terraform.PolicySet.relationships.policies.data.id | String | ID of the policies associated with the Terraform policy set. | 
| Terraform.PolicySet.relationships.policies.data.type | String | Type of the policies associated with the Terraform policy set. | 
| Terraform.PolicySet.relationships.workspaces.data.id | String | ID of the workspaces associated with the Terraform policy set. | 
| Terraform.PolicySet.relationships.workspaces.data.type | String | Type of the workspaces associated with the Terraform policy set. | 
| Terraform.PolicySet.relationships.projects.data.id | String | Relationship information for projects associated with the Terraform policy set. | 
| Terraform.PolicySet.relationships.workspace-exclusions.data | Unknown | Relationship information for workspace exclusions associated with the Terraform policy set. | 
| Terraform.PolicySet.links.self | String | Link to the Terraform policy set data. | 
| Terraform.PolicySet.links.self | String | Link to the Terraform policy set. | 
| Terraform.PolicySet.links.first | String | Link to the first page of Terraform policy sets. | 
| Terraform.PolicySet.links.prev | Unknown | Link to the previous page of Terraform policy sets. | 
| Terraform.PolicySet.links.next | Unknown | Link to the next page of Terraform policy sets. | 
| Terraform.PolicySet.links.last | String | Link to the last page of Terraform policy sets. | 
| Terraform.PolicySet.meta.pagination.current-page | Number | Current page number in the pagination of Terraform policy sets. | 
| Terraform.PolicySet.meta.pagination.page-size | Number | Number of items per page in the pagination of Terraform policy sets. | 
| Terraform.PolicySet.meta.pagination.prev-page | Unknown | Link to the previous page in the pagination of Terraform policy sets. | 
| Terraform.PolicySet.meta.pagination.next-page | Unknown | Link to the next page in the pagination of Terraform policy sets. | 
| Terraform.PolicySet.meta.pagination.total-pages | Number | Total number of pages in the pagination of Terraform policy sets. | 
| Terraform.PolicySet.meta.pagination.total-count | Number | Total number of Terraform policy sets. | 

#### Command example
```!terraform-policy-set-list```
#### Context Example
```json
{
    "Terraform": {
        "PolicySet": {
            "attributes": {
                "agent-enabled": false,
                "created-at": "2023-11-08T11:25:06.196Z",
                "description": null,
                "global": false,
                "kind": "sentinel",
                "name": "test-policy-set",
                "policy-count": 1,
                "project-count": 0,
                "updated-at": "2023-11-08T11:25:06.196Z",
                "versioned": false,
                "workspace-count": 1
            },
            "id": "polset-hc2bvqDW8YRgHEt8",
            "links": {
                "self": "/api/v2/policy-sets/polset-hc2bvqDW8YRgHEt8"
            },
            "relationships": {
                "organization": {
                    "data": {
                        "id": "example-org-40dc3b",
                        "type": "organizations"
                    }
                },
                "policies": {
                    "data": [
                        {
                            "id": "pol-ycCqXorxsFjaH5aK",
                            "type": "policies"
                        }
                    ]
                },
                "projects": {
                    "data": []
                },
                "workspace-exclusions": {
                    "data": []
                },
                "workspaces": {
                    "data": [
                        {
                            "id": "ws-u7kVixWpJYWiERMG",
                            "type": "workspaces"
                        }
                    ]
                }
            },
            "type": "policy-sets"
        }
    }
}
```

#### Human Readable Output

>### Terraform Policy Sets
>|Organization|Policies ids|Policy Set name|Policy set id|Workspaces|
>|---|---|---|---|---|
>| example-org-40dc3b | pol-ycCqXorxsFjaH5aK | test-policy-set | polset-hc2bvqDW8YRgHEt8 | ws-u7kVixWpJYWiERMG |


### terraform-policies-checks-list

***
List the policy checks for a Terraform run.

#### Base Command

`terraform-policies-checks-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| run_id | The run ID to list results for. | Optional | 
| policy_check_id | The policy check ID to retrieve details for. | Optional | 
| page_number | The page number of the results to return. Default is 1. | Optional | 
| page_size | The number of results to return per page. Default is 20, maximum is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Terraform.PolicyCheck.id | String | The policy check ID. | 
| Terraform.PolicyCheck.type | String | Type of the Terraform policy check data. | 
| Terraform.PolicyCheck.attributes.result.result | Boolean | Overall result of the Terraform policy check. | 
| Terraform.PolicyCheck.attributes.result.passed | Number | Number of policy checks that passed. | 
| Terraform.PolicyCheck.attributes.result.total-failed | Number | Total number of policy checks that failed. | 
| Terraform.PolicyCheck.attributes.result.hard-failed | Number | Number of policy checks that resulted in hard failures. | 
| Terraform.PolicyCheck.attributes.result.soft-failed | Number | Number of policy checks that resulted in soft failures. | 
| Terraform.PolicyCheck.attributes.result.advisory-failed | Number | Number of policy checks that resulted in advisory failures. | 
| Terraform.PolicyCheck.attributes.result.duration-ms | Number | Duration of the policy check execution in milliseconds. | 
| Terraform.PolicyCheck.attributes.result.sentinel | Unknown | Sentinel-specific result of the policy check. | 
| Terraform.PolicyCheck.attributes.scope | String | Scope or context of the Terraform policy check. | 
| Terraform.PolicyCheck.attributes.status | String | Status of the Terraform policy check. | 
| Terraform.PolicyCheck.attributes.status-timestamps.queued-at | Date | Timestamp indicating when the Terraform policy check was queued. | 
| Terraform.PolicyCheck.attributes.status-timestamps.soft-failed-at | Date | Timestamp indicating when the Terraform policy check encountered a soft failure. | 
| Terraform.PolicyCheck.attributes.actions.is-overridable | Boolean | Flag indicating whether the Terraform policy check is overridable. | 
| Terraform.PolicyCheck.attributes.permissions.can-override | Boolean | Flag indicating whether the user has permission to override the Terraform policy check. | 
| Terraform.PolicyCheck.relationships.run.data.id | String | Unique identifier for the Terraform run associated with the policy check. | 
| Terraform.PolicyCheck.relationships.run.data.type | String | Type of the Terraform run associated with the policy check. | 
| Terraform.PolicyCheck.links.output | String | Link to the output of the Terraform policy check. | 

#### Command example
```!terraform-policies-checks-list run_id=run-8wpCneWr4TLSzfat```
#### Human Readable Output

>### Terraform Policy Checks
>**No entries.**
