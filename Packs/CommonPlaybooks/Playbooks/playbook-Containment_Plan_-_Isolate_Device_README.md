This playbook is one of the sub-playbooks in the containment plan. 
The playbook executes actions to isolate the Endpoint, which is a crucial step in the containment process.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* SetAndHandleEmpty

### Commands

* core-get-endpoints
* setParentIncidentContext
* core-isolate-endpoint

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| HostContainment | Whether to execute endpoint isolation. | True | Optional |
| EndpointID | The endpoint ID to run commands over. |  | Optional |
| EndpointHostName | The endpoint hostname. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.Isolation.endpoint_id | The isolated endpoint ID. | unknown |

## Playbook Image

---

![Containment Plan - Isolate Device](../doc_files/Containment_Plan_-_Isolate_Device.png)
