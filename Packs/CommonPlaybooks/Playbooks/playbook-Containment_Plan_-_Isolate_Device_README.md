## Containment Plan - Isolate Device

This playbook is a sub-playbook within the containment plan playbook.
The playbook isolates devices using core commands.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

This playbook does not use any integrations.

### Scripts

* SetAndHandleEmpty

### Commands

* core-isolate-endpoint
* core-get-endpoints
* setParentIncidentContext

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
