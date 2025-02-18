Gets information about processes which open connections to known bad IP addresses.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* uptycs-get-threat-source
* uptycs-get-parent-information
* uptycs-get-process-child-processes
* uptycs-get-process-information
* uptycs-get-alerts
* uptycs-get-process-open-sockets
* uptycs-get-threat-indicator

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** |  **Required** |
| --- | --- | --- | --- |
| alert_id | The unique Uptycs ID for a particular alert. | ${incident.alertid} | Required |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Uptycs.Proc.pid | The PID for the process. | number |
| Uptycs.Proc.upt_add_time | The time that the process was spawned. | date |
| Uptycs.Proc.upt_remove_time | The time that the process was removed. | date |
| Uptycs.Parent.pid | THe PID of the parent process. | number |
| Uptycs.Parent.upt_add_time | The time that the process was spawned. | date |
| Uptycs.Parent.upt_remove_time | The time that the process was removed. | date |
| Uptycs.Sockets.local_address | The local IP address for the specified connection. | string |
| Uptycs.Sockets.local_port | The local port for specified connection. | number |
| Uptycs.Sockets.remote_port | The remote port for specified connection. | number |
| Uptycs.Children.pid | The PID of a child process. | number |
| Uptycs.Children.upt_add_time | The time that the process was spawned. | date |
| Uptycs.Children.upt_remove_time | The time that the process was removed. | date |

## Playbook Image
---
![Uptycs_Bad_IP_Incident](../doc_files/Uptycs_-_Bad_IP_Incident.png)
