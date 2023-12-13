Commit the PAN-OS Panorama or Firewall configuration. If specified as Panorama, it also pushes the Policies to the specified Device Group in the instance.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

Panorama

### Scripts

PrintErrorEntry

### Commands

* pan-os
* pan-os-push-to-device-group
* pan-os-commit-status
* pan-os-commit

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| device-group |  |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Panorama.Commit | All the fields from the commit command. | unknown |
| Panorama.Push | All the fields from the push command. | unknown |

## Playbook Image

---

![PAN-OS Commit Configuration v2](../doc_files/PAN-OS_Commit_Configuration_v2.png)
