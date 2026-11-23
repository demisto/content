Looks up what tLab Anti-APT already knows about a file, without submitting anything.

Use this before a detonation sub-playbook: a sample the sandbox has already analyzed needs no second analysis, and the answer comes back in one call instead of minutes.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* TLabAntiAPTLookup

### Scripts

This playbook does not use any scripts.

### Commands

* file

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | The file to look up. Defaults to every file in the incident. | File | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TLabAntiAPT.File | What tLab knows about the file. | Unknown |
| DBotScore | The DBot score object. | Unknown |
| File | The file object. | Unknown |
