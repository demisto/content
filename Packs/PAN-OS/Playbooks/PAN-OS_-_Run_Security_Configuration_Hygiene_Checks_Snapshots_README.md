POC (CRTX-291227). Same checks and outputs as 'PAN-OS - Run Security Configuration Hygiene Checks', split into atomic commands: each pan-os-hygiene-get-snapshot task makes exactly one PAN-OS API call and stores the result as a file, and pan-os-hygiene-evaluate-snapshots runs the six existing hygiene checks on those files with no API calls.

API calls: 2 + 2 per connected firewall.

NOTE: This playbook is intended for use with a single PAN-OS Integration Instance connected to Panorama.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Panorama

### Scripts

* PrintErrorEntry
* Set

### Commands

* pan-os-hygiene-evaluate-snapshots
* pan-os-hygiene-get-snapshot

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| targetDevice | The serial number of a specific firewall to target \(Used when connected to Panorama\) \[Optional\].<br/><br/>When connected to Panorama, leaving this blank will run the checks against Panorama configuration as well as all currently connected managed firewalls. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PANOS.ConfigurationHygiene.Summary | A list of hygiene check summaries \(constructed as dictionaries\) describing the overall result of hygiene checks and how many issues of each type were found, if any. | unknown |
| PANOS.ConfigurationHygiene.Result | A list of hygiene check results \(constructed as dictionaries\) including a description of the issue found, the configuration location \(container name\), and the name of the object affected by the issue. | unknown |
