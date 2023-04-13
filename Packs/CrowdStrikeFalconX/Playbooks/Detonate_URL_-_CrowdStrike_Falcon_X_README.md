This playbook uploads, detonates, and analyzes URLs for the CrowdStrike Falcon Intelligence Sandbox.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* CrowdStrikeFalconX

### Scripts

* IsIntegrationAvailable

### Commands

* cs-fx-submit-url

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| URL | The details of the URL to detonate. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotScore | The Dbot Score of the analyzed URL | unknown |
| csfalconx.resource | URL analysis report info | unknown |
| csfalconx.resource.sandbox.http_requests | URL analysis report info | unknown |
| csfalconx.resource.sandbox | URL analysis report info | unknown |
| csfalconx.resource.sandbox.processes | URL analysis report info | unknown |
| csfalconx.resource.sandbox.processes.handles | URL analysis report info | unknown |
| csfalconx.resource.sandbox.extracted_files | URL analysis report info | unknown |
| csfalconx.resource.sandbox.file_metadata | URL analysis report info | unknown |
| csfalconx.resource.sandbox.dns_requests | URL analysis report info | unknown |
| csfalconx.resource.sandbox.contacted_hosts | URL analysis report info | unknown |
| csfalconx.resource.sandbox.contacted_hosts.associated_runtime | URL analysis report info | unknown |
| csfalconx.resource.sandbox.mitre_attacks | URL analysis report info | unknown |
| csfalconx.resource.sandbox.mitre_attacks.parent | URL analysis report info | unknown |
| csfalconx.resource.sandbox.signatures | URL analysis report info | unknown |
| csfalconx.resource.intel | URL analysis report info | unknown |

## Playbook Image

---

![Detonate URL - CrowdStrike Falcon Intelligence Sandbox](../doc_files/Detonate_URL_-_CrowdStrike_Falcon_Intelligence_Sandbox.png)
