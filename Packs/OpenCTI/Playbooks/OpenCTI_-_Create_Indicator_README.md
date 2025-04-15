Create indicator at OpenCTI.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* OpenCTI

### Scripts

This playbook does not use any scripts.

### Commands

* opencti-indicator-create
* opencti-label-create
* opencti-external-reference-create

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| label_name | Label name to add to new indicator. |  | Optional |
| type | The indicator type to create. Possible values:  "Account", "Domain", "Email", "File-md5", "File-sha1", "File-sha256", "Host", "IP", "IPV6", "Registry Key" and "URL". |  | Required |
| marking_definition_id | Marking definition id to add to new indicator. Use opencti-marking-definition-list to get marking id.  |  | Optional |
| created_by_id | Creator of the new indicator. Use opencti-organization-list to find all organizations id at opencti, or use  opencti-organization-create to create new organization id. |  | Optional |
| external_reference_source_name | External References Source Name. In order to use external references, external_reference_url and external_reference_source_name are mandatory. |  | Optional |
| external_reference_url | External References URL. In order to use external references, external_reference_url and external_reference_source_name are mandatory. |  | Optional |
| description | New indicator description. |  | Optional |
| score | New indicator score. Valid value: number between 0 to 100. |  | Optional |
| value | Indicator value. |  | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| OpenCTI.Indicator.id | New indicator id. | string |

## Playbook Image

---
![OpenCTI Create Indicator](../doc_files/OpenCTI_-_Create_Indicator.png)