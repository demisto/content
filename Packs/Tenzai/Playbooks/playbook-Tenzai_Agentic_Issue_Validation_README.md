Validates an ASM-discovered exposure with Tenzai's agentic penetration testing.
Triggers a Tenzai validation assessment, polls until it completes, fetches the verdict,
and records the verdict in the Tenzai issue fields. It does not change the issue severity.

> **Warning:** This playbook runs **active penetration testing against the live production asset** and **consumes Tenzai credits**. Because ASM attribution can occasionally be wrong, it gates on analyst approval by default (`RequireAnalystApproval` = true) before testing starts, and it first checks that an enabled Tenzai integration instance exists. Enabling the **Tenzai - Agentic Issue Validation** trigger causes every matching High/Critical ASM exposure to run this active testing automatically — leave the trigger disabled and run validation ad-hoc from the Validate button unless you intend that, and keep `RequireAnalystApproval` set to true.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* Tenzai

### Scripts

* IsIntegrationAvailable
* StartAgenticValidation

### Commands

* setIncident
* tenzai-get-scan

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| RequireAnalystApproval | When true \(default\), the playbook pauses for an analyst to approve before Tenzai starts active testing, because validation runs live penetration testing against the production asset and consumes Tenzai credits. Set to false to start validation automatically without approval. | true | Optional |
| PollingInterval | The interval, in seconds, between Tenzai scan status polls. | 60 | Optional |
| PollingTimeout | The maximum time, in seconds, to wait for the Tenzai scan to reach a terminal state before giving up. | 3600 | Optional |

## Playbook Outputs

---
There are no outputs for this playbook.

## Playbook Image

---

![Tenzai Agentic Issue Validation](../doc_files/Tenzai_Agentic_Issue_Validation.png)
