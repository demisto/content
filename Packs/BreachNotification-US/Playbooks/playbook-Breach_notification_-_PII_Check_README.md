This playbook processes a checklist to help an analyst discern whether the breached data contains any Personally Identifiable Information (PII) according to California law.

DISCLAIMER: Please consult with your legal team before implementing this playbook.

**Source: http://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.82.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set

### Commands
This playbook does not use any commands.

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PIICompromised | Store the fact that PII compromised. | boolean |
| HealthInsuranceBreached | Store the fact that the breach contains PII type of health insurance information. | unknown |
| MedicalInformationBreached | Store the fact that the breach contains PII type of medical information. | unknown |
| FinancialInformationBreached | Store the fact that the breach contains PII type of financial information. | unknown |
| AccountInformationBreached | Store the fact that the breach contains PII type of account information. | unknown |
| UniqueIdentificationNumberBreached | Store the fact that the breach contains PII type of unique identification number. | unknown |
| UniqueBiometricDataBreached | Store the fact that the breach contains PII type of unique biometric data. | unknown |

<!-- Playbook PNG image comes here -->