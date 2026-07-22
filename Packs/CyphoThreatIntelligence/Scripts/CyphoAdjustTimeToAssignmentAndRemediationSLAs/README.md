# Cypho Adjust Time to Assignment and Remediation SLAs

This automation manages **Time to Assignment** and **Remediation SLA** tracking for Cypho-related incidents in Cortex XSOAR.

The script is triggered automatically when an incident is assigned to an analyst. Upon assignment, it stops the **Time to Assignment** timer and starts the **Remediation SLA** timer, ensuring accurate SLA measurements and reliable SOC performance metrics.

By automating SLA timer transitions, this script eliminates manual intervention, prevents timing inconsistencies, and ensures that analyst response and remediation efforts are tracked correctly across the incident lifecycle.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | field-change-triggered |

## Inputs

---

There are no manual inputs for this script.  
The automation automatically uses:

- The incident assignment event
- Predefined SLA timer fields associated with Cypho incidents

## Outputs

---

There are no outputs for this script.  
The script performs background SLA timer adjustments within Cortex XSOAR.

## ✔ Notes

- This script is designed to run **automatically** and should not be executed manually.
- Triggered when an incident owner is assigned.
- Stops the **Time to Assignment** timer and starts the **Remediation SLA** timer.
- Ensures accurate SLA tracking and SOC KPI calculations.
- Designed for seamless integration with Cypho and Cortex XSOAR incident workflows.
