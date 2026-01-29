# Cypho Severity Change

This automation is triggered when the **severity** field of a Cypho-related incident is updated in Cortex XSOAR.

The script synchronizes the updated severity value with the corresponding issue in Cypho, ensuring that both platforms remain consistent. This allows analysts to manage incident severity directly from XSOAR without performing manual updates in Cypho.

The automation is designed to work as a **field-change-triggered** script and is typically attached to the **Cypho Severity** incident field. It validates that the incident is properly assigned before executing the update, ensuring accountability and accurate analyst activity tracking.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | field-change-triggered |

## Inputs

---
There are no inputs for this script.  
The automation automatically uses the updated incident severity field and the associated Cypho ticket metadata.

## Outputs

---
There are no outputs for this script.  
The script performs a background synchronization with Cypho and updates the external issue severity accordingly.

## ✔ Notes

- This script is intended to run automatically and should not be executed manually.
- The incident must be assigned before the severity change is synchronized.
- Designed for seamless integration with Cypho and Cortex XSOAR incident workflows.
