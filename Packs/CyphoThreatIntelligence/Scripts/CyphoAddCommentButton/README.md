# Cypho Add Comment Button

This automation allows analysts to **add a comment to a Cypho issue directly from Cortex XSOAR**.

The script is designed to be used as a **button automation** on Cypho-related incidents. When executed, it synchronizes the analyst’s comment from XSOAR to the corresponding issue in Cypho, ensuring that investigation notes, explanations, and analyst feedback remain consistent across both platforms.

The automation validates that the incident is properly **assigned to an owner** before executing the action. This ensures accountability, accurate analyst activity tracking, and alignment with Cypho’s incident management workflow.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | incident-action, button |

## Inputs

---

There are no manual inputs for this script.  
The automation automatically uses:

- The current incident owner
- The analyst comment provided in XSOAR
- The associated Cypho ticket ID

## Outputs

---

There are no outputs for this script.  
The script performs a background synchronization and adds the comment to the corresponding Cypho issue.

## ✔ Notes

- This script is intended to be executed via a **button** on the incident layout.
- The incident **must be assigned** before a comment can be added.
- Designed to reduce manual context switching between Cypho and Cortex XSOAR.
- Ensures consistent documentation and investigation notes across platforms.
