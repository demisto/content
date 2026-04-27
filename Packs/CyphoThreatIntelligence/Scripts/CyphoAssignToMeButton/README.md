# Cypho Assign To Me

This automation allows an analyst to **assign a Cypho-related incident to themselves directly from Cortex XSOAR** with a single button click.

The script synchronizes the assignment action with Cypho, ensuring that the issue owner is updated consistently across both platforms. This guarantees accurate ownership tracking, accountability, and proper analyst attribution throughout the incident lifecycle.

The automation is designed to simplify incident ownership management by eliminating manual assignment steps in Cypho. Once executed, the incident is immediately assigned to the current analyst in XSOAR and reflected accordingly in Cypho.

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

- The currently logged-in analyst
- The Cypho ticket ID associated with the incident
- The active incident context in Cortex XSOAR

## Outputs

---

There are no outputs for this script.  
The script performs a background synchronization and updates the issue assignee in Cypho.

## ✔ Notes

- This script is intended to be executed via an **incident action button**.
- Designed to ensure that incidents are explicitly assigned before any further actions are taken.
- Helps maintain accurate SOC metrics such as MTTR and analyst accountability.
- Prevents unassigned incidents from being modified unintentionally.
- Fully aligned with Cypho and Cortex XSOAR incident management workflows.
