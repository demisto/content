# Cypho Approve Issue

This automation allows analysts to **approve a Cypho issue directly from Cortex XSOAR**.

The script synchronizes the approval action with Cypho, ensuring that the issue status in Cypho accurately reflects the decision made by the analyst in XSOAR. This eliminates the need for manual approval actions in external systems and maintains consistency across platforms.

The automation enforces ownership validation before execution, ensuring that the incident is assigned to an analyst. This guarantees proper accountability, accurate activity tracking, and reliable SOC metrics such as MTTR and analyst attribution.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | incident-action |

## Inputs

---

There are no manual inputs for this script.  
The automation automatically uses:

- The Cypho ticket ID associated with the incident
- The assigned incident owner
- Analyst email mapped from the XSOAR user context

## Outputs

---

There are no direct outputs for this script.  
The script performs a background approval action in Cypho and updates the external issue state accordingly.

## ✔ Notes

- This script is intended to be executed via an **incident action button**.
- The incident **must be assigned** before approval can be performed.
- Ensures synchronization between XSOAR and Cypho issue status.
- Prevents unauthorized or untracked approval actions.
- Designed for seamless integration with Cypho and Cortex XSOAR incident workflows.
