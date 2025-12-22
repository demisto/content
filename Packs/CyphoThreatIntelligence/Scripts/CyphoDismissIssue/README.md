# Cypho Dismiss Issue

This automation allows analysts to **dismiss a Cypho issue directly from Cortex XSOAR** when the issue has been reviewed and determined to be non-actionable or non-critical.

The script synchronizes the dismissal action from XSOAR to Cypho, ensuring that the issue status remains consistent across both platforms. This eliminates the need for analysts to manually update issue status in Cypho and helps maintain a clean and accurate incident lifecycle.

The automation enforces **incident ownership validation** before execution. This guarantees that only an assigned analyst can dismiss an issue, preserving accountability, accurate audit trails, and reliable SOC performance metrics such as MTTR and analyst attribution.

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
- The Cypho ticket ID associated with the incident
- The dismissal action triggered by the analyst

## Outputs

---

There are no outputs for this script.  
The script performs a background synchronization and updates the issue status in Cypho to **Dismissed**.

## ✔ Notes

- This script is intended to be executed via a **button** on the incident layout.
- The incident **must be assigned** before the dismissal action is allowed.
- Designed to prevent unauthorized or automated dismissals.
- Ensures accurate tracking of analyst decisions and incident resolution flow.
- Seamlessly integrates Cypho issue lifecycle management with Cortex XSOAR workflows.
