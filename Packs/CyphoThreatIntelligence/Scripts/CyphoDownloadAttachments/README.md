# Cypho Download Attachments

This automation enables analysts to **download all attachments associated with a Cypho issue directly from Cortex XSOAR**.

The script retrieves attachment metadata from Cypho, securely downloads each available file, and attaches them to the XSOAR incident. This eliminates the need for analysts to manually access Cypho to retrieve evidence, artifacts, or supporting documentation.

The automation is designed to streamline investigations by ensuring that all relevant files are readily available within the incident context in XSOAR, improving analysis speed and operational efficiency.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | incident-action, attachment |

## Inputs

---

There are no manual inputs for this script.  
The automation automatically uses:

- The Cypho ticket ID associated with the incident
- Attachment metadata retrieved from Cypho
- The active incident context in Cortex XSOAR

## Outputs

---

Downloaded attachments are added to the incident as files.  
Each successfully retrieved attachment is stored in XSOAR and made available for analyst review.

## ✔ Notes

- This script is intended to be executed via an **incident action button**.
- If no attachments exist for the issue, the script exits gracefully without errors.
- Supports downloading multiple attachments in a single execution.
- Enhances investigation workflows by centralizing all evidence within XSOAR.
- Fully compatible with Cypho and Cortex XSOAR incident management processes.
