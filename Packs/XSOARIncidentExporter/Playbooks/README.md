Trigger playbook for Cortex XSOAR-sourced alerts in Cortex XSIAM. Runs the CloseFromXSOAR script to sync close status from the source Cortex XSOAR incident.

## Setup

To activate this playbook in Cortex XSIAM:

1. Navigate to **Settings** > **Automation & Feed** > **Trigger Playbooks**.
2. Click **+ New Trigger Playbook**.
3. Set the trigger condition so it matches alerts pushed by the XSOAR Incident Exporter integration (e.g., filter on the alert source or vendor field containing "XSOAR").
4. Select **Close XSIAM Case From XSOAR** as the playbook to run.
5. Save and enable the trigger.

When a Cortex XSOAR incident is re-pushed after being closed, the playbook reads the close status from the alert description and closes the corresponding Cortex XSIAM case with the mapped reason and notes.
