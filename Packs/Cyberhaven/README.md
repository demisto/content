The Cyberhaven pack enables security operations teams to fetch and investigate DLP (Data Loss Prevention) incidents from the Cyberhaven data security platform directly within Cortex XSOAR. By synchronizing Cyberhaven incidents with XSOAR in real time, analysts can manage DLP investigations, review event and data lineage details, and update incident status.

##### What does this pack do?

- Fetch DLP incidents from Cyberhaven and create corresponding XSOAR incidents.
- List and filter Cyberhaven DLP incidents by severity, status, assignee, user, and time range.
- Update incident status, close reason, close note, and assignee.
- Retrieve full event details for one or more Cyberhaven events by ID.
- Retrieve data lineage chains between two Cyberhaven event IDs.
- Mirror incident updates from XSOAR back to Cyberhaven (status, owner, close reason, close notes).
- Automatically close XSOAR incidents when the corresponding Cyberhaven incident is closed (via the included playbook).
