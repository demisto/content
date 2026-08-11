Gurucul Risk Analytics (GRA) is a data science–backed cloud-native platform that predicts, detects, and prevents breaches. It ingests and analyzes data from the network, IT systems, cloud platforms, EDR, applications, IoT, HR, and more to give you a comprehensive contextual view of user and entity behaviors.

This Content Pack integrates GRA with Cortex XSOAR so analysts can investigate high-risk entities and take action from XSOAR.

### What does this pack do?

- Fetch GRA **Incidents** or **Alerts** into XSOAR as incidents (choose one fetch type per integration instance).
- Create corresponding XSOAR incidents with classifiers, mappers, layouts, and playbooks for investigation.
- Investigate and act from the War Room using commands.
- Continue working with existing GRA **Cases** using `gra-case-*` commands, layouts, and scripts (Cases are no longer fetched as new incidents).
- Configure XSOAR workflows based on GRA risk score and entity context.

### Pack contents

- **Gurucul-GRA** integration
- Incident types, fields, classifiers, and mappers for GRA Incidents, Alerts, and Cases
- Layouts and playbooks for investigation workflows
- Display and close/update scripts used by the layouts and playbooks

For command details and fetch setup, see the Gurucul-GRA integration documentation on the Cortex XSOAR Developer Hub.
