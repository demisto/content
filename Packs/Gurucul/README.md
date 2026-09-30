Gurucul Risk Analytics (GRA) is a data science–backed cloud-native platform that predicts, detects, and prevents breaches. It ingests and analyzes data from the network, IT systems, cloud platforms, EDR, applications, IoT, HR, and more to give you a comprehensive contextual view of user and entity behaviors.

This Content Pack integrates GRA with Cortex so analysts can investigate high-risk entities and take action from Cortex.

## What does this pack do?

- Fetch GRA **Incidents** or **Alerts** into Cortex as incidents (choose one fetch type per integration instance).
- Create corresponding Cortex incidents with mappers, layouts, and incident types for investigation.
- Investigate and act from the War Room using commands.
- Continue working with existing GRA **Cases** using `gra-case-*` commands, layouts, and scripts (Cases are no longer fetched as new incidents). Resource-named account commands are deprecated in favor of Data Source commands.
- Configure Cortex workflows based on GRA risk score and entity context.

## Pack contents

- **Gurucul-GRA** integration (fetch Incidents or Alerts; War Room commands)
- Incident types **GRAIncident** and **GRAAlert**, with incoming mappers, custom fields, and layouts
- **GRACase** type, fields, layout, and Case commands for existing Case records (Cases are not fetched)
- Layout scripts (anomaly, analytical features, alert history and classifiers) and close/update post-processing scripts

For command details and fetch setup, see the Gurucul-GRA integration documentation on the Cortex Developer Hub.
