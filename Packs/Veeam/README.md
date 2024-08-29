The Veeam App for Palo Alto Networks XSOAR allows Veeam Data Platform Advanced and Premium customers to combine the automation and orchestration features of Cortex XSOAR with a simple and powerful [Veeam Data Platform](https://www.veeam.com/products/veeam-data-platform.html) that goes beyond backup, providing businesses with reliable data protection, seamless recovery, and streamlined data management. Using the data received from Veeam Backup & Replication and Veeam ONE REST APIs the Veeam App creates custom incidents related to malware detection and the health state of the backup infrastructure components. These incidents can be managed through built-in Veeam Incident Dashboard and resolved manually or automatically with built-in Veeam playbooks.

The pack includes:
- Veeam Incident Dashboard: an overview of all API activities and incidents handled by the Veeam App
- Leverage custom incident types and fields related to malware detection and health state of the backup infrastructure components
- Predefined incident classifiers and incoming mappers for incident types
- Ingestion of the most important security alerts and detections:
  - Configuration Backup State
  - Malware Detection
  - Backup Repository State
  - Triggered Alarm
- Predefined playbooks to remediate incidents:
  - Start configuration backup
  - Start Instance VM Recovery manually
  - Start Instance VM Recovery automatically
  - Resolve alarms triggered by Veeam ONE

# Documentation

[Veeam App for Palo Alto XSOAR User Guide](https://helpcenter.veeam.com/docs/security_plugins_xsoar/guide/)