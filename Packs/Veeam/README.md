# Overview

Secure backup is critical to your cyber resilience. [Veeam Data Platform](https://www.veeam.com/products/veeam-data-platform.html) provides comprehensive capabilities to extend the principles of Zero Trust to data backup and recovery including Proactive Threat Hunting, Immutability Everywhere, and Secure Access.

<~XSOAR>
Using the data received from Veeam Backup & Replication and Veeam ONE REST APIs, the app creates custom incidents related to malware detection and the health state of the backup infrastructure components. These incidents can be managed through the built-in Veeam Incident dashboard and resolved manually or automatically with built-in Veeam playbooks.

The content pack includes:

- Veeam Incident Dashboard: an overview of all API activities and incidents handled by the Veeam App
- Leverage custom incident types and fields related to malware detection and the health state of the backup infrastructure components
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

[Veeam Helpcenter User Guide](https://helpcenter.veeam.com/docs/security_plugins_xsoar/guide/)

# Screenshots

![The XSOAR Dashboard](https://raw.githubusercontent.com/demisto/content/master/Packs/Veeam/doc_files/Veeam_XSOAR_Dashboard.png)

![Veeam - Start Instant VM Recovery Automatically](https://raw.githubusercontent.com/demisto/content/master/Packs/Veeam/doc_files/Veeam_XSOAR_Playbooks.png)
</~XSOAR>
<~XSIAM>
This app allows Veeam Data Platform Advanced and Premium users to monitor various security activities in their Veeam backup infrastructure and use leverage pre-defined automation playbooks via REST API for:

- Veeam Backup & Replication
- Veeam ONE


### Monitoring:
The app gets information from the event forwarding capabilities via syslog servers integrated with Veeam Backup & Replication and Veeam ONE, parses the data and displays it on the Veeam Data Platform Monitoring dashboard. For events and alarms with Medium, High and Critical severity, the app displays them on the Veeam Security Activities dashboard.
It includes:
- Built-in dashboards to monitor job statuses and security activities on a daily basis.
- Built-in reports.
- Multiple data source support.

***Information:***\
Correlation rules are not included in the content pack. To download and import them manually, please follow [this](https://www.veeam.com/download_add_packs/vmware-esx-backup/palo-alto-xsiam-monitoring/) link.

### Automation:
Using the data available in Palo Alto Networks Cortex XSIAM you can leverage built-in Veeam playbooks such as:
- Start configuration backup
- Start Instance VM Recovery manually
- Start Instance VM Recovery automatically
- Resolve alarms triggered by Veeam ONE


# Documentation

[Veeam Helpcenter User Guide for XSIAM Monitoring](https://helpcenter.veeam.com/docs/security_plugins_xsiam/guide/)

The documentation also includes examples of correlation rules for Veeam security activities.

[Veeam Helpcenter User Guide for XSOAR Automation](https://helpcenter.veeam.com/docs/security_plugins_xsiam/guide/)

# Screenshots

![The Security Dashboard](https://raw.githubusercontent.com/demisto/content/master/Packs/Veeam/doc_files/Veeam_Security_Activities_Dashboard_image.png)

![The Monitoring Dashboard](https://raw.githubusercontent.com/demisto/content/master/Packs/Veeam/doc_files/Veeam_Data_Platform_Monitoring_Dashboard_image.png)
</~XSIAM>