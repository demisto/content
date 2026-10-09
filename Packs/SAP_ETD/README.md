# SAP Enterprise Threat Detection

## Overview

SAP Enterprise Threat Detection (ETD) identifies, analyzes, and neutralizes cyberattacks in SAP applications. It provides real-time monitoring and alerting for security events across SAP landscapes.

This pack includes an integration that fetches alerts from SAP ETD and ingests them into Cortex XSIAM for centralized security monitoring, correlation, and threat analysis.

Both SAP ETD editions are supported:

- **On-Premise**: Basic authentication against the Alert Pull API (`Alerts.xsjs`). Requires the alert publishing job to be active.
- **Cloud Edition**: OAuth2 client credentials against the Data Retriever service on SAP BTP.
