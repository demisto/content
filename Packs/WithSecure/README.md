# WithSecure Content Pack for Cortex XSOAR

The WithSecure Content Pack provides comprehensive integration with WithSecure Elements platform, enabling automated threat detection, incident management, and response capabilities for Cortex XSOAR.

## What Does This Pack Do?

- **Security Event Collection**: Collects security events from WithSecure Endpoint Protection (EPP), Endpoint Detection and Response (EDR), Collaboration Protection (ECP), and Exposure Management (XM) engines
- **Incident Management**: Fetches and manages Broad Context Detections (BCDs) as Cortex XSOAR incidents with configurable filtering
- **Automated Response**: Provides commands to isolate compromised endpoints, trigger malware scans, and manage incident lifecycle
- **Device Management**: Query and manage endpoint devices with advanced filtering capabilities
- **Real-time Threat Detection**: Continuous monitoring and collection of security events for threat analysis

## Before You Start

Make sure you have the following content packs:
- Base
- Common Scripts
- Common Types

## Pack Configurations

To get up and running with this pack, you must:

1. Create API credentials in [WithSecure Elements Security Center](https://elements.withsecure.com/)
2. Navigate to **Management > API Clients** and create a new API client
3. Configure appropriate scopes:
   - `connect.api.read` for event collection and querying
   - `connect.api.write` for incident management and response actions
4. Save the Client ID and Client Secret (shown only once)

For detailed setup instructions, see the [WithSecure Event Collector integration README](Packs/WithSecure/Integrations/WithSecureEventCollector/README.md).

## Use Cases

- **Automated Threat Response**: Automatically isolate compromised endpoints when critical EDR incidents are detected
- **Incident Investigation**: Query incidents, get detailed detections, and track investigation progress
- **Endpoint Management**: Monitor and manage endpoint protection status across your organization
- **Malware Containment**: Trigger on-demand scans when suspicious activity is detected

## Playbooks

- **WithSecure EDR Incident Response**: Automated response playbook for critical EDR incidents that isolates endpoints, triggers scans, and manages incident workflow

