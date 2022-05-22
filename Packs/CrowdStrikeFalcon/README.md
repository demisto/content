CrowdStrike Falcon is one of the leaders in the Endpoint Protection Platform (EPP) market.
This SaaS platform provides a holistic solution for protecting enterprise assets ( Such as servers and endpoints) and stopping different types of attacks/threats aiming to impact your organization. Moreover, the platform provides real-time response actions, vulnerability assessment, and other security-wise features.

## What does this pack do?
- Enable incident mirroring between Cortex XSOAR incidents and CrowdStrike Falcon incidents or detections
- Provides real-time response features

## Playbooks
This content pack includes the following playbooks. These playbooks auto isolate/unisolate endpoints by the device ID that was provided in the playbook. The playbooks can be used as part of a Malware investigation.
- Crowdstrike Falcon - Isolate Endpoint
- Crowdstrike Falcon - Unisolate Endpoint


## Setup Instructions
1. Ensure you have the following content packs:
   - Base
   - Common Scripts
   - Common Types
2. To set up the CrowdStrike Falcon integration, you will need to get an API client ID and secret from CrowdStrike support: support@crowdstrike.com.
3. To run the playbooks, provide the ID of the device you want to isolate/unisolate.

