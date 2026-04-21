# Superna Zero Trust

## Overview

The **Superna Zero Trust** pack integrates Cortex XSOAR with Superna's Zero Trust ransomware detection and containment platform. It enables automated ransomware response by triggering critical path snapshots and enforcing NAS user lockout/unlock actions through the Superna SERA API.

## Use Cases

- **Ransomware Containment**: Immediately lock out a suspected compromised user from all NAS storage access to stop lateral spread
- **Data Preservation**: Trigger a critical path snapshot at the moment ransomware is detected to preserve a clean recovery point
- **Automated Recovery**: Unlock users after investigation or remediation is complete

## What's in This Pack

### Integrations

- **Superna Zero Trust** — Connects to the Superna SERA API to execute containment and recovery commands

### Playbooks

| Playbook | Description |
|----------|-------------|
| Superna Zero Trust Snapshot | Creates a critical path snapshot for ransomware rapid recovery |
| Superna Zero Trust User Lockout | Locks a user out of NAS storage access |
| Superna Zero Trust Request User Storage Lockout | Requests and confirms NAS storage lockout for a user |
| Superna Zero Trust Request User Storage UnLockout | Requests and confirms NAS storage unlock for a user |

## Configuration

To use this pack, configure the **Superna Zero Trust** integration instance with:

- **API URL**: The base URL of your Superna Zero Trust / SERA server
- **API Key**: An API key generated from the Superna management interface

See the [integration README](Integrations/SupernaZeroTrust/README.md) for full setup instructions.

## Support

For support, contact [support@superna.io](mailto:support@superna.io) or visit [https://www.superna.io](https://www.superna.io).
