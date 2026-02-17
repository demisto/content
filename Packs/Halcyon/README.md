# Halcyon

Halcyon is a device management platform that helps organizations monitor, control, and secure their network of devices. It provides centralized tools for overseeing hardware and software inventory, deploying updates, enforcing security policies, and ensuring compliance across device environments.

## What does this pack do?

This pack enables you to collect security alerts and events from the Halcyon platform and ingest them into Cortex XSIAM for analysis and correlation.

### Key Features

- **Event Collection**: Automatically fetches alerts and events from Halcyon's API
- **Dual Log Types**: Supports both security alerts and operational events
- **Automatic Authentication**: Handles token-based authentication with automatic refresh
- **Configurable Fetch Limits**: Control the volume of data collected per fetch cycle

### Data Collected

| Log Type | Description | Time Field |
|----------|-------------|------------|
| Alerts | Security alerts from Halcyon | `lastOccurredAt` |
| Events | Operational events from Halcyon | `occurredAt` |

### Dataset

All collected data is stored in the `halcyon_halcyon_raw` dataset in Cortex XSIAM.

## Pack Contents

### Integrations

- **Halcyon** - Event collector integration for fetching alerts and events from the Halcyon platform

### Modeling Rules

- **Halcyon** - XDM mapping rules for normalizing Halcyon data to the Cortex Data Model

## Getting Started

1. Obtain your Halcyon API credentials (username and password)
2. Configure the Halcyon integration instance in Cortex XSIAM
3. Enable event fetching to start collecting data

For detailed configuration instructions, see the [Halcyon Integration README](Integrations/Halcyon/README.md).

## Requirements

- Cortex XSIAM version 8.2.0 or later
- Valid Halcyon account with API access

## Support

For support, please contact Cortex XSOAR support or visit the [Palo Alto Networks support portal](https://www.paloaltonetworks.com/support).
