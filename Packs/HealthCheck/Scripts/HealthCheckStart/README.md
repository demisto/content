# HealthCheckStart

## Overview

This script triggers the HealthCheck playbook by creating a new alert with all the expected data pre-populated in the alert fields.

The script makes a local API call to `public_api/v1/alerts/create_alert` with a fixed payload that matches the alert schema expected by the HealthCheck playbook trigger. Once the alert is created, a clickable link to the new alert is posted in the War Room.

## Usage

This script should be run from the **Playground** investigation.

After execution, a War Room entry will appear with a direct link to the created HealthCheck alert, which will automatically trigger the HealthCheck playbook via the configured alert trigger.

## Alert Data

The script creates an alert with the following fixed fields:

| Field | Value |
|---|---|
| Vendor | PANW |
| Product | XSIAM Manual |
| Severity | High |
| Category | Healthcheck Report |
| Alert Name | Healthcheck Report and BPA diagnostics |
| Alert Type | Automation |
| Alert Domain | DOMAIN_HEALTH |
| Description | New Healthcheck data collection alert |

## Notes

- This script is available on **XSIAM only** (not XSOAR).
- No context output is written — the result is a War Room markdown entry with a hyperlink to the created alert.
- The script requires the `core-api-post` command to be available (provided by the Cortex Core integration).
