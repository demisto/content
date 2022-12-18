This Automation script uses the XSOAR API to get the audit logs and pushes them to Splunk HEC. Dependencies: SlunkPy and Demisto REST API integrations

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| timeframe | timeframe to fetch in hours |

## Outputs
---
There are no outputs for this script.

### Troubleshooting
Multi tenant environments should be configured with Cortex Rest API instance when using this automation and 
make sure *Use tenant* parameter (in Cortex Rest API integration) is checked to make sure that API calls are made to the current tenant
instead of the master tenant.