Vega integration for fetching alerts and incidents from the Vega platform.
This integration was integrated and tested with version xx of Vega.

## Configure Vega in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Base URL | The Base URL of the Vega API. | True |
| Access Key ID | The Access Key ID used to authenticate with the Vega API. | True |
| Access Key | The Access Key used to authenticate with the Vega API. | True |
| Fetch incidents |  | False |
| Vega Entities to fetch | Select the Vega entities to fetch as XSOAR incidents. | True |
| Alert Severities to fetch | Filter alerts by severity. If empty, all severities are fetched. | False |
| Alert Statuses to fetch | Filter alerts by status. If empty, all statuses are fetched. | False |
| Alert Verdicts to fetch | Filter alerts by verdict. If empty, all verdicts are fetched. | False |
| Incident Severities to fetch | Filter incidents by severity. If empty, all severities are fetched. | False |
| Incident Statuses to fetch | Filter incidents by status. If empty, all statuses are fetched. | False |
| Incident Verdicts to fetch | Filter incidents by verdict. If empty, all verdicts are fetched. | False |
| Incident type |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
