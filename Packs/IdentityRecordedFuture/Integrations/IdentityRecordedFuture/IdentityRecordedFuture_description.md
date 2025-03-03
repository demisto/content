Unique threat intelligence technology that automatically serves up relevant insights in real time.

# Recorded Future Identity Integration for Cortex XSOAR

The Recorded Future Identity integration for Cortex XSOAR provides comprehensive threat intelligence capabilities
focused on identity-related exposures. This integration enables security teams to automate the detection, investigation,
and response to identity threats using Recorded Future's rich dataset.

## Available Actions

### Identity Actions

- **Search for identities**: Automate searches for compromised identities within the Recorded Future Identity dataset.
- **Lookup for specific identity**: Retrieve detailed information about specific identities, including associated
  breaches and exposures.
- **Password lookup**: Verify the exposure status of password hashes against the Recorded Future dataset.

### Playbook Alert Actions

- **Fetch Playbook alerts**: Import Playbook alerts specific to identity threats, providing detailed information on each
  alert.
- **Update Playbook alert status**: Change the status of Playbook alerts and add comments or actions taken.

## Setup

A valid API Token for Recorded Future Identity Intelligence needed to fetch information.
[Get help with Recorded Future for Cortex XSOAR](https://www.recordedfuture.com/integrations/).

### Configuration

1. **Navigate to Integrations**:
    - Go to **Settings** > **Integrations** > **Servers & Services**.

2. **Search for Recorded Future Identity**:
    - In the search bar, type **Recorded Future Identity**.

3. **Add a New Instance**:
    - Click **Add instance** to create and configure a new integration instance.

4. **Enter Configuration Parameters**:
    - Fill in the required parameters such as Server URL and API Token.
    - Adjust optional settings like proxy usage and incident fetching as needed.

5. **Test the Configuration**:
    - Click **Test** to ensure the settings are correct and that the connection to Recorded Future is successful.

### Configuration Parameters

| **Parameter**                                 | **Description**                                                                                                                         | **Required** |
|-----------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|--------------|
| Server URL                                    | The URL to the Recorded Future ConnectAPI.                                                                                              | True         |
| API Token                                     | A valid API token from Recorded Future. [Get help with Recorded Future for Cortex XSOAR](https://www.recordedfuture.com/integrations/). | True         |
| Trust any certificate (unsecure)              | Option to trust any certificate.                                                                                                        | False        |
| Use system proxy settings                     | Option to use system proxy settings.                                                                                                    | False        |
| Password properties                           | Password properties that are used as a filter.                                                                                          | False        |
| Limit Identities                              | Limit of identities to get (min is 0 and max is 10,000).                                                                                | False        |
| Domains                                       | List of domains to use in search and lookup commands (e.g., mycompany.com, nextcompany.com).                                            | True         |
| Fetch incidents                               | Enable fetching incidents.                                                                                                              | False        |
| First Incident Fetch: Time Range              | Limit incidents to include in the first fetch by time range.                                                                            | False        |
| Maximum number of incidents per fetch         | Limit the number of incidents returned per fetch.                                                                                       | False        |
| Playbook Alerts: Fetched Statuses             | Choose what statuses to include in the fetch (New, In Progress, Dismissed, Resolved).                                                   | False        |
| Playbook Alerts: Fetched Priorities Threshold | Choose the priority threshold to fetch alerts of the selected priority and higher (Informational < Moderate < High).                    | False        |
| Incident type                                 | Specify the incident type.                                                                                                              | False        |

### Pre-Process Rule

The integration pulls in Playbook alerts from Recorded Future based on its updates, creating the need for a
preprocessing rule that updates existing incidents instead of creating duplicates. Follow the guidelines below to
configure the preprocessing rule.

1. Navigate to **Settings** > **Objects Setup** > **Pre-Process Rules**.
2. Click **New Rule**.
3. Name the rule appropriately.
4. In the **Conditions for Incoming Incident** section, enter:
    - **Name** - **Includes** - **Recorded Future Playbook Alert**
5. In the **Action** section, select **Drop and update**.
6. In the **Update** section, enter
    - **Link to** - **Oldest incident** - **Created within the last** - *Your desired timeframe*
    - **DbotMirrorId** - **Is identical (Incoming Incident)** - **to incoming incident**

> The configuration of the preprocessing rule is optional, but highly recommended.

![Pre-process Rule](../../doc_files/playbook_alerts_pre_process_rule.png)

Copyright (C) 2020-2024 Recorded Future, Inc.