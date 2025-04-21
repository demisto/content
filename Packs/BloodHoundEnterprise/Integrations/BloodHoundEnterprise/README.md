# BloodHound Enterprise Integration for Cortex XSIAM

Use this integration to fetch audit logs from BloodHound Enterprise as events in Cortex XSIAM.
This integration was integrated and tested with version 1.0.0 of BloodHound Enterprise.

## Configure BloodHound Enterprise on Cortex XSIAM

1. Navigate to **Settings** > **Configurations** > **Automation & Feed Integrations**.
2. Search for **BloodHoundEnterprise**.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**                              | **Required** | **Description**                                                                      |
    |--------------------------------------------|---------------|--------------------------------------------------------------------------------------|
    | Server URL                                 | Yes           | The URL of your BloodHound Enterprise server.                                        |
    | API Token ID                               | Yes           | The ID associated with the API Token Key.                                            |
    | API Token Key                              | Yes           | The key used for authentication with the BloodHound Enterprise API.                  |
    | Fetch events                               | No            | Enable this to fetch events automatically.                                           |
    | Maximum number of events per fetch         | No            | Limits the number of events fetched in each cycle. Default is 5000.                  |
    | Trust any certificate (not secure)         | No            | Allow the integration to trust any SSL certificate, even if it's not secure.         |
    | Use system proxy settings                  | No            | Use the system's proxy configuration for connecting to the server.                   |

4. Click **Test** to validate the connection using the provided details.

## Note:
    This API can be run only with ADMIN privileges.

## Commands

The following commands can be executed from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
Each command returns relevant information that you can use for further analysis or alerting.

### bloodhound-get-events

Retrieves events from BloodHound Enterprise based on the specified date range.  
This command allows you to monitor and analyze recent events directly from the Cortex XSIAM interface.

#### Base Command

`bloodhound-get-events`

#### Input

| **Argument Name**    | **Description**                                                                                                    | **Required** |
|----------------------|--------------------------------------------------------------------------------------------------------------------|--------------|
| start                | The start date for filtering events. Use ISO 8601 format (e.g., 2024-07-10T08:08:46Z). Default is one minute back  | No           |
| end                  | The end date for filtering events. Use ISO 8601 format (e.g., 2024-07-11T08:09:47Z). Default is current time       | No           |
| should_push_events   | Set to `true` to create events in Cortex XSIAM; `false` will only display them.                                    | No           |
| limit                | The maximum number of events to return. Default is 10.                                                             | No           |

#### Example Usage

```shell
!bloodhound-get-events start="2024-07-10T08:00:00Z" end="2024-07-11T08:00:00Z" limit=100 should_push_events=true

