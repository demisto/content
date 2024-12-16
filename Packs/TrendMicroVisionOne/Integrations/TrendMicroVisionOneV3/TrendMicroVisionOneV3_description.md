# Integration Author: Trend Micro

Support and maintenance for this integration are provided by the author. Please use the following contact details:

- **Email**: [integrations@trendmicro.com](mailto:integrations@trendmicro.com)

***
Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro Vision One prevents the majority of attacks with automated protection.

## Obtaining Trend Micro Vision One V3 API Credentials

Configuring the Trend Micro Vision One integration requires API credentials generated in Trend Micro Vision One. It is recommended that a new role be created with just the permissions required for this integration. You can create a new role for this integration by following these steps in Trend Micro Vision One.

1. Navigate to **Administration** > **User Roles**
2. Click on the **Add** button
3. Provide a name and descriptions for the role such as **Cortex XSOAR**
4. Click on the **Permissions** button and assign the following permissions to the role:

| **Category**        | **Application**              | **Permission**                          |
| ------------------- | ---------------------------- | --------------------------------------- |
| Threat Intelligence | Suspicious Object Management | View, filter, and search                |
| Threat Intelligence | Suspicious Object Management | Manage lists and configure settings     |
| Threat Intelligence | Suspicious Object Management | View object in Sandbox Analysis         |
| Threat Intelligence | Sandbox Analysis             | View, filter, and search                |
| Threat Intelligence | Sandbox Analysis             | Submit objects                          |
| XDR                 | Workbench                    | Add exceptions                          |
| XDR                 | Workbench                    | Modify alert details                    |
| XDR                 | Workbench                    | View, filter, and search                |
| Response Management | Response Management          | View, filter, and search Task List tab  |
| Response Management | Response Management          | Approve/Reject Automated Response tasks |
| Response Management | Response Management          | Collect file                            |
| Response Management | Response Management          | Delete/Quarantine messages              |
| Response Management | Response Management          | Isolate endpoint                        |
| Response Management | Response Management          | Terminate process                       |
| Response Management | Response Management          | View network exceptions                 |
| Response Management | Response Management          | Add to block list                       |
| Response Management | Response Management          | Edit network exceptions                 |
| Response Management | Response Management          | Submit to sandbox                       |

You can then create a user account and generate an API key to be used for the Cortex XSOAR integration by following these steps in Trend Micro Vision One.

1. Navigate to **Administration** > **User Accounts**
2. Click on the **Add Account** button
3. Fill in the **Add Account** details assigning the role you created in the previous step and choosing **APIs only** as the access level
4. Complete the account creation process by following the steps in the email sent
5. This will generate an **Authentication token** that can then be used to configure the Cortex XSOAR integration

## Configure Trend Micro Vision One V3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Trend Micro Vision One.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter**            | **Description**                                                               | **Required** |
    | ------------------------ | ----------------------------------------------------------------------------- | ------------ |
    | Name                     | Unique name for this Trend Micro Vision One instance                          | True         |
    | Fetch Incidents          | Choose if the integration should sync incidents                               | True         |
    | Incident Type            | Ensure the "Trend Micro Vision One XDR Incident" type is selected             | True         |
    | Mapper (Incoming)        | Ensure the "Trend Micro Vision One V3 XDR - Incoming Mapper" type is selected | True         |
    | API URL                  | Base URL for Trend Micro Vision One API                                       | True         |
    | API Key                  | API token for authentication                                                  | True         |
    | Incidents Fetch Interval | How often do you want to check for new incidents                              | False        |
    | Sync On First Run (days) | How many days to go back during first sync                                    | False        |
    | Max Incidents            | Maximum Number of Workbenches to Retrieve                                     | False        |

4. Click **Test** to validate the URLs, token, and connection.

***
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/trend-micro-vision-one-v3)