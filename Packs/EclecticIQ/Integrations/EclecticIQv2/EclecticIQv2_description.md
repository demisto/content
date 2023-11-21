#### Integration Author: EclecticIQ
## EclecticIQ Platform 
* Threat Intelligence Platform that connects and interprets intelligence data from open sources, commercial suppliers and industry partnerships. EclecticIQ Platform is used through Cortex XSOAR to get the reputation of IOCs and their related entities.

## Obtaining EclecticIQ Platform API Credentials
Configuring the EclecticIQ integration requires API credentials generated in EclecticIQ Platform. It is recommended that a new role be created with just the permissions required for this integration. You can create a new role for this integration by following these steps in EclecticIQ Platform.
1. Login into the EclecticIQ Platform using the **username** and **password**
2. Navigate to **Settings** > **User Management**
3. Click on the **Create User** button
4. Provide a **name**, **email**, **group** and **user type** 
5. Assign the roles for the user in the **assigned role** field and click **save** button
6. Navigate to **API token** and click on **add**
7. Provide the **description** and click on **generate token**.

## Configure EclecticIQ Platform v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for EclecticIQ Platform v2
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name | Unique name for this EclecticIQ instance | True |
| URL | Base URL for EclecticIQ  API | True |
| API Key | API token for authentication  | True |

4. Click **Test** to validate the URLs, token, and connection.

### Commands
* Execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. EclecticIQ_create_observable: create observable in the EclecticIQ Intelligence Center Platform
2. EclecticIQ_create_sighting: create sighting in the EclecticIQ Intelligence Center Platform
3. EclecticIQ_lookup_observables: lookup observables from EclecticIQ Intelligence Center Platform




