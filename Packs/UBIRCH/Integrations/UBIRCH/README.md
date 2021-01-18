The UBIRCH solution can be seen as an external data certification provider, as a data notary service, giving data receivers the capability to verify data they have received with regard to its authenticity and integrity and correctness of sequence.
This integration was integrated and tested with version 1.0.0 of UBIRCH
## Configure UBIRCH on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for UBIRCH.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | url | Your MQTT host name | True |
    | port | port | True |
    | credentials | Username | True |
    | longRunning | Long running instance | False |
    | customerId | Customer id | True |
    | stage | Stage | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.