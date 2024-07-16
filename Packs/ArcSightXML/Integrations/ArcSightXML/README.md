Deprecated. Use the ArcSight ESM v2 integration instead.

## Configure ArcSight XML on Cortex XSOAR

1. * For XSOAR 6.x users: Navigate to **Settings** > **Integrations** > **Instances**.
   * For XSOAR 8.x users: Navigate to **Settings & Info** > **Settings** > **Integrations** > **Instances**.
   * For XSIAM users: Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation & Feed Integrations**.
2. Search for ArcSight XML.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Fetch incidents | False |
    | Incident type | False |
    | Directory from which to get XML files and create incidents. | True |
    | Directory to which put command XML files. | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### arcsight-update-case

***
Create an XML to update a case.

#### Base Command

`arcsight-update-case`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| caseId | ID of the case. | Required | 
| name | Name of the case. | Required | 
| stage | The stage of the case. | Required | 

### arcsight-fetch-xml

***
Used for testing. Should fetch XML file and return an XSOAR incident object.

#### Base Command

`arcsight-fetch-xml`

#### Input

There is are no inputs for this command.

