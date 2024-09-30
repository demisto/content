Deprecated. Use the ArcSight ESM v2 integration instead.

## Configure ArcSight XML in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Fetch incidents | False |
| Incident type | False |
| Directory from which to get XML files and create incidents. | True |
| Directory to which put command XML files. | True |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
