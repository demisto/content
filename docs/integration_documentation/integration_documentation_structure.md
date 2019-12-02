## Overview
Type of the product and common use case through Demisto.
  What is this integration good for? 
  What does the integration do? 
Known limitations (only if needed in this high level view)
What version of the integrated product was tested (and what versions we believe are supported. e.g. tested on 2.0, should work on 2.0 and up) 

## To set up [integration name] to work with Demisto:
Just list the requirements for integrating with Demisto. You can include links to third-party documentation if necessary.

* API token
* Credentials 
* Etc

## To set up the integration on Demisto:
For example:
1. Go to ‘Settings > Integrations > Servers & Services’
2. Locate [integration name] by searching for it using the search box on the top of the page.
3. Click ‘Add instance’ to create and configure a new integration. You should configure the following settings:  

   **Name**: A textual name for the integration instance.

   **Appliance IP/Hostname**: The hostname or IP address of the appliance being used.

   **Appliance Port**: The appliance port being used.

   **Username and Password**: The username and password, or toggle to Credentials.

   **Fetch incidents**: Select whether to automatically create Demisto incidents from this integration instance. 

   **Test** What is tested and what to do if the test fails


## Fetched Incidents Data
Information needed to use the fetch-incidents option.

What can be fetched? (e.g. events or cases but not "observations")

How are we filtering? (e.g. "ID" / "Created Date" / "Seen Date" / configurable? )

Initial fetch parameters (from now? 10mins back?)


## Use Cases
Anything specific about the 3rd-party product that user should know that will help understand how to run commands with parameters. For example, Archer applications are inter-connected using content id.
Followed by use case.

## Commands
When listing commands with inputs and outputs use the following structure:
1. command1
2. command2
3. command3


### 1. Command1

   #### Input
|Argument Name | Description | Required |
| ---- | ---- | ---- |
|argument1 | Filter the x by the y. | Required |
   
#### Context Output
|Path | Type | Description |
| ---- | ---- | ---- |
|Integration.Output | string | The indicator score. |
 
   #### Context Output (JSON)

    `{`

     `...`

    `}`


   #### Human Readable Output (War Room)

   ` {`

     `...`

    `}`


or state
This Integration does not have commands but....

## Additional info:
such as command examples, usage examples, etc.

## Known Limitations
## Troubleshooting 

This integration was integrated and tested with version [x.y.z.w] of [integration name]"