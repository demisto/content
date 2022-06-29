## Access to BMC Helix ITSM
- The credentials (username and password parameters) are used to authenticate with the ITSM API for the provided instance URL. 

- The role of the user should have access to service requests, change requests, problem investigation, known error, task and incidents. Keep in mind that in order to delete a ticket the user must have an Admin role. 

## Display ID vs. Request ID
- **Display ID** (ID number) is a unique identification to reference a specific ticket. This field allows us to understand the ID of the ticket as it displayed in BMC Helix ITSM. 

- **Request ID** is a unique core field of the ticket. Although it is not exposed to the user, it allows us to acess directly to the resource ticket through REST API calls, and execute - Update, Delete and Get operations on the ticket. In the intergration it is a required argument for most of the commands. 