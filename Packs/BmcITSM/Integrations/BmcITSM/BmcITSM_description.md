## Access to BMC Helix ITSM
- The username and password credentials are used to authenticate with the ITSM API for the provided instance URL. 

- The user role should have access to the following ticket types:
    - Service request
    - Change request
    - Problem investigation
    - Known error
    - Task
    - Incident    

**Note:**  
To delete a ticket the user must have an Admin role. 

## Display ID vs. Request ID
- **Display ID** (ID number) is a unique ID that references a specific ticket. This field is comparable to the ticket ID as it displayed in BMC Helix ITSM.

- **Request ID**  is a unique core field of the ticket. Although it is not exposed to the user, it directly accesses the resource ticket through REST API calls, and executes Update, Delete, and Get operations on the ticket. In the integration it is a required argument for most of the commands.
