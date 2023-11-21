## Mandiant Advantage Attack Surface Management

### Prerequisites
- A Mandiant Advantage Attack Surface Management account

### Get Credentials
- Log into `asm.advantage.mandiant.com`
- Navigate to `Account Settings`, then to `API Keys`
- Click `Generate New Key`, then copy the Access Key and Secret Key that are displayed.

### Get Project ID
- Configure the Access Key and Secret Key based on the "Get Credentials" section
- Run `!attacksurfacemanagement-get-projects` in the Playground.
- Use the numeric Project ID from the response in the configuration for this integration

### Get Collection IDs
- Configure the Access Key and Secret Key based on the "Get Credentials" section
- (Optionally) Configure the Project ID based on the "Get Project ID" section
- Run `!attacksurfacemanagement-get-collections` in the Playground to get a list of all collections in the currently 
configured project.  If specified, the `project_id` parameter will override the Project ID in the configuration.  The
project ID must be provided manually or included in the configuration to use this command.
- Use the ID from the response in the configuration for this integration.  To specify multiple collections, separate
them using a `,`