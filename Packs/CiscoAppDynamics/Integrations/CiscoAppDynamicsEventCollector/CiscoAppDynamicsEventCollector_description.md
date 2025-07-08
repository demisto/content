## API Clients

To create API clients, you are required to be assigned to the role of an **Account Owner or an Administer**. You can view the API Client settings in the Settings > Administration page of the Controller.

## How to Create API Clients

You can create new API Client identity types that can be used to generate OAuth tokens.

1. Log in to the Controller UI as an Account Owner or other roles with the Administer users, groups, roles, permission.
2. Click  > Administration.
3. Click the API Clients tab to view the list of existing clients.
4. Click + Create.
5. Enter the Client Name and Description.
6. Click Generate Secret to populate the Client Secret.
7. This will generate a UUID as the secret of the API Client.
8. Set the Default API-generated Token Expiration. This expiration only applies to authentication tokens generated through the /controller/api/oauth/access_token REST API, not to Temporary Access Tokens generated from the UI. See Using the Access Token.
9. Add the Roles you would like to associate with this API Client. You can add or remove roles at any time.
10. Click Save at the top right.

## Application ID

You can find the application_id in the Controller UI:

1. Navigate to Applications in the AppDynamics Controller.
2. Select the application you are interested in.
3. The application ID is visible in the URL as application = ID.
