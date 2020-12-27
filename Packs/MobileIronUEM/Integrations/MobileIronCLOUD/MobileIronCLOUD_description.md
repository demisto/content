## MobileIron Cloud - Getting Started

1. Log in to the MobileIron Cloud Admin console.
2. Open the users section.
3. Click the create user button and select the option to create a new API user. It is recommended to create a new user for the Cortex XSOAR integration specifically and not reuse an existing one.
4. Fill in all the required details (i.e., use demisto-api-user as the username) and make sure you enter a strong password.
5. When setting up the Cortex XSOAR integration, use the auto-generated email address as the username and the password you 
defined as the MobileIron tenant credentials.
6. Click the `Test` button and ensure the connection can be established.

Refer to the API documentation at the MobileIron community for more details on setting up the API user.

### MobileIron Cloud - Spaces

If you are dividing the devices into different spaces, it is important to make sure the integration
points to the correct `Partition ID (Device Space ID)`.
 
You should leave this value blank if you are not using spaces or if you want the integration to automatically resolve the 
default space ID.  
