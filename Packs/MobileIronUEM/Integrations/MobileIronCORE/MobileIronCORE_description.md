## MobileIron Core - Getting Started

1. Log in to the MobileIron Core Admin console.
2. Open the `Users` top section.
3. Click on the `create local user` button. It is recommended to create a new user for the Cortex XSOAR integration specifically and not reuse
an existing one.
4. Make sure you enter all the details and keep note of the User ID (ex. demisto-api-user) and the password specifically.
5. Click on the `Admins` top section
6. Add the user you just created as an admin to the instance.
6. When setting up the Cortex XSOAR integration use User ID as the username and the password you defined as the MobileIron tenant credentials.
7. Click the `Test` button and ensure the connection can be established.

Refer to the API documentation at the MobileIron community for more details on setting up the API user.

### MobileIron Core - Spaces

If you are dividing the devices into different spaces, it is important to make sure the integration
points to the correct `Device Admin Space ID`.
 
In most cases, this is set to the value *1* for the global space ID.
