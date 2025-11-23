# Versa Director

## Authentication

This integration supports twp authentication methods:

- Basic
- Advanced

By default, Advanced Authentication is used in the integration. To use basic authentication, see [Basic Authentication](#basic-authentication).

### Basic Authentication

Basic authentication method is based on the *Username* and *Password* parameters only.

1. Enter the required values for the *Username* and *Password* parameters in the Versa Director instance configuration.
2. Check the **Use Basic Authentication** checkbox.

### Advanced Authentication

#### Using *Client ID* and *Client Secret*

**Note**: While this authentication method is represented by **Client ID** and **Client Secret** (which may be passed either as parameters or arguments), the **Username** and **Password** parameters must be specified during the initialization process.

##### If *Client ID* and *Client Secret* are available

1. Enter valid **Username** and **Password** parameters and, optionally, **Client ID** and **Client Secret**.
2. In the Playground, run the `!vd-auth-start` command, optionally passing the **client_id** and **client_secret** command arguments.

   **Note**: If client credentials are not provided as command arguments, an attempt will be made to use the specified configuration parameters.

   The new Auth Token along with all of its relevant information will be saved in the internal integration context.
2. Uncheck the **Use Basic Authentication** checkbox (if checked) and, optionally, clear the previously specified **Username** and **Password** parameter fields.

##### If *Client ID* and *Client Secret* are NOT available

1. Enter valid **Username** and **Password** parameters and check the **Use Basic Authentication** checkbox.
2. In the Playground, run the run  the `vd-auth-start` command, optionally passing the **auth_client_name** and **description** arguments.

   **Note**: If the **auth_client_name** argument is not passed, a default name is used, which may cause conflicts if an Auth Client was already created with the same name.

   The command will create a new **Client ID**, **Client Secret**, and **Auth Token**. The **Client ID** and **Client Name** will be displayed in a message.
4. Uncheck the **Use Basic Authentication** checkbox and, optionally, clear the previously specified **Username** and **Password** parameter fields.

#### Using an *Auth Token* Directly

This method requires a valid Auth Token. If the Auth Token has expired at any point, it cannot be refreshed.

1. Directly specify the **Auth Token** parameter.
2. Uncheck the **Use Basic Authentication** checkbox.

---

## Notes

1. If an Auth Token is created using the `!vd-auth-start` command, a process is initiated each time a command is run to check if the Auth Token is valid. If not, there will be an attempt to send a request for a new Auth Token using Refresh Token. If successful, the Integration Context will be updated.

2. Run the `!vd-auth-test` command to test connectivity using the chosen authentication method. Note that if the *Organization Name* parameter is passed, its validity will also be checked.
