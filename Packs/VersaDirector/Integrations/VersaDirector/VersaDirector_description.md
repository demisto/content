# Versa Director

## Versa Director Authentication flow:

- **Versa Director** integration can work in 2 authentication methods: 
   - Basic
   - Advanced
- By default, Auth Token Authentication will be used in the integration. To use basic authentication, see [Basic Authentication](#basic-authentication).

### Basic Authentication

Basic authentication method is based on the *Username* and *Password* parameters.

1. Enter the required values for the *Username* and *Password* parameters in the Versa Director instance configuration.
2. Check the **Use Basic Authentication** checkbox.

### Advanced Authentication

**NOTE**: *Auth Client* Creates Auth Tokens. It is represented by the *Client ID* and *Client Secret* parameters/arguments.

#### Use *Client ID* and *Client Secret*
If *Client ID* and *Client Secret* are available:
1. Run the `vd-auth-start` command, passing *Client ID* and *Client Secret* as arguments.

   If *Client ID* and *Client Secret* are not provided as arguments, an attempt will be made to use *Client ID* and *Client Secret* as parameters from the instance configuration.

   The new Auth Token along with all of its relevant information will be saved in the integration context.
2. Uncheck the **Use Basic Authentication** checkbox.

#### If *Client ID* and *Client Secret* are NOT available:
1. Check the **Use Basic Authentication** checkbox.
2. Run  the `vd-auth-start` command.

   _Optional_: Run  the `vd-auth-start` command with the *Auth Client Name* argument. (If *Auth Client Name* is not passed, a default name will be used. This may cause conflicts if an Auth Client was already created with the same name.)

   The command will create a new *Client ID*, *Client Secret*, and *Auth Token*. The *Client ID* and *Client Name* will be displayed in a message.
4. Uncheck the **Use Basic Authentication** checkbox.

#### Use Auth Token
This method requires a valid Auth Token. If the Auth Token is expired at any point, it cannot be refreshed.

1. Pass the *Auth Token* parameter inside the Instance Configuration.
2. Uncheck the **Use Basic Authentication** checkbox.



##### NOTES: 
1. If an Auth Token is created using the `vd-auth-start` command, a process is initiated each time a command is run to check if the Auth Token is valid. If not, there will be an attempt to send a request for a new Auth Token using Refresh Token. If successful, the Integration Context will be updated.
2. Run the `vd-auth-test` command to test connectivity using the chosen authentication method. Note that if the *Organization Name* parameter is passed, its validity will also be checked.
