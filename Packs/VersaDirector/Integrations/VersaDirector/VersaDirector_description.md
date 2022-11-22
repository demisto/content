# Versa Director

## Versa Director Authentication flow:

- **Versa Director Integration can work in 2 authentication methods: Basic and Advanced**
- **By default, Auth Token Authentication will be used in the integration, to use basic authentication see the Basic Authentication section**

### Basic Authentication

Basic authentication method based on ***Username*** and ***Password*** parameters.

1. Enter required ***Username*** and ***Password*** parameters in the Versa Director instance configuration.
2. Check the ***Use Basic Authentication*** checkbox.

### Advanced Authentication

**NOTE**: ***Auth Client*** Creates Auth Tokens. It is represented with ***Client ID*** and ***Client Secret*** parameters/arguments.

#### Use ***Client ID*** and ***Client Secret***:
##### 1. If ***Client ID*** and ***Client Secret*** are available:
1. Run `vd-auth-start` command, passing ***Client ID*** and ***Client Secret*** as arguments.
   If ***Client ID*** and ***Client Secret*** are not provided as arguments, an attempted will be made to use ***Client ID*** and ***Client Secret*** as parameters from the instance configuration.
3. The new Auth Token along with all of its relevant information will be saved in the integration context.
4. Uncheck the ***Use Basic Authentication*** checkbox.

##### 2. If ***Client ID***, ***Client Secret*** are NOT available:
1. Check the ***Use Basic Authentication*** checkbox.
2. Run  `vd-auth-start` command.
   _Optional_: Run  `vd-auth-start` command with ***Auth Client Name*** argument. (if ***Auth Client Name*** is not passed, a default name will be used - this may cause conflicts if an Auth Client already created with the same name).
3. The command will create new ***Client ID*** and ***Client Secret*** and ***Auth Token***, displaying ***Client ID*** and ***Client Name*** in a message.
4. Uncheck the ***Use Basic Authentication*** checkbox.

#### Use Auth Token:

1. Pass ***Auth Token*** parameter inside the Instance Configuration.
2. Uncheck the ***Use Basic Authentication*** checkbox.
3. This method requires a valid Auth Token. If the Auth Token is expired at any point, it cannot be refreshed.

##### NOTES: 
1. If an Auth Token is created using `vd-auth-start`, a process is initiated every-time a command is run to check if the Auth Token is valid. If not, there will be an attempt to send a request for a new Auth Token using Refresh Token, If successful, the Integration Context will be updated.
2. Run `vd-auth-test` to test connectivity using chosen authentication method (please take note that if the ***Organization Name*** parameter is passed, its validity will also be checked).