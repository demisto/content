# Versa Director

## Versa Director Authentication flow:

- **Versa Director Integration can work in 2 authentication methods: Basic or Auth Token.**
- **By default, Auth Token Authentication will be used in the integration, to use basic authentication see the Basic Authentication section**

### Basic Authentication:

Basic authentication method based on ***Username*** and ***Password*** parameters (default authentication method).
  
**To use this method:**

1. Enter required ***Username*** and ***Password*** parameters in the Versa Director instance configuration.
2. Check the ***Use Basic Authentication*** checkbox.

### Auth Token:

#### There are 3 methods to use Auth Token authentication:

##### 1. If user have valid authentication parameters, meaning ***Client ID*** and ***Client Secret*** are available:
1. Run `vd-auth-start` command, passing ***Client ID*** and ***Client Secret*** as arguments to generate new Auth Token using the existing Client. If not provided. ***Client ID*** and ***Client Secret*** will be taken from the instance configuration.
2. The new Auth Token along with all of its relevant information will be saved in the integration context.
3. Uncheck the ***Use Basic Authentication*** checkbox.

##### 2. If user do not have valid authentication parameters, meaning ***Client ID***, ***Client Secret*** are not available:
1. Check the ***Use Basic Authentication*** checkbox.
1. Run  `vd-auth-start` command, passing ***Token Name*** argument (if ***Token Name*** is not passed, a default name will be used - this may cause conflicts if an Auth Client already created with the same name).
2. The command will create a new Auth Client, and will generate a new Auth Token using the newly created Auth Client, displaying ***Client ID*** and ***Client Name*** in a message for later use.
3. Uncheck the ***Use Basic Authentication*** checkbox.
   
##### 3. Use ***Auth Token*** only:
1. Pass ***Auth Token*** parameter inside the Instance Configuration.
2. Uncheck the ***Use Basic Authentication*** checkbox.
3. This method requires a valid Auth Token. If the Auth Token is expired at any point, it cannot be refreshed.

##### NOTES: 
1. If an Auth Token is created using `vd-auth-start`, a process is initiated every-time a command is run to check if the Auth Token is valid. If not, there will be an attempt to send a request for a new Auth Token using Refresh Token, If successful, the Integration Context will be updated.
2. Run `vd-auth-test` to test connectivity using chosen authentication method (please take note that if the ***Organization Name*** parameter is passed, its validity will also be checked).