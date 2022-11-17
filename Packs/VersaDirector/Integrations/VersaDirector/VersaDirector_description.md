# Versa Director

## Versa Director Authentication flow:

- **Versa Director Integration can work in 2 authentication methods: Basic or Auth Token.**
- ***Username*** and ***Password*** parameters are required for both authentication methods. 

### Basic Authentication:

Basic authentication method based on ***Username*** and ***Password*** parameters (default authentication method).
  
**To use this method:**

1. Enter required ***Username*** and ***Password*** parameters in the Versa Director instance configuration.
2. uncheck the ***Use Auth Token*** checkbox.

### Auth Token:

#### There are 3 methods to use Auth Token authentication:

##### If an Auth Client already exists, and ***Client ID***, ***Client Secret*** are available:
1. Run `vd-auth-start` command, passing ***Client ID*** and ***Client Secret*** as arguments to generate new Auth Token using the given Auth Client.
2. The new Auth Token along with all of its relevant information will be saved in the integration context.
3. Check the ***Use Auth Token*** checkbox.

##### If an Auth Client does not exist, and ***Client ID***, ***Client Secret*** are not available:
 1. Run  `vd-auth-start` command, passing ***Token Name*** argument (if ***Token Name*** is not passed, a default name will be used - this may cause conflicts if an Auth Client already created with the same name).
2. The command will create a new Auth Client, and will generate a new Auth Token using the newly created Auth Client, displaying ***Client ID*** and ***Client Name*** in a message for later use.
3. Check the ***Use Auth Token*** checkbox.
   
##### If  If an Auth Client already exists, and ***Client ID***, ***Client Secret*** and ***Auth Token*** are available:
1. Pass ***Client ID***, ***Client Secret*** and ***Auth Token*** parameters inside the Instance Configuration.
2. Check the ***Use Auth Token*** checkbox.
3. This method requires a valid Auth Token. If the Auth Token is expired at any point, it cannot be refreshed.

##### NOTES: 
1. If an Auth Token is created using `vd-auth-start`, a process is initiated every-time a command is run to check if the Auth Token is valid. If not, there will be an attempt to send a request for a new Auth Token using Refresh Token, If successful, the Integration Context will be updated.
2. Run `vd-auth-test` to test connectivity using chosen authentication method (please take note that if the parameter ***Organization Name*** is passed, its validity will also be checked).