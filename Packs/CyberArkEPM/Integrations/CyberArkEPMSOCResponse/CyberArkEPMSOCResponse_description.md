## CyberArk EPM Help

### Authentication
The authentication to EPM requires the following parameters:

* EPM authentication
    - url: `https://<EPM_server>` (for example: https://login.epm.cyberark.com/login)
    - username
    - password
    - [application ID](https://docs.cyberark.com/Idaptive/Latest/en/Content/Applications/AppsOvw/SpecifyAppID.htm#%23SpecifytheApplicationID)

### Endpoint Information

- To uniquely identify an endpoint the following command arguments are used: 
    * Endpoint name.
    * Endpoint External IP.
  In addition to that a pre-defined risk plan must be provided (i.e. `Medium_Risk_Plan`)
