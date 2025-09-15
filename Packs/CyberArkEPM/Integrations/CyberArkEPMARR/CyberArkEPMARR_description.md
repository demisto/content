## CyberArk EPM Help

### Authentication
There are two methods to authenticate EPM and SAML (currently only via Okta).
Every method needs different parameters as show in the following:

* EPM authentication
    - url: `https://<EPM_server>` (for example: https://login.epm.cyberark.com/login)
    - username
    - password
    - [application ID](https://docs.cyberark.com/Idaptive/Latest/en/Content/Applications/AppsOvw/SpecifyAppID.htm#%23SpecifytheApplicationID)



* SAML authentication (advanced settings) currently supported only via Okta.
    - url: `https://login.epm.cyberark.com/SAML/Logon`
    - username
    - password
    - authentication URL [Okta example](https://developer.okta.com/docs/reference/api/authn/#authentication-operations): `https://[COMPANY_NAME].okta.com/api/v1/authn`
    - application URL: `https://[COMPANY_NAME].okta.com/home/[APP_NAME]/[APP_ID]`

### Endpoint Information

- To uniquely identify an endpoint the following command arguments are used: 
    * Endpoint name.
    * Endpoint External IP.
  In addition to that a pre-defined risk plan must be provided (i.e. `Medium_Risk_Plan`)
