## CyberArk EPM Help

### Authentication
There are two methods to authenticate EPM and SAML (currently only via Okta).
Every method needs different parameters as show in the following:

* EPM authentication
    - url: `https://<EPM_server>` (for example: https://login.epm.cyberark.com/login)
    - username
    - password
    - [application ID](https://docs.cyberark.com/Idaptive/Latest/en/Content/Applications/AppsOvw/SpecifyAppID.htm#%23SpecifytheApplicationID)
    - set name (comma separated value)


* SAML authentication (advanced settings) currently supported only via Okta.
    - url: `https://login.epm.cyberark.com/SAML/Logon`
    - username
    - password
    - authentication URL [Okta example](https://developer.okta.com/docs/reference/api/authn/#authentication-operations): `https://[COMPANY_NAME].okta.com/api/v1/authn`
    - application URL: `https://[COMPANY_NAME].okta.com/home/[APP_NAME]/[APP_ID]`
    - set name (comma separated value)

### Fetch Information

- There are three event types that are fetched for the Event Collector: 
    * Policy audits.
    * Admin audits.
    * Events.

* The `set name` parameter contains a list of names to which the events are related.
* The `max fetch` parameter is for every event type and for every name in the `set name` parameter which means that for `max fetch` that equals 1000 the actually max events fetched will be 3000 * sum of names in the `set name` parameter.
