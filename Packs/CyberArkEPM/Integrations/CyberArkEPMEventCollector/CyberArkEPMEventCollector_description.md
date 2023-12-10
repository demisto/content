## Qualys Vulnerability Management Help

### Authentication
There are two methods to authenticate EPM and SAML,
Every method needs different parameters as following.

* EPM authentication
    - url: `https://<EPM_server>`
    - username: `admin`
    - password: `123456`
    - application ID: `1111`
    - set name: `admin, jhon`


* SAML authentication
    - url: `https://<EPM_server>`
    - username: `admin`
    - password: `123456`
    - authentication URL: `https://paloaltonetworks.okta.com/api/v1/authn`
    - application URL: `https://paloaltonetworks.okta.com/home/[APP_NAME]/[APP_ID]`
    - set name: `admin, jhon`

### Fetch Information

- There are three event types that are fetched for the Event Collector: 
    * Policy audits.
    * Admin audits.
    * Events.

* The `set name` parameter contains a list of names to which the events are related.
* The `max fetch` parameter is for every event type and for every name in the `set name` parameter which means that for `max fetch` that equals 1000 the actually max events fetched will be 3000 * sum of names in the `set name` parameter.
