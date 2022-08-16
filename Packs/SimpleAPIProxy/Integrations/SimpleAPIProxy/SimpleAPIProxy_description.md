#### Configuration
- ***Lists to Publish*** - This is the comma separated list of list names you with to publish under the configured instance. Example: mylist1,mylist2,mylist3
- ***List Items on Individual Lines*** - For XSOAR Lists that are comma separated text, this will take all the list items and return them on a separate line, one list item per line.

We recommend that you use Cortex XSOAR server rerouting when using this integration:

1. Navigate to  **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the value for the ***instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add *instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>* and set the value to *true*. See the following [reference article](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.

**Note**: The ***Listen Port*** needs to be available, which means it has to be unique for each integration instance. It cannot be used by other long-running integrations.

#### Security
- We recommend using the authorization header, as described below, to validate the requests sent from your app. If you do not use this header it might result in information leakage from unpermitted requests.

- To validate an incident request creation you can use the *Username/Password* integration parameters for one of the following:
     * Basic authentication
     * Verification token given in a request header, by setting the username to `_header:<HEADER-NAME>` and the password to be the header value. 
     
        For example, if the request included in the `Authorization` header the value `Bearer XXX`, then the username should be set to `_header:Authorization` and the password should be set to `Bearer XXX`.
    
- If you are not using server rerouting as described above, you can configure an HTTPS server by providing a certificate and private key.

#### Proxied API Definition
##### Target API Base Path
The base of the API path to interface with without a trailing slash. e.g `https://ipinfo.io`

##### API Credential Type
- None: No authentication needed
- Basic: This is HTTP basic authentication in the header will have `Authorization: Basic [base64 encoded string of username/password]`
- Bearer Token: Takes the password field as the API token and applies it as a header value `Authorization: Bearer [TOKEN HERE]`
- Custom Header: Takes the username as the header field and password as the value. Example: `[UsernameField]: [PasswordField]`

#### API Permission Definition
This is the definition of allowed commands and methods that can be executed via this integration instance.  The permissions below would allow GET/POST against {target_base_url}/v1/users as well as /v1/users/* and /v1/users* as the permissions validate the clients request starts with a specific target.  Also allows the same type of wildcarding but only GET requests for /v1/groups.

##### Example
`{
  "Permissions": [
    {
      "target":"/v1/users",
      "allowed_methods":["GET","POST"]
    },
    {
      "target":"/v1/groups",
      "allowed_methods":["GET"]
    }
  ]
}`