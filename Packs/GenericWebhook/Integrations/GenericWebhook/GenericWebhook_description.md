We recommend that you use Cortex XSOAR server rerouting when using this integration:

1. Navigate to  **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the value for the ***instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add *instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>* and set the value to *true*. See the following [reference article](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.

**Note**: The ***Listen Port*** needs to be available, which means it has to be unique for each integration instance. It cannot be used by other long-running integrations.

#### Security
- We recommend using the authorization header, as described below, to validate the requests sent from your app. If you do not use this header it might result in incident creation from unexpected requests.

- To validate an incident request creation you can use the *Username/Password* integration parameters for one of the following:
     * Basic authentication
     * Verification token given in a request header, by setting the username to `_header:<HEADER-NAME>` and the password to be the header value. 
     
        For example, if the request included in the `Authorization` header the value `Bearer XXX`, then the username should be set to `_header:Authorization` and the password should be set to `Bearer XXX`.
    
- If you are not using server rerouting as described above, you can configure an HTTPS server by providing a certificate and private key.
