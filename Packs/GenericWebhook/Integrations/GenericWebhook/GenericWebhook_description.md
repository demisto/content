We recommend that you use Cortex XSOAR server rerouting when using this integration:

<~XSOAR_ON_PREM>
1. Navigate to  **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the value for the ***instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>*** key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add *instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>* and set the value to *true*. See the following [reference article](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.
</~XSOAR_ON_PREM>


**Note**: The **Listen Port**, when configurable, needs to be available, which means it has to be unique for each integration instance. It cannot be used by other long-running integrations. For more information about long-running integrations, see the <~XSIAM>[Forward requests to long-running integrations](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Forward-Requests-to-Long-Running-Integrations) article.</~XSIAM> <~XSOAR_SAAS>Forward Requests to Long-Running Integrations article: [Cortex XSOAR 8 Cloud](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Forward-Requests-to-Long-Running-Integrations) or [Cortex XSOAR 8 On-prem](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Integration-commands-in-the-CLI) documentation.</~XSOAR_SAAS>

#### Security
- We recommend using authentication to validate the requests sent from your app, even if it's not required. Not using authentication could result in non-authorized parties creating incidents/issues in your system.

- To validate an incident request creation you can use the *Username/Password* integration parameters<~XSOAR_ON_PREM> for one of the following</~XSOAR_ON_PREM>:
     * Basic authentication using the username and password fields to validate incoming webhook requests
<~XSOAR_ON_PREM>     * Verification token given in a request header, by setting the username to `_header:<HEADER-NAME>` and the password to be the header value. 
     
        For example, if the request included in the `Authorization` header the value `Bearer XXX`, then the username should be set to `_header:Authorization` and the password should be set to `Bearer XXX`.</~XSOAR_ON_PREM>
    
- If you are not using server rerouting as described above, you can configure an HTTPS server by providing a certificate and private key.