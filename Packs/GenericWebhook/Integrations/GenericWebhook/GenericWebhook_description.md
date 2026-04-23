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

#### Incident Mirroring

The Generic Webhook integration can perform incident mirroring by utilizing the different integration which has the mirroring capability. To enable the mirroring, configure the integration instance which can provide mirroring capabilities and set the following parameters in the Generic Webhook integration instance:

- **Mirroring Direction**: Set the direction of incident mirroring between Cortex XSOAR and the external system. Options are *Incoming*, *Outgoing*, or *Incoming And Outgoing*.
- **Mirror Tag for Notes**: Tag value used to mirror Cortex XSOAR notes back to the external system. Defaults to `note`.
- **Mirror Instance**: The integration instance name to use for mirroring.

#### Incident Deduplication

To prevent duplicate incidents from being created by repeated webhook triggers, set the **Duplication Key** parameter to one or more field names or paths (comma-separated). When a new request arrives, the integration checks whether any of the specified field values match a previously seen value. If a match is found, the incident is silently dropped.

- **Simple key**: Set **Duplication Key** to a top-level field name that is unique per event, for example `incidentId`.
- **JSON Path**: JSON Path expressions are supported for extracting values from nested objects or arrays. For example, if your payload contains a `data` object with an `id` field, set **Duplication Key** to `data.id`.
