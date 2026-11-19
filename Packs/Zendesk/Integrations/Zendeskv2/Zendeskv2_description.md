Use the Zendesk V2 integration to perform operations related to users, tickets, attachments, and more.

### Authentication Methods

This integration offers the following authentication methods. Configure only one of them; configuring more than one returns an error.

- **OAuth 2.0 (Client Credentials) - Recommended.** Fill in **Client ID**, **Client Secret** and, optionally, **Scope**.
- **API token - Deprecated.** Username in the format `<email>/token` and the API token as the password. Zendesk will deactivate API tokens on April 30, 2027 ([notice](https://developer.zendesk.com/documentation/authentication/oauth-migration/)).
- **Username and password - Deprecated.** Your Zendesk email and password. Migrate to OAuth ([notice](https://developer.zendesk.com/api-reference/introduction/security-and-auth/)).

### Configuring OAuth Authentication

An administrator must register an OAuth client in Zendesk and generate a client secret before configuring the integration:

1. In Zendesk Admin Center, go to **Apps and integrations → APIs → OAuth Clients**.
2. Create a new OAuth client. Record the **Client ID** (the "Unique identifier" value) and generate a **Client Secret** (shown once, copy it immediately).
3. Ensure the OAuth client is enabled for the **Client Credentials** grant and has the required scopes (read, write) allowed at the client level.
4. In the instance configuration, enter the Client ID and Client Secret. Leave **Scope** as `read write`, or enter a space-separated list of narrower scopes.

### Required permissions

This integration enables executing commands with different permission levels.
**The Test button does not ensure sufficient permissions for all integration commands.**
please look at the description of the command for more information on the required permission.
To learn more about Zendesk roles refer to:
[Understanding Zendesk Support user roles](https://support.zendesk.com/hc/en-us/articles/4408883763866-Understanding-Zendesk-Support-user-roles#topic_ibd_fdq_cc)
[About team member product roles and access](https://support.zendesk.com/hc/en-us/articles/4408832171034)

For more information about Zendesk V2 integration, see the [Integration documentation](https://xsoar.pan.dev/docs/reference/integrations/zendesk-v2)