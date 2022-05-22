SaaS Security is an integrated CASB (Cloud Access Security Broker) solution that helps Security teams like yours meet 
the challenges of protecting the growing availability of sanctioned and unsanctioned SaaS applications and maintaining 
compliance consistently in the cloud while stopping threats to sensitive information, users, and resources. 
SaaS Security options include SaaS Security API (formerly Prisma SaaS) and the SaaS Security Inline add-on.


## Configure SaaS Security on Cortex XSIAM


## Create the Client ID and Client Secret on SaaS Security
In the SaaS Security UI, do the following:
1. Navigate to **Settings** > **External Service**.
2. Click **Add API Client**.
3. Specify a unique name for the API client.
4. Authorize the API client for the required scopes. You use these scopes in the POST request to the /oauth/token endpoint. The Required Scopes are:
    - Log access — Access log files. You can either provide the client log access API or add a syslog receiver.
    - Incident management — Retrieve and change the incident status.
    - Quarantine management — Quarantine assets and restore quarantined assets.
6. Copy the client ID and client secret.<br/>
Tip: Record your API client secret somewhere safe. For security purposes, it’s only shown when you create or reset the API client. If you lose your secret you must reset it, which removes access for any integrations that still use the previous secret.
7. Add the **Client ID** and **Client Secret** to Cortex XSOAR.<br/>
Note: For more information see the [SaaS Security Administrator's Guide](https://docs.paloaltonetworks.com/saas-security/saas-security-admin/saas-security-api/syslog-and-api-integration/api-client-integration/add-your-api-client-app.html)


## Commands
You can execute these commands from the Cortex XSOAR CLI as part of an automation or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.