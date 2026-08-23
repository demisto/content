## Box Event Collector

Collect events from Box's logs using the [events endpoint](https://developer.box.com/reference/get-events/) with enterprise login.

### Obtaining the Credentials JSON

1. **Ensure Admin Privileges**: The user making the API call must have admin privileges.
2. **Enable the Required Scope**: The Box application must have the **Manage enterprise properties** scope checked.
3. **Create a JWT App**: Create a JWT (Server Authentication) application in Box to obtain the credentials. Follow the [Box V2 guide](https://xsoar.pan.dev/docs/reference/integrations/box-v2#configure-the-box-application-to-interface-with-xsoar) to configure the app.
4. **Provide the Credentials JSON**: Paste the JSON configuration generated for the app into the **Credentials JSON** parameter.
