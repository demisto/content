## QintelQWatch Help

To configure an instance of this integration in Cortex XSOAR, you will need to supply your Crosslink Client ID and Client Secret. Refer to the [Integrations Getting Started Page](https://docs.qintel.com/integrations/overview) for details on how to retrieve these tokens.

### Base Setup

Specify the following to configure this instance:

1. Enter your **Client ID** for **Qintel Credentials**
2. Enter your **Client Secret** for **Password**
3. (Optional) Enter a custom QWatch API URL

### Fetch Incidents Setup

To enable fetching of QWatch alerts, configure the following:

1. Select the **Fetch Incidents** radio button
2. (Optional) Set the **Limit number of records per fetch** field which controls how many exposure records will be retrieve for each alert (max: 10000)
3. (Optional) Set the **First fetch time** field which controls how far back the integration looks for alerts the first time it runs. This must be expressed as a date string such as "10 days", "1 year". (default: 3 days, max: 90 days)
4. (Optional) Set the **Incident Fetch Interval** which controls how often XSOAR fetches alerts. It is recommended that the default setting of **6 hours** be used.
5. (Optional) Set the **Default Incident Severity** which controls the base severity for incidents created from QWatch alerts.