## Trend Micro Email Security Event Collector
Use this integration to collect operation logs from Trend Micro Email Security.
You can also use the ***trend-micro-get-events*** command to manually collect events.

In order to use this integration, you need to enter your Trend Micro Email Security credentials in the relevant integration instance parameters.

### For the service URL parameter, attention to the following table:

The value of service URL varies according to your location:
    | **Location** | **Service Root URL** |
    | --- | --- |
    | North America, Latin America and Asia Pacific | api.tmes.trendmicro.com |
    | Europe, the Middle East and Africa | api.tmes.trendmicro.eu |
    | Australia and New Zealand | api.tmes-anz.trendmicro.com |
    | Japan | api.tmems-jp.trendmicro.com |
    | Singapore | api.tmes-sg.trendmicro.com |
    | India | api.tmes-in.trendmicro.com |


### For API Key parameter, attention to the following:

1. Go to Administration > Service Integration.
2. On the API Access tab, click Add to generate a key.
The API Key is the global unique identifier for your application to authenticate its access to Trend Micro Email Security. It must be used together with the administrator account that created it. A new API Key is enabled by default.

For more information about API Key see [here](https://docs.trendmicro.com/en-us/enterprise/trend-micro-email-security-online-help/configuring-administ/service-integration/api-access/obtaining-an-api-key.aspx)



### Max Fetch
Note: There are three types of fetches that the integration fetches, when the max fetch parameter is set to 1000 then 1000 logs will be retrieved from each type so that a total of 3000 logs can be retrieved.

