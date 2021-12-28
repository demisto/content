## SOCRadar Threat Feed
Use the SOCRadar Threat Feed integration to fetch indicators provided by SOCRadar Recommended Collections via SOCRadar Threat Intelligence Feeds.

### How to obtain an API key

To obtain your SOCRadar incident API key please navigate to **Company Settings** page in SOCRadar platform. Under the **API Options** tab retrieve your API key or regenerate a new one. 

After obtaining the SOCRadar incident API key insert it into **API Key** field.

### Rate Limits

To prevent abuse and ensure service stability, all API requests are rate limited. Rate limits specify the maximum number of API calls that can be made in a minute period. The exact number of calls that your application can make per minute varies based on company plan. 

Please bear in mind that you should be careful about the your API key's rate limit especially when you plan to have multiple instances of SOCRadar Threat Feed integration with the same API key. If the instances will require more access to the SOCRadar Threat Feed API than your API key's rate limit then this integration will not work properly due to rate limit exceeding.

### Further Information

For further information please see [SOCRadar Threat Feeds/IOC API](https://platform.socradar.com/docs/api/threat_intel_api/) documentation. 
