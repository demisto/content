## SOCRadar Threat Feed

Use the SOCRadar Threat Feed integration to fetch indicators from SOCRadar Collection Based IOC Feed using collection UUIDs.

### How to obtain an API key

To obtain your SOCRadar API key, navigate to **Settings** page in the SOCRadar platform. Under the **API&Integration -> API Options** page, retrieve your company API key or regenerate a new one.

After obtaining the SOCRadar API key, insert it into the **API Key** field.

### How to get Collection UUIDs

1. Log in to the SOCRadar platform.
2. Navigate to **CTI > Tactical Intelligence > Threat & Premium Feeds** section.
3. Create a custom collection or use existing ones.
4. Copy the collection UUID(s) from the collection detail page.
5. Enter the UUID(s) as a comma-separated list in the **Collection UUIDs** field.

You can add as many collection UUIDs as you need. Each UUID corresponds to a specific threat feed collection on the SOCRadar platform.

### Rate Limits

To prevent abuse and ensure service stability, all API requests are rate limited. Rate limits specify the maximum number of API calls that can be made in a minute period. The exact number of calls that your application can make per minute varies based on company plan.

Please bear in mind that you should be careful about your API key's rate limit, especially when you plan to have multiple instances of SOCRadar Threat Feed integration with the same API key. If the instances will require more access to the SOCRadar Threat Feed API than your API key's rate limit, then this integration will not work properly due to rate limit exceeding.

### Further Information

For further information please see [SOCRadar Threat Feeds/IOC API](https://platform.socradar.com/docs/api/threat_intel_api/) documentation.
