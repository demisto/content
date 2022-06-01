## SOCRadar Incidents
Use the SOCRadar Incidents integration to fetch incidents from SOCRadar and take appropriate actions over those incidents.
***
### How to obtain an API key

To obtain your SOCRadar incident API key please navigate to **Company Settings** page in SOCRadar platform. Under the **API Options** tab retrieve your API key or regenerate a new one. 

After obtaining the SOCRadar incident API key insert it into **API Key** field.

### How to configure
- ***Company ID***: Every incident in SOCRadar associates with a company. Insert the SOCRadar company ID of the company that you want to obtain incidents.
- ***Maximum number of incidents to fetch*** (Default is *20*): Insert the maximum number of incidents to fetch from SOCRadar in each fetching period. (Limited to max 50)
- ***Resolution Status*** (Default is *All*): Resolution status of incidents to fetch. (All, Resolved, Not Resolved)
- ***FP Status*** (Default is *All*): False positive status of incidents to fetch. (All, FP, Not FP)
- ***Incident Main Type***: Main type of incidents to fetch. All incident main types can be found under **Incident Summary & Options** tab in your company's settings page within SOCRadar platform. Leave it blank to fetch all main type of incidents.
- ***Incident Sub Type***: Sub type of incidents to fetch. All incident sub types can be found under **Incident Summary & Options** tab in your company's settings page within SOCRadar platform. Leave it blank to fetch all sub type of incidents.

### Rate Limits

To prevent abuse and ensure service stability, all API requests are rate limited. Rate limits specify the maximum number of API calls that can be made in a minute period. The exact number of calls that your application can make per minute varies based on company plan. 

Please bear in mind that you should be careful about the your API key's rate limit especially when you plan to have multiple instances of SOCRadar incident integration with the same API key. If the instances will require more access to the SOCRadar incident API than your API key's rate limit then this integration will not work properly due to rate limit exceeding.

### Further Information

For further information about the usage and rate limitation of SOCRadar incident API please see [SOCRadar Incident API](https://platform.socradar.com/docs/api/incident_api/) documentation.