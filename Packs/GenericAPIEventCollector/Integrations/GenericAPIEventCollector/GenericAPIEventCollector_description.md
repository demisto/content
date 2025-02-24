
The Generic API Event Collector allows you to ingest data from any API endpoint into Cortex.
By configuring this collector, you can gather data from various systems and bring it into the Cortex ecosystem for better analysis and correlation.
Please note that this integration is currently in Beta, and as such, it may be subject to future changes.
# Configuration Guide
To successfully set up the Generic API Event Collector, you need to provide the following mandatory configuration fields:
1. Vendor and Product
   This information is required to define the dataset name for storing the collected data. It is crucial that the correct
   Vendor and Product values are added so that data can be ingested and categorized properly. The name of the ingested dataset will be in the format: `{Vendor}_{Product}_generic_raw`
2. Server URL
   This is the URL of the server to which the collector will connect to gather data. Ensure that the URL is accessible and correct to enable proper data retrieval.
3. API Endpoint
   The specific API endpoint that the collector should reach out to.
   This endpoint will determine which data is retrieved by the collector.
4. Authentication Type
   The authentication method required by the server must be specified. The supported authentication types include:
   - Basic Authentication (username and password)
   - Token Based Authentication (Token key)
   - Bearer Token (API key)
   - Raw Token (for custom token-based authentication)
   - No Authorization (for publicly accessible data)
5. HTTP Method
   Specify the HTTP method the collector should use to reach the API endpoint. The supported methods are:
   - GET (to retrieve information)
   - POST (if the endpoint requires sending specific parameters to retrieve data)

# Additional Information
Once the collector is configured, it will begin to collect data periodically as per your configuration.
The collected data will be stored in a dataset defined by the Vendor and Product values provided.
You can use this data to create alerts, run queries, and generate reports within Cortex.

## Disclaimer
Note: This is a beta integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
