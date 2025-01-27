
The Generic API Collector allows you to ingest data from any API endpoint into XSIAM. By configuring this collector, you can gather data from various systems and bring it into the XSIAM ecosystem for better analysis and correlation. Please note that this integration is currently in Beta, and as such, it may be subject to future changes.
Configuration Guide
To successfully set up the Generic API Collector, you need to provide the following mandatory configuration fields:
1. Vendor and Product
   This information is required to define the dataset name for storing the collected data. It is crucial that the correct
   Vendor and Product values are added so that data can be ingested and categorized properly.
2. Server URL
   This is the URL of the server to which the collector will connect to gather data. Ensure that the URL is accessible and correct to enable proper data retrieval.
3. API Endpoint
   Provide the specific API endpoint that the collector should reach out to. This endpoint will determine which data is retrieved by the collector.
4. Authentication Type
   You must specify the authentication method required by the server. The supported authentication types include:
   Basic Authentication (username and password)
   Token Based Authentication (Token key)
   Bearer Token (API key)
   OAuth2 (for more secure authentication)
   No Authentication (for publicly accessible data)
5. HTTP Method
   Specify the HTTP method the collector should use to reach the API endpoint. The supported methods are:
   GET (to retrieve information)
   POST (if the endpoint requires sending specific parameters to retrieve data)
   Additional Information
   Once the collector is configured, it will begin to collect data periodically as per your configuration. The collected data will be stored in a dataset defined by the Vendor and Product values provided.
   You can use this data to create alerts, run queries, and generate reports within XSIAM.
   As this integration is in Beta, please provide feedback for improvements or report any issues to the development team.