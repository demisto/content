## Configure an instance for ExtraHop Reveal(x)
1. Enter a unique **Name** for the instance.
2. Enter the **URL** of the ExtraHop system this instance will connect to.
3. If configuring an instance for ExtraHop Reveal(x) 360, select **On Cloud** and enter the **Client ID** and **Client Secret** generated from your ExtraHop system.
4. If configuring an instance for ExtraHop Reveal(x) Enterprise, unselect **On Cloud** and enter the **API Key** generated from your ExtraHop system.
5. Complete the following configuration options:

| **Parameter** | **Description** |
| --- | --- |
| Fetches incidents | Select to enable this instance to fetch detection events. Otherwise, select **Do not fetch**. Each API call fetches a maximum of 200 detection events. |
| Classifier | Specifies the type of incident to be created for detection events ingested by this instance. |
| Incident type | Specifies the type of incident to be created for detection events ingested by this instance if a **Classifier** is not specified. |
| Mapper | Specifies how detection events ingested by this instance are mapped to Cortex XSOAR incident fields. |
| Trust any certificate (not secure) | Specifies whether to allow connections without verifying SSL certificate's validity. |
| Use system proxy settings | Specifies whether to use XSOAR system proxy settings to connect to the API. |
| First fetch time | Specifies the beginning timestamp from which to start fetching detection events. |
| Incidents Fetch Interval | Specifies how often the instance fetches detection events. Because each API call fetches a maximum of 200 detection events, we recommend specifying one minute intervals to fetch all detection events. |
| Advanced Filter | Applies a filter to the list of detections or metrics based on a JSON-specific query. |
| Do not use by default | Select to disable running commands through the Cortex XSOAR CLI on this instance of the integration. |
| Log Level | Specifies the level of logging to enable for this instance of the integration. |
| Run on | Specifies whether to run the instance of the integration on a single engine. |
    
6. Click **Test** to validate the URL, credentials, and connection.