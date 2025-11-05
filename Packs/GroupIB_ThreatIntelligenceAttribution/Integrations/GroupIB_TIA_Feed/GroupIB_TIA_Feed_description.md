### Group-IB Threat Intelligence Feed
  
  
- This section explains how to configure the instance of Threat Intelligence Feed in Cortex XSOAR.  
  
1. Open Group-IB TI web interface. (It may be either new interface: [https://tap.group-ib.com](https://tap.group-ib.com))  
2. To generate API key(password):  
2.1. In the new interface: click on your name in the right upper corner -> choose **Profile** option -> switch to **Security and Access** tab -> click **Personal token** -> follow instructions to generate API token.  
3. Your server URL is the same as your TI web interface URL.  
4. Your username is the email that you use to enter in the web interface.   
5. **Important**: When configuring the **Limit (items per request)** parameter, please follow the recommendations for each collection in the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations). Note that this limit applies to all collections in the instance. For optimal performance, consider creating separate integration instances for different collections or groups of collections with similar optimal limit values. The limit determines how many records are fetched in a single API request. For example, if "Number of requests per collection" is 2 and limit is 500, you will get up to 1000 records per collection per fetch cycle (2 requests × 500 records each).  
6. For detailed information about collections, their structure, and available fields, refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).  
7. Don't forget to contact Group-IB to add to allow list your Cortex IP or public IP of a proxy that you are using with Cortex.