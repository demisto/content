### Group-IB Threat Intelligence
  
  
- This section explains how to configure the instance of Threat Intelligence in Cortex XSOAR.  
  
1. Open Group-IB TI web interface. (It may be either new interface: [https://tap.group-ib.com](https://tap.group-ib.com))  
2. To generate API key(password):  
2.1. In the new interface: click on your name in the right upper corner -> choose **Profile** option -> switch to **Security and Access** tab -> click **Personal token** -> follow instructions to generate API token.  
3. Your server URL is the same as your TI web interface URL.  
4. Your username is the email that you use to enter in the web interface.
5. **Important**: When configuring the **Limit (items per request)** parameter, please follow the recommendations for each collection in the [official API Limitations documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FStarting%20Guide%2FAPI%20Limitations%2FAPI%20Limitations). Note that this limit applies to all collections in the instance. For optimal performance, consider creating separate integration instances for different collections or groups of collections with similar optimal limit values. The limit determines how many records are fetched in a single API request. For example, if "Number of requests per collection" is 2 and limit is 500, you will get up to 1000 records per collection per fetch cycle (2 requests × 500 records each).  
6. **Note**: The filters "Include combolist type in data", "Include unique type in data", and "Enable filter 'Probable Corporate Access'" apply **only** to the `compromised/account_group` collection and have no effect on other collections.  
7. For detailed information about collections, their structure, and available fields, refer to the [official Collections Details documentation](https://tap.group-ib.com/hc/api?scope=integrations&q=en%2FIntegrations%2FCollections%20Info%2FCollections%20Details%2FCollections%20Details).  
8. Set classifier and mapper with Group-IB Threat Intelligence classifier and mapper or with our own if you want so.
9. Go to Settings->Integrations->Pre-Processing Rules and set up the pre-processing rule:
* Set up conditions: "gibid Is not empty (General)" and "Type Doesn't equal(String) GIB Data Breach".
* Action: "Run a script".
* Script: "GIBIncidentUpdate" (will recreate closed incidents if they get an update, in other cases will update the existing one) or "GIBIncidentUpdateIncludingClosed"(will only update incidents). 
10. Don't forget to contact Group-IB to add to allow list your Cortex IP or public IP of a proxy that you are using with Cortex.