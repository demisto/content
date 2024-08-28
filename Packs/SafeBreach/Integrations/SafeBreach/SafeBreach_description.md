### SafeBreach Commands from XSOAR

This package enables organizations to integrate SafeBreach into the enterprise workflows with commands for managing tests, insight indicators, simulators and deployments, users, API keys, integration issues, and more.


### To configure the integration on SafeBreach:

1. From the main menu, click **Settings > API Keys**.
2. Retrive account ID from this screen and use as the accountId parameter when configuring the SafeBreach integration in Cortex XSOAR.
3. Click **Create API Key**.  
    The Create API Key pop-up is displayed.
4. Provide a name for the API key and optionally include a description, and then click CreateCreate.  
    The API key is created and displayed.  
    **Note**: Currently API keys have admin privileges.  
    **Important**: You will not have access to the key through SafeBreach Management again. It is
each user’s responsibility to store the keys safely after creating them.
5. Use the generated API token as apiKey parameter when configuring the SafeBreach integration in Cortex XSOAR.
6. Use your SafeBreach Management URL as the url parameter when configuring the SafeBreach integration in Cortex XSOAR.



### What does this package do?
This package allows your organization to operate SafeBreach through XSOAR using commands for operations, such as managing tests, insight indicators, simulators and deployments, users, API keys, integration issues, and more.
