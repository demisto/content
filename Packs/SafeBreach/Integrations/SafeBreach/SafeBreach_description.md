### SafeBreach Commands from XSOAR

This package enables organizations to integrate SafeBreach into the enterprise workflows with commands for managing tests, insight indicators, simulators and deployments, users, API keys, integration issues, and more.


### To configure the integration on SafeBreach:
1. Open the Navigation bar → … → CLI Console.
2. Type “config accounts” to get the account ID.
3. Use the IDas the accountId parameter when configuring the SafeBreach integration in Cortex XSOAR.
4. Type “config apikeys” to list existing API keys. OR
 Add a new API key by typing: “config apikeys add --name <key_name>”
5. Use the generated API token as apiKey parameter when configuring the SafeBreach integration in Cortex XSOAR.
6. Use your SafeBreach Management URL as the url parameter when configuring the SafeBreach integration in Cortex XSOAR.



### What does this package do?
This package allows your organization to operate SafeBreach through XSOAR using commands for operations, such as managing tests, insight indicators, simulators and deployments, users, API keys, integration issues, and more.
