## Wiz Inc.
This section explains how to fully configure the instance of Wiz Inc. Integration in Cortex XSOAR.
### Integration flow
- If "Fetch incidents" is checked, on initialization, XSOAR pulls all Wiz Issues as XSOAR incidents (this may take time, depending on the number of Issues to pull). By default, only 7 days back will be fetched. This can be increased upon Integration creation.
There Are 2 integration flows:
- If "Do not fetch" is checked, no fetching of Wiz Issues by XSOAR will be made.
- You can always choose to push Wiz Issues as they happen, by configuring the Wiz Automation Rule to send new Issues to XSOAR as they happen. For more info visit the [Cortex XSOAR Integration doc](https://docs.wiz.io/wiz-docs/docs/cortex-xsoar-integration).


## Steps to follow
- Navigate to [service accounts](https://app.wiz.io/settings/service-accounts) to create a Service Account
- Click on Add Service Account
- Scope the permissions to read:issues
- In the Cortex XSOAR Integration instance configuration window:
    - Check **Fetches incidents** radio button
    - Choose **Wiz Classifier** as your classifier
    - Choose Wiz **Mapper Webhook** as your mapper
    - Paste the Service Account ID and Secret from Wiz, or create a set of credentials beforehand.
    - Choose max Issues to fetch (up to 200)
    - Use system proxy settings checkbox 
    - Click "Test" button to make sure the Service Account ID/Secret is valid and then click the "Done" button
    
- If Issue Streaming Type is "Wiz", return back to Wiz Portal and:
    - Navigate to [actions](https://app.wiz.io/settings/automation/actions)
    - Click "Add Action" 
    - Choose "Cortex XSOAR" in the Action drop down
    - Paste Cortex XSOAR host url (so Wiz will know to where to stream Issues)
    - Paste Cortex XSOAR generated API Key (in XSOAR portal: Settings -> Integrations -> API Keys -> Get Your Key)