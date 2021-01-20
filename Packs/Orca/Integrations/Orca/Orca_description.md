## Orca Security
This section explains how to fully configure the instance of Orca Security in Cortex XSOAR.
### Integration flow
- If "Pull Past Alerts" is checked, on initialization, XSOAR pulls all Orca Alerts as XSOAR incidents (this may take time, depending on the number of Alerts to pull)
- After Connecting XSOAR integration on Orca platform, Orca will stream in realtime Alerts to XSOAR (including Alert state changes)


## Steps to follow
- Go to https://app.orcasecurity.io/integrations
- Click on "CONNECT CORTEX XSOAR" 
- Click on "SHOW ORCA API KEY" and copy Api Key
- In the Cortex Xsoar configuration window:
    - Check "Fetches-incidents" radio button
    - Choose Orca Alert - Classification as your classifier
    - Choose Orca Mapper as your mapper
    - Paste the Api Key copied from Orca
    - Choose max fetch (up to 200)
    - Check Trust any certificate (not secure) checkbox
    - Use system proxy settings checkbox
    - Choose if to check "Fetch Existing Alerts" and/or "Also Fetch Informational Alerts" checkboxes
    - Click "Test" button to make sure Api Key is valid and then click the "Done" button
- Return back to Orca Platform and:
    - Paste Cortex XSOAR host url (so Orca will know to where to stream Alerts)
    - Paste Cortex XSOAR generated Api Key (On XSOAR platform: Settings -> Integrations -> API Keys -> Get Your Key)

    





