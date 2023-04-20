## Orca Security
This section explains how to fully configure the instance of Orca Security in Cortex XSOAR.
### Integration flow
XSOAR will query for Orca Alerts/ Alert updates every 1 minute 


## Steps to follow
- Go to https://app.orcasecurity.io/integrations
- Click on "CONNECT CORTEX XSOAR" 
- Click on "Generate a new token" and copy Api Token
- In the Cortex Xsoar configuration window:
    - Check "Fetches-incidents" radio button
    - Choose Orca Alert - Classification as your classifier
    - Choose Orca Mapper as your mapper
    - Paste the Api Token copied from Orca
    - Choose max fetch (up to 200)
    - Check Trust any certificate (not secure) checkbox
    - Use system proxy settings checkbox
    - Choose if to check "Fetch Existing Alerts" and/or "Also Fetch Informational Alerts" checkboxes
    - Click "Test" button to make sure Api Key is valid and then click the "Done" button
    





