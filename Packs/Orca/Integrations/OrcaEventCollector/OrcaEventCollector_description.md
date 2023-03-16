## Orca Security
This section explains how to fully configure the instance of Orca Security in Cortex XSOAR.
### Integration flow
XSOAR will query for Orca Alerts/ Alert updates every 1 minute 


## Steps to follow
1. In Orca, navigate to **Settings > Users & Permissions > API** and click **Create API Token**.
2. Enter or select the following criteria:
   - Enter the token name
   - Enter a description
   - Mark or clear Never Expire: Never expire is marked by default. The expiration date can be configured by clearing the checkbox.
   - Mark or clear Public: You can define public tokens that are not linked to a specific user. The token is scoped according to the user that created them but can still be used if the user is removed from the organization.
     Select a role. 
   - Select the accounts that you want users to have access to 
3. Click **Create Token**.
4. Copy the token and click Continue
5. In the Cortex XSIAM configuration window:
    - Paste the Api Token copied from Orca.
    - Enter the server url.
    - Enter the First fetch time (default is 3 days)
    - Choose max fetch (up to 1000)
    - Check Trust any certificate (not secure) checkbox
    - Use system proxy settings checkbox
   - Check "Fetches events" radio button
   - Click "Test" button to make sure Api Key is valid and then click the "Done" button