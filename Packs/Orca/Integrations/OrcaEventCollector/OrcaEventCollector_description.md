## Orca Security
This section explains how to fully configure the instance of Orca Security in Cortex XSIAM.

## Steps to follow to configure orca Security
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
    - Enter the server url. For more information about the different regions and ips [click](https://docs.orcasecurity.io/docs/regions-and-ips)
    - Paste the Api Token copied from Orca.
    - Enter the First fetch time (default is 3 days)
    - Choose max fetch (up to 1000)
    - Check Trust any certificate (not secure) checkbox
    - Use system proxy settings checkbox
    - Check "Fetches events" radio button
    - Click "Test" button to make sure Api Key is valid and then click the "Done" button

For more information about managing api tokens in Orca security [click](https://docs.orcasecurity.io/v1/docs/managing-api-tokens)