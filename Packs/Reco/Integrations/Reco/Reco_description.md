## Reco
This section explains how to fully configure the instance of Reco Integration in Cortex XSOAR.

### Integration flow
- If "Fetch incidents" is checked, on initialization, XSOAR pulls all Reco alerts as XSOAR incidents. By default, only 7 days back will be fetched. This can be increased upon Integration creation.
There are 2 integration flows:
- If "Do not fetch" is checked, no fetching of Reco alerts by XSOAR will be made.
- You can always choose to push Reco alerts as they happen, by configuring the Reco platform to send new alerts to XSOAR in real-time.

## Steps to follow
- Log in to your Reco portal at your company's Reco instance
- Navigate to **Integrations** in the Reco portal
- Switch to the **API Keys** tab
- Click on **Add API Key** to create a new key
- Provide a descriptive name for the key (e.g., "XSOAR Integration") and click **Add**
- **Important**: Copy and securely save the API key immediately, as it won't be fully visible after you navigate away
- In the Cortex XSOAR Integration instance configuration window:
  - Check **Fetches incidents** radio button
  - Enter your Reco instance URL (e.g., https://domain.reco.ai)
  - Paste the API Key you generated in the Reco portal
  - Select the "Use system proxy settings" checkbox if required
  - Click "Test" button to verify the connection and then click "Done"

- To enable real-time alert streaming from Reco to XSOAR:
  - In the Reco portal, navigate to **Integrations > SOAR**
  - Select "Cortex XSOAR" from the integration options
  - Enter your Cortex XSOAR URL
  - Paste your Cortex XSOAR API Key (in XSOAR portal: Settings -> Integrations -> API Keys -> Get Your Key)
  - Configure any additional alert filters if needed
  - Click "Save" to activate the integration