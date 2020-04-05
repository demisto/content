## SafeBreach Simulations & Insights
  This integration allows to leverage SafeBreach simulation results and insights to automatically remediate multiple malicious indicators with immediate threat to your environment.

  To configure the integration on SafeBreach:
  1. Open the **Navigation bar** → … → **CLI Console**
  2. Type **config accounts** to find out the account id
  3. Use the id as the **accountId** parameter in Demisto configuration
  4. Type **config apikeys** to list existing API keys \
  OR \
  Add a new one by typing: **config apikeys add --name <key_name>**
  5. Use the generated API token as **apiKey** parameter in Demisto configuration
  6. Use your SafeBreach Management URL as the **url** parameter in Demisto configuration