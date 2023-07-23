## SafeBreach Simulations & Insights

This integration leverages SafeBreach simulation results and insights to remediate malicious indicators that expose your environment to real risks.

  To configure the integration on SafeBreach:

  1. Open the **Navigation bar** → … → **CLI Console**.
  2. Type **config accounts** to get the account id.
  3. Use the id as the **accountId** parameter when configuring the SafeBreach integration in Cortex XSOAR.
  4. Type **config apikeys** to list existing API keys \
  OR \
  Add a new one by typing: **config apikeys add --name <key_name>**
  5. Use the generated API token as **apiKey** parameter when configuring the SafeBreach integration in Cortex XSOAR.
  6. Use your SafeBreach Management URL as the **url** parameter when configuring the SafeBreach integration in Cortex XSOAR.