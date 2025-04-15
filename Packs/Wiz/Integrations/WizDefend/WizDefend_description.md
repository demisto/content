## Wiz Inc.
This section explains how to fully configure the instance of Wiz Defend Integration in Cortex XSOAR.
### Integration flow
- If "Fetch incidents" is checked, on initialization, XSOAR pulls all Wiz Detections as XSOAR incidents (this may take time, depending on the number of Issues to pull). By default, only 7 days back will be fetched. This can be increased upon Integration creation.


## Steps to follow
- In Wiz, navigate to [Settings > Integrations ↗](https://app.wiz.io/settings/automation/integrations) then click **Add Integration**
  - Under the required category or by using the search bar, select the third-party tool.
  - On the New Integration page
      - For **Name** —Enter a meaningful name.
      - For **Scope** —Set the Project's scope.
  - Click **Add Integration**. A new service account is created.
  - Copy and save the **client ID**, **client secret**, **API Endpoint URL** and **Authenticate API URL** for the next steps.
- In the Cortex XSOAR Integration instance configuration window:
    - Check **Fetches incidents** radio button
    - Choose **Wiz Classifier** as your classifier
    - Choose Wiz **Mapper Webhook** as your mapper
    - Paste the credentials obtained from Wiz in the previous step.
