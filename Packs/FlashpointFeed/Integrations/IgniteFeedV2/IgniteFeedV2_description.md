## Configure an API account on Flashpoint Ignite

- Login/Register at [Ignite](https://app.flashpoint.io/) platform.
- Click on your profile icon on the top right and select the **API Tokens** option from the dropdown. Alternatively, click on <https://app.flashpoint.io/tokens> to be taken directly to the Generate Token page.
- Click on the **Generate New Token** button.
- Enter the required details (i.e., Token Name, Ignite Username) and click on **Generate Token** button.
- Click on the **Copy Token to Clipboard** button and paste it into the integration, code, or API call. Then, click on the **Save & Close** button to save the generated token and close the token generation page.

## Indicator Reputation

All the fetched indicators are marked with the reputation selected in the **Indicator Reputation** parameter.

**Note:** Do not set the **Indicator Reputation** parameter if you want to set the reputation based on the Ignite score. The score tiers are mapped to the reputations as follows:

| **Ignite Score Tier** | **Indicator Reputation** |
| --- | --- |
| No Score | Unknown |
| Informational | Benign |
| Suspicious | Suspicious |
| Malicious | Malicious |
