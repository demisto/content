## RaDark Integration
#### Configuration Instructions:

* Name the instance under the **Name** field.
* Choose **Fetches Incidents**. \
**This will enable the flow of intelligence items to your dedicated dashboard.*
* Keep **Classifier** as N/A.
* Set **Incident Type** as "RaDark".
* Set **Mapper** as "RaDark - Incoming Mapper"
* Enter a valid **API key** from your RaDark monitor:
  * Sign-in to RaDark.
  * On the Discovery panel, click on the user icon located in the lower-left corner of the page.
  * Click **Generate API Key**.
  * Paste the value to XSOAR.
* Determine the **First Time Fetching** field based on the required time frame.
* It’s recommended to untick the following fields: \
**In case these features are needed to you, it’s possible to enable them*
  * **Trust any certificate**
  * **Use system proxy settings**
* Enter a valid **Monitor ID** from your RaDark monitor:
  * Sign-in to RaDark.
  * Copy a 4 digit-string from the URL (monitorId=****).
  * Paste the value to XSOAR.
* Set the **Incidents Fetch Interval**:
  * 00 Hours.
  * 10 Minutes.
* Set the **Max Incidents to Fetch Each Fetching** to 10.
* Based on the **Incident Types** description and your requirements, determine which types should be included in your integration. \
**To remove an incident type, untick it from the automatically generated list presented in the field.*

Before saving, click on **Test** to check proper connectivity to RaDark. \
Click **Save & Exit** to start the fetching process. \
**The first results are expected to appear up to 10 minutes after the configuration process is done.*

---
[View Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/ra-dark)