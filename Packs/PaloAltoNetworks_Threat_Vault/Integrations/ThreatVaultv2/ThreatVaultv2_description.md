## Get Your API Key
  1. Log in to the [Palo Alto Networks Customer Service Portal](https://support.paloaltonetworks.com/Support) with an account that has Super User privileges.
  2. Select **Assets** and then **API Key Management**.
  3. From the **Select an API key** drop down, select the API key based on the subscription type.
  4. Set your API key in the API key field of the integration configuration
   
See [this documentation](https://support.paloaltonetworks.com/Support) for information about the API key.


### Fetch-incidents
-  Fetch-incidents imports the daily release notes.
-  Set the fetch-interval parameter to once a day. If there is no release notes, the fetch command will try to fetch the next day again.
- When setting the command for the first time, you can set the first-fetch parameter to fetch the release messages at a specified previous time.
