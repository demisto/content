### Get a RadwareCloudDDos API Key

Users with the “Admin Users” role can generate up to 10 API Keys that will be used by the API. Generating the keys are done via the Cloud Portal | API keys screen
Note the following:
- The API Key can be generated and shown only once. Once you get the API key, you will no longer be able to retrieve this key, only create a new key.
- Do not store the key where unauthorized users can access it. Anyone with this API Key will be able to perform any of the actions that the key authorizes.
- The API Key has an expiration date and can be used only until the predefined expiration date.
- API Key uses rules authorization (permissions) and can be used only per the rule it was assigned with, any call that the rule does not permit will result with access denied error code.

## Account/Service ID
All Rest API calls are limited to your Portal Account, and you can use it only on your account data. All API keys require a unique ID that identifies the account. This account ID is found in the Cloud Services portal: navigate to Accounts -> API Keys, click on the Account ID Details button and the Account ID will be listed there; each service has its own unique ID. Ensure you are using the correct one for the API you are working with.
