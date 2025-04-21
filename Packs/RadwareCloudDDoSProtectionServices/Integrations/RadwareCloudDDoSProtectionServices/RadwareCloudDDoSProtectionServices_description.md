### Authentication and Authorization
The authentication method used is API Keys
Generating the keys are done via the Cloud Portal | API keys screen.
1. Navigate to Accounts -> API Keys
2. Click on the + icon to create a new API Key
3. Fill out the form in the pane that appears on the right of the display:
4. Click Save. The Add New API Key dialog box will appear:
5. Copy the API Key that appears in the window.
6. Click Confirm to confirm the creation of the new API Key.
Note the following:
• The API Key can be generated and shown only once. Once you get the API key, you will no longer be able to retrieve this key, only create a new key.
• Do not store the key where unauthorized users can access it. Anyone with this API Key will be able to perform any of the actions that the key authorizes.
• The API Key has an expiration date and can be used only until the predefined expiration date.
• API Key uses rules authorization (permissions) and can be used only per the rule it was assigned with, any call that the rule does not permit will result with access denied error code.

All Rest API calls are limited to your Portal Account, and you can use it only on your account data. All API keys require a unique ID that identifies the account. This account ID is found in the Cloud Services portal: navigate to Accounts -> API Keys, click on the Account ID Details button and the Account ID will be listed there; each service has its own unique ID. Ensure you are using the correct one for the API you are working with.
s are limited to your Portal Account, and you can use it only on your account data. All API keys require a unique ID that identifies the account. This account ID is found in the Cloud Services portal: navigate to Accounts -> API Keys, click **Account ID Details** and the Account ID will be listed there. Each service has its own unique ID. Ensure you are using the correct one for the API you are working with.