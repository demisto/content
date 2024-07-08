## Google Chat Integration Help

In order to use this integration, you need to enter your Zoom credentials in the relevant integration instance parameters.

### Redirect user's response to Xsoar

Navigate to [here](https://console.cloud.google.com/apis/credentials) > click on the button +CREATE CREDENTIALS > OAuth client ID > under Authorized redirect URIs insert your XSOAR url
#### And
Navigate to [here](https://console.cloud.google.com/apis/dashboard) > Click on the +ENABLE APIS AND SERVICES > choose GOOGLE CHAT API > go to configuration > 
under Connection settings click on App URL > and set the App URL as followed <your-xsoar-url>/instance/execute/<name-og-the-instance> 
### Space ID param

Go to Google Chat and log in with your Google account [here](https://chat.google.com) > Enter on the required space > display the url (e.g https://mail.google.com/chat/u/0/#chat/space/123456) > the ID after the space is the space ID (e.g 123456)

### Space Key param

Navigate to [here](https://console.cloud.google.com/apis/credentials) > click on the button +CREATE CREDENTIALS > API KEY > copy the created key

### Service Account JSON param

Navigate to [here](https://console.cloud.google.com/apis/credentials) > click on the button +CREATE CREDENTIALS > Service Accounts > create your service account 
After creating the service account > click on the three dots > select "Manage keys" and then click on "Add key". > Save the downloaded JSON file. Copy the JSON body into the space token parameter.

### Add permission to access the API

- Navigate to [here](https://console.cloud.google.com/apis/credentials/consent) > choose the user type > go to scope section > ADD OR REMOVE SCOPES > add all endpoints related to Google Chat API