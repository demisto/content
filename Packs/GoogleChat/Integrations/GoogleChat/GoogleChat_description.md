## Google Chat Integration Help

In order to use this integration, you need to enter your google chat credentials in the relevant integration instance parameters.

### Space ID param

Go to Google Chat and log in with your Google account [here](https://chat.google.com) > Enter on the required space > display the url (e.g https://mail.google.com/chat/u/0/#chat/space/123456) > the ID after the space is the space ID (e.g 123456).

### Space Key param

Navigate to [here](https://console.cloud.google.com/apis/credentials) > click on the button +CREATE CREDENTIALS > API KEY > copy the created key.

### Service Account JSON param

Navigate to [here](https://console.cloud.google.com/apis/credentials) > click on the button +CREATE CREDENTIALS > Service Accounts > create your service account 
After creating the service account > click on the three dots > select "Manage keys" and then click on "Add key". > Save the downloaded JSON file. Copy the JSON body into the space token parameter.

### Google chat Ask
In order to use the google chat ask it is required to follow the below steps:
1. Enable the Long running instance param.
2. Fill the Listen Port param with an unused port.
3. Fil the App URL with your xsoar url.