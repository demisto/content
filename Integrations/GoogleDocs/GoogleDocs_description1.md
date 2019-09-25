 ##Creating a Service Account
1. Go to the [Google documentation](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount) and follow the procedure in the Creating a Service Account section. After you create a service account, a Service Account Private Key file is downloaded. You will need this file when configuring an instance of the integration.
2. Grant the Compute Admin permission to the Service Account to enable the Service Account to perform certain Google Cloud API commands.
3. In Demisto, configure an instance of the Google Cloud Compute integration. For the Service Account Private Key parameter, add the Service Account Private Key file contents (JSON).


##Create document command:

Creates a blank document. It's not possible to pass body arguments.
That's a limitation by the google api. For inserting content you should the update document command.

##Update document command:  
Update a document based upon it's ID. Actions to perform are passed in the following format:

* action1{param1,param2,...};action2{param1,param2,...}...

It is then converted to:  
* action1(param1,param2,...), action2(param1,param2),...


where action1 is the function name to be called and param1 and param2 are the parameters  

For example:  
insertText(5,hello)  
insertTable(5,7,7);insertText(5,hello)

