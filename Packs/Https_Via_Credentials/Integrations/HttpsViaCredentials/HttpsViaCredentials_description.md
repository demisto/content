1. Ensure you have valid credentials stored in XSOAR under the Credentials tab.
2. When creating a new instance of the http request instance, use label called 'Credentials' and select the credentials you wish to use.
3. When using within a playbook, you will be choosing the http_request command. 
You MUST supply a valid url, method of request, and authentication type for the request to work. If the method of authentication isn't supplied, please use the 'N/A' option and use the 'headers' argument to supply proper means of authentication.