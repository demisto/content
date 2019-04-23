Create a Service Account
Follow the instructions [here](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#creatinganaccount) in the "Creating a Service Account" section.
Grant Permissions
In order for the Service Account to carry out certain Google cloud API commands, it is required that you grant the Service Account roles with the necessary permissions. The nex screens after creating the srvice account will be Service account permissions you will need to give you account the role of "Compute Engine -> Compute Admin".
Setup Integration Instance
All the integration parameters to set up an instance are in the Service Account Credentials File that was downloaded to your machine in step 1 when you created a Service Account. Copy each value to its matching integration parameter without its surrounding quotes.