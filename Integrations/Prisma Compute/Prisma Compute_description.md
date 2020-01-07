 Before you can use the Prisma Compute integration on Demisto, there are several configuration steps requeired on the Prisma Cloud Platform.  
 
## Prerequisites
### Configure Demisto alert profile in Prisma Compute:
- Login to your Prisma Compute console
- Navigate to Manage -> Alerts
- Create a new alert profile by clicking the "Add Profile" button
- Choose "Demisto" from the provider list on the left and choose what would you like Demisto to be alerted about from the alert triggers on the right
- Click "Save" to save the alert profile

## Integration setup on Desmito
- Login to Desmito
- Navigate to Settings -> Integrations
- Under "Servers and Services" search for "Prisma Compute" and click "Add Instance" 
- Under "Server and Port" enter the full URL of your Prisma Compute console. 
  If you are not sure, navigate to the Demisto alert profile we have configured on Prisma Compute and click the copy button next to the displayed console URL
- Enter the required credentials to login to Prisma Compute
- Under "Prisma Compute CA Certificate" provide the CA certificate used in Prisma Compute if you wish to use a secure (HTTPS) connection. 
  If you are not sure, like before navigate to the alert pofile on Prisma Compute and use the copy button to copy the certificate. 
Note: if is also possible to check the "Trust any certificate (not secure)" box and avoid providing the CA certificate. However, please note that this method is not recommended due to security concerns
- Make sure to check the "Fetches incidents" checkbox so any new alerts from Prisma Compute will be fetched into Demisto 
