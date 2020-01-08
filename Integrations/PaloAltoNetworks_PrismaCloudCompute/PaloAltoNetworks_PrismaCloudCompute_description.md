Before you can use the Prisma Cloud Compute integration on Demisto, there are several configuration steps requeired on the Prisma Cloud Platform.  
 
## Prerequisites
### Configure Demisto alert profile in Prisma Cloud Compute:
- Login to your Prisma Cloud Compute console.
- Navigate to Manage -> Alerts.
- Create a new alert profile by clicking the "Add Profile" button.
- Choose "Demisto" from the provider list on the left and choose what would you like Demisto to be alerted about from the alert triggers on the right.
- Click "Save" to save the alert profile.

## Integration setup on Desmito
- Login to Desmito.
- Navigate to Settings -> Integrations.
- Under "Servers and Services" search for "Prisma Cloud Compute" and click "Add Instance". 
- From the Demisto alert profile you have created on the previous step, copy the URL using the copy button and paste it 
  under "Prisma Cloud Compute Full URL". 
- Enter the required credentials to login to Prisma Cloud Compute.
- If you are using Prisma Cloud Compute on-premise, you should add CA certificate used on Prisma Cloud Compute to establish a secured HTTPS connection.
  Please find the required CA certificate on the Demisto alert profile as before and fill it in the "Prisma Cloud Compute CA Certificate" box. 
Note: it is also possible to check the "Trust any certificate (not secure)" box and avoid providing the CA certificate. However, please note that this method is not recommended due to security concerns
- Make sure to check the "Fetches incidents" checkbox so any new alerts from Prisma Cloud Compute will be fetched into Demisto. 
