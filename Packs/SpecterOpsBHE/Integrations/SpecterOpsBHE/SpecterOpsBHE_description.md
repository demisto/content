## BloodHound Enterprise
BloodHound Enterprise is a powerful tool for reducing risk in Active Directory and Microsoft Azure environments. This integration enables automated retrieval of attack path findings from BloodHound into Cortex XSOAR, streamlining incident creation and investigation.

### Details for BloodHound Enterprise workflow:

Please configure the instance by providing following mandatory details:
- **(Required)** BloodHound Enterprise Domain ( eg. https://example.bloodhoundenterprise.io)
- **(Required)** Token ID 
- **(Required)** Token Key
- Proxy URL
- Proxy URL Username
- Proxy URL Password
- Finding Environment
- Finding category

### To Fetch Attack Paths from BHE:
- **(Required)** Please select the Fetches incidents checkbox.
- Please set the Incident Type to “SpecterOpsBHE Attack Path”.
- **(Required)** Incidents Fetch Interval - Please choose a time interval for fetching attack paths (Default is 10 mins) .

### Steps to get BloodHound Enterprise API Token ID and Token Key
- Log in to your BloodHound Enterprise (BHE) tenant.
- From the left sidebar, navigate to My Profile.
- Select API Key Management.
- Click Create Token.
- Enter a descriptive name for the token and click Save.
- Copy and securely store the displayed API Key/ID pair, then click Close.


