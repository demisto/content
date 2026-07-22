## BloodHound Enterprise
BloodHound Enterprise reduces risk in Active Directory and Microsoft Azure environments by continuously identifying and quantifying attack paths that attackers use to escalate privileges. The SpecterOpsBHE integration enables automated retrieval of attack path findings from BloodHound into Cortex XSOAR, streamlining incident creation and investigation.

### Set up a SpecterOpsBHE integration instance

Configure a SpecterOpsBHE integration instance by providing the following mandatory details:
- **(Required)** BloodHound Enterprise Domain (for example, https://example.bloodhoundenterprise.io)
- **(Required)** Token ID 
- **(Required)** Token Key
- Proxy URL
- Proxy URL username
- Proxy URL password
- Finding environment
- Finding category

### Configure the Instance to Fetch Attack Paths from BHE
- **(Required)** Select the **Fetches incidents** checkbox.
- Set the **Incident Type** to SpecterOpsBHE Attack Path.
- **(Required)** Choose the **Incidents Fetch Interval** for fetching attack paths (Default is 10 mins).

### Get the BloodHound Enterprise API Token ID and Token Key
- Log in to your BloodHound Enterprise (BHE) tenant.
- From the left sidebar, navigate to **My Profile**.
- Select **API Key Management**.
- Click **Create Token**.
- Enter a descriptive name for the token and click **Save**.
- Copy and securely store the displayed API Key/ID pair, then click **Close**.
  - The **ID** corresponds to the **Token ID** parameter in the integration configuration.
  - The **Key** corresponds to the **Token Key** parameter in the integration configuration.