## Palo Alto Networks Enterprise DLP
Palo Alto Networks Enterprise DLP discovers and protects company data across every data channel and repository. Integrated Enterprise DLP enables data protection and compliance everywhere without complexity.

### Setup
Go to the `Settings` tab on the DLP web interface. 
Choose `Alerts` on the left menu. Follow all the steps under `Setup Instructions`.
Make sure the toggle at the bottom is switched on.

### Authentication
There are 2 methods to authenticate.
1. Use Enterprise DLP API **Access Token** and **Refresh Token**.
2. Use Cortex XSOAR's credentials store with a **Client ID** and **Client Secret** as the `username` and `password` in case you are using Enterprise DLP through a SASE platform.

For more information on how to create the above credentials, see [the documentation](https://docs.paloaltonetworks.com/enterprise-dlp/enterprise-dlp-admin/configure-enterprise-dlp/configure-exact-data-matching/configure-connectivity-to-the-dlp-cloud-service).
