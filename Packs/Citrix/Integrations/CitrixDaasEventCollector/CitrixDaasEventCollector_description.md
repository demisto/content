In order to access Citrix DaaS, the Citrix Cloud environment must be properly configured.

## Configuration steps

### Prerequisites

**Get Access to Citrix Cloud**

Sign up for a free Citrix Cloud account, or log in to Citrix Cloud.

Citrix Cloud API Access with Service Principals
To create and set up a service principal:

1. Open the Citrix Cloud console and click the menu icon in the upper-left corner.

2. Select **Identity and Access Management** > **API Access** > **Service principals** > **Create service principal** and follow the steps to complete the setup.
    If these options do not appear, you may not have sufficient permissions to manage service principals. Contact your administrator to get the required full access permission.

3. Add the credentials to your secret management tool as the secret is only displayed once.

4. Get the Customer ID (a required parameter for the Citrix-CustomerId header).
    a. Log in to the [Citrix Cloud](https://onboarding.cloud.com).
    b. From the menu, select **Identity and Access Management**.
    c. Click the **API Access** tab. You can see the customer ID in the description above the **Create Client** button.

### Locate your tenant's Citrix Cloud ID

1. Log in to https://citrix.cloud.com
2. If you have access to multiple tenants, select the relevant one from the list of tenant names and Citrix Cloud IDs and sign in to it.  
    The tenant's Citrix Cloud ID (for example, ctxtsnaxa) is displayed at the top right corner of the screen.
