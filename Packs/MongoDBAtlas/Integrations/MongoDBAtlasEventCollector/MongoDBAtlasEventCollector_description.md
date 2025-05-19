## MongoDB Atlas

### To create an API key for a project using the MongoDB Atlas UI:


1. Log in to MongoDB Atlas.
2. Click **Access Manager** in the navigation bar, then click your project.
3. Navigate to **Applications**.
4. Click **Create Application** and then click **API Key**.
5. Enter a **Description** and set **Project Permissions**. For reading alerts and events, you can set the Project Permissions to "Read Only".
6. Copy and save the **Public Key**. The public key acts as the username when making API requests.
7. Copy and save the **Private Key**. The private key acts as the password when making API requests.

    **WARNING**: Save the Private Key securely! The Private Key is only displayed once on this page. Click **Copy** to copy it to your clipboard. Save and secure both the Public and Private Keys.
8. Add an API Access List Entry by clicking **Add Access List Entry**.
9. Enter an IP address from which MongoDB Atlas should accept API requests for this API Key. You can also click **Use Current IP Address** if the host you are using to access MongoDB Atlas will also make API requests using this API Key.
10. Click **Save**.
11. Click **Done**.

### IMPORTANT

You need to allow access from Cortex XSIAM to MongoDB via the UI by adding a Cortex XSIAM IP address:
https://cloud.mongodb.com/v2/<customer_organization_id>#/security/network/accessList 
