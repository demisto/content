## MongoDB Atlas Help

### To create an API key for a project using the MongoDB Atlas UI:

1. Navigate to the Access Manager page for your project.
If it is not already displayed, select the organization that contains your desired project from the  Organizations menu in the navigation bar.
2. Select your desired project from the list of projects in the Projects page.
3. Click the vertical ellipsis () next to your project name in the upper left corner and select Project Settings.
4. Click Access Manager in the navigation bar, then click your project.
5. Click Create API Key.
6. Enter the API Key Information.
7. On the Create API Key page:
    - Enter a description.
    - In the Project Permissions menu, select the new role or roles for the API key.
    - Click **Next**.
    - Copy and save the Public Key. The public key acts as the username when making API requests.
    - Copy and save the Private Key. The private key acts as the password when making API requests.
    - *WARNING* - Save the Private Key! The Private Key is only shown once on this page. Click **Copy** to add the Private Key to the clipboard. Save and secure both the Public and Private Keys.
9. Add an API Access List Entry by clicking **Add Access List Entry**.
10. Enter an IP address from which you want MongoDB Atlas to accept API requests for this API Key. You can also click **Use Current IP Address** if the host you are using to access MongoDB Atlas will also make API requests using this API Key.
11. Click **Save**.
12. Click **Done**.

### IMPORTANT

You need to allow access from Cortex XSIAM to MongoDB via the UI by adding a Cortex XSIAM IP address:
https://cloud.mongodb.com/v2/<customer_organization_id>#/security/network/accessList 