### Steps to get the ***Access Key*** for the API authentication

#### On the FortiAuthenticator WebUI, create a new user for API or edit an existing one.

Under the **Authentication** > **User Management**, edit the user: 

1. Under **User Role**, select **Administrator**.
2. Enable **Web service access**.
3. Under **User Information**, please ensure there's a valid **email** address.
4. Click **OK** to save the details.
5. The **Web Service Access Secret Key** used to authenticate to the API is emailed to the user.

#### Note
Ensure email routing is working (i.e. the FortiAuthenticator is able to send mail) beforehand as the API Key will be delivered by email.
