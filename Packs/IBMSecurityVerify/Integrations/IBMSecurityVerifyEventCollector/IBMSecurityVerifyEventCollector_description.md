## IBM Security Verify Event Collector

The integration is designed for customers using IBM Security Verify to collect and analyze security events across their organization's network. By connecting to the IBM Security Verify Event Collector, organizations can effectively monitor, manage, and respond to potential security incidents in real-time.

The API Credentials include a combination of **Client ID** and **Client Secret**. These credentials are equivalent to a username and password and should be handled with care. It is strongly recommended to keep the **Client ID** and **Client Secret** secure and not share them with unauthorized parties to prevent potential security breaches.

To obtain the **Client ID** and **Client Secret**, follow these steps:

1. **Log in to the IBM Security Verify UI**.
2. **Click on the profile icon** located at the top right corner of the interface.
3. **Select "Switch to admin"** to access administrative settings.
4. Navigate to **Security > API Access**.
5. Click on **Add API Client** to generate the necessary credentials.
6. After clicking on **Add API Client**, make sure to assign the following permissions to the API client:
   - **Manage reports**
   - **Read reports**

![Creating an API Client](https://github.com/demisto/content-assets/raw/master/Assets/IBMSecurityVerify/Creating_an_API_Client.gif)


By following these steps, you will ensure that you are in the correct administrative mode before accessing the API credentials, which are essential for connecting and interacting with the IBM Security Verify Event Collector. Keeping the **Client ID** and **Client Secret** secure is critical to preventing unauthorized access and potential security breaches.
