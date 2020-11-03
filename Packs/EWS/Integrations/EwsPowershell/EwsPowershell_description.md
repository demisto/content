<<<<<<< HEAD
To allow access to EWS extended, an administrator has to approve the Demisto app using an device-code flow, by running the following commands:
    1. Fill the following integration parameters:
        a. Exchange Web Services (EWS) URI.
        b. Search and Compliance URI.
        c. Proxy if needed.
        d. Trust any certificated if needed.
    2. `!ews-start-auth` - You  will be prompt to to open the page https://microsoft.com/devicelogin and enter generated code.
    3. `!ews-complete-auth` - Demisto will collect the credentials which created after your consent in step 1.
    4. `!ews-test-auth` - Test if uthorization finished successfully.

After completing all the follow steps, Your integration is succefully configured.
=======
## Hello World
- This section explains how to configure the instance of HelloWorld in Cortex XSOAR.
- You can use the following API Key: `43ea9b2d-4998-43a6-ae91-aba62a26868c`
>>>>>>> 7fb2b7fefaeace4f7ad069d8775178a57538f5a7
