Configure an API account on Flashpoint
-------------------------------
 - Login/Register at [Flashpoint](https://fp.tools/) platform. 
 - Navigate to API & Integrations and select the **Manage API Tokens**.
 - Click on "GENERATE TOKEN" button and enter the required details to generate
    token. (i.e- token label,username and password)
 - Click on GENERATE button once all required data are entered.


Configure Flashpoint instance on Demisto
-------------------------------

1.  Navigate to **Settings** \> **Integrations**  \> **Servers &
    Services**.
2.  Search for Flashpoint.
3.  Click **Add instance** to create and configure a new integration
    instance.
    -   **Name**: a textual name for the integration instance.
    -   **URL**: URL of the Flashpoint platform (default is https://fp.tools)
    -   **API Key**: The API key generated using above steps
    -   **Trust any certificate (not secure)**: Whether to trust any SSL certificate while communicating with Flashpoint 
    -   **Use system proxy settings**: Whether to use system proxy settings

4.  Click **Test** to validate the new instance.
