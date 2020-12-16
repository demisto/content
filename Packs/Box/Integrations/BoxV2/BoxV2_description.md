Manage Box users
This integration was integrated and tested with API version 2.0 of Box v2

## Configure the Box Application to Interface with XSOAR
1. Navigate to [the developer console](https://app.box.com/developers/console) for Box.
2. Click *Create a New App*.
3. Select *Custom App* and when prompted, select *Server Authentication (with JWT)*
4. Enter your desired App Name.
5. In the Configuration menu under Application Access, select *Enterprise*.
6. Under the Advanced Features option, enable both *Perform Actions as Users* and *Generate User Access Tokens*.
7. In the Add and Manage Public Keys section, click *Generate a Public/Private Keypair* and follow the prompts.
8. Next click *Save Changes* un the upper right-hand corner.
9. Lastly navigate to the bottom of the page and select *Download as a JSON*.

Once you have obtained the JSON file, copy and paste its contents into the `Credentials JSON` parameter.

Before testing the integration, please navigate to the General Settings for your app in the developer console and click 
Review and Submit. Your enterprise admin will need to approve the app before your integration will start working.

From the General Settings menu, you may also obtain your *User ID* for the service account.

## Configure Box v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Box v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | insecure | Trust any certificate \(not secure\) | False |
    | credentials_json | Credentials JSON | True |
    | as_user | As User for Fetching Incidents | False |
    | event_type |  | False |
    | default_user | Default User | False |
    | search_user_id | Auto-detect user IDs based on their email address. | False |
    | incidentType | Incident type | False |
    | isFetch | Fetch incidents | False |
    | first_fetch | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;, e.g., 12 hours, 7 days\) | False |
    | max_fetch |  | False |

4. Click **Test** to validate the URLs, token, and connection.