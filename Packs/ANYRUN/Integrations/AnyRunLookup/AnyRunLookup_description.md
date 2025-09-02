## ANY.RUN TI Lookup
This section explains how to configure the instance of ANY.RUN TI Lookup in Cortex XSOAR.  
API-KEY from your ANY.RUN account is required.

## Generate API token
* Follow [ANY.RUN Sandbox](https://app.any.run/)
* Profile > API and Limits > Generate > Copy


## Add instance
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ANY.RUN.
3. Click **Add instance** to create and configure a new integration instance.
4. Insert ANY.RUN API-KEY into the **Password** parameter
5. Click **Test** to validate the URLs, token, and connection.


| **Parameter**    | **Description**                                                                                                                                                | **Required** |
|------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| Password         | ANY.RUN API-KEY without prefix                                                                                                                               | True |
| Server's FQDN    | Go to Settings &amp; Info → Settings → Integrations → API Keys. Click Copy API URL. Your FQDN is saved in the clipboard. Inline it without http/https protocol | True |
| XSOAR API-KEY ID | In the API Keys table, locate the ID field. Note your corresponding ID number                                                                                  | True |
| XSOAR API-KEY    | XSOAR API-KEY                                                                                                                                                  | True |