## ANY.RUN TI Feed
This section explains how to configure the instance of ANY.RUN TI Feed in Cortex XSOAR.  
A Basic auth token from your ANY.RUN account is required.

## Generate Basic auth token
Please Contact your ANY.RUN account manager to get your basic token 

## Add instance
1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ANY.RUN.
3. Click **Add instance** to create and configure a new integration instance.
4. Insert ANY.RUN TI Feed Basic Token into the **Password** parameter
5. Click **Test** to validate the URLs, token, and connection.

| **Parameter**    | **Description**                                                                                                                                                | **Required** |
|------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| Password         | Example. Basic с2vtio5fbl...l0RvUag==                                                                                                                                | True |
| Server's FQDN    | Go to Settings &amp; Info → Settings → Integrations → API Keys. Click Copy API URL. Your FQDN is saved in the clipboard. Inline it without http/https protocol | True |
| XSOAR API-KEY ID | In the API Keys table, locate the ID field. Note your corresponding ID number                                                                                  | True |
| XSOAR API-KEY    | XSOAR API-KEY                                                                                                                                                  | True |