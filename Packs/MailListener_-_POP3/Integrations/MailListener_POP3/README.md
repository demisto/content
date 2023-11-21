Listen to a mailbox, enable incident triggering via e-mail

## Configure MailListener - POP3 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MailListener - POP3.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. example.com) | True |
    | Port | False |
    | Email | True |
    | Password | True |
    | Use SSL connection | False |
    | Fetch incidents | False |
    | First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | False |
    | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.