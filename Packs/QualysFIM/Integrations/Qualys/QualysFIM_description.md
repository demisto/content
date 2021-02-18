## Authentication

Before you start, make sure that you have Qualys login credentials.

The Qualys API server URL that you should use for API requests depends on the platform where your account is located.

    Platforms and URLS:
    Qualys US Platform 1: https://gateway.qg1.apps.qualys.com
    Qualys US Platform 2: https://gateway.qg2.apps.qualys.com
    Qualys US Platform 3: https://gateway.qg3.apps.qualys.com
    Qualys EU Platform 1: https://gateway.qg1.apps.qualys.eu
    Qualys EU Platform 2: https://gateway.qg2.apps.qualys.eu
    Qualys India Platform 1: https://gateway.qg1.apps.qualys.in
    Qualys Private Cloud Platform(Custom Platform): https://gateway.<customer_base_url>


This integration was integrated and tested with version 2.6.0.0-23 of qualys_fim
## Configure qualys_fim on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for qualys_fim.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Username |  | True |
    | Qualys API Platform URL | The Qualys API server URL that you should use for API requests depends on the platform where your account is located.<br/><br/>Platforms and URLS:<br/>Qualys US Platform 1: https://gateway.qg1.apps.qualys.com<br/>Qualys US Platform 2: https://gateway.qg2.apps.qualys.com<br/>Qualys US Platform 3: https://gateway.qg3.apps.qualys.com<br/>Qualys EU Platform 1: https://gateway.qg1.apps.qualys.eu<br/>Qualys EU Platform 2: https://gateway.qg2.apps.qualys.eu<br/>Qualys India Platform 1: https://gateway.qg1.apps.qualys.in<br/>Qualys Private Cloud Platform\(Custom Platform\): https://gateway.&amp;lt;customer_base_url&amp;gt; | True |
    | Fetch incidents |  | False |
    | Fetch time | First fetch timestamp \(&amp;lt;number&amp;gt; &amp;lt;time unit&amp;gt;\) e.f 12 hours, 7 days etc. | False |
    | Incident Type |  | False |
    | Max Fetch |  | False |
    | Fetch Filter | Filter the incidents fetching by providing a query using Qualys syntax.<br/>i.e: "id:ebe6c64a-8b0d-3401-858d-d57fb25860c7"<br/><br/>Please refer to "how to search" Qualys FIM guide for more information about Qualys syntax:<br/>https://qualysguard.qg2.apps.qualys.com/fim/help/search/language.htm | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.