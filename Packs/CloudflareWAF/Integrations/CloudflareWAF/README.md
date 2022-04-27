# Cloudflare WAF
Cloudflare WAF integration allows customers to manage firewall rules, filters, and IP-lists.
It also allows to retrieve zones list for each account.
This integration was integrated and tested with version 4 of Cloudflare.

## Configure CloudflareWAF  on Cortex XSOAR
1. Navigate to Settings > Integrations > Servers & Services.
2. Search for CloudflareWAF.
3. Click Add instance to create and configure a new integration instance.

    | Parameter       |	Description                                                            | Required  |
    |-----------------|------------------------------------------------------------------------|-----------|
    | User Token      | App Registration Client ID                                             |	True   |
    | Account ID      |	Account identifier                                                     |	True   |
    | Default Zone ID |	The domain identifier. Zone ID can be override when executing commands |	False  |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

....