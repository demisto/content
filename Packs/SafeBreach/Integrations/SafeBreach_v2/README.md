Deprecated. No available replacement.

## Configure SafeBreach v2 (Deprecated) for Cortex XSOAR Integration

1. Open the **Navigation bar** → … → **CLI Console**
2. Type **config accounts** to find out the account id
3. Use the id as the **accountId** parameter in Cortex XSOAR configuration
4. Type **config apikeys** to list existing API keys \
OR \
Add a new one by typing: **config apikeys add --name <key_name>**
5. Use the generated API token as **apiKey** parameter in Cortex XSOAR configuration
6. Use your SafeBreach Management URL as the **url** parameter in Cortex XSOAR configuration

## Configure SafeBreach v2 (Deprecated) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SafeBreach v2 (Deprecated).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | SafeBreach Managment URL | For example, https://yourorg.safebreach.com | True |
    | Account ID | Obtained with "config accounts" SafeBreach command | True |
    | API Key | Generated with "config apikeys add" SafeBreach command | True |
    | Insight Category |  |  |
    | Insight Data Type |  |  |
    | Non Behavioral Indicator Reputation | Non-Behavioral Indicator from this integration instance will be marked with this reputation |  |
    | Behavioral Reputation | Behavioral Indicator from this integration instance will be marked with this reputation |  |
    | Indicators Limit | The maximum number of indicators to generate. The default is 1000. |  |
    | Fetch indicators |  |  |
    | Source Reliability | Reliability of the source providing the intelligence data | True |
    | Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed |  |
    |  |  |  |
    | Feed Fetch Interval |  |  |
    | Bypass exclusion list | When selected, the exclusion list is ignored for indicators from this feed. This means that if an indicator from this feed is on the exclusion list, the indicator might still be added to the system. |  |
    |  |  |  |
    | Trust any certificate (not secure) |  |  |
    | Use system proxy settings |  |  |
    | Indicator Reputation | Indicators from this integration instance will be marked with this reputation |  |
    | Tags | Supports CSV values. |  |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
