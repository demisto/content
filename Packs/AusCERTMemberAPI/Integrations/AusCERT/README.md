Integration for polling the AusCERT API for Member Security Incident Notifications and threat intelligence.
## Configure AusCERT on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AusCERT.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Fetch incidents | False |
    | API Key from MSIN AusCERT Portal | False |
    | First fetch time | True |
    | Incidents Fetch Interval | False |
    | Trust any certificate (not secure) | False |
    | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### auscert_get_combined_feed

***
Fetches indicators from the combined threat feed.

#### Base Command

`auscert_get_combined_feed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range | Time range to fetch indicators for. Possible values are: 1, 7. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| auscertIndicators | unknown |  | 

### auscert_get_malware_feed

***
Fetches indicators from the Malware threat feed.

#### Base Command

`auscert_get_malware_feed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range | No description provided. Possible values are: 1, 7. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| auscertIndicators | unknown |  | 

### auscert_get_phishing_feed

***
Fetches indicators from the Phishing threat feed.

#### Base Command

`auscert_get_phishing_feed`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| time_range | No description provided. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| auscertIndicators | unknown |  | 
