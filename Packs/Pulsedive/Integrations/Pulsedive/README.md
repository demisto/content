Use the Pulsedive integration to get OSINT threatintel for incidents.

## Integrate Pulsedive into Cortex XSOAR

Leverage Pulsedive threat intelligence in Cortex XSOAR to enrich any domain, URL, or IP. Retrieve risk scores and factors, investigate contextual data, pivot on any data point, and investigate potential threats.
Register Free: https://pulsedive.com/login
About: https://pulsedive.com/about/
Contact: mailto:support@pulsedive.com

## Configure Pulsedive on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Pulsedive.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Key | True |
    | Trust any certificate (not secure) | False |


4. Click **Test** to validate that the integration can reach Pulsedive.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of domains | Required | 

#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs | Required | 

#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs | Required | 

#### Base Command

`pulsedive-scan`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The value to scan | Required | 
| scan_type | You can choose between passive and active scanning. Default value is 'active' | Optional | 

#### Base Command

`pulsedive-scan-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| qid | QID recieved from scan command | Required | 
