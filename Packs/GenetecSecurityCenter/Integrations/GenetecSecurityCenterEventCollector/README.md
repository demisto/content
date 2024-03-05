Security Center is the foundation of our unified security portfolio. It lets you connect your security at your own pace, starting with a single core system. Even if you're only interested in upgrading your video surveillance or access control, taking the next step is easy.

## Configure Armis Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Genetec Security Center Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | Username | Username &amp;amp; Password. | True |
    | Password |  | True |
    | Application ID |  | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Maximum number of events per fetch | Alerts and activity events. |  |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### baseintegration-dummy

***
[Enter a description of the command, including any important information users need to know, for example required permissions.]

#### Base Command

`baseintegration-dummy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dummy | [Enter a description of the argument, including any important information users need to know, for example, default values.]. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| BaseIntegration.Output | String | \[Enter a description of the data returned in this output.\] | 
