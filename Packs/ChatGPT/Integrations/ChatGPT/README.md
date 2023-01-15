This ChatGPT Integration.
Create by Bar Halifa-levi Trustnet LTD
## Configure ChatGPT on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for ChatGPT.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    |  | True |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ask-chatgpt
***
 


#### Base Command

`ask-chatgpt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prompt | Please ask ChatGPT what ever you want. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ChatGPT.MSG.Answer | unknown |  | 
