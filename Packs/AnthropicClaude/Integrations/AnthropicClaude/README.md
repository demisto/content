Designed to assist security professionals with security investigations, threat hunting, and anomaly detection, leveraging Anthropic Claude's natural language conversational capabilities.
## Configure Anthropic Claude on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Anthropic Claude.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Server URL |  | True |
    | API Key |  | True |
    | Model | The model that will process the inputs and generate the response. | False |
    | Model (Optional - overrides selected choice) | The model that will process the inputs and generate the response. | False |
    | Max tokens | The maximum number of tokens that can be generated for the response. Required by Anthropic's API \(defaults to 1024\). | True |
    | Temperature | Sets the randomness in responses. Lower values \(closer to 0\) produce more deterministic and consistent outputs, while higher values \(up to 1\) increase randomness and variety. | False |
    | Top P | Enables nucleus sampling where only the top 'p' percent \(0 to 1\) of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### claude-send-message

***
Send a plain message to the selected Claude model and receive the generated response.

#### Base Command

`claude-send-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message that the Claude model will respond to. | Required | 
| reset_conversation_history | Whether to keep previously sent messages in a conversation context or start a new conversation. Possible values are: yes, no. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional | 
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 1) increase randomness and variety. | Optional | 
| top_p | (0-1) Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the Claude model. | 

### claude-check-email-header

***
Checking email header for possible security issues. It is possible to keep asking questions on the provided info using 'claude-send-message'. Resets conversation context by default.

#### Base Command

`claude-check-email-header`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of an uploaded '.eml' file. | Required | 
| additional_instructions | Additional instructions or security issue to focus on. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional | 
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 1) increase randomness and variety. | Optional | 
| top_p | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the Claude model. | 

### claude-check-email-body

***
Check email body for possible security issues. It is possible to keep asking questions on the provided info using 'claude-send-message'. Resets conversation context by default.

#### Base Command

`claude-check-email-body`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of an uploaded '.eml' file. | Required | 
| additional_instructions | Additional instructions or security issue to focus on. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional | 
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 1) increase randomness and variety. | Optional | 
| top_p | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the Claude model. | 

### claude-create-soc-email-template

***
Create an email template out of the conversation context to be sent from the SOC.

#### Base Command

`claude-create-soc-email-template`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| additional_instructions | Additional instructions or security issue to focus on. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional | 
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 1) increase randomness and variety. | Optional | 
| top_p | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AnthropicClaude.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the Claude model. | 
