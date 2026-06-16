Designed to assist security professionals with security investigations, threat hunting, and anomaly detection, leveraging OpenAI GPT models' natural language conversational capabilities.
This integration was integrated and tested with version xx of OpenAi ChatGPT v3.

## Configure OpenAI GPT in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| ChatGPT Server URL | The base URL for the ChatGPT Platform Compliance APIs. | False |
| OpenAI API Key | The OpenAI Platform API key used by the chat-completion commands. Required only when running those commands or when running test-module without the event-collector keys. | False |
| Admin API Key | The Admin API key for the OpenAI Platform. Required only when fetching the "OpenAI Audit logs" event type. | False |
| Compliance API Key | The Compliance API key for the ChatGPT Platform. Required when fetching Compliance event types. | False |
| Workspace ID | The Compliance workspace UUID \(for example, 4a4676f3-3d74-4723-b696-c93e6d01078a\). Required when fetching Compliance event types. | False |
| Model | The model that will process the inputs and generate the completion. | False |
| Model (Optional - overrides selected choice) | The model that will process the inputs and generate the completion. | False |
| Max tokens | The maximum number of tokens that can be generated for the response. \(Allows controlling tokens' consumption\). | False |
| Temperature | Sets the randomness in responses. Lower values \(closer to 0\) produce more deterministic and consistent outputs, while higher values \(up to 2\) increase randomness and variety. It is generally recommended altering this or top_p but not both. | False |
| Top P | Enables nucleus sampling where only the top 'p' percent \(0 to 1\) of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. It is generally recommended altering this or temperature but not both. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Fetch events |  | False |
| Events types to fetch | The event types to fetch. OpenAI Audit logs uses the Admin API; all other selections use the Compliance API and require a Workspace ID. | False |
| Maximum number of OpenAI Audit events per fetch | The maximum number of Audit events to return per fetch. | False |
| Maximum number of Compliance events per fetch | The maximum number of Compliance events to return per fetch. | False |
| Events Fetch Interval |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### gpt-send-message

***
Send a plain message to the selected GPT model and receive the generated response.

#### Base Command

`gpt-send-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message that the GPT model will respond to. | Required | 
| reset_conversation_history | Whether to keep previously sent messages in a conversation context or start a new conversation. Possible values are: yes, no. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional | 
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 2) increase randomness and variety. It is generally recommended altering this or top_p but not both. | Optional | 
| top_p | (0-1) Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. It is generally recommended altering this or temperature but not both. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAiChatGPTV3.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the GPT model. | 

### gpt-check-email-header

***
Checking email header for possible security issues. It is possible to keep asking questions on the provided info using 'gpt-send-message'. Resets conversation context by default.

#### Base Command

`gpt-check-email-header`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of an uploaded '.eml' file. | Required | 
| additional_instructions | Additional instructions or security issue to focus on. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional | 
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 2) increase randomness and variety. It is generally recommended altering this or top_p but not both. | Optional | 
| top_p | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. It is generally recommended altering this or temperature but not both. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAiChatGPTV3.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the GPT model. | 

### gpt-analyze-email-header

***
Analyzes email headers for potential security issues using the OpenAI Responses API. This is the Responses-API counterpart of gpt-check-email-header (which uses the Chat Completions API).

#### Base Command

`gpt-analyze-email-header`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The entry ID of an uploaded .eml file. | Required | 
| additional_instructions | The additional instructions or security issue to focus on. Substituted into the prompt template. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. Maps internally to the API body field max_output_tokens. | Optional | 
| temperature | The randomness level in responses. Lower values (closer to 0) produce more deterministic outputs, while higher values (up to 2) increase variety. It is generally recommended to alter this or top_p but not both. | Optional | 
| top_p | The nucleus sampling threshold where only the top p percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. Range 0-1. It is generally recommended to alter this or temperature but not both. | Optional | 
| reasoning_effort | The reasoning effort level for reasoning models (o1, o3, o4, gpt-5). Controls how much thinking the model does before responding. Possible values are: low, medium, high. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAiChatGPTV3.Response | Unknown | The conversation state including the response_id. | 
| OpenAiChatGPTV3.Response.user | String | The prompt sent to the model. | 
| OpenAiChatGPTV3.Response.assistant | String | The assistant response text. | 
| OpenAiChatGPTV3.Response.response_id | String | The OpenAI response ID. | 

### gpt-analyze-email-body

***
Analyzes email body for potential security risks using the OpenAI Responses API. This is the Responses-API counterpart of gpt-check-email-body (which uses the Chat Completions API).

#### Base Command

`gpt-analyze-email-body`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | The entry ID of an uploaded .eml file. | Required | 
| additional_instructions | The additional instructions or security issue to focus on. Substituted into the prompt template. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. Maps internally to the API body field max_output_tokens. | Optional | 
| temperature | The randomness level in responses. Lower values (closer to 0) produce more deterministic outputs, while higher values (up to 2) increase variety. It is generally recommended to alter this or top_p but not both. | Optional | 
| top_p | The nucleus sampling threshold where only the top p percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. Range 0-1. It is generally recommended to alter this or temperature but not both. | Optional | 
| reasoning_effort | The reasoning effort level for reasoning models (o1, o3, o4, gpt-5). Controls how much thinking the model does before responding. Possible values are: low, medium, high. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAiChatGPTV3.Response | Unknown | The conversation state including the response_id. | 
| OpenAiChatGPTV3.Response.user | String | The prompt sent to the model. | 
| OpenAiChatGPTV3.Response.assistant | String | The assistant response text. | 
| OpenAiChatGPTV3.Response.response_id | String | The OpenAI response ID. | 

### gpt-check-email-body

***
Check email body for possible security issues. It is possible to keep asking questions on the provided info using 'gpt-send-message'. Resets conversation context by default.

#### Base Command

`gpt-check-email-body`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entry_id | Entry ID of an uploaded '.eml' file. | Required | 
| additional_instructions | Additional instructions or security issue to focus on. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional | 
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 2) increase randomness and variety. It is generally recommended altering this or top_p but not both. | Optional | 
| top_p | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. It is generally recommended altering this or temperature but not both. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAiChatGPTV3.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the GPT model. | 

### openai-get-events

***
Manually retrieves events from OpenAI. Use this command for development and debugging only, as it may produce duplicate events, exceed API rate limits, or disrupt the fetch mechanism.

#### Base Command

`openai-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| event_type | A comma-separated list of event types to retrieve. If not specified, uses the value configured in the integration parameters. Possible values are: OpenAI Audit logs, Conversation Messages, Apps, Apps Auth, Compliance Audit, Auth, Codex, ChatGPT, Codex Security, Workspace Agents. | Optional | 
| limit | The maximum number of events to return per stream. Default is 50. | Optional | 
| start_time | The lookback start time for the fetch. Supports ISO 8601 or relative time (for example, "3 days ago", "2099-01-01T00:00:00Z"). | Optional | 
| should_push_events | Whether retrieved events are also ingested by Cortex. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAI.Event.id | String | The unique identifier of the event. | 
| OpenAI.Event._event_type | String | The upstream event_type for Compliance events. Left empty for Audit events. | 
| OpenAI.Event.source_log_type | String | The source log type used by downstream parsing rules. | 
| OpenAI.Event._time | Date | The event timestamp in ISO 8601 format. | 

### gpt-create-soc-email-template

***
Create an email template out of the conversation context to be sent from the SOC.

#### Base Command

`gpt-create-soc-email-template`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| additional_instructions | Additional instructions or security issue to focus on. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. | Optional | 
| temperature | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 2) increase randomness and variety. It is generally recommended altering this or top_p but not both. | Optional | 
| top_p | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. It is generally recommended altering this or temperature but not both. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAiChatGPTV3.Conversation | Dictionary | Entire conversation \(if not reset\) between the user and the GPT model. | 

### gpt-draft-soc-email

***
Drafts a SOC email template using the OpenAI Responses API. This command uses the Responses API which is recommended for all new projects (instead of gpt-create-soc-email-template which uses the Chat Completions API). Consumes prior conversation context by design (e.g. from a preceding gpt-analyze-email-body call).

#### Base Command

`gpt-draft-soc-email`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| additional_instructions | The specific issue or focus area to weave into the template. Substituted into the prompt template. | Optional | 
| max_tokens | The maximum number of tokens that can be generated for the response. Maps internally to the API body field max_output_tokens. | Optional | 
| temperature | The randomness level in responses. Lower values (closer to 0) produce more deterministic outputs, while higher values (up to 2) increase variety. It is generally recommended to alter this or top_p but not both. | Optional | 
| top_p | The nucleus sampling threshold where only the top p percent of probable tokens are considered. Lower values result in more focused outputs, while higher values increase diversity. Range 0-1. It is generally recommended to alter this or temperature but not both. | Optional | 
| reasoning_effort | The reasoning effort level for reasoning models (o1, o3, o4, gpt-5). Controls how much thinking the model does before responding. Possible values are: low, medium, high. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAiChatGPTV3.Response | Unknown | The conversation state including the response_id. | 
| OpenAiChatGPTV3.Response.user | String | The prompt sent to the model. | 
| OpenAiChatGPTV3.Response.assistant | String | The assistant response text. | 
| OpenAiChatGPTV3.Response.response_id | String | The OpenAI response ID. | 

### gpt-create-response

***
Sends a message to the OpenAI Responses API and receives the generated response. This command uses the Responses API which is recommended for all new projects (instead of gpt-send-message which uses the Chat Completions API). Supports multi-turn conversations via previous_response_id, reasoning effort control for o-series and gpt-5 models, and background execution.

#### Base Command

`gpt-create-response`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The user message to send. | Required | 
| reset_conversation_history | Whether to discard the existing conversation context and start fresh. Possible values are: yes, no. Default is no. | Optional | 
| max_tokens | The maximum number of output tokens. Falls back to instance config. Maps internally to the API body field max_output_tokens. | Optional | 
| temperature | The randomness level in responses. Falls back to instance config. Range 0-2. Lower values produce more deterministic outputs, while higher values increase variety. | Optional | 
| top_p | The nucleus sampling threshold. Falls back to instance config. Range 0-1. Lower values result in more focused outputs, while higher values increase diversity. | Optional | 
| reasoning_effort | The reasoning effort level. Honored only for reasoning families (o1, o3, o4, gpt-5); silently dropped on others. Default medium. Possible values are: none, minimal, low, medium, high, xhigh. | Optional | 
| background | Whether to run the model response in the background. When true, the command uses polling to wait for the response to complete. Possible values are: true, false. | Optional | 
| compact_threshold | The token threshold at which compaction should be triggered for this entry. Minimum 1000. | Optional | 
| model | The model to use. Use the gpt-list-models command to see available models. Falls back to instance config. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAiChatGPTV3.Response | Unknown | The conversation state including the response_id for multi-turn continuity. | 
| OpenAiChatGPTV3.Response.user | String | The user message sent. | 
| OpenAiChatGPTV3.Response.assistant | String | The assistant response text. | 
| OpenAiChatGPTV3.Response.response_id | String | The OpenAI response ID used for multi-turn conversation continuity. | 

### gpt-list-models

***
Lists all models available to the configured API key. Lets users discover models per their actual API-key tier without redeploying the integration when OpenAI ships new ones.

#### Base Command

`gpt-list-models`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAiChatGPTV3.Model.Id | String | The model identifier \(e.g., gpt-4, gpt-3.5-turbo\). | 
| OpenAiChatGPTV3.Model.Created | Number | The Unix timestamp of when the model was created. | 
| OpenAiChatGPTV3.Model.OwnedBy | String | The organization or entity that owns the model. | 

### gpt-create-moderation

***
Runs text or an image through the OpenAI Moderations API and returns per-category flagging results. Exactly one of text, entry_id, or image_url must be provided.

#### Base Command

`gpt-create-moderation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | A comma-separated list of text strings to moderate. Exactly one of text, entry_id, or image_url must be provided. | Optional | 
| entry_id | The war-room entry ID of an uploaded image file. The file is base64-encoded internally and posted as a data URL. Exactly one of text, entry_id, or image_url must be provided. | Optional | 
| image_url | The publicly reachable HTTP(S) URL of an image (limited to 20 MB). Exactly one of text, entry_id, or image_url must be provided. | Optional | 
| model | The moderation model to use. Possible values are: omni-moderation-latest, omni-moderation-2024-09-26. Default is omni-moderation-latest. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenAiChatGPTV3.Moderation.Flagged | Boolean | Whether the content was flagged by the moderation model. | 
| OpenAiChatGPTV3.Moderation.Categories | Unknown | The object of boolean values indicating which categories were flagged. | 
| OpenAiChatGPTV3.Moderation.CategoryScores | Unknown | The object of float values indicating the confidence score for each category. | 
