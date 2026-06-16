
## OpenAI GPT

### Instance Configuration

- #### Generate an API Key

    1. Sign up or log in to [OpenAI developer platform](https://platform.openai.com).
    2. Generate a new API key at [OpenAI developer platform - api-keys](https://platform.openai.com/api-keys).

- #### Choose a GPT model to interact with

    1. This integration supports only the **'Chat Completions'** endpoint. Therefore, you can only configure models that support this endpoint (_https://api.openai.com/v1/chat/completions_).

    2. For tasks requiring deep understanding and extensive inputs, opt for more advanced models (e.g. gpt-4). These models offer a larger context window, allowing them to process bigger documents, and provide more refined and comprehensive responses.
    The more elementary models (e.g. gpt-3.5) often provide shallower answers and input analysis.
    Refer to [Models overview](https://platform.openai.com/docs/models/overview) for more information.

- #### Text generation setting (Optional)

   1. **max-tokens**: The maximum number of tokens that can be generated for the response. (Allows controlling tokens' consumption). Default: unset.
   2. **temperature**: Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 2) increase randomness and variety. It is generally recommended altering this or top_p but not both. Default: 1.
   3. **top_p**: Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values (closer to 0) result in more focused outputs, while higher values (closer to 1) increase diversity. It is generally recommended altering this or temperature but not both. Default: unset.

- #### Event Collector — Generate API Keys

    1. **Admin API Key** (required for `OpenAI Audit logs`): generate from the OpenAI Platform admin console. Used to call `/v1/organization/audit_logs`.
    2. **Compliance API Key** (required for any Compliance event type): generate from the ChatGPT Platform. Used to call `/v1/compliance/workspaces/{workspace_id}/...`.
    3. **Workspace ID** (required for any Compliance event type): the UUID of the compliance workspace whose events you want to collect.

- #### Event Collector — Select event types to fetch

    Toggle **Fetch events**, then select one or more **Events types to fetch**:

    | User-facing label      | Source                               | Required credentials                       |
    |------------------------|--------------------------------------|--------------------------------------------|
    | OpenAI Audit logs      | OpenAI Platform — Admin API          | Admin API Key                              |
    | Conversation Messages  | ChatGPT Platform — Compliance API    | Compliance API Key + Workspace ID          |
    | Apps                   | ChatGPT Platform — Compliance API    | Compliance API Key + Workspace ID          |
    | Apps Auth              | ChatGPT Platform — Compliance API    | Compliance API Key + Workspace ID          |
    | Compliance Audit       | ChatGPT Platform — Compliance API    | Compliance API Key + Workspace ID          |
    | Auth                   | ChatGPT Platform — Compliance API    | Compliance API Key + Workspace ID          |
    | Codex                  | ChatGPT Platform — Compliance API    | Compliance API Key + Workspace ID          |
    | ChatGPT                | ChatGPT Platform — Compliance API    | Compliance API Key + Workspace ID          |
    | Codex Security         | ChatGPT Platform — Compliance API    | Compliance API Key + Workspace ID          |
    | Workspace Agents       | ChatGPT Platform — Compliance API    | Compliance API Key + Workspace ID          |

    Selecting an event type without its matching credentials raises an informative error at instance test time, naming the missing parameter.

- #### Event Collector — Datasets

    Each Event Collector stream lands in its own Cortex dataset:

    | Stream                | Vendor   | Product               | Dataset                           |
    |-----------------------|----------|-----------------------|-----------------------------------|
    | OpenAI Audit logs     | `openai` | `chatgpt_audit`       | `openai_chatgpt_audit_raw`        |
    | Compliance logs (all) | `openai` | `chatgpt_compliance`  | `openai_chatgpt_compliance_raw`   |

- #### Event Collector — Tuning (Optional)

    | Parameter                                       | Default                   | Description                                                              |
    |-------------------------------------------------|---------------------------|--------------------------------------------------------------------------|
    | Maximum number of OpenAI Audit events per fetch | 1000                      | Cap on Audit events ingested per fetch cycle.                            |
    | Maximum number of Compliance events per fetch   | 900                       | Cap on Compliance events ingested per fetch cycle.                       |
    | Events Fetch Interval                           | 1 minute                  | How often the scheduled fetch runs.                                      |
    | ChatGPT Server URL                              | `https://api.chatgpt.com` | Base URL of the ChatGPT Compliance API. Override only for non-default tenants. |

- #### Click 'Test'

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.

### gpt-send-message

***
Send a message as a prompt to the GPT model.

`!gpt-send-message message="<MESSAGE_TEXT>"`

#### Input

| **Argument Name**          | **Description**                                                                                                                                             | **Required** |
|----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| message                    | The message to send to the GPT model wrapped with quotes.                                                                                                   | Yes          |
| reset_conversation_history | Whether to reset conversation history or keep it as context for the sent message. (Conversation history is not reset by default).                           | No           |
| max_tokens                 | The maximum number of tokens that can be generated for the response. Overrides text generation setting for the specific message sent.                       | No           |
| temperature                | Sets the randomness in responses. Overrides text generation setting for the specific message sent.                                                          | No           |
| top_p                      | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Overrides text generation setting for the specific message sent. | No           |

### gpt-check-email-body

***
Check email body for possible security issues.

`!gpt-check-email-body entryId="<ENTRY_ID_OF_UPLOADED_EML_FILE>"`

#### Input

| **Argument Name**      | **Description**                                                                                                                                             | **Required** |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| entryId                | Entry ID of an uploaded _.eml_ file from the context window.                                                                                                    | Yes          |
| additionalInstructions | Provide additional instructions for the GPT model when analyzing the email body.                                                                            | No           |
| max_tokens             | The maximum number of tokens that can be generated for the response. Overrides text generation setting for the specific message sent.                       | No           |
| temperature            | Sets the randomness in responses. Overrides text generation setting for the specific message sent.                                                          | No           |
| top_p                  | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Overrides text generation setting for the specific message sent. | No           |

### gpt-check-email-header

***
Check email body for possible security issues.

`!gpt-check-email-header entryId="<ENTRY_ID_OF_UPLOADED_EML_FILE>"`

#### Input

| **Argument Name**      | **Description**                                                                                                                                             | **Required** |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| entryId                | Entry ID of an uploaded _.eml_ file from context window.                                                                                                    | Yes          |
| additionalInstructions | Provide additional instructions for the GPT model when analyzing the email headers.                                                                         | No           |
| max_tokens             | The maximum number of tokens that can be generated for the response. Overrides text generation setting for the specific message sent.                       | No           |
| temperature            | Sets the randomness in responses. Overrides text generation setting for the specific message sent.                                                          | No           |
| top_p                  | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Overrides text generation setting for the specific message sent. | No           |

### gpt-analyze-email-header

***
Analyze email headers for potential security issues using the OpenAI Responses API. This command uses the Responses API which is recommended for all new projects (instead of `gpt-check-email-header` which uses the Chat Completions API).

`!gpt-analyze-email-header entry_id="3@123" additional_instructions="Pay close attention to SPF/DKIM."`

#### Input

| **Argument Name**        | **Description**                                                                                                                                                                                                                                                    | **Required** |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| entry_id                 | Entry ID of an uploaded _.eml_ file.                                                                                                                                                                                                                               | Yes          |
| additional_instructions  | Additional instructions or security issue to focus on. Substituted into the prompt template.                                                                                                                                                                       | No           |
| max_tokens               | The maximum number of tokens that can be generated for the response. Maps internally to the API body field `max_output_tokens`.                                                                                                                                    | No           |
| temperature              | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 2) increase randomness and variety.                                                                                     | No           |
| top_p                    | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Range 0–1.                                                                                                                                                              | No           |
| reasoning_effort         | Reasoning effort level for reasoning models (o1, o3, o4, gpt-5). Controls how much thinking the model does before responding. Possible values: `low`, `medium`, `high`.                                                                                           | No           |

#### Context Output

| **Path**                              | **Type** | **Description**                        |
|---------------------------------------|----------|----------------------------------------|
| OpenAiChatGPTV3.Response              | Unknown  | Conversation state including the response_id. |
| OpenAiChatGPTV3.Response.user         | String   | The prompt sent to the model.          |
| OpenAiChatGPTV3.Response.assistant    | String   | The assistant response text.           |
| OpenAiChatGPTV3.Response.response_id  | String   | The OpenAI response ID.                |

#### Human Readable Output

Two war-room entries are produced:

1. A table of the parsed email headers.
2. The AI verdict followed by a token-usage table. A _Reasoning tokens_ row appears in the usage table when a reasoning model is used.

### gpt-analyze-email-body

***
Analyze email body for potential security risks using the OpenAI Responses API. This command uses the Responses API which is recommended for all new projects (instead of `gpt-check-email-body` which uses the Chat Completions API).

`!gpt-analyze-email-body entry_id="3@123"`

#### Input

| **Argument Name**        | **Description**                                                                                                                                                                                                                                                    | **Required** |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| entry_id                 | Entry ID of an uploaded _.eml_ file.                                                                                                                                                                                                                               | Yes          |
| additional_instructions  | Additional instructions or security issue to focus on. Substituted into the prompt template.                                                                                                                                                                       | No           |
| max_tokens               | The maximum number of tokens that can be generated for the response. Maps internally to the API body field `max_output_tokens`.                                                                                                                                    | No           |
| temperature              | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 2) increase randomness and variety.                                                                                     | No           |
| top_p                    | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Range 0–1.                                                                                                                                                              | No           |
| reasoning_effort         | Reasoning effort level for reasoning models (o1, o3, o4, gpt-5). Controls how much thinking the model does before responding. Possible values: `low`, `medium`, `high`.                                                                                           | No           |

#### Context Output

| **Path**                              | **Type** | **Description**                        |
|---------------------------------------|----------|----------------------------------------|
| OpenAiChatGPTV3.Response              | Unknown  | Conversation state including the response_id. |
| OpenAiChatGPTV3.Response.user         | String   | The prompt sent to the model.          |
| OpenAiChatGPTV3.Response.assistant    | String   | The assistant response text.           |
| OpenAiChatGPTV3.Response.response_id  | String   | The OpenAI response ID.                |

#### Human Readable Output

Two war-room entries are produced:

1. A table of the parsed email body (text and HTML).
2. The AI verdict followed by a token-usage table. A _Reasoning tokens_ row appears in the usage table when a reasoning model is used.

### gpt-create-soc-email-template

***
Create an email template out of the conversation context to be sent from the SOC.

`!gpt-create-soc-email-template`

#### Input

| **Argument Name**      | **Description**                                                                                                                                             | **Required** |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| additionalInstructions | Provide additional instructions for the GPT model when analyzing the email headers.                                                                         | No           |
| max_tokens             | The maximum number of tokens that can be generated for the response. Overrides text generation setting for the specific message sent.                       | No           |
| temperature            | Sets the randomness in responses. Overrides text generation setting for the specific message sent.                                                          | No           |
| top_p                  | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Overrides text generation setting for the specific message sent. | No           |

### gpt-draft-soc-email

***
Draft a SOC email template using the OpenAI Responses API. This command uses the Responses API which is recommended for all new projects (instead of `gpt-create-soc-email-template` which uses the Chat Completions API). Consumes prior conversation context by design (e.g. from a preceding `gpt-analyze-email-body` call).

#### XSOAR sequence (typical phishing flow)

```
!gpt-analyze-email-body entry_id="3@123"
…assistant returns analysis…
!gpt-draft-soc-email additional_instructions="Notify the user the email was quarantined."
```

#### Input

| **Argument Name**        | **Description**                                                                                                                                                                                                                                                    | **Required** |
|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| additional_instructions  | Specific issue or focus area to weave into the template. Substituted into the prompt template.                                                                                                                                                                     | No           |
| max_tokens               | The maximum number of tokens that can be generated for the response. Maps internally to the API body field `max_output_tokens`.                                                                                                                                    | No           |
| temperature              | Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 2) increase randomness and variety.                                                                                     | No           |
| top_p                    | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Range 0–1.                                                                                                                                                              | No           |
| reasoning_effort         | Reasoning effort level for reasoning models (o1, o3, o4, gpt-5). Controls how much thinking the model does before responding. Possible values: `low`, `medium`, `high`.                                                                                           | No           |

#### Context Output

| **Path**                              | **Type** | **Description**                        |
|---------------------------------------|----------|----------------------------------------|
| OpenAiChatGPTV3.Response              | Unknown  | Conversation state including the response_id. |
| OpenAiChatGPTV3.Response.user         | String   | The prompt sent to the model.          |
| OpenAiChatGPTV3.Response.assistant    | String   | The assistant response text.           |
| OpenAiChatGPTV3.Response.response_id  | String   | The OpenAI response ID.                |

#### Human Readable Output

Two war-room entries are produced:

1. The SOC email template context output (`replace_existing=True` — running twice overwrites the previous draft).
2. The AI-generated template followed by a token-usage table. A _Reasoning tokens_ row appears in the usage table when a reasoning model is used.

### openai-get-events

***
Manually fetch a bounded batch of Audit and/or Compliance events for development/debugging. Does NOT advance the persisted `last_run` cursor, so it is safe to run against production tenants. Use `should_push_events=true` to additionally ingest the fetched events into the matching Cortex dataset.

#### Base Command

`openai-get-events`

#### Input

| **Argument Name**     | **Description**                                                                                                                                                                                                                                                                                          | **Required** |
|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| event_type            | The event type(s) to fetch. Comma-separated list. Possible values: `OpenAI Audit logs`, `Conversation Messages`, `Apps`, `Apps Auth`, `Compliance Audit`, `Auth`, `Codex`, `ChatGPT`, `Codex Security`, `Workspace Agents`. Defaults to the values configured in the integration parameters.             | No           |
| limit                 | Maximum number of events to return per stream. Default: `50`.                                                                                                                                                                                                                                            | No           |
| start_time            | Lookback start time for the fetch. Supports ISO 8601 or relative time (e.g., `3 days ago`, `2099-01-01T00:00:00Z`).                                                                                                                                                                                       | No           |
| should_push_events    | If `true`, the command also pushes the retrieved events to Cortex (Audit -> `openai_chatgpt_audit_raw`, Compliance -> `openai_chatgpt_compliance_raw`). Possible values: `true`, `false`. Default: `false`.                                                                                               | No           |

#### Context Output

| **Path**                     | **Type** | **Description**                                                  |
|------------------------------|----------|------------------------------------------------------------------|
| OpenAI.Event.id              | String   | The unique identifier of the event.                              |
| OpenAI.Event._event_type     | String   | Upstream `event_type` (Compliance only). Empty for Audit events. |
| OpenAI.Event.source_log_type | String   | Source log type used by downstream parsing/modeling rules.       |
| OpenAI.Event._time           | Date     | The event timestamp in ISO 8601 format.                          |

#### Human Readable Output

>### OpenAI GPT Events
>
>|id|_event_type|source_log_type|_time|
>|---|---|---|---|
>| FAKE_AUDIT_EVENT_001 |  | openai_audit_logs | 2099-01-01T00:00:00Z |
>| FAKE_LISTING_002 | AUDIT_LOG | compliance_audit_log | 2099-01-02T00:00:00Z |

### gpt-create-response

***
Send a message to the OpenAI Responses API and receive the generated response. This command uses the Responses API which is recommended for all new projects (instead of `gpt-send-message` which uses the Chat Completions API). Supports multi-turn conversations via `previous_response_id`, reasoning effort control for o-series and gpt-5 models, and background execution.

`!gpt-create-response message="What is the capital of France?"`

#### Input

| **Argument Name**            | **Description**                                                                                                                                                                                                                                                    | **Required** |
|------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| message                      | The user message to send.                                                                                                                                                                                                                                          | Yes          |
| reset_conversation_history   | Discard the existing conversation and start fresh. Possible values: `yes`, `no`. Default: `no`.                                                                                                                                                                    | No           |
| max_tokens                   | The maximum number of output tokens. Maps internally to the API body field `max_output_tokens`.                                                                                                                                                                    | No           |
| temperature                  | Sets the randomness in responses. Range 0–2.                                                                                                                                                                                                                       | No           |
| top_p                        | Enables nucleus sampling. Range 0–1.                                                                                                                                                                                                                               | No           |
| reasoning_effort              | Reasoning effort level for reasoning models (o1, o3, o4, gpt-5). Possible values: `none`, `minimal`, `low`, `medium`, `high`, `xhigh`.                                                                                                                            | No           |
| background                   | Whether to run the model response in the background. When `true`, the command uses polling to wait for the response to complete. Possible values: `true`, `false`.                                                                                                 | No           |
| model                        | The model to use. Falls back to instance config.                                                                                                                                                                                                                   | No           |

#### Context Output

| **Path**                              | **Type** | **Description**                                                    |
|---------------------------------------|----------|--------------------------------------------------------------------|
| OpenAiChatGPTV3.Response              | Unknown  | Conversation state including the response_id for multi-turn continuity. |
| OpenAiChatGPTV3.Response.user         | String   | The user message sent.                                             |
| OpenAiChatGPTV3.Response.assistant    | String   | The assistant response text.                                       |
| OpenAiChatGPTV3.Response.response_id  | String   | The OpenAI response ID used for multi-turn conversation continuity.|

### gpt-list-models

***
List all models available to the configured API key. Lets users discover models per their actual API-key tier without redeploying the integration when OpenAI ships new ones.

`!gpt-list-models`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path**                       | **Type** | **Description**                                          |
|--------------------------------|----------|----------------------------------------------------------|
| OpenAiChatGPTV3.Model.Id       | String   | The model identifier (e.g. gpt-4, gpt-3.5-turbo).       |
| OpenAiChatGPTV3.Model.Created  | Number   | Unix timestamp of when the model was created.            |
| OpenAiChatGPTV3.Model.OwnedBy  | String   | The organization or entity that owns the model.          |

### gpt-create-moderation

***
Run text or an image through the OpenAI Moderations API and return per-category flagging results. Exactly one of `text`, `entry_id`, or `image_url` must be provided.

`!gpt-create-moderation text="I am going to hurt that person."`

`!gpt-create-moderation image_url="https://example.com/image.png"`

`!gpt-create-moderation entry_id="3@123"`

#### Input

| **Argument Name** | **Description**                                                                                                                                          | **Required** |
|--------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| text               | One or more text strings to moderate. Exactly one of `text`, `entry_id`, or `image_url` must be provided.                                                | No           |
| entry_id           | War-room entry ID of an uploaded image file. The file is base64-encoded internally and posted as a data URL. Exactly one of `text`, `entry_id`, or `image_url` must be provided. | No           |
| image_url          | Publicly reachable HTTP(S) URL of an image (limited to 20 MB). Exactly one of `text`, `entry_id`, or `image_url` must be provided.                      | No           |
| model              | The moderation model to use. Possible values: `omni-moderation-latest`, `omni-moderation-2024-09-26`. Default: `omni-moderation-latest`.                 | No           |

#### Context Output

| **Path**                                  | **Type** | **Description**                                                        |
|-------------------------------------------|----------|------------------------------------------------------------------------|
| OpenAiChatGPTV3.Moderation.Flagged        | Boolean  | Whether the content was flagged by the moderation model.               |
| OpenAiChatGPTV3.Moderation.Categories     | Unknown  | Object of boolean values indicating which categories were flagged.     |
| OpenAiChatGPTV3.Moderation.CategoryScores | Unknown  | Object of float values indicating the confidence score for each category. |
