
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
