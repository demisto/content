# Google Gemini Integration

This integration provides access to Google Gemini's large language models for AI-powered analysis and chat capabilities in Cortex XSOAR or XSIAM. Supports both Google AI Studio (API key) and Google Cloud Vertex AI (service account) authentication.

## Configure GoogleGemini in Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Google Gemini.
3. Click **Add instance** to create and configure a new integration instance.

## Configure GoogleGemini in Cortex XSIAM

1. Go to Marketplace
2. Search for GoogleGemini
3. Add ContentPack
4. Search for GoogleGemini in Data Source and Integrations
5. Create new instance

### Instance Configuration Parameters

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Authentication Type | Choose whether to authenticate with a Google AI Studio API Key or a Google Cloud Vertex AI Service Account. | True |
| Server URL | For AI Studio: https://generativelanguage.googleapis.com. For Vertex AI: https://aiplatform.googleapis.com \(auto-detected if unchanged\). | True |
| API Key | API Key for Google AI Studio authentication. Required when using AI Studio. | False |
| Service Account Key (JSON) | Service Account Key JSON for Vertex AI authentication. Required when using Vertex AI. | False |
| Project ID | Google Cloud Project ID. Required when using Vertex AI. | False |
| Location | Google Cloud location for Vertex AI \(e.g., 'global', 'us-central1'\). Defaults to 'global'. | False |
| Default Model | Please choose only one model. | True |
| Max tokens | The maximum number of tokens that can be generated for the response \(1-10000\). Defaults to 1024. | True |
| Temperature | Controls the degree of randomness in token selection. Lower values \(closer to 0\) produce more deterministic outputs, while higher values \(up to 2.0\) increase randomness and creativity. | False |
| Top P | Changes how the model selects tokens for output. Tokens are selected from most to least probable until their cumulative probability equals the topP value \(0.0-1.0\). Lower values for less random responses, higher values for more random responses. | False |
| Top K | Consider only the top K most probable tokens when generating text. Affects the diversity of the generated content. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

### Supported Models

The integration supports various Gemini models including:

**Stable Models:**

- gemini-2.5-flash
- gemini-2.5-pro
- gemini-3.1-flash-lite
- gemini-3.5-flash-lite
- gemini-3.5-flash
- gemini-3.6-flash
- gemini-3.7-flash
- gemini-3.8-flash

Note: You can also use the freetext model field to specify newer models not in the dropdown list.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### google-gemini-send-message

***
Send a chat message to the Gemini AI model.

#### Base Command

`google-gemini-send-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prompt | The prompt or question to send to the AI model. | Required |
| model | The Gemini model to use for this request. If not specified, uses the default model from configuration. | Optional |
| history | Optional conversation history in JSON format. Array of message objects with 'role' (user/model) and 'parts' containing text.<br/>Example: [{"role": "user", "parts": [{"text": "Hello"}]}, {"role": "model", "parts": [{"text": "Hi there!"}]}]. | Optional |
| save_conversation | If true, saves the complete conversation (including the current exchange) to context under GoogleGemini.Chat.History for reuse in subsequent calls. Possible values are: true, false. | Optional |
| temperature | The degree of randomness in token selection for this call. Overrides the instance-level Temperature parameter. Lower values (closer to 0) produce more deterministic outputs, while higher values (up to 2.0) increase randomness and creativity. | Optional |
| max_tokens | The maximum number of tokens that can be generated for this response (1-10000). Overrides the instance-level Max tokens parameter for this call. If not specified, the instance-level value is used. | Optional |
| max_input_tokens | The maximum number of input tokens (prompt + history combined) allowed for this request. If exceeded and truncate=false, the command returns an error reporting the actual vs. allowed token count. | Optional |
| truncate | Whether to automatically truncate the oldest history entries first, then the prompt itself, to fit within the budget if max_input_tokens is exceeded. If false (default), an error is returned instead. Possible values are: true, false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleGemini.Chat.Prompt | String | The original prompt sent to the model. |
| GoogleGemini.Chat.Response | String | The AI model's response. |
| GoogleGemini.Chat.Model | String | The model used for generation. |
| GoogleGemini.Chat.Temperature | Number | The temperature setting used. |
| GoogleGemini.Chat.MaxTokens | Number | The maximum number of output tokens configured for the request. |
| GoogleGemini.Chat.History | Unknown | Complete conversation history in Gemini format, updated when save_conversation=true. Can be used as input for the history argument in subsequent calls. |
| GoogleGemini.Chat.ConversationId | String | A unique identifier, used to identify the chat session. |
| GoogleGemini.Chat.InputTokenCount | Number | The number of input \(prompt\) tokens consumed by the request, as reported by the model. |
| GoogleGemini.Chat.OutputTokenCount | Number | The number of output \(response\) tokens generated by the model. |
| GoogleGemini.Chat.TotalTokenCount | Number | The total number of tokens \(input \+ output\) consumed by the request. |
| GoogleGemini.Chat.Truncated | Boolean | Whether the history and/or prompt were automatically truncated to fit within max_input_tokens. |

#### Command Examples

```!google-gemini-send-message prompt="What is artificial intelligence?"```

```!google-gemini-send-message prompt="Analyze this suspicious email for potential threats" model="gemini-2.5-pro"```

```!google-gemini-send-message prompt="Continue our previous discussion" history='[{"role": "user", "parts": [{"text": "Hello"}]}, {"role": "model", "parts": [{"text": "Hi there! How can I help you?"}]}]'```

```!google-gemini-send-message prompt="What are the next investigation steps?" save_conversation=true```

```!google-gemini-send-message prompt="Brainstorm creative phishing detection rules" temperature=1.2```

```!google-gemini-send-message prompt="Provide a detailed incident summary" max_tokens=2048```

```!google-gemini-send-message prompt="Summarize the incident" history='[{"role": "user", "parts": [{"text": "Hello"}]}, {"role": "model", "parts": [{"text": "Hi there! How can I help you?"}]}]' max_input_tokens=8000 truncate=true```

#### Conversation History Management

When `save_conversation=true`, the integration:

- Automatically retrieves existing conversation history from context
- Uses the last exchange (user + model response) to provide context for the current request
- Saves the complete updated conversation history to `GoogleGemini.Chat.History`
- Allows analysts to maintain conversation continuity without manually managing JSON history

#### Human Readable Output

The command returns the AI model's response as human-readable output in the War Room.
