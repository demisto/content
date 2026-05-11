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
| Authentication Type | Choose between "AI Studio API Key" or "Vertex AI Service Account" | True |
| Server URL | For AI Studio: `https://generativelanguage.googleapis.com`. For Vertex AI: `https://aiplatform.googleapis.com` (auto-detected if unchanged). | True |
| API Key | Google AI Studio API key. Required when using AI Studio. | False |
| Service Account Key (JSON) | Service Account Key JSON for Vertex AI authentication. Required when using Vertex AI. | False |
| Project ID | Google Cloud Project ID. Required when using Vertex AI. | False |
| Location | Google Cloud location for Vertex AI (e.g., `global`, `us-central1`). Defaults to `global`. | False |
| Default Model | Select a Gemini model from the dropdown | True |
| Max tokens | Maximum number of tokens in the response (default: 1024) | True |
| Temperature | Controls randomness in responses (0.0-2.0) | False |
| Top P | Nucleus sampling parameter (0.0-1.0) | False |
| Top K | Top-k sampling parameter | False |
| Trust any certificate (not secure) | Whether to ignore SSL certificate verification | False |
| Use system proxy settings | Whether to use system proxy configuration | False |

### Supported Models

The integration supports various Gemini models including:

**Stable Models:**

- gemini-2.5-flash
- gemini-2.5-pro
- gemini-2.0-flash
- gemini-2.0-flash-lite  
- gemini-1.5-flash
- gemini-1.5-flash-8b
- gemini-1.5-pro

**Preview Models:**

- gemini-2.0-flash-preview-image-generation

**Audio/TTS Models:**

- gemini-2.5-flash-preview-native-audio-dialog
- gemini-2.5-flash-exp-native-audio-thinking-dialog
- gemini-2.5-flash-preview-tts
- gemini-2.5-pro-preview-tts

**Specialized Models:**

- text-embedding-004 (for embeddings)
- models/embedding-001 (for embeddings)
- models/aqa (for attributed question-answering)

Note: You can also use the freetext model field to specify newer models not in the dropdown list.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### google-gemini-send-message

***
Send a prompt to Google Gemini and receive an AI-generated response.

#### Base Command

`google-gemini-send-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prompt | The prompt or question to send to the AI model | Required |
| model | Override the instance default model for this specific request | Optional |
| history | Conversation history in JSON format for maintaining context across multiple interactions | Optional |
| save_conversation | Whether to automatically save and retrieve conversation history (default: false) | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleGemini.Chat.Prompt | String | The original prompt sent to the model |
| GoogleGemini.Chat.Response | String | The AI model's response |
| GoogleGemini.Chat.Model | String | The model used for generation |
| GoogleGemini.Chat.Temperature | Number | The temperature parameter used for response generation |
| GoogleGemini.Chat.History | Array | Complete conversation history (when save_conversation=true) |
| GoogleGemini.Chat.ConversationId | String | A unique identifier, used to identify the chat session |

#### Command Examples

```!google-gemini-send-message prompt="What is artificial intelligence?"```

```!google-gemini-send-message prompt="Analyze this suspicious email for potential threats" model="gemini-1.5-pro"```

```!google-gemini-send-message prompt="Continue our previous discussion" history='[{"role": "user", "parts": [{"text": "Hello"}]}, {"role": "model", "parts": [{"text": "Hi there! How can I help you?"}]}]'```

```!google-gemini-send-message prompt="What are the next investigation steps?" save_conversation=true```

#### Conversation History Management

When `save_conversation=true`, the integration:

- Automatically retrieves existing conversation history from context
- Uses the last exchange (user + model response) to provide context for the current request
- Saves the complete updated conversation history to `GoogleGemini.Chat.History`
- Allows analysts to maintain conversation continuity without manually managing JSON history

#### Human Readable Output

The command returns the AI model's response as human-readable output in the War Room.

## Setup Instructions

### AI Studio (API Key)

1. **Obtain API Key**: Visit [Google AI Studio](https://makersuite.google.com/app/apikey) to create an API key.
2. **Configure Integration**: Add a new GoogleGemini integration instance, set Authentication Type to **AI Studio API Key**, and enter your API key.
3. **Test Connection**: Use the Test button to verify connectivity.
4. **Start Using**: Execute the `google-gemini-send-message` command for AI interactions.

### Vertex AI (Service Account)

1. **Create a Service Account**: In the Google Cloud Console, go to **IAM & Admin** > **Service Accounts** and create a service account with the **Vertex AI User** role.
2. **Generate a JSON Key**: On the service account page, create a new JSON key and download it.
3. **Configure Integration**: Add a new GoogleGemini integration instance, set Authentication Type to **Vertex AI Service Account**, and paste the full JSON key contents into the Service Account Key field.
4. **Set Project ID**: Enter your Google Cloud Project ID.
5. **Set Location**: Enter the location (default: `global`). Use `us-central1`, `europe-west4`, etc. for regional endpoints.
6. **Test Connection**: Use the Test button to verify connectivity.

## Troubleshooting and Tips

- Ensure your API key has access to the Generative Language API.
- Verify your Cortex XSOAR or XSIAM instance can access the configured endpoint.
- Check that the specified model is available in your region.
- Review usage quotas and rate limits for your API key or project.
- The integration attempts to use models not included in the official list and issues a warning.
- Ensure the service account has the `roles/aiplatform.user` role and the Vertex AI API is enabled in your project.
- For AI Studio, use the server URL `https://generativelanguage.googleapis.com`. For Vertex AI, the URL auto-switches to `https://aiplatform.googleapis.com` by default.
