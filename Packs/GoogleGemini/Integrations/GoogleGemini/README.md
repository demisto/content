# Google Gemini Integration

This integration provides access to Google Gemini's large language models for AI-powered analysis and chat capabilities in Cortex XSOAR.

## Configure GoogleGemini in Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Google Gemini.
3. Click **Add instance** to create and configure a new integration instance.

### Instance Configuration Parameters

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The base URL for the Gemini API (default: https://generativelanguage.googleapis.com) | True |
| API Key | Your Google AI API key with Generative Language API access | True |
| Model | Select a Gemini model from the dropdown | True |
| Max Tokens | Maximum number of tokens in the response (default: 1024) | False |
| Temperature | Controls randomness in responses (0.0-1.0) | False |
| Top P | Nucleus sampling parameter | False |
| Top K | Top-k sampling parameter | False |
| Trust any certificate (not secure) | Whether to ignore SSL certificate verification | False |
| Use system proxy settings | Whether to use system proxy configuration | False |

### Supported Models

The integration supports various Gemini models including:

**Stable Models:**

- gemini-2.0-flash
- gemini-2.0-flash-lite  
- gemini-1.5-flash
- gemini-1.5-flash-8b
- gemini-1.5-pro

**Preview Models:**

- gemini-2.5-flash-preview-05-20
- gemini-2.5-pro-preview-06-05
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

1. **Obtain API Key**: Visit [Google AI Studio](https://makersuite.google.com/app/apikey) to create an API key
2. **Configure Integration**: Add a new GoogleGemini integration instance with your API key
3. **Test Connection**: Use the Test button to verify connectivity
4. **Start Using**: Execute the `google-gemini-send-message` command for AI interactions

## Troubleshooting

- **API Key Issues**: Ensure your API key has access to the Generative Language API
- **Network Connectivity**: Verify your XSOAR instance can reach https://generativelanguage.googleapis.com
- **Model Availability**: Check that the specified model is available in your region
- **Rate Limits**: Review usage quotas and rate limits for your API key
- **Unsupported Models**: The integration will warn but attempt to use models not in the official list
