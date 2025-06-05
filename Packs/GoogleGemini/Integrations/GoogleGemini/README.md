# Google Gemini Integration

This integration provides access to Google's Gemini large language models for AI-powered analysis and chat capabilities in XSOAR.

## Configuration

### Parameters

- **Gemini API URL**: The base URL for the Gemini API (default: https://generativelanguage.googleapis.com)
- **API Key**: Your Google Cloud API key with Gemini API access enabled
- **Default Model**: The default Gemini model to use (default: gemini-2.5-flash-preview-05-20)
- **Trust any certificate**: Whether to ignore SSL certificate verification (not recommended for production)
- **Use system proxy settings**: Whether to use system proxy configuration

### Supported Models

- gemini-2.0-flash
- gemini-2.0-flash-lite
- gemini-1.5-flash
- gemini-1.5-flash-8b
- gemini-1.5-pro
- gemini-2.5-flash-preview-05-20
- gemini-2.5-pro-preview-05-06
- gemini-2.0-flash-preview-image-generation
- gemini-2.5-flash-preview-native-audio-dialog
- gemini-2.5-flash-exp-native-audio-thinking-dialog
- text-embedding-004
- models/aqa

## Commands

### googlegemini-chat

Send a chat message to the Gemini AI model.

#### Arguments

- **prompt** (required): The prompt or question to send to the AI model
- **model** (optional): The specific Gemini model to use for this request
- **max_tokens** (optional): Maximum number of tokens in the response (1-10000, default: 10000)
- **temperature** (optional): Temperature for response generation (0.0 to 1.0, default: 0.7)
- **history** (optional): Conversation history in JSON format for maintaining context

#### Example Usage

```
!googlegemini-chat prompt="What is artificial intelligence?"
```

```
!googlegemini-chat prompt="Explain machine learning" model="gemini-1.5-pro" max_tokens="2000" temperature="0.5"
```

```
!googlegemini-chat prompt="Continue our discussion" history='[{"role": "user", "parts": [{"text": "Hello"}]}, {"role": "model", "parts": [{"text": "Hi there!"}]}]'
```

#### Outputs

- **GoogleGemini.Chat.prompt**: The original prompt sent to the model
- **GoogleGemini.Chat.response**: The AI model's response
- **GoogleGemini.Chat.model**: The model used for generation
- **GoogleGemini.Chat.temperature**: The temperature setting used

## Setup Instructions

1. Obtain a Google Cloud API key with Gemini API access
2. Configure the integration with your API key
3. Test the connection using the Test button
4. Start using the googlegemini-chat command for AI interactions

## Troubleshooting

- Ensure your API key has the necessary permissions for Gemini API
- Check that your network allows connections to the Gemini API endpoint
- Verify the model name is correctly specified and supported
- Review rate limits and quotas for your API key
