# Google Gemini Pack

In today's rapidly evolving threat landscape, security teams need intelligent analysis capabilities to process large volumes of data, generate insights, and accelerate incident response. The Google Gemini pack brings Google's advanced AI models directly into your XSOAR workflows, enabling natural language processing, content analysis, and intelligent automation for security operations.

## What does this pack do?

This pack provides the following capabilities:

- **Intelligent Text Analysis**: Process and analyze security data, logs, and incident details using Google's advanced language models
- **Natural Language Queries**: Ask questions about security events and get contextual responses in plain language  
- **Content Generation**: Generate summaries, reports, and documentation based on incident data and investigation findings
- **Conversational AI**: Maintain conversation context across multiple interactions for complex analysis workflows
- **Flexible Model Selection**: Choose from multiple Gemini models including the latest Gemini 2.0 Flash for optimal performance
- **Configurable Parameters**: Fine-tune AI responses with temperature, top-p, top-k, and token limit controls

The pack contains the **GoogleGemini** integration that connects to Google's Generative AI API, allowing you to incorporate powerful language model capabilities into your security automation and investigation processes. The integration supports both **Google AI Studio** (API key) and **Google Cloud Vertex AI** (service account) authentication.

## Before You Start

### Requirements

- Cortex XSOAR version 6.10.0 or later
- One of the following authentication methods:
  - A Google AI Studio API key with access to the Generative Language API
  - A Google Cloud service account with the **Vertex AI User** role
- Network connectivity to `https://generativelanguage.googleapis.com` (AI Studio) or `https://aiplatform.googleapis.com` (Vertex AI)

### Option A: Getting Your AI Studio API Key

1. Visit the [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key or use an existing one
3. Ensure the key has access to the Generative Language API

### Option B: Setting Up Vertex AI Service Account

1. In the Google Cloud Console, go to **IAM & Admin** > **Service Accounts**
2. Create a service account with the **Vertex AI User** role (`roles/aiplatform.user`)
3. Generate a JSON key and download it
4. Ensure the Vertex AI API is enabled in your project

## Configuration

1. In XSOAR, navigate to **Settings** > **Integrations**
2. Search for "Google Gemini" and add a new instance
3. Set the **Authentication Type** to either "AI Studio API Key" or "Vertex AI Service Account"
4. Configure the following parameters:

**Common Parameters:**

- **Model**: Select a Gemini model or enter a custom model name
- **Max Tokens**: Maximum response length (default: 1024)
- **Temperature**: Controls randomness (0.0-2.0, optional)
- **Top P**: Nucleus sampling parameter (optional)
- **Top K**: Top-k sampling parameter (optional)

**AI Studio Parameters:**

- **API Key**: Your Google AI API key

**Vertex AI Parameters:**

- **Service Account Key (JSON)**: The full JSON key contents for your service account
- **Project ID**: Your Google Cloud Project ID
- **Location**: Google Cloud location (e.g., `global`, `us-central1`; defaults to `global`)

## Using the Integration

### Basic Usage

Use the `google-gemini-send-message` command to send prompts to the AI model:

```
!google-gemini-send-message prompt="Analyze this suspicious email and identify potential IOCs"
```

### With Conversation History

Maintain context across multiple exchanges:

```
!google-gemini-send-message prompt="What are the next investigation steps?" history='[{"role":"user","parts":[{"text":"Previous question"}]},{"role":"model","parts":[{"text":"Previous response"}]}]'
```

### With Automatic Conversation Management

Enable conversation history management to automatically maintain context:

```
!google-gemini-send-message prompt="Analyze this alert" save_conversation=true
```

When `save_conversation` is enabled, the integration automatically:

- Retrieves previous conversation context from `${GoogleGemini.Chat.History}`
- Includes the last exchange (user + model response) for context
- Saves the complete updated conversation history for future use

## Integration Commands

- **google-gemini-send-message**: Send a prompt to Google Gemini and receive an AI-generated response

## Troubleshooting

- **API Key Issues**: Ensure your API key has access to the Generative Language API
- **Vertex AI Auth Errors**: Ensure the service account has the `roles/aiplatform.user` role and the Vertex AI API is enabled in your project
- **Server URL**: For AI Studio, use `https://generativelanguage.googleapis.com`. For Vertex AI, the URL auto-switches to `https://aiplatform.googleapis.com` if left at the default
- Check network connectivity to Google's API endpoints  
- Verify that the selected model is available in your region
- Review rate limits and usage quotas for your API key or project

For additional support, refer to the [Google AI documentation](https://ai.google.dev/) or contact the pack maintainer.
