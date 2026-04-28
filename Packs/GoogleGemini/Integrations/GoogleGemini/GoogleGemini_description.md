# Google Gemini Integration

The Google Gemini integration provides seamless access to Google's advanced large language models from within Cortex XSOAR, empowering analysts with intelligent AI assistance for investigation workflows and decision-making processes. This integration enables AI-powered chat conversations, text analysis, and natural language processing capabilities for enhanced security automation. Multiple Gemini models are supported, including 2.0 Flash and 1.5 Pro variants.

Supports two authentication modes:
- **AI Studio API Key**: For use with Google AI Studio (generativelanguage.googleapis.com)
- **Vertex AI Service Account**: For use with Google Cloud Vertex AI (aiplatform.googleapis.com)


## Setup Instructions (AI Studio)

1. **Obtain API Key**: Visit [Google AI Studio](https://makersuite.google.com/app/apikey) to create an API key.
2. **Configure Integration**: Add a new GoogleGemini integration instance, set Authentication Type to "AI Studio API Key", and enter your API key.
3. **Test Connection**: Use the Test button to verify connectivity.
4. **Start Using**: Execute the `google-gemini-send-message` command for AI interactions.

## Setup Instructions (Vertex AI)

1. **Create a Service Account**: In the Google Cloud Console, go to IAM & Admin > Service Accounts and create a service account with the "Vertex AI User" role.
2. **Generate a JSON Key**: On the service account page, create a new JSON key and download it.
3. **Configure Integration**: Add a new GoogleGemini integration instance, set Authentication Type to "Vertex AI Service Account", and paste the full JSON key contents into the Service Account Key field.
4. **Set Project ID**: Enter your Google Cloud Project ID.
5. **Set Location**: Enter the location (default: `global`). Use `us-central1`, `europe-west4`, etc. for regional endpoints.
6. **Test Connection**: Use the Test button to verify connectivity.

## Troubleshooting

- **API Key Issues**: Ensure your API key has access to the Generative Language API.
- **Network Connectivity**: Verify your XSOAR instance can reach the configured endpoint.
- **Model Availability**: Check that the specified model is available in your region.
- **Rate Limits**: Review usage quotas and rate limits for your API key or project.
- **Unsupported Models**: The integration will warn but attempt to use models not in the official list.
- **Vertex AI Auth Errors**: Ensure the service account has the `roles/aiplatform.user` role and the Vertex AI API is enabled in your project.
- **Server URL**: For AI Studio, use `https://generativelanguage.googleapis.com`. For Vertex AI, the URL auto-switches to `https://aiplatform.googleapis.com` if left at the default.
