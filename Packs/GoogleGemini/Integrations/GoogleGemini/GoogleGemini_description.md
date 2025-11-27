# Google Gemini Integration

The Google Gemini integration provides seamless access to Google's advanced large language models from within Cortex XSOAR, empowering analysts with intelligent AI assistance for investigation workflows and decision-making processes. This integration enables AI-powered chat conversations, text analysis, and natural language processing capabilities for enhanced security automation. Multiple Gemini models are supported, including 2.0 Flash and 1.5 Pro variants.


## Setup Instructions

1. **Obtain API Key**: Visit [Google AI Studio](https://makersuite.google.com/app/apikey) to create an API key.
2. **Configure Integration**: Add a new GoogleGemini integration instance with your API key.
3. **Test Connection**: Use the Test button to verify connectivity.
4. **Start Using**: Execute the `google-gemini-send-message` command for AI interactions.

## Troubleshooting

- **API Key Issues**: Ensure your API key has access to the Generative Language API.
- **Network Connectivity**: Verify your XSOAR instance can reach https://generativelanguage.googleapis.com.
- **Model Availability**: Check that the specified model is available in your region.
- **Rate Limits**: Review usage quotas and rate limits for your API key.
- **Unsupported Models**: The integration will warn but attempt to use models not in the official list.
