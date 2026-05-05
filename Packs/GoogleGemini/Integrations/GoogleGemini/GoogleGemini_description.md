# Google Gemini Integration

The Google Gemini integration provides seamless access to Google's advanced large language models from within Cortex XSOAR, empowering analysts with intelligent AI assistance for investigation workflows and decision-making processes. This integration enables AI-powered chat conversations, text analysis, and natural language processing capabilities for enhanced security automation. Multiple Gemini models are supported, including 2.0 Flash and 1.5 Pro variants.

This integration supports two authentication modes:
- **AI Studio API Key**: For use with [Google AI Studio](generativelanguage.googleapis.com).
- **Vertex AI Service Account**: For use with [Google Cloud Vertex AI](aiplatform.googleapis.com).


## AI Studio

1. In [Google AI Studio](https://makersuite.google.com/app/apikey), create an API key.
2. In Cortex XSOAR, add a new GoogleGemini integration instance.  
3. Set **Authentication Type** to `AI Studio API Key`, and enter your API key.
4. Click **Test** to verify the connectivity.
4. Run the `google-gemini-send-message` command for AI interactions.

## Vertex AI

1. In the Google Cloud Console, go to **IAM & Admin** > **Service Accounts** and create a service account with the Vertex AI User role.
2. On the service account page, create a new JSON key and download it.
3. In Cortex XSOAR, add a new GoogleGemini integration instance.  
4. Set **Authentication Type** to `Vertex AI Service Account` and paste the full JSON key contents into the **Service Account Key** field.
5. Enter your Google Cloud **Project ID**.
5. **Set Location**: Enter the location (default: `global`). Use `us-central1`, `europe-west4`, etc. for regional endpoints.
7. Click **Test** to verify connectivity.

## Troubleshooting and Tips

- Ensure your API key has access to the Generative Language API.
- Verify your Cortex XSOAR instance can access the configured endpoint.
- Check that the specified model is available in your region.
- Review usage quotas and rate limits for your API key or project.
- The integration attempts to use models not included in the official list and issues a warning.
- Ensure the service account has the `roles/aiplatform.user` role and the Vertex AI API is enabled in your project.
- **Server URL**: For AI Studio, use `https://generativelanguage.googleapis.com`. For Vertex AI, the URL auto-switches to `https://aiplatform.googleapis.com` if left at the default.
