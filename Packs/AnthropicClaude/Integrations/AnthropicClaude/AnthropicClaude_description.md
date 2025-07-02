## Anthropic Claude


### Generate an API Key
1. Sign-up or login to [https://console.anthropic.com](https://console.anthropic.com).
2. Generate a new API Key at [https://console.anthropic.com/keys](https://console.anthropic.com/keys).

### Models & Rate Limits
The integration utilizes the **'Messages'** endpoint. Therefore, it will only be possible to configure models that support the following endpoint: _https://api.anthropic.com/v1/messages_.

_Claude models offer different capabilities, with more advanced models providing better reasoning and comprehension capabilities._

For tasks requiring deep understanding and extensive inputs, opt for more advanced models (e.g. claude-3-opus). These models offer a larger context window, allowing them to process bigger documents, and provide more refined and comprehensive responses.
The more basic models (e.g. claude-3-haiku) often provide simpler answers but are faster and less costly.
- [Models overview](https://docs.anthropic.com/claude/docs/models-overview)

- Each model has its own rate limits: Refer to [rate-limits](https://docs.anthropic.com/claude/reference/rate-limits).


### How to use this integration with XSIAM
This integration allows you to:
- Send messages to Claude models and receive AI-generated responses
- Analyze email headers and bodies for security threats
- Generate SOC email templates

---