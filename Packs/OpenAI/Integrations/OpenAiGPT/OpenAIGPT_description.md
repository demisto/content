## OpenAI GPT


### Generate an API Key
1. Sign-up or login to [https://platform.openai.com](https://platform.openai.com).
2. Generate a new API Key at [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys).

### Models & Rate Limits
The integration utilizes the **'Chat Completions'** endpoint merely. Therefore, it will only be possible to configure models that support this endpoint (_https://api.openai.com/v1/chat/completions_). 

For tasks requiring deep understanding and extensive inputs, opt for more advanced models (e.g. gpt-4). These models offer a larger context window, allowing them to process bigger documents, and provide more refined and comprehensive responses.
The more elementary models (e.g. gpt-3.5) often provide shallower answers and input analysis.
- [Models overview](https://platform.openai.com/docs/models/overview)

- Each model has its own requests' rate-limit: Refer to [rate-limits](https://platform.openai.com/docs/guides/rate-limits).


### How to use this integration with XSOAR
#### The following blog post 'Palo Alto Networks - Playbook of the week' by Sameh Elhakim explains how to use this integration in your playbooks:

https://www.paloaltonetworks.com/blog/security-operations/using-chatgpt-in-cortex-xsoar/