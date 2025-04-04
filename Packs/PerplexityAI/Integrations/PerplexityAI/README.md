Perplexity AI is a web search engine that uses a large language model to process queries and synthesize responses based on web search results.  With a conversational approach, Perplexity AI allows users to ask follow-up questions and receive answers with citations to its sources from the internet.
## Configure Perplexity AI on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Perplexity AI.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | URL for Perplexity AI |  | True |
    | Perplexity AI API Key |  | True |
    | Perplexity AI API Key |  | True |
    | Cloudflare Access Client Id |  | False |
    | Cloudflare Access Client Secret |  | False |
    | Perplexity AI Model | Available models are: sonar,sonar-pro,sonar-deep-research,sonar-reasoning,sonar-reasoning-pro,r1-1776 | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### deepresearch-chat

***
Send a chat message.  You may need to increase the command timeout in "advanced settings" from the default 5 minutes

#### Base Command

`deepresearch-chat`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| systemmessage | The system message to influence how the user message is handled - used in the "system" role. Default is Be precise and concise.. | Optional | 
| usermessage | The user's question - used in the "users" role. | Required | 
| recentfilter | Limit search to recent hour, day, week, month. Possible values are: hour, day, week, month. | Optional | 
| domainfilter | Limit search to these domains. CSV list of domains of up to 3 domains. A '-' in front of the domain excludes it. | Optional | 
| jsonout | Include JSON output in context if yes, with markdown in war room. Possible values are: yes, no. Default is no. | Optional | 
| citations | Include research citations in the output. Possible values are: yes, no. Default is no. | Optional | 
| thinking | Include thinking in the output. Possible values are: yes, no. Default is no. | Optional | 
| contextsize | How much context is returned as results. Possible values are: low, medium, high. Default is medium. | Optional | 

#### Context Output

There is no context output for this command.
