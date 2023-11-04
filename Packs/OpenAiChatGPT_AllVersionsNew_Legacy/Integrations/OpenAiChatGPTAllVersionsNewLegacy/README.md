This integration provides access to the OpenAI ChatGPT API, which generates human-like responses to text prompts.

OpenAI ChatGPT is a revolutionary conversational AI system that is designed to interact with humans just like real people, this cutting-edge system is capable of understanding human language, responding to complex queries, and even mimicking human personality traits. Using advanced natural language processing techniques, OpenAI ChatGPT can simulate human conversation to an unprecedented degree of accuracy and effectiveness, making it an ideal tool for a wide range of applications, including customer service, virtual assistance, and more.
## Configure OpenAi ChatGPT (All Versions New & Legacy) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for OpenAi ChatGPT (All Versions New & Legacy).
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL: (e.g. https://api.openai.com/) | True |
    | API Key | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | ChatGPT Version | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### chatgpt-send-prompt

***
Send Text Message as a prompt to ChatGPT

#### Base Command

`chatgpt-send-prompt`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| prompt | Add your question or text. | Required | 

#### Context Output

There is no context output for this command.
