
## OpenAI GPT
### Instance Configuration

- #### Generate an API Key
    1. Sign-up or login to [OpenAI developer platform](https://platform.openai.com).
    2. Generate a new API Key at [OpenAI developer platform - api-keys](https://platform.openai.com/api-keys).

- #### Choose a GPT model to interact with
    1. The integration utilizes the **'Chat Completions'** endpoint merely. Therefore, it will only be possible to configure models that support this endpoint (_https://api.openai.com/v1/chat/completions_). 

    2. For tasks requiring deep understanding and extensive inputs, opt for more advanced models (e.g. gpt-4). These models offer a larger context window, allowing them to process bigger documents, and provide more refined and comprehensive responses.
    The more elementary models (e.g. gpt-3.5) often provide shallower answers and input analysis. 
    Refer to [Models overview](https://platform.openai.com/docs/models/overview) for more information.
  
- #### Text generation setting (Optional)
   
   1. **max-tokens**: The maximum number of tokens that can be generated for the response. (Allows controlling tokens' consumption). Default: unset.
   2. **temperature**: Sets the randomness in responses. Lower values (closer to 0) produce more deterministic and consistent outputs, while higher values (up to 2) increase randomness and variety. It is generally recommended altering this or top_p but not both. Default: 1.
   3. **top_p**: Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Lower values (closer to 0) result in more focused outputs, while higher values (closer to 1) increase diversity. It is generally recommended altering this or temperature but not both. Default: unset.

- #### Click 'Test'


## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.

### gpt-send-message
***
Send a message as a prompt to the GPT model.

`!gpt-send-message message="<MESSAGE_TEXT>"`

#### Input

| **Argument Name**          | **Description**                                                                                                                                             | **Required** |
|----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| message                    | The message to send to the GPT model wrapped with quotes.                                                                                                   | Yes          | 
| reset_conversation_history | Whether to reset conversation history or keep it as context for the sent message. (Conversation history is not reset by default).                           | No           | 
| max_tokens                 | The maximum number of tokens that can be generated for the response. Overrides text generation setting for the specific message sent.                       | No           | 
| temperature                | Sets the randomness in responses. Overrides text generation setting for the specific message sent.                                                          | No           | 
| top_p                      | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Overrides text generation setting for the specific message sent. | No           | 



### gpt-check-email-body
***
Check email body for possible security issues.

`!gpt-check-email-body entryId="<ENTRY_ID_OF_UPLOADED_EML_FILE>"`

#### Input

| **Argument Name**      | **Description**                                                                                                                                             | **Required** |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| entryId                | Entry ID of an uploaded _.eml_ file from the context window.                                                                                                    | Yes          | 
| additionalInstructions | Provide additional instructions for the GPT model when analyzing the email body.                                                                            | No           | 
| max_tokens             | The maximum number of tokens that can be generated for the response. Overrides text generation setting for the specific message sent.                       | No           | 
| temperature            | Sets the randomness in responses. Overrides text generation setting for the specific message sent.                                                          | No           | 
| top_p                  | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Overrides text generation setting for the specific message sent. | No           |

### gpt-check-email-header
***
Check email body for possible security issues.

`!gpt-check-email-header entryId="<ENTRY_ID_OF_UPLOADED_EML_FILE>"`

#### Input

| **Argument Name**      | **Description**                                                                                                                                             | **Required** |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| entryId                | Entry ID of an uploaded _.eml_ file from context window.                                                                                                    | Yes          | 
| additionalInstructions | Provide additional instructions for the GPT model when analyzing the email headers.                                                                         | No           | 
| max_tokens             | The maximum number of tokens that can be generated for the response. Overrides text generation setting for the specific message sent.                       | No           | 
| temperature            | Sets the randomness in responses. Overrides text generation setting for the specific message sent.                                                          | No           | 
| top_p                  | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Overrides text generation setting for the specific message sent. | No           |


### gpt-create-soc-email-template
***
Create an email template out of the conversation context to be sent from the SOC.

`!gpt-create-soc-email-template`

#### Input

| **Argument Name**      | **Description**                                                                                                                                             | **Required** |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| additionalInstructions | Provide additional instructions for the GPT model when analyzing the email headers.                                                                         | No           | 
| max_tokens             | The maximum number of tokens that can be generated for the response. Overrides text generation setting for the specific message sent.                       | No           | 
| temperature            | Sets the randomness in responses. Overrides text generation setting for the specific message sent.                                                          | No           | 
| top_p                  | Enables nucleus sampling where only the top 'p' percent of probable tokens are considered. Overrides text generation setting for the specific message sent. | No           |

