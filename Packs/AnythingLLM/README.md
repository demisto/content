# Anything LLM 
This content pack contains an integration for Anything LLM that supports using Retrieval Augmented Generation (RAG) with an LLM and user documents embedded in a vector DB.  The LLM and vector DB can be fully local for maximum data privacy or configured to use cloud-based services such as OpenAI. A variety of LLMs and vector DBs are supported. Anything LLM itself can be installed on customer infrastructure or accessed as a cloud service. 

### Locally Hosted

#### Example local LLM models:

* Llama3
* Llama2
* Codellama
* Mistral
* Gemma
* Orca

#### Example local vector DBs:

* LanceDB
* Chroma
* Milvus

### Cloud Hosted

#### Example cloud LLM services:

* OpenAI
* Google Gemini
* Anthropic
* Cohere
* Hugging Face
* Perplexity

#### Example cloud vector DB services:

* Pinecode
* QDrant
* Weaviate

## Setup

For local installation of Anything LLM, install it on a host running:

* Linux
* Windows
* Mac

Once Anything LLM is installed:

* Generate an API key for the XSOAR integration
* Activate your selected LLM and vector DB
* Configure the XSOAR integration instance with **url** and **apikey**

## Use

For the most accurated results, **query** mode is recommended for chats.  This preloads the chat context based on the initial query with similar results from documents embedded in a workspace and avoids most hallucinations. In a large document, **query** mode does not ensure a complete answer depending on the number of times the query topic is mentioned in the embedded documents and limits on the number of returned similar results and size of the context window in the selected LLM.  Text splitting and chunking can be adjusted from the defaults to better support a specific use case. Adjusting the **similarityThreshold** and **topN** settings in a workspace are often beneficial to optimize the workspace for a use case.

#### Update Workspace Settings

The following JSON keys are currently supported for updating:

* name                  - workspace name
* openAiTemp            - LLM temperature (0 - 1) where 1 is more creative and 0 is more repeatable
* openAiHistory         - chat history length to keep in context
* openAiPrompt          - prompt 
* similarityThreshold   - vector DB similarity (None, 0.25, 0.50, 0.75)
* topN                  - top N similar results to return to chat context (1 - 12)
* chatMode              - query mode focuses on using the embedded document data, chat mode is traditional LLM chatting (query, chat)
* queryRefusalResponse  - message to respond with when similar results are not found in embedded documents

Example command to update workspace settings:

```
!anyllm-workspace-settings workspace="Unit42 Reports" settings="{\"openAiTemp\": \"0.30\", \"similarityThreshold\": \"0.50\", \"openAiHistory\": \"35\", \"topN\": \"8\", \"chatMode\": \"query\"}"
```
