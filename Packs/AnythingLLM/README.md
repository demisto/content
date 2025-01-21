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
* Phi

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

## Local System Setup

For local installation of Anything LLM, install it on a host running:

* Linux
* Windows
* Mac

For testing and development, a system with 16GB RAM can run the Llama 3.2 11 Billion parameter and similar small models in 12-14 GB RAM but is relatively slow in question answering using the CPU. For production use, a GPU-based system with sufficient VRAM for your LLM model is recommended.  For example, The Llama 3.3 70 Billion parameter model requires a GPU with 48-64 GB of VRAM.

## XSOAR Integration Configuration

* Generate an API key for the XSOAR integration
* Activate your selected LLM and vector DB
* Configure the XSOAR integration instance with **url** and **apikey**

## Use

For the most accurate results, **query** mode is recommended for chats.  This preloads the chat context based on the initial query with similar results from documents embedded in a workspace and avoids most hallucinations. In a large document, **query** mode does not ensure a complete answer depending on the number of times the query topic is mentioned in the embedded documents and limits on the number of returned similar results and size of the context window in the selected LLM.  Text splitting and chunking can be adjusted from the defaults to better support a specific use case. Adjusting the **similarityThreshold** and **topN** settings in a workspace are often beneficial to optimize the workspace for a use case.

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
!anyllm-workspace-settings workspace="Unit42 Reports" settings="{\"openAiTemp\": \"0.10\", \"similarityThreshold\": \"0.50\", \"openAiHistory\": \"35\", \"topN\": \"8\", \"chatMode\": \"query\"}"
```

# Use Case Development

The Anything LLM content pack provides an interactive environment for data and prompt engineering for developing the steps needed in an automated use case. To use it, create a new incident of type **AI Playground**.  The layout provides two tabs: **Workspace and Document Management** and **AI Playground** for uploading and embedding documents into a workspace for a use case and developing the needed prompts and workspace settings (Mode, Temperature, Similarity, and TopN). Some use cases may require just *Retrieval Augmented Generation* (RAG) where a few, similar pieces of text are retrieved from embedded documents while other use cases may require additional text to be added to the context of an LLM conversation.

The general use case development process is:

* Create an incident with a type of **AI Playground**
* Create a workspace and configure its settings. The **anyllm-workspace-new** command is used to create a workspace
* Upload and embed needed documents in the workspace
* Develop and test prompts with any additional text required (via LLM document or XSOAR text search)
* Once the desired results are achieved, build the playbook and automations needed to automate the use case

## Example Use Cases

* XSOAR Integration Help
* XSOAR Script Help
* XSOAR Help
* XSOAR Natural Language Commands
* Manual Procedure Guidance
* Threat Blog Summaries
* Advisory Summaries
* CVE summaries
* Investigation Summaries 

## Workspace and Document Management

### Workspaces

The **Workspace and Document Management** tab of the incident layout enables management of workspaces and documents. The **Workspaces** section lists the available workspaces and allows configuration of their settings and selecting the current workspace by editing the table and using one of the **Action** options.   For the current workspace, the list of embedded documents in that workspace are displayed in the **Workspace Embedded Documents** section.  The **Action** options you can take there are to **Remove** the embedded document, **Pin** the embedded document to the workspace that makes all the embedded content available in the conversation context, and **Unpin** the embedded document from the workspace.  Care must be taken to not consume all the conversation context space by pinning a large document.

### Documents

The **Documents** section displays all the documents that have been uploaded and are available for embedding in a workspace.  The available **Action** options are **Embed** which embeds the document into the current workspace, or **Delete** which deletes the document from the catalog. Documents with a **Title** prefixed by an XSOAR war room file entry ID are text searchable by first uploading them to the war room and then use the **Process War Room Text File Entry for Upload** button to preprocess the document, followed by the **Upload Processed Information as LLM Document** button.  XSOAR search results from the **AI Playground** can also be processed and uploaded using the **Process Search Results for Upload** button followed by the **Upload Processed Information as LLM Document** button.  External text can also be uploaded as a searchable LLM document using the same process with the **Process Text for Upload** button. In version 2.0 of the content pack, the **Process Web Link for Upload** button uploads the document to the catalog but not as a searchable document.

### Document Embedding

When a document is embedded into a workspace, it is split into up to 1000 character chunks (default configuration). Each text chunk is converted into an array of 384 (default) real numbers and stored in a vector database. A new query is used to search for the TopN (4 - 12) results, whose text is added to the conversation context along with the query and sent to the LLM for a response.  Similarity search of an embedded document returns only the top chunks based on distance (cosine similarity) from the embedded form of the query - much like the distance between two points in 3 dimensional space.  Use of RAG reduces hallucination and allows using data LLM models are not trained on.  In **query** mode, if 0 results are returned in the similarity search of the vector database, the query is aborted with “no relevant documentation” message. You may still get incorrect results if similarity search returns results and there is related information the model was trained on. Prompt engineering addresses this as well as adding text search results to conversation context to supplement RAG results. In **chat** mode, the question uses results from a similarity search but does not require it.

### Document Management

For documents specific to an investigation, they are added to the investigation's war room.  Documents that span use cases and individual investigations, to retain their searchability, a dedicated incident is created the the documents uploaded to that war room.  These incidents should be flagged for long term retention since their XSOAR file entry ID is associated to the investigation IDs.  As an example, Mitre ATT&CK documentation would be uploaded to an incident dedicated to retaining them as searchable documents across many investigations.

## AI Playground

The **AI Playground** tab is where prompts are developed against a workspace and its embedded documents and any additional text from LLM documents and XSOAR searches using the **Text Search...** buttons and adding useful search results to the conversation context with the **Add Search Results to Conversation** button. During ad hoc investigative use, a conversation with investigative value is saved to the war room with the **Save Conversation to the War Room** button.  

## General Tips and Guidance

* Clean uploaded documentation from extraneous text (ie: HTML and PDF formatting and page footers/headers) when embedding a document since data is returned in 1000 character chunks to ensure similarity data being searched for is retrieved. Extraneous text may cause the TopN chunks to be returned without the data needed
* In a workspace, only embed the documents needed for the use case.  It may be advantageous to create a workspace for an investigation, dynamically embed needed documents, then delete the workspace at incident closure
* Depending on the LLM model used, asking three precise questions about A, then B, then C, may give better results than one question about A and B and C. Once the three questions are asked and results in the conversation context, asking the final question about all three results may be more effective
* Once a partial result is achieved and the full conversation context is no longer needed for subsequent questions, start a new conversation thread with no context. Keeping the context small and focused increases accuracy of responses
* An incorrect response in the conversation context pollutes subsequent results. Testing and tuning your approach prevents this
* Setting the workspace **Temperature** to the lowest value supported by your LLM model provides more deterministic results
* If similarity search is not returning the correct results, review the number of chunks being returned. If too few chunks, increase the **Top N** setting or reduce the **Similarity** setting.  If too many chunks are returned without the correct data, increase the **Similarity** setting.  This is where clean data facilitates proper results
* Be aware of the context window size of your LLM model and how it relates to the data you are adding to the conversation context either via similarity search, text search, or pinning an embedded document to a workspace. Filling the context window causes incomplete results
* Context windows are usually specified in tokens and each token may be a character or a word in size. So an 8K context window may support approximately 16K characters
* Larger context windows increases VRAM memory requirements and the time it takes to answer a question
* When searching structured text like YAML or JSON where you need only a set of lines, a regex pattern such as **(?s)\d(?<=[\d\[\].])(.*?:TLS)** helps minimize text added to the conversation context. This is a simple pattern example to: find all the lines starting with either a defanged IP or domain and finishing with a line with ":TLS"

## Example Automation

Below is an example automation to summarize an investigation by looking at the sequence of completed tasks.  In addition to the investigation **id** and **workspace** name, the following **question** was also passed as an argument: *Summarize the task in the following JSON. Please include name, start and completed dates, description and script and script arguments for each task. If it is a condition task, only tell me what branch it took.*

```
import collections
import uuid


def main():
    try:
        incid = demisto.args().get("id", "")
        workspace = demisto.args().get("workspace", "")
        question = demisto.args().get("question", "")
        if incid == "" or workspace == "" or question == "":
            return
        resp = execute_command("core-api-get", { "uri": f"/inv-playbook/{incid}"})
        tasks = {}

        for k, t in resp['response']['tasks'].items():
            if t['type'].lower() in ["regular", "condition", "playbook"] and t['state'].lower() == "completed":
                tasks[t['completedDate']] = t

        sortedtasks = collections.OrderedDict(sorted(tasks.items()))
        results = ""

        for k, v in sortedtasks.items():
            thread_uuid = str(uuid.uuid4())
            execute_command("anyllm-workspace-thread-new", {'workspace': workspace, 'thread': thread_uuid})
            prompt = f"{question}: {json.dumps(v)}"
            results += f"\n{execute_command('anyllm-workspace-thread-chat', {'message': prompt, 'mode': 'chat', 'workspace': workspace, 'thread': thread_uuid})['textResponse']}\n"
            execute_command("anyllm-workspace-thread-delete", {'workspace': workspace, 'thread': thread_uuid})

        return_results(CommandResults(readable_output=results))
    except Exception as ex:
        if thread_uuid != "":
            execute_command("anyllm-workspace-thread-delete", {'workspace': workspace, 'thread': thread_uuid})
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute SummarizeInvestigation. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
```
