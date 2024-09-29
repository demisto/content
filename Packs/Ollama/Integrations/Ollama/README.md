Integrate with open source LLMs using Ollama. With an instance of Ollama running locally you can use this integration to have a conversation in an Incident, download models, and create new models.
## Configure Ollama in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Protocol | HTTP or HTTPS | False |
| Server hostname or IP | Enter the Ollama IP or hostname | True |
| Port | The port Ollama is running on | True |
| Path | By default Ollama's API path is /api, but you may be running it behind a proxy with a different path. | True |
| Trust any certificate (not secure) | Trust any certificate \(not secure\) | False |
| Use system proxy settings | Use system proxy settings | False |
| Cloudflare Access Client Id | If Ollama is running behind CLoudflare ZeroTrust, provide the Service Access ID here. | False |
| Cloudflare Access Client Secret | If Ollama is running behind CLoudflare ZeroTrust, provide the Service Access Secret here. | False |
| Default Model | Some commands allow you to specify a model. If no model is provided, this value will be used. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ollama-list-models

***
Get a list of all available models

#### Base Command

`ollama-list-models`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ollama.models | unknown | Output of the command | 

### ollama-model-pull

***
Pull a model

#### Base Command

`ollama-model-pull`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | Name of model to pull. See https://ollama.com/library for a list of options. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ollama.pull | unknown | Output of the command | 

### ollama-model-delete

***
Delete a model

#### Base Command

`ollama-model-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The name of the model to delete. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ollama.delete | unknown | Output of the command | 

### ollama-conversation

***
General chat command that tracks the conversation history in the Incident.

#### Base Command

`ollama-conversation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The model name. | Optional | 
| message | The message to be sent. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ollama.history | unknown | Output of the command | 

### ollama-model-info

***
Show information for a specific model.

#### Base Command

`ollama-model-info`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | name of the model to show. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ollama.show | unknown | Output of the command | 

### ollama-model-create

***
Create a new model from a Modelfile.

#### Base Command

`ollama-model-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | name of the model to create. | Required | 
| model_file | contents of the Modelfile. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ollama.create | unknown | Output of the command | 

### ollama-generate

***
Generate a response for a given prompt with a provided model. Conversation history IS NOT tracked.

#### Base Command

`ollama-generate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| model | The model name. | Optional | 
| message | The message to be sent. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ollama.generate | unknown | Output of the command | 