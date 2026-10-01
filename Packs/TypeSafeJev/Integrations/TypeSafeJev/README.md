Use TypeSafe Jev typed judgments and calibrated probabilities in Cortex XSIAM and XSOAR playbooks.
This integration was integrated and tested with version xx of TypeSafe Jev.

## Configure TypeSafe Jev in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| API Key | The TypeSafe API key used to authenticate Jev requests. Generate or manage keys in the TypeSafe console. | True |
| Model | The default Jev model. Use a pinned version when playbook thresholds have been validated against that version. | False |
| Model (optional free text override) | The optional model name that overrides the selected model. | False |
| Request timeout | The HTTP request timeout in seconds. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### jev-evaluate

***
Evaluate a state against one or more typed TypeSafe questions in a single request.

#### Base Command

`jev-evaluate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | The text or JSON state to evaluate. Valid JSON is sent as structured state; other values are sent as text. | Required | 
| questions | The JSON object whose keys are question IDs and whose values are TypeSafe Noul, Choice, or Score question definitions. | Required | 
| model | The optional model override for this request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TypeSafeJev.Evaluation.model | String | The versioned model that handled the request. | 
| TypeSafeJev.Evaluation.answers | Unknown | The typed answers keyed by the submitted question IDs. | 
| TypeSafeJev.Evaluation.usage.input_tokens | Number | The number of input tokens used by the request. | 
| TypeSafeJev.Evaluation.usage.output_tokens | Number | The number of output tokens reported for the request. | 

### jev-noul

***
Evaluate one yes/no judgment and return the probability that the answer is yes.

#### Base Command

`jev-noul`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | The text or JSON state to evaluate. | Required | 
| instructions | The narrow yes/no judgment to make about the state. | Required | 
| true_criteria | The optional description of what a yes result means. | Optional | 
| false_criteria | The optional description of what a no result means. | Optional | 
| model | The optional model override for this request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TypeSafeJev.Noul.model | String | The versioned model that handled the request. | 
| TypeSafeJev.Noul.probability | Number | The probability of yes, from 0 to 1. | 
| TypeSafeJev.Noul.usage | Unknown | The token usage for the request. | 

### jev-choice

***
Select one option from a defined set and return the complete probability distribution.

#### Base Command

`jev-choice`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | The text or JSON state to evaluate. | Required | 
| instructions | The decision Jev should make about the state. | Required | 
| criteria | The JSON object mapping each option name to its description or null. Include a no-match option when appropriate. | Required | 
| model | The optional model override for this request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TypeSafeJev.Choice.model | String | The versioned model that handled the request. | 
| TypeSafeJev.Choice.choice | String | The selected option. | 
| TypeSafeJev.Choice.probabilities | Unknown | The probability distribution over all supplied options. | 
| TypeSafeJev.Choice.confidence | Number | The confidence derived from the probability distribution. | 
| TypeSafeJev.Choice.usage | Unknown | The token usage for the request. | 

### jev-score

***
Score state against ordered levels and return the weighted score and probability distribution.

#### Base Command

`jev-score`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| state | The text or JSON state to evaluate. | Required | 
| instructions | The dimension Jev should score about the state. | Required | 
| criteria | The JSON array of two to ten ordered, standalone level descriptions. | Required | 
| model | The optional model override for this request. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TypeSafeJev.Score.model | String | The versioned model that handled the request. | 
| TypeSafeJev.Score.score | Number | The probability-weighted score across the ordered levels. | 
| TypeSafeJev.Score.legend | Unknown | The mapping from numeric level to its description. | 
| TypeSafeJev.Score.probabilities | Unknown | The probability distribution over the levels. | 
| TypeSafeJev.Score.confidence | Number | The confidence derived from the probability distribution. | 
| TypeSafeJev.Score.usage | Unknown | The token usage for the request. | 

### jev-list-models

***
List model aliases available to the configured TypeSafe account.

#### Base Command

`jev-list-models`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| TypeSafeJev.Model.name | String | The model name or alias. | 
| TypeSafeJev.Model.description | String | The model description. | 
| TypeSafeJev.Model.release_date | Date | The model release date. | 
