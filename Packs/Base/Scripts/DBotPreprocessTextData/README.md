Pre-process text data for the machine learning text classifier.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* DBot Create Phishing Classifier V2
* DBot Create Phishing Classifier V2 From File
* Get Mails By Folder Pathes
* Get Mails By Folder Paths

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | The input file entry ID or the file content \(as a string\). |
| removeShortTextThreshold | Sample text for which the total number words are less than or equal to this number will be ignored. |
| dedupThreshold | Remove emails with similarity greater than this threshold, range 0-1, where 1 is completly identical. |
| textFields | A comma-separated list of incident field names with the text to process. You can also use "\|" if you want to choose the first non-empty value from a list of fields. |
| inputType | The input type. |
| preProcessType | Text pre-processing type. The default is "json". |
| cleanHTML | Whether to remove HTML tags. Default is "true". |
| whitelistFields | A comma-separate list of fields inside the JSON by which to filter. |
| hashSeed | If non-empty, hash every word with this seed. |
| outputFormat | The output file format. |
| outputOriginalTextFields | Whether to add the original text fields to the output. Default is "false". |
| language | The language of the input text. Default is "Any". Can be "Any", "English", "German", "French", "Spanish", "Portuguese", "Italian", "Dutch", or "Other". If "Any"  or "Other" is selected, the script preprocess the entire input, no matter what its acutual language is. If a specific language is selected, the script filters out any other language from the output text. |
| tokenizationMethod | Tokenization method for text. Only required when the language argument is set to "Other". Can be "tokenizer", "byWords", or "byLetters". Default is "tokenizer". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotPreProcessTextData.Filename | The output file name. | String |
| DBotPreProcessTextData.TextField | The original text field inside the file. | String |
| DBotPreProcessTextData.TextFieldProcessed | The processed text field inside the JSON file. | String |
| DBotPreProcessTextData.FileFormat | The output file format. | String |
