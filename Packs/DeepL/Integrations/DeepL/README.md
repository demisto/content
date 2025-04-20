This integration uses DeepL (https://www.deepl.com/) to translate text or files
This integration was integrated and tested with DeepL

## Configure DeepL in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://api-free.deepl.com) | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### deepl-usage
***
Get current API key usage


#### Base Command

`deepl-usage`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepL.Usage | unknown | Usage statistics of API key | 

### deepl-translate-text
***
Translates input text


#### Base Command

`deepl-translate-text`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | input the text that you want to translate. | Required | 
| source_lang | Select source language. If not selected DeepL will autodetect. Possible values are: BG, CS, DA, DE, EL, EN, ES, ET, FI, FR, HU, IT, JA, LT, LV, NL, PL, PT, RO, RU, SK, SL, SV, ZH. | Optional | 
| target_lang | Target language to translate to. Possible values are: BG, CS, DA, DE, EL, EN-GB, EN-US, EN, ES, ET, FI, FR, HU, IT, JA, LT, LV, NL, PL, PT-PT, PT-BR, PT, RO, RU, SK, SL, SV, ZH. | Required | 
| split_sentences | Sets whether the translation engine should first split the input into sentences. This is enabled by default. Possible values are: "0" - no splitting at all, whole input is treated as one sentence "1" (default) - splits on punctuation and on newlines "nonewlines" - splits on punctuation only, ignoring newlines. Possible values are: 0, 1. | Optional | 
| preserve_formatting | Sets whether the translation engine should respect the original formatting, even if it would usually correct some aspects. Possible values are: "0" (default) "1" The formatting aspects affected by this setting include: Punctuation at the beginning and end of the sentence Upper/lower case at the beginning of the sentence. Possible values are: 0, 1. | Optional | 
| formality | Sets whether the translated text should lean towards formal or informal language. This feature currently only works for target languages "DE" (German), "FR" (French), "IT" (Italian), "ES" (Spanish), "NL" (Dutch), "PL" (Polish), "PT-PT", "PT-BR" (Portuguese) and "RU" (Russian).Possible options are: "default" (default) "more" - for a more formal language "less" - for a more informal language. Possible values are: default, more, less. | Optional | 
| glossary_id | Specify the glossary to use for the translation. Important: This requires the source_lang parameter to be set and the language pair of the glossary has to match the language pair of the request. | Optional | 
| tag_handling | Sets which kind of tags should be handled. Options currently available: "xml" "html". Possible values are: xml, html. | Optional | 
| non_splitting_tags | Comma-separated list of XML tags which never split sentences. | Optional | 
| outline_detection | . | Optional | 
| splitting_tags | Comma-separated list of XML tags which always cause splits. | Optional | 
| ignore_tags | Comma-separated list of XML tags that indicate text not to be translated. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepL.TranslatedText | string | Output of Translation | 

### deepl-submit-document
***
Please note that with every submitted document of type .pptx, .docx or .pdf you are billed a minimum of 50'000 characters with the DeepL API plan, no matter how many characters are included in the document.  Because the request includes a file upload, it must be an HTTP POST request containing multipart/form-data. This call returns immediately after the document was uploaded and queued for translation. Further requests must be sent to the API to get updates on the translation progress or to download the translated document once the translation is finished (see other document request types below).  Once the document is fully uploaded, the translation starts immediately. Please be aware that the uploaded document is automatically removed from the server after the translation is done. You have to upload the document again in order to restart the translation.  The maximum upload limit for any document is 10MB and 1.000.000 characters.


#### Base Command

`deepl-submit-document`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source_lang | Language of the document to be translated.  If this parameter is omitted, the API will attempt to detect the language of the text and translate it. Possible values are: BG, CS, DA, DE, EL, EN, ES, ET, FI, FR, HU, IT, JA, LT, LV, NL, PL, PT, RO, RU, SK, SL, SV, ZH. | Optional | 
| target_lang | Target language to translate to. Possible values are: BG, CS, DA, DE, EL, EN-GB, EN-US, EN, ES, ET, FI, FR, HU, IT, JA, LT, LV, NL, PL, PT-PT, PT-BR, PT, RO, RU, SK, SL, SV, ZH. | Required | 
| file | The document file to be translated. The file name should be included in this part's content disposition. As an alternative, the filename parameter can be used. The following file types and extensions are supported: "docx" - Microsoft Word Document "pptx" - Microsoft PowerPoint Document "pdf" - Portable Document Format "htm / html" - HTML Document "txt" - Plain Text Document Please note that in order to translate PDF documents you need to give one-time consent to using the Adobe API via the account interface. | Required | 
| filename | The name of the uploaded file. Can be used as an alternative to including the file name in the file part's content disposition. | Optional | 
| formality | Sets whether the translated text should lean towards formal or informal language. This feature currently only works for target languages "DE" (German), "FR" (French), "IT" (Italian), "ES" (Spanish), "NL" (Dutch), "PL" (Polish), "PT-PT", "PT-BR" (Portuguese) and "RU" (Russian).Possible options are: "default" (default) "more" - for a more formal language "less" - for a more informal language. Possible values are: default, more, less. | Optional | 
| glossary_id | Specify the glossary to use for the document translation. Important: This requires the source_lang parameter to be set and the language pair of the glossary has to match the language pair of the request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepL.DocumentSubmission | string | Translated Document | 
| DeepL.DocumentSubmission.document_id | string | Document ID returned | 
| DeepL.DocumentSubmission.document_key | string | Document Key returned | 

### deepl-check-document-status
***
The status of the document translation process can be checked by sending a status request to the document specific status URL.


#### Base Command

`deepl-check-document-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| document_key | The document encryption key that was sent to the client when the document was uploaded to the API. | Required | 
| document_id | The document id  that was sent to the client when the document was uploaded to the API. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DeepL.DocumentStatus | string | Returns the status of the submitted document | 
| DeepL.DocumentStatus.billed_characters | number | How many characters were billed. | 
| DeepL.DocumentStatus.document_id | string | ID of the submitted document | 
| DeepL.DocumentStatus.status | string | Status of the translation | 

### deepl-get-document
***
Get the translated document


#### Base Command

`deepl-get-document`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| document_key | The document encryption key that was sent to the client when the document was uploaded to the API. | Required | 
| document_id | The document id  that was sent to the client when the document was uploaded to the API. | Required | 
| filename | Filename to use for the file. Default is TranslatedFile. | Optional | 


#### Context Output

There is no context output for this command.