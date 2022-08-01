This integration uses nltk to compare with word and Brown corpuses. Use the test command while setting up the integration to download the corpus data.
This integration was integrated and tested with version xx of Dictionary

## Configure Dictionary on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Dictionary.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### find-english-words
***
Finds English words in the given text


#### Base Command

`find-english-words`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| text | Text input to search English words. | Required | 
| corpus | NLTK Corpus to check against. Possible values are: nltk-words, brown, webtext, reuters. | Required | 
| removePunctuation | Do you want to remove punctuation from the text before comparing with the corpus?. Possible values are: Yes, No. Default is Yes. | Optional | 
| lemmatize | Do you want to lemmatize (contexually remove inflectional endings only and return the base or dictionary form of a word) the text before comparing with the corpus?. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


