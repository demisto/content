Predict text label using a pre-trained machine learning phishing model, and get the most important words used in the classification decision.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml, phishing |
| Cortex XSOAR Version | 5.0.0 |

## Used In
---
This script is used in the following playbooks and scripts.
* Phishing Investigation - Generic v2

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| modelName | The model name \(or list name\) in Demisto. |
| hashSeed | Seed for the hash function, at the pre-process stage. |
| emailSubject | Subject of the email. |
| emailBody | Body of the email. |
| emailBodyHTML | HTML body of the email. Only use this field if the emailBody argument is empty. |
| topWordsLimit | Maximum number of positive/negative words to return for the model decision. Default is 20. |
| wordThreshold | Threshold to determine word importance \(range 0-1\). Default is 0.05. |
| modelStoreType | How the model is stored in Demisto. Can be "list" or "mlModel". Default is "list". |
| minTextLength | Minimum number of characters for the prediction. |
| labelProbabilityThreshold | The label probability threshold. Default is 0.8. |
| confidenceThreshold | The confidence threshold. The model will provide predictions only if their confidence is above this threshold. |
| returnError | Whether to return an error when there is no prediction. Default is "true". |
| setIncidentFields | Whether to set Demisto out-of-the-box DBot fields. |
| language | The language of the input text. Default is "Any". Can be "Any", "English", "German", "French", "Spanish", "Portuguese", "Italian", "Dutch", or "Other". If "Any"  or "Other" is selected, the script preprocess the entire input, no matter what its acutual language is. If a specific language is selected, the script filters out any other language from the output text. |
| tokenizationMethod | Tokenization method for text. Only required when the language argument is set to "Other". Can be "tokenizer", "byWords", or "byLetters". |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotPredictPhishingWords.Label | The predicted label. | String |
| DBotPredictPhishingWords.Probability | The predicted probability \(range 0-1\). | Number |
| DBotPredictPhishingWords.PositiveWords | A list of words in the input text that supports the model decision. | Unknown |
| DBotPredictPhishingWords.NegativeWords | A list of words in the input text that do not support the model decision. These words better support a different classification class. | Unknown |
| DBotPredictPhishingWords.TextTokensHighlighted | The input text \(after pre-processing\) with the positive words that support the model decision. | String |
