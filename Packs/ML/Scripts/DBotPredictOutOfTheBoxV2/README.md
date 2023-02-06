Predict phishing incidents using the out-of-the-box pre-trained model.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | phishing, ml |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| emailSubject | Subject of the email. |
| emailBody | Body of the email. |
| emailBodyHTML | HTML body of the email. Only use this field if the emailBody argument is empty. |
| topWordsLimit | Maximum number of positive/negative words to return for the model decision.  |
| wordThreshold | Threshold to determine word importance \(range 0-1\). Default is 0.05. |
| minTextLength | Minimum number of characters for the prediction. |
| labelProbabilityThreshold | The label probability threshold. Default is 0. |
| confidenceThreshold | The confidence threshold. The model will provide predictions only if their confidence is above this threshold. |
| returnError | Whether to return an error when there is no prediction. Default is "true". |
| setIncidentFields | Whether to set Cortex XSOAR out-of-the-box DBot fields. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotPredictPhishingWords.Label | The predicted label. | String |
| DBotPredictPhishingWords.Probability | The predicted probability \(range 0-1\). | Number |
| DBotPredictPhishingWords.PositiveWords | A list of words in the input text that supports the model decision. | Unknown |
| DBotPredictPhishingWords.NegativeWords | A list of words in the input text that do not support the model decision. These words better support a different classification class. | Unknown |
| DBotPredictPhishingWords.TextTokensHighlighted | The input text \(after pre-processing\) with the positive words that support the model decision. | String |
