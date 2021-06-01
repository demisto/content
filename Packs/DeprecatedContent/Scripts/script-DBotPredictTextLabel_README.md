Predicts the text label using pre-trained machine learning phishing model.
Note: The training playbook must run successfully first.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | ml, phishing |
| Cortex XSOAR Version | 4.1.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| inputText | The input text to predict on. |
| modelListName | The XSOAR list name that stores the machine learning model. |
| hashData | Whether the input text is hashed. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotPredictTextLabel.Label | The suggested label. | string |
| DBotPredictTextLabel.Probability | The prediction probability.  | number |
| DBotPredictTextLabel.InputTextNumberOfTokens | The number of tokens in the input text. | number |
| DBotPredictTextLabel.InputTextTokens | The input text. | Unknown |
