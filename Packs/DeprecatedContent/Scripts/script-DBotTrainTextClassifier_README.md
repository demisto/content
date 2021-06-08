Creates a text classifier model using machine learning.
Each line of the text file is sample data, and it has to have a tag.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | phishing, ml |
| Cortex XSOAR Version | 4.1.0+ |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| trainingFileName | The name of the text file (the format is described in the script details). The file should be attached in the War Room. |
| modelStoreListName | The name of the list to store the model binary (as base64). The list must exist in Cortex XSOAR (with any value). |
| precisionThreshold | The precision threshold. The model will be stored only above this threshold. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotTextClassifier.TrainDataSize | The number of training samples. | number |
| DBotTextClassifier.ListName | The model list name in Cortex XSOAR. | Unknown |
| DBotTextClassifier.Precision | The model precision (precent). | number |
| DBotTextClassifier.Recall | The model recall (precent). | number |
