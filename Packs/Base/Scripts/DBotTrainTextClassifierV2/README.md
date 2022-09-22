Train a machine learning text classifier.

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

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| input | The input file entry ID or JSON string. |
| modelName | The model name to store in the system. |
| storeModel | Whether to store the model in the system. |
| overrideExistingModel | Whether to override the existing model if a model with the same name exists. Default is "false". |
| targetAccuracy | The target accuracy, between 0 and 1. Default is 0.8. |
| maxBelowThreshold | Maximum nubmer of samples below the threshold \(for the target accuracy\). |
| tagField | The field name with the label. Supports a comma-separated list, the first non-empty value will be taken. |
| textField | The field name with the text to train. |
| phishingLabels | A comma-separated list of email tags values and mapping. The script considers only the tags specified in this field. You can map label to another value by using this format: LABEL:MAPPED_LABEL. For example, for 4 values in email tag: malicious, credentials harvesting, inner communitcation, external legit email, unclassified. While training, we want to ignore "unclassified" tag, and refer to "credentials harvesting" as "malicious" too. Also, we want to     merge "inner communitcation" and "external legit email" to one tag called "non-malicious". The input will be: malicious, credentials harvesting:malicious, inner communitcation:non-malicious, external legit email:non-malicious |
| trainSetRatio | The ratio of the training set to the entire data set, which is used for model evaluation. |
| inputType | The input type. |
| keywordMinScore | Minimum score for a word to be considered as a keyword between 0 and 1. |
| metric | The metric to use for evaluating the model. |
| findKeywords | Whether to extract keywords for the model. Can be "true" or "false". Default is "true". |
| returnPredictionsOnTestSet | Whether to return a file that contains the model's predictions on the test set. Can be "true" or "false". Default is "false". |
| originalTextFields | A comma-separated list of incident fields names with the unprocessed text.<br/>You can also use "\|" if you want to choose the first non-empty value from a list of fields. |
| preProcessType | Text pre-processing type. The default is "json". |
| trainingAlgorithm | The training algorithm to use for training the model. Default is "auto". If "auto" is selected, the training algorithm will be chosen automatically based on the number of incidents per each label.  Use "from_scratch" to train a new model from scratch, based on your incidents only. In general, "from_scratch" will perform better where the number of incidents is high \(500 incidents or more per each verdict\). "fine-tune" trains a model based on the out-of-the-box model. "fine-tune" will perform better when the number of incidents is relatively low. It's possible to train multiple models using different algorithms options, and compare their results. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotPhishingClassifier.ModelName | The model name. | String |
| DBotPhishingClassifier.EvaluationScores | The model evaluation scores \(precision, coverage, etc.\) for the found threshold. | Unknown |
| DBotPhishingClassifier.ConfusionMatrix | The model evaluation confusion matrix for the found threshold. | Unknown |
| DBotPhishingClassifierNoThresh.EvaluationScores | The model evaluation scores \(precision, coverage, etc.\) for threshold = 0. | Unknown |
| DBotPhishingClassifierNoThresh.ConfusionMatrix | The model evaluation confusion matrix for threshold = 0. | Unknown |
