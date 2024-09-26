Evaluates an ML model in production.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies

---
This script uses the following commands and scripts.

* GetIncidentsByQuery
* GetMLModelEvaluation

## Used In

---
This script is used in the following playbooks and scripts.

* EvaluateMLModllAtProduction-Test

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| incidentTypes | A common-separated list of incident types by which to filter. |
| incidentsQuery | The incident query to fetch the training data for the model. |
| emailTagKey | The field name with the email tag. Supports a comma-separated list, the first non-empty value will be taken. |
| emailPredictionKey | The field name with the model prediction. |
| emailPredictionProbabilityKey | The field name with the model prediction probability. |
| modelTargetAccuracy | The model target accuracy, between 0 and 1. |
| phishingLabels | A comma-separated list of email tags values and mapping. The script considers only the tags specified in this field. You can map label to another value by using this format: LABEL:MAPPED_LABEL. For example, for 4 values in email tag: malicious, credentials harvesting, inner communitcation, external legit email, unclassified. While training, we want to ignore "unclassified" tag, and refer to "credentials harvesting" as "malicious" too. Also, we want to merge "inner communitcation" and "external legit email" to one tag called "non-malicious". The input will be: malicious, credentials harvesting:malicious, inner communitcation:non-malicious, external legit email:non-malicious |
| additionalFields | A comma-separated list of incident field names to include in the results file. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| EvaluateMLModllAtProduction.EvaluationScores | The model evaluation scores \(precision, coverage, etc.\) for the found threshold. | Unknown |
| EvaluateMLModllAtProduction.ConfusionMatrix | The model evaluation confusion matrix for the found threshold. | Unknown |
| EvaluateMLModllAtProductionNoThresh.EvaluationScores | The model evaluation scores \(precision, coverage, etc.\) for threshold = 0. | Unknown |
| EvaluateMLModllAtProductionNoThresh.ConfusionMatrix | The model evaluation confusion matrix for threshold = 0. | Unknown |
