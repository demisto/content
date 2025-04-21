Finds a threshold for ML model, and performs an evaluation based on it

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ml |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| yTrue | A list of labels of the test set |
| yPred | A list of dictionaries contain probability predictions for all classes |
| targetPrecision | minimum precision of all classes, ranges 0-1 |
| targetRecall | minimum recall of all classes, ranges 0-1 |
| detailedOutput | if set to 'true', the output will include a full explanation of the confidence threshold meaning |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| GetMLModelEvaluation.Threshold | The found thresholds which meets the conditions of precision and recall | String |
| GetMLModelEvaluation.ConfusionMatrixAtThreshold | The model evaluation confusion matrix for mails above the threshold. | Unknown |
| GetMLModelEvaluation.Metrics | Metrics per each class \(includes precision, true positive, coverage, etc.\) | Unknown |
