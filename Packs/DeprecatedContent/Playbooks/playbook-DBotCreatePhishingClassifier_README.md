Deprecated. Use "DBot Create Phishing Classifier V2" playbook instead. Create a phishing classifier using machine learning technique, based on email content

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Base64ListToFile
* DBotPredictPhishingEvaluation
* DBotPreparePhishingData
* DBotTrainTextClassifier

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| modelListStoreName | The name of Demisto list to store the model | phishing_model | Optional |
| emailTextKey | Incident key to extract email body text | details | Optional |
| emailSubjectKey | Incident key to extract email subject | emailsubject | Optional |
| emailTagKey | Incident key expression to extract email tag | closeReason | Optional |
| phishingLabels | Comma-separated values of email tags values and mapping. The script going to consider only the tags specify in this field. You can map label to another value by using this format: LABEL:MAPPED_LABEL. For example: let's say we have 4 values in email tag: malicious, credentials harvesting, inner communitcation, external legit email, unclassified. While training, we want to ignore "unclassified" tag, and refer to "credentials harvesting" as "malicious" too. Also, we want to merge "inner communitcation" and "external legit email" to one tag called "non-malicious". The input will be: malicious, credentials harvesting:malicious, inner communitcation:non-malicious, external legit email:non-malicious | * | Optional |
| incidentsTrainingQuery | The incidents query to fetch the training data for the model | type:Phishing and created:&gt;="180 days ago" and created:&lt;"7 days ago" | Optional |
| incidentsEvaluationQuery | The incidents query to fetch the test data for the model | type:Phishing and created:&gt;="7 days ago" | Optional |
| maxIncidentsToFetchOnTraining | Maximum number of incidents to fetch while training the model | 2000 | Optional |
| isContextNeeded | Is context data needed to get email text\\subject\\tag value? | no | Optional |
| historicalDataFileListName | The name of demisto list contains historical data samples for the algorithm |  | Optional |
| hashData | Preform hash function to the words \(to anonymize the data\). Choose between yes/no | no | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotPredictPhishingEvaluation.F1 | F1 score \(0-1\) | number |
| DBotPredictPhishingEvaluation.Precision | Precision score \(0-1\) | number |
| DBotTextClassifier.ListName | Model list name in Demisto | unknown |

## Playbook Image
---
![DBot Create Phishing Classifier](Insert the link to your image here)