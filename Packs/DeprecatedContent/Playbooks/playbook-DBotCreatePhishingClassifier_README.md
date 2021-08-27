DEPRECATED. Use "DBot Create Phishing Classifier V2" playbook instead. Creates a phishing classifier using machine learning technique, based on the email content.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

## Sub-playbooks
This playbook does not use any sub-playbooks.

## Integrations
This playbook does not use any integrations.

## Scripts
* DBotPredictPhishingEvaluation
* DBotTrainTextClassifier
* DBotPreparePhishingData
* Base64ListToFile

## Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| modelListStoreName | The name of the Cortex XSOAR list to store the model. | phishing_model | Optional |
| emailTextKey | The incident key to extract email body text. | details | Optional |
| emailSubjectKey | The incident key to extract email subject. | emailsubject | Optional |
| emailTagKey | The incident key expression to extract email tag. | closeReason | Optional |
| phishingLabels | The CSV list of email tags values and mapping. The script going to consider only the tags specified in this field. You can map label to another value by using this format: LABEL:MAPPED_LABEL. For example: let's say we have 4 values in email tag: malicious, credentials harvesting, inner communitcation, external legit email, unclassified. While training, we want to ignore "unclassified" tag, and refer to "credentials harvesting" as "malicious" too. Also, we want to merge "inner communitcation" and "external legit email" to one tag called "non-malicious". The input will be: malicious, credentials harvesting:malicious, inner communitcation:non-malicious, external legit email:non-malicious. | * | Optional |
| incidentsTrainingQuery | The incidents query to fetch the training data for the model. | type:Phishing and created:>="180 days ago" and created:<"7 days ago" | Optional |
| incidentsEvaluationQuery | The incidents query to fetch the test data for the model. | type:Phishing and created:>="7 days ago" | Optional |
| maxIncidentsToFetchOnTraining | The maximum number of incidents to fetch while training the model. | 2000 | Optional |
| isContextNeeded | Wether the context data needed to get email text\\subject\\tag value? | no | Optional |
| historicalDataFileListName | The name of Cortex XSOAR list contains historical data samples for the algorithm. | - | Optional |
| hashData | The preform hash function to the words (to anonymize the data). Choose "yes" or "no". | no | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DBotPredictPhishingEvaluation.F1 | The F1 score (0-1). | number |
| DBotPredictPhishingEvaluation.Precision | The precision score (0-1). | number |
| DBotTextClassifier.ListName | The model list name in Cortex XSOAR. | unknown |

## Playbook Image
---
![DBotCreatePhishingClassifier](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/DBot_Create_Phishing_Classifier.png)
