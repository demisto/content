AWS Sagemaker - Cortex XSOAR Phishing Email Classifier
## Configure AWS Sagemaker in Cortex


| **Parameter** | **Required** |
| --- | --- |
| AWS access key | True |
| AWS secret key | True |
| AWS Region code | False |
| Endpoint Name | True |
| Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### predict-phishing
***
Classify input text (usually email content)


#### Base Command

`predict-phishing`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| inputText | The input text (usually email subject + body). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotPhishingPrediction.Label | string | The predicated label: malicious \\ other | 
| DBotPhishingPrediction.Probability | number | The predication probability \(range 0-1\) | 


#### Command Example
```!predict-phishing inputText="Dear Info, Please confirm account password...", "Major Update: General Availability feedback..."```