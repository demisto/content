Amazon Web Services Bedrock service integration to Cortex XSOAR.
This integration was integrated and tested with version 1.0 of AWS Bedrock.

## Configure AWS Bedrock on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS Bedrock.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | AWS Default Region |  | False |
    | Role Arn |  | False |
    | Role Session Name |  | False |
    | Role Session Duration |  | False |
    | Access Key |  | False |
    | Access Key |  | False |
    | Secret Key |  | False |
    | Secret Key |  | False |
    | Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
    | Retries |  | False |
    | PrivateLink service URL |  | False |
    | STS PrivateLink URL |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-bedrock-ask-question

***
Ask a question to AWS Amazon Bedrock.

#### Base Command

`aws-bedrock-ask-question`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| question | The question to be sent to AWS Bedrock. | Optional | 
| model | Model to use in AWS Bedrock. Default is anthropic.claude-v2. | Required | 
| max_tokens_to_sample | Model to use in AWS Bedrock. Default is 300. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Bedrock.Response | String | The response replied by AWS Bedrock API | 
