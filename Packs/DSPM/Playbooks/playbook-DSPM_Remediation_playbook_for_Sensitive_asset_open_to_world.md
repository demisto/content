# DSPM Remediation Playbook for Sensitive Asset Open to World

## Overview

The **DSPM Remediation Playbook for Sensitive Asset Open to World** is designed to handle incidents where sensitive assets are exposed to the public. This playbook focuses on remediating vulnerabilities, specifically for Amazon S3 buckets, and manages the incident flow to ensure that sensitive assets are protected and properly mitigated.

The playbook checks the cloud provider, applies public access blocks for AWS S3 buckets, updates risk statuses, and sends notifications to users via Slack in case of successful or unsuccessful remediation attempts.

## Key Features

- Identifies cloud provider (AWS) and applies corresponding public access policies.
- Automates remediation by configuring public access block for S3 buckets.
- Sends Slack notifications to users regarding remediation success or failure.
- Updates DSPM risk status upon successful remediation.
- Tracks and logs any encountered errors during the remediation process.

## Playbook Flow

1. **Identify Cloud Provider**: The playbook checks the cloud provider of the asset (currently supports AWS).
2. **Remediate AWS S3 Bucket**: The playbook configures public access blocks for the identified AWS S3 bucket.
3. **Error Handling**: If errors occur during the mitigation process, a notification is sent, and the user is informed via Slack.
4. **Risk Status Update**: Upon successful remediation, the status of the risk is updated to 'INVESTIGATING' on the DSPM platform.
5. **Final Notifications**: Slack notifications are sent to indicate the success or failure of the remediation.

## Scripts Used

### 1. `aws-s3-put-public-access-block`

- **Description**: This script modifies the PublicAccessBlock configuration for an Amazon S3 bucket to restrict public access.
- **Key Arguments**:
  - `BlockPublicAcls`: Blocks new public ACLs (set to `true`).
  - `BlockPublicPolicy`: Blocks public bucket policies (set to `true`).
  - `bucket`: Name of the S3 bucket (dynamically set from the incident).
- **Step-by-Step**:
  1. Identify the bucket name from the incident.
  2. Call the AWS S3 command with the necessary arguments.
  3. Apply the public access block on the bucket.

### 2. `DSPMOverwriteListAndNotify`

- **Description**: This automation script overwrites a specified list (blocklist) and sends a Slack notification informing the user about the success or failure of a task.
- **Key Arguments**:
  - `list_name`: The name of the block list to overwrite.
  - `message`: Slack message content with information on the outcome.
- **Step-by-Step**:
  1. Overwrite the block list with the task's outcome (success or error).
  2. Send a Slack notification to inform the user.

### 3. `DSPMCheckAndSetErrorEntries`

- **Description**: This script checks for errors in the previous tasks by examining the provided entry IDs. It returns "yes" if errors are found and "no" if not.
- **Key Arguments**:
  - `entry_id`: The ID of the task entries to check for errors.
- **Step-by-Step**:
  1. Retrieve the entry ID from the previous task.
  2. Check if there are any error entries.
  3. Proceed with the appropriate task based on the result (either continue or notify of the error).

### 4. `dspm-update-risk-finding-status`

- **Description**: Updates the risk finding status on the DSPM platform.
- **Key Arguments**:
  - `riskFindingId`: The ID of the risk finding from the incident.
  - `status`: The status to set (e.g., `INVESTIGATING`).
- **Step-by-Step**:
  1. Extract the risk finding ID from the incident.
  2. Call the DSPM API to update the risk status to 'INVESTIGATING'.

### 5. `DSPMIncidentList`

- **Description**: Adds an incident to a list for reprocessing if the remediation fails.
- **Key Arguments**:
  - `incident_data`: The data of the current incident to be added to the list.
- **Step-by-Step**:
  1. Extract the incident object from the playbook.
  2. Add the incident to the DSPM incident list for reprocessing.

## Step-by-Step Script Usage

1. **Start the Playbook**: The playbook begins by identifying the cloud provider of the asset.
2. **Apply AWS S3 Public Access Block**: If the asset is hosted on AWS, the `aws-s3-put-public-access-block` script is executed to restrict public access to the S3 bucket.
3. **Check for Errors**: After applying the public access block, the `DSPMCheckAndSetErrorEntries` script checks if any errors occurred during the process.
4. **Handle Errors**: If an error is found, the playbook sends an error notification using `DSPMOverwriteListAndNotify` and logs the issue. If no errors are found, the playbook proceeds to update the risk finding status.
5. **Update Risk Status**: The `dspm-update-risk-finding-status` script updates the risk finding status to 'INVESTIGATING' on the DSPM platform.
6. **Final Notification**: A final Slack notification is sent to inform the user of the outcome (success or failure) using the `DSPMOverwriteListAndNotify` script.
7. **Reprocessing on Failure**: If any part of the playbook fails, the `DSPMIncidentList` script adds the incident to a list for future reprocessing.