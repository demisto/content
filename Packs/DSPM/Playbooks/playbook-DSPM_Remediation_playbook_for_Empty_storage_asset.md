# DSPM Remediation Playbook for Empty Storage Assets

This playbook is designed to remediate risks associated with empty storage assets across AWS, Azure, and GCP environments. It identifies the cloud provider for the asset and proceeds to delete the storage container or bucket accordingly. Additionally, it sends notifications via Slack to inform stakeholders about the status of the remediation process.

## Playbook Workflow

### Overview:
1. **Identify Cloud Provider**: The playbook first checks which cloud provider (AWS, Azure, or GCP) the asset belongs to.
2. **Remediate Empty Storage Assets**: Based on the cloud provider, the playbook deletes the corresponding storage container or bucket.
3. **Notification**: It sends a notification to Slack to inform users about the status of the remediation, whether successful or if any errors occurred.
4. **Update DSPM Status**: The playbook updates the DSPM risk status to "INVESTIGATING".
5. **Error Handling**: The playbook checks if there are any errors encountered during execution and notifies the users.

---

## Playbook Tasks

### 1. Check the Cloud Provider of the Asset
- **Description**: This task checks whether the asset belongs to AWS, Azure, or GCP.
- **Conditional Logic**: Depending on the cloud provider, the playbook will proceed to the respective task for storage deletion.
  - AWS ➡️ Task: Delete AWS S3 Bucket
  - Azure ➡️ Task: Delete Azure Storage Container
  - GCP ➡️ Task: Delete GCS Bucket

---

### 2. Delete AWS S3 Bucket
- **Task Name**: `aws-s3-delete-bucket`
- **Script**: AWS - S3
- **Description**: Deletes the specified AWS S3 bucket.
- **Arguments**: 
  - `bucket_name`: Name of the bucket to be deleted.

---

### 3. Delete Azure Storage Container
- **Task Name**: `azure-storage-container-delete`
- **Script**: Azure Storage Container
- **Description**: Marks the specified Azure storage container for deletion. Both the container and its contents will be deleted during garbage collection.
- **Arguments**:
  - `container_name`: Name of the container to be deleted.

---

### 4. Delete GCS Bucket
- **Task Name**: `gcs-delete-bucket`
- **Script**: Google Cloud Storage
- **Description**: Deletes the specified Google Cloud Storage bucket.
- **Arguments**:
  - `bucket_name`: Name of the bucket to be deleted.

---

### 5. Check for Errors in Remediation
- **Task Name**: `DSPMCheckAndSetErrorEntries`
- **Script**: Custom script to check if errors occurred during the remediation.
- **Description**: This script checks for errors in the previous tasks. If errors are found, it sets the error messages in the XSOAR context.

---

### 6. Notify Success via Slack
- **Task Name**: `DSPMOverwriteListAndNotify`
- **Description**: This task sends a success message to a Slack channel, informing users that the remediation was successful.
- **Arguments**:
  - `list_name`: The block list name.
  - `message`: Success message sent to Slack.

---

### 7. Notify Failure via Slack
- **Task Name**: `DSPMOverwriteListAndNotify`
- **Description**: If errors are found during remediation, this task sends an error message to Slack, notifying users of the failure.
- **Arguments**:
  - `list_name`: The block list name.
  - `message`: Error message sent to Slack.

---

### 8. Update DSPM Risk Finding Status
- **Task Name**: `dspm-update-risk-finding-status`
- **Script**: DSPM
- **Description**: This task updates the DSPM risk finding status to "INVESTIGATING".
- **Arguments**:
  - `riskFindingId`: The risk finding ID.
  - `status`: Status to be updated to (e.g., INVESTIGATING).

---

### 9. Final Error Check and Notification
- **Task Name**: `DSPMCheckAndSetErrorEntries`
- **Description**: After updating the DSPM risk finding status, this script checks for any errors. If errors are encountered, a Slack notification is sent.

---

## Usage Instructions

1. Ensure that the cloud provider is correctly identified in the incident object.
2. Set up the proper permissions for the respective cloud provider actions:
   - For AWS S3, ensure the playbook has permission to delete buckets.
   - For Azure Storage, ensure the playbook has permission to delete containers.
   - For Google Cloud Storage, ensure the playbook has permission to delete buckets.
3. Set up a Slack integration and configure the Slack channel where the notifications will be sent.
4. Configure the DSPM integration to update the status of risk findings.

---

This playbook streamlines the remediation of empty storage assets across cloud environments, allowing for a seamless workflow with built-in notifications and error handling.