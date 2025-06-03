 <~XSIAM>
 
## Overview
BeyondTrust Endpoint Privilege Management (EPM) is a platform for managing user privileges and application control on Windows and macOS devices. 
It supports least privilege policies and simplifies endpoint compliance with centralized management and auditing.
 
## This pack includes:
 
Data normalization capabilities:
    * Modeling rules for BeyondTrust EPM events include computer, activity, and authorization request logs ingested via the S3 Collector on Cortex XSIAM.
    * The ingested BeyondTrust EPM logs can be queried in XQL Search using the *`beyondtrust_epm_raw`* dataset.
   
***
 
## Data Collection
 
### AWS side
Sign in to your AWS account and create a dedicated Amazon S3 bucket, which collects the generic logs that you want to capture.

For more information on creating an S3 bucket,  [see Ingest Generic Logs from Amazon S3.](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3) for further instructions on how to create a S3 bucket.
 
### BeyondTrust EPM side
Add the AWS S3 Bucket in EPM
1. Select Configuration, and then select SIEM Settings.
2. Select Enable SIEM Integration to turn on the feature.
3. From the Integration Type list, select S3
4. Enter the details for your storage site:
    - Access Key ID: Enter the value created when you added the user.
    - Secret Access Key: Enter the value created when you added the user.
    - Bucket: Enter the name of the S3 bucket.
    - Region: Select or search for the name of the region where your storage bucket resides.
5. Select the data format: CIM - Common Information Model or ECS - Elastic Common Schema.
6. Select Server-Side Encryption to encrypt files sent to the S3 bucket using the default AWS encryption key.
7. Click Validate Settings to test the connection to your storage site.
8. Click Save Settings.
 
For more information [Link to the official docs](https://docs.beyondtrust.com/epm-wm/docs/welcome-to-endpoint-privilege-management-for-windows-and-mac).
 
### Connect Cortex XSIAM to the AWS S3 bucket.
To connect Cortex XSIAM to the AWS S3 bucket, follow the below steps.
1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source**.
2. If you have already configured an **Amazon S3 Collector**, select the **3 dots** and then select **+ Add New Instance**. If not, select **+ Add Data Source**, search for "Amazon S3" and then select **Connect**.
4. Set the following values:
 
    | Parameter    | Value                                                                                                                                           |
    |:-------------|:------------------------------------------------------------------------------------------------------------------------------------------------|                 
    | `SQS URL`    | For more information, see  [Configure an Amazon Simple Queue Service (SQS).](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3). |
    | `Name`       | BeyondTrust EPM Logs.                 |
    | `AWS Client ID`     |                                                                                                                                   |
    | `AWS Client Secret`    |                                                                                                                                  |
    | `Log Type`     | Generic.                                                                                                                                  |
    | `Log Format`    | Select the relevant log format.                                                                                                                                 |
    | `Vendor`     | Enter BeyondTrust.                                                                                                                                  |
    | `Product`    | Enter EPM.                                                                                                                                 |
    | `Compression`    | Select the desired compression.                                                                                                                                 |
 
For more information, see this [Ingest Generic Logs from Amazon S3.](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3).
 
</~XSIAM>