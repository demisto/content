<~XSIAM>

# Cisco Umbrella cloud security

### Collect Access Logs from Cisco Umbrella cloud security

#### AWS - S3 bucket

**On AWS**

Ensure you have the below prerequisites:

1. A login to Amazon AWS service
2. A bucket configured in Amazon S3 to be used for storing logs.

See this [doc](https://docs.umbrella.com/deployment-umbrella/docs/setting-up-an-amazon-s3-bucket#prerequisites) for further instructions on how to create a S3 bucket, and how to configure it for your needs.

**On Cisco Umbrella cloud security**

1. Navigate to **Admin** > **Log Management** and select **Use your company-managed Amazon S3 bucket**.
2. In the **Bucket Name** field type the bucket name you created in Amazon S3 and click **Verify**.
3. After Cisco Umbrella verifies your bucket, it saves a file called **README_FROM_UMBRELLA.txt** in the bucket.
   Open the file and copy and paste the token listed in it into **Token Number** and click **Save**.

For more information, refer to the official Cisco Umbrella [documentation](https://docs.umbrella.com/deployment-umbrella/docs/setting-up-an-amazon-s3-bucket#enable-logging).

At the end of this process, you should have a folder created for each type of log in your bucket:

- auditlogs
- dnslogs
- proxylogs

Note:
Make sure that the Log schema version is configure to **v8**.
More information can be found [here](https://docs.umbrella.com/deployment-umbrella/docs/log-formats-and-versioning)

**On Cortex XSIAM:**

1. Navigate to **Settings** > **Data Sources** > **Add Data Source**.
2. Click **Amazon S3**.
3. Click **Connect** or **Connect Another Instance**.
4. Set the following values:
   - SQS URL - Refer to Configure an Amazon Simple Queue Service (SQS) [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3).
   - Name as `Cisco Umbrella`
   - AWS Client ID
   - AWS Client Secret
   - Log Type as `Generic`
   - Log Format as `Raw`
   - Vendor as `cisco`
   - Product as `umbrella`
   - Compression as `gzip`
   - Multiline Parsing Regex as `^\"\d{4,}`

For more information, see this [doc](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3).

</~XSIAM>
