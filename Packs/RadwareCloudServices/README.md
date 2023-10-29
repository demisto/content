<~XSIAM>
# Radware Cloud Services

### Collect Access Logs from Radware Cloud Services

#### AWS - S3 bucket

**On AWS**

Sign in to your AWS account and create a dedicated Amazon S3 bucket, which collects the generic logs that you want to capture.

See this[doc](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3) for further instructions on how to create a S3 bucket.

**On Radware Cloud Services**

1. Contact the Radware Support team in order to enable Access logs.
2. Navigate to **Account Settings** and fill the below attributes:
   - Bucket Name
   - Region
   - Access Key
   - Secret Key
   - Prefix (optional)
3. Click the **Advanced** tab and enable **Access log**.
4. Select the application to which to export all Access logs.

For more information, refer to the official Radware [documentation](https://support.radware.com/).

**On XSIAM:**

1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source**.
2. Click **Amazon S3**.
3. Click **Connect** or **Connect Another Instance**.
4. Set the following values:
   - SQS URL - Refer to Configure an Amazon Simple Queue Service (SQS) [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3). 
   - Name as `Radware Access Log`
   - AWS Client ID
   - AWS Client Secret
   - Log Type as `Generic`
   - Log Format as `JSON`
   - Vendor as `radware`
   - Product as `access_logs`
   - Compression as `gzip`
5. Creating a new HTTP Log Collector will allow you to generate a unique token. Save it since it will be used later.
6. Click the 3 dots next to the newly created instance and copy the API URL. It will also be used later.

For more information, see this [doc](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3).

</~XSIAM>