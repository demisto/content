</~XSIAM>
# AWS Elastic Load Balancing
This pack includes Cortex XSIAM content.

## Important Notes
* Time in this pack is parsed with the calculaton of UTC 00:00+.

## Configuration on Server Side
When you enable access logs for your load balancer, you must specify the name of the S3 bucket where the load balancer will store the logs. The bucket must have a bucket policy that grants Elastic Load Balancing permission to write to the bucket.

Follow the steps:
1. Create an S3 bucket, as described [here](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#access-log-create-bucket).
2. Attach a policy to your S3 bucket, as described [here](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy).
3. Configure access logs, as described [here](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy).
4. Verify bucket permissions, as described [here](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#verify-bucket-permissions).

## Collect Events from Vendor
In order to use the collector, use the [XDRC (XDR Collector)](#xdrc-xdr-collector) option.

### XDRC (XDR Collector)
To create or configure the Amazon S3 collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Ingest-Network-Flow-Logs-from-Amazon-S3).

You can configure the specific vendor and product for this instance.
 
1. Navigate to **Settings** &rarr; **Data Sources** &rarr **Add Data Source**.
2. Click **Amazon S3**.
3. Click **Connect** or **Connect Another Instance**.
4. Select the **Access Key** or **Assumed Role** filter, according to the implementation method of your choice.
5. When configuring the new Amazon S3 data source, set the following values:
   | Parameter     | Value   
   | :---          | :---        
   | `SQS URL`     | Enter **SQS URL**.
   | `Name`        | Enter **ELB**.
   | `Role ARN`/`AWS Client ID`    | Enter **Role ARN / AWS Client ID**.
   | `External Id`/`AWS Client Secret` | Enter **External Id / AWS Client Secret**.
   | `Log Type`    | Enter **Generic**. 
   | `Log Format`  | Enter **Raw**.
   | `Compression` | Enter **uncompressed**. 

For additional information, see [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Generic-Logs-from-Amazon-S3).

</~XSIAM>