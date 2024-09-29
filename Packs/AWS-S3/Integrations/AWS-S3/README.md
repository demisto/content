Amazon Web Services Simple Storage Service (S3).

This integration was integrated and tested with API Version 2012-11-05.

For detailed instructions about setting up authentication, see: [AWS Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication).


## Configure AWS - S3 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | Role Arn | False |
| roleSessionName | Role Session Name | False |
| defaultRegion | AWS Default Region | False |
| sessionDuration | Role Session Duration | False |
| access_key | Access Key | False |
| secret_key | Secret Key | False |
| timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 second will be used. | False |
| retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-s3-create-bucket
***
Create AWS S3 bucket.


#### Base Command

`aws-s3-create-bucket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | The name of S3 bucket to create (in lowercase). | Required | 
| acl | ACL for S3 bucket. Possible values are: private, public-read, public-read-write, authenticated-read. | Optional | 
| locationConstraint | Specifies the region where the bucket will be created. If you don't specify a region, the bucket will be created in US Standard. | Optional | 
| grantFullControl | Allows grantee the read, write, read ACP, and write ACP permissions on the bucket. | Optional | 
| grantRead | Allows grantee to list the objects in the bucket. | Optional | 
| grantReadACP | Allows grantee to read the bucket ACL. | Optional | 
| grantWrite | Allows grantee to create, overwrite, and delete any object in the bucket. | Optional | 
| grantWriteACP | Allows grantee to write the ACL for the applicable bucket. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3.Buckets.BucketName | string | The name of the bucket that was created. | 
| AWS.S3.Buckets.Location | string | The AWS Region the bucket was created. | 


#### Command Example
``` !aws-s3-create-bucket bucket=test acl=private```

#### Human Readable Output
AWS S3 Buckets

| BucketName | Location  |
| --- | --- | 
| test | test |



### aws-s3-delete-bucket
***
Delete AWS S3 bucket.


#### Base Command

`aws-s3-delete-bucket`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | Name of S3 bucket to delete. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-s3-delete-bucket bucket=test ```

#### Human Readable Output
The bucket was deleted.


### aws-s3-list-buckets
***
List all S3 buckets in AWS account


#### Base Command

`aws-s3-list-buckets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3.Buckets.BucketName | string | The name of the bucket. | 
| AWS.S3.Buckets.CreationDate | date | Date the bucket was created. | 


#### Command Example
``` !aws-s3-list-buckets```

#### Human Readable Output
AWS S3 Buckets

| BucketName | CreationDate  |
| --- | --- |
| backup-lab | 2018-04-29T13:31:57 |
| test | 2018-05-06T06:34:30 | 



### aws-s3-get-bucket-policy
***
Get AWS S3 Bucket Policy


#### Base Command

`aws-s3-get-bucket-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | Name of bucket. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3.Buckets.Policy.Version | string | S3 Bucket Policy Version. | 
| AWS.S3.Buckets.Policy.PolicyId | string | S3 Bucket Policy ID. | 
| AWS.S3.Buckets.Policy.Sid | string | S3 Bucket Policy Statment ID. | 
| AWS.S3.Buckets.Policy.Action | string | S3 Bucket Policy Statment Action. | 
| AWS.S3.Buckets.Policy.Principal | string | S3 Bucket Policy Statment Principal. | 
| AWS.S3.Buckets.Policy.Resource | string | S3 Bucket Policy Statment Resource. | 
| AWS.S3.Buckets.Policy.Effect | string | S3 Bucket Policy Statment Effect. | 
| AWS.S3.Buckets.Policy.Json | string | AWS S3 Policy Json output. | 
| AWS.S3.Buckets.Policy.BucketName | string | S3 Bucket Name. | 


#### Command Example
```!aws-s3-get-bucket-policy bucket=test ```


### aws-s3-delete-bucket-policy
***
Deletes the policy from the bucket.


#### Base Command

`aws-s3-delete-bucket-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | Name of S3 bucket. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-s3-delete-bucket-policy bucket=test```

#### Human Readable Output
Policy deleted from test.



### aws-s3-download-file
***
Download a file from S3 bucket to war room.


#### Base Command

`aws-s3-download-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | The name of S3 bucket. | Optional | 
| key | The S3 object key to download. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!aws-s3-download-file bucket=test key=test.txt ```

### aws-s3-list-bucket-objects
***
List object in S3 bucket.


#### Base Command

`aws-s3-list-bucket-objects`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | The name of S3 bucket. | Required | 
| prefix | Limits the response to keys that begin with the specified prefix. | Optional |
| delimiter | A delimiter is a character you use to group keys. | Optional |
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3.Buckets.Objects.Key | Unknown | The name of S3 object. | 
| AWS.S3.Buckets.Objects.Size | Unknown | Object size. | 
| AWS.S3.Buckets.Objects.LastModified | Unknown | Last date object was modified. | 


#### Command Example
``` !aws-s3-list-bucket-objects bucket=test prefix=testing delimiter='/'```

#### Human Readable Output
AWS S3 Bucket Objects

| Key | Size | LastModified |
| --- | --- | --- |
| demi2018-04-05-14-29-49-76DA472F25CB951F | 323.0 B | 2018-04-05T14:29:51 |


### aws-s3-put-bucket-policy
***
Replaces a policy on a bucket. If the bucket already has a policy, the one in this request completely replaces it.


#### Base Command

`aws-s3-put-bucket-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | Name of S3 bucket. | Required | 
| policy | The bucket policy to apply in json format. | Required | 
| confirmRemoveSelfBucketAccess | Set this parameter to true to confirm that you want to remove your permissions to change this bucket policy in the future. Possible values are: True, False. | Optional | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-s3-put-bucket-policy bucket=test policy={"Version":"2012-10-17","Id":"Policy1519481415511","Statement":[{"Sid":"Stmt1519ds34548138sf5929","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789:user/itai"},"Action":"s3:","Resource":"arn:aws:s3:::test"},{"Sid":"Stmt1345519481414395","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789:user/bob"},"Action":"s3:","Resource":"arn:aws:s3:::test"}]}```

#### Human Readable Output

Successfully applied bucket policy to test bucket.


### aws-s3-upload-file
***
Upload file to S3 bucket


#### Base Command

`aws-s3-upload-file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryID | Entry ID of the file to upload. | Required | 
| bucket | The name of the bucket to upload to. | Required | 
| key | The name of the key to upload to. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-s3-upload-file bucket="bucket name" key="file name to be displayed" entryID=##@##```

#### Human Readable Output

File {file name to be displayed} was uploaded successfully to {bucket name}'


### aws-s3-get-public-access-block
***
Retrieves the PublicAccessBlock configuration for an Amazon S3 bucket.


#### Base Command

`aws-s3-get-public-access-block`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | The name of the Amazon S3 bucket whose PublicAccessBlock configuration you want to retrieve. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3.Buckets.BucketName.PublicAccessBlockConfiguration.BlockPublicAcls | Boolean | Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket. | 
| AWS.S3.Buckets.BucketName.PublicAccessBlockConfiguration.IgnorePublicAcls | Boolean | Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket. | 
| AWS.S3.Buckets.BucketName.PublicAccessBlockConfiguration.BlockPublicPolicy | Boolean | Specifies whether Amazon S3 should block public bucket policies for this bucket. | 
| AWS.S3.Buckets.BucketName.PublicAccessBlockConfiguration.RestrictPublicBuckets | Boolean | Specifies whether Amazon S3 should restrict public bucket policies for this bucket. | 

#### Command Example
``` !aws-s3-get-public-access-block bucket="bucket name"```

#### Human Readable Output

AWS S3 Bucket Public Access Block

| BlockPublicAcls | IgnorePublicAcls | BlockPublicPolicy | RestrictPublicBuckets |
| --- | --- | --- | --- | 
| True | False | True | False |


### aws-s3-put-public-access-block
***
Creates or modifies the PublicAccessBlock configuration for an Amazon S3 bucket.


#### Base Command

`aws-s3-put-public-access-block`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | The name of the bucket to upload to. | Required | 
| BlockPublicAcls | Specifies whether Amazon S3 should block public access control lists (ACLs) for this bucket and objects in this bucket. | Required | 
| IgnorePublicAcls | Specifies whether Amazon S3 should ignore public ACLs for this bucket and objects in this bucket. | Required | 
| BlockPublicPolicy | Specifies whether Amazon S3 should block public bucket policies for this bucket. | Required | 
| RestrictPublicBuckets | Specifies whether Amazon S3 should restrict public bucket policies for this bucket. | Required | 
| region | The AWS Region, if not specified the default region will be used. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` !aws-s3-put-public-access-block bucket="bucket name" BlockPublicAcls=True IgnorePublicAcls=False BlockPublicPolicy=True RestrictPublicBuckets=True```

#### Human Readable Output

Successfully applied public access block to the {bucket} bucket.

### aws-s3-get-bucket-encryption
***
Get AWS S3 Bucket Encryption

#### Base Command

`aws-s3-get-bucket-encryption`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| bucket | The name of the bucket from which the server-side encryption configuration is retrieved. | Required |
| expectedBucketOwner | The account ID of the exepcted bucket owner. | Optional |
| region | The AWS Region, if not specified the default region will be used. | Optional |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional |
| roleSessionName | An identifier for the assumed role session. | Optional |
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.S3.Buckets.BucketName.ServerSideEncryptionConfiguration.Rules.ApplyServerSideEncryptionByDefault.SSEAlgorithm | String | S3 Bucket Encryption SSE Algorithm. |
| AWS.S3.Buckets.BucketName.ServerSideEncryptionConfiguration.Rules.ApplyServerSideEncryptionByDefault.KMSMasterKeyID | String | S3 Bucket Encryption KMS Master Key ID. |
| AWS.S3.Buckets.BucketName.ServerSideEncryptionConfiguration.Rules.BucketKeyEnabled | Boolean | S3 Bucket Encryption Key Enabled. |

#### Command Example

``` !aws-s3-put-public-access-block bucket="bucket name" BlockPublicAcls=True IgnorePublicAcls=False BlockPublicPolicy=True RestrictPublicBuckets=True```


#### Context Example

```
{
    "AWS": {
        "S3": {
            "Buckets": [
                {
                    "BucketName": "bucket-a",
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {
                                "ApplyServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "AES256"
                                }
                            }
                        ]
                    }
                }
            ]
        }
    }
}
```