The AWS EKS integration allows for the management and operation of Amazon Elastic Kubernetes Service (EKS) clusters.
This integration was integrated and tested with version 1.29 of AWS-EKS.

## Configure AWS-EKS in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| AWS Default Region | AWS Default Region | True |
| Access Key |  | True |
| Secret Key |  | True |
| Timeout | The time in seconds till a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout followed after a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 seconds will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| Trust any certificate (not secure) | Trust any certificate \(not secure\) | False |
| Use system proxy settings | Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### aws-eks-list-clusters

***
Lists the Amazon EKS clusters in your Amazon Web Services account in the specified Amazon Web Services Region.

#### Base Command

`aws-eks-list-clusters`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of clusters to return. Default is 50. | Optional | 
| next_token | The nextToken value returned from a previous paginated request, where maxResults was used and the results exceeded the value of that parameter. | Optional | 
| region | The AWS Region. If not specified, the configured region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.Cluster.ClustersNames | List | A list of all of the clusters for your account in the specified Amazon Web Services Region. | 
| AWS.EKS.Cluster.NextToken | List | The nextToken value returned from a previous paginated request, where maxResults was used and the results exceeded the value of that parameter. | 

#### Command example
```!aws-eks-list-clusters```
#### Context Example
```json
{
    "AWS": {
        "EKS": {
            "Cluster": {
                "ClustersNames": [
                    "cluster_name1",
                    "cluster_name2"
                ],
                "NextToken": null
            }
        }
    }
}
```

#### Human Readable Output

>### The list of clusters
>| Clusters Names |
>|----------------|
>| cluster_name1  |
>| cluster_name2  |


### aws-eks-update-cluster-config

***
Updates an Amazon EKS cluster configuration. Only one type of update is allowed. Potentially harmful: once the authentication mode is updated to 'API' it is irreversible.

#### Base Command

`aws-eks-update-cluster-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | The name of the Amazon EKS cluster to update. | Required | 
| resources_vpc_config | A JSON representation of the VPC configuration used by the cluster control plane. An example: "{'subnetIds': ['string'], 'securityGroupIds': ['string'], 'endpointPublicAccess': True, 'endpointPrivateAccess': True, 'publicAccessCidrs': ['string']}". | Optional | 
| logging | A JSON representation of the logging configuration for the cluster. An example: "{'clusterLogging': [{'types': ['api', 'audit', 'authenticator', 'controllerManager', 'scheduler'], 'enabled': true}]}". | Optional | 
| authentication_mode | Whether to update the authentication mode to 'API_AND_CONFIG_MAP' or not. Possible values are: true, false. | Optional | 
| region | The AWS Region. If not specified, the configured region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.UpdateCluster.clusterName | String | The name of the cluster. | 
| AWS.EKS.UpdateCluster.id | Integer | The ID of the update. | 
| AWS.EKS.UpdateCluster.status | String | The status of the update. | 
| AWS.EKS.UpdateCluster.type | String | The type of the update. | 
| AWS.EKS.UpdateCluster.params | Object | The parameters of the update. | 
| AWS.EKS.UpdateCluster.createdAt | String | The creation date of the object. | 
| AWS.EKS.UpdateCluster.errors | Object | Any errors associated with a failed update. | 

#### Command example
```!aws-eks-update-cluster-config cluster_name=CLUSTER_NAME logging="{'clusterLogging': [{'types': ['api', 'authenticator', 'audit'], 'enabled': false}]}"```
#### Context Example
```json
{
    "AWS": {
        "EKS": {
            "UpdateCluster": {
                "createdAt": "2024-02-26 09:38:11.578000+00:00",
                "errors": [],
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "CLUSTER_NAME",
                "params": [
                    {
                        "type": "ClusterLogging",
                        "value": "{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\"],\"enabled\":false}]}"
                    }
                ],
                "status": "InProgress",
                "type": "LoggingUpdate"
            }
        }
    }
}
```

#### Human Readable Output

>### Updated Cluster Config Information
>|Cluster Name| ID                                   |Status|Type|Params|
>|---|--------------------------------------|---|---|---|
>| CLUSTER_NAME | 11111111-1111-1111-1111-111111111111 | InProgress | LoggingUpdate | {'type': 'ClusterLogging', 'value': '{"clusterLogging":[{"types":["api","audit","authenticator"],"enabled":false}]}'} |


### aws-eks-describe-cluster

***
Describes an Amazon EKS cluster.

#### Base Command

`aws-eks-describe-cluster`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | The name of the cluster to describe. | Required | 
| region | The AWS Region. If not specified, the configured region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.DescribeCluster.name | String | The name of your cluster. | 
| AWS.EKS.DescribeCluster.arn | String | The Amazon Resource Name \(ARN\) of the cluster. | 
| AWS.EKS.DescribeCluster.createdAt | String | The creation date of the object. | 
| AWS.EKS.DescribeCluster.version | String | The Kubernetes server version for the cluster. | 
| AWS.EKS.DescribeCluster.endpoint | String | The endpoint for your Kubernetes API server. | 
| AWS.EKS.DescribeCluster.roleArn | String | The Amazon Resource Name \(ARN\) of the IAM role that provides permissions for the Kubernetes control plane to make calls to Amazon Web Services API operations on your behalf. | 
| AWS.EKS.DescribeCluster.resourcesVpcConfig.subnetIds | List | The subnets associated with your cluster. | 
| AWS.EKS.DescribeCluster.resourcesVpcConfig.securityGroupIds | List | The security groups associated with the cross-account elastic network interfaces that are used to allow communication between your nodes and the Kubernetes control plane. | 
| AWS.EKS.DescribeCluster.resourcesVpcConfig.clusterSecurityGroupId | String | The cluster security group that was created by Amazon EKS for the cluster. Managed node groups use this security group for control-plane-to-data-plane communication. | 
| AWS.EKS.DescribeCluster.resourcesVpcConfig.vpcId | String | The VPC associated with your cluster. | 
| AWS.EKS.DescribeCluster.resourcesVpcConfig.endpointPublicAccess | Boolean | Whether the public API server endpoint is enabled. | 
| AWS.EKS.DescribeCluster.resourcesVpcConfig.endpointPrivateAccess | Boolean | This parameter indicates whether the Amazon EKS private API server endpoint is enabled. | 
| AWS.EKS.DescribeCluster.resourcesVpcConfig.publicAccessCidrs | List | The CIDR blocks that are allowed access to your cluster’s public Kubernetes API server endpoint. | 
| AWS.EKS.DescribeCluster.kubernetesNetworkConfig.serviceIpv4Cidr | String | The CIDR block that Kubernetes Pod and Service object IP addresses are assigned from. | 
| AWS.EKS.DescribeCluster.kubernetesNetworkConfig.serviceIpv6Cidr | String | The CIDR block that Kubernetes Pod and Service IP addresses are assigned from if you created a 1.21 or later cluster with version 1.10.1 or later of the Amazon VPC CNI add-on and specified ipv6 for ipFamily when you created the cluster. | 
| AWS.EKS.DescribeCluster.kubernetesNetworkConfig.ipFamily | String | The IP family used to assign Kubernetes Pod and Service objects IP addresses. | 
| AWS.EKS.DescribeCluster.logging.clusterLogging | Object | The cluster control plane logging configuration for your cluster. | 
| AWS.EKS.DescribeCluster.identity | Object | The identity provider information for the cluster. | 
| AWS.EKS.DescribeCluster.status | String | The current status of the cluster. | 
| AWS.EKS.DescribeCluster.certificateAuthority.data | String | The Base64-encoded certificate data required to communicate with your cluster. | 
| AWS.EKS.DescribeCluster.clientRequestToken | String | A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. | 
| AWS.EKS.DescribeCluster.platformVersion | String | The platform version of your Amazon EKS cluster. | 
| AWS.EKS.DescribeCluster.tags | Object | A dictionary containing metadata for categorization and organization. | 
| AWS.EKS.DescribeCluster.encryptionConfig.resources | List | Specifies the resources to be encrypted. The only supported value is secrets. | 
| AWS.EKS.DescribeCluster.encryptionConfig.provider | Object | Key Management Service \(KMS\) key. | 
| AWS.EKS.DescribeCluster.connectorConfig.activationId | String | A unique ID associated with the cluster for registration purposes. | 
| AWS.EKS.DescribeCluster.connectorConfig.activationCode | String | A unique code associated with the cluster for registration purposes. | 
| AWS.EKS.DescribeCluster.connectorConfig.activationExpiry | String | The expiration time of the connected cluster. | 
| AWS.EKS.DescribeCluster.connectorConfig.provider | String | The cluster’s cloud service provider. | 
| AWS.EKS.DescribeCluster.connectorConfig.roleArn | String | The Amazon Resource Name \(ARN\) of the role to communicate with services from the connected Kubernetes cluster. | 
| AWS.EKS.DescribeCluster.id | String | The ID of your local Amazon EKS cluster on an Amazon Web Services Outpost. | 
| AWS.EKS.DescribeCluster.health.issues | List | An object representing the health issues of your local Amazon EKS cluster on an Amazon Web Services Outpost. | 
| AWS.EKS.DescribeCluster.outpostConfig.outpostArns | Object | An object representing the configuration of your local Amazon EKS cluster on an Amazon Web Services Outpost. | 
| AWS.EKS.DescribeCluster.outpostConfig.controlPlaneInstanceType | String | The Amazon EC2 instance type used for the control plane. | 
| AWS.EKS.DescribeCluster.outpostConfig.controlPlanePlacement | Object | An object representing the placement configuration for all the control plane instances of your local Amazon EKS cluster on an Amazon Web Services Outpost. | 
| AWS.EKS.DescribeCluster.accessConfig.bootstrapClusterCreatorAdminPermissions | Boolean | Specifies whether or not the cluster creator IAM principal was set as a cluster admin access entry during cluster creation time. | 
| AWS.EKS.DescribeCluster.accessConfig.authenticationMode | String | The current authentication mode of the cluster. | 

#### Command example
```!aws-eks-describe-cluster cluster_name=CLUSTER_NAME```
#### Context Example
```json
{
    "AWS": {
        "EKS": {
            "DescribeCluster": {
                "accessConfig": {
                    "authenticationMode": "API_AND_CONFIG_MAP"
                },
                "arn": "arn",
                "certificateAuthority": {
                    "data": "data_key"
                },
                "createdAt": "2024-02-26 09:38:11.578000+00:00",
                "endpoint": "endpoint",
                "health": {
                    "issues": []
                },
                "identity": {
                    "oidc": {
                        "issuer": "issuer"
                    }
                },
                "kubernetesNetworkConfig": {
                    "ipFamily": "ipv4",
                    "serviceIpv4Cidr": "11.111.1.1/11"
                },
                "logging": {
                    "clusterLogging": [
                        {
                            "enabled": true,
                            "types": [
                                "api",
                                "audit",
                                "authenticator",
                                "controllerManager",
                                "scheduler"
                            ]
                        }
                    ]
                },
                "name": "CLUSTER_NAME",
                "platformVersion": "eks.1",
                "resourcesVpcConfig": {
                    "clusterSecurityGroupId": "sg-id",
                    "endpointPrivateAccess": true,
                    "endpointPublicAccess": true,
                    "publicAccessCidrs": [
                        "111.111.111.111/11"
                    ],
                    "securityGroupIds": [
                        "sg-id"
                    ],
                    "subnetIds": [
                        "subnet-id"
                    ],
                    "vpcId": "vpc-id"
                },
                "roleArn": "roleArn",
                "status": "ACTIVE",
                "tags": {},
                "version": "1.29"
            }
        }
    }
}
```

#### Human Readable Output

>### Describe Cluster Information
>|Cluster Name|Status| ARN     |Created At|Version|
>|---|---|---------|---|---|
>| roleArn | ACTIVE | roleArn | 2024-02-26 09:38:11.578000+00:00 | 1.29 |


### aws-eks-create-access-entry

***
Creates an access entry.

#### Base Command

`aws-eks-create-access-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | The name of the cluster for which to create an access entry. | Required | 
| principal_arn | ARN of the IAM principal for the AccessEntry. | Required | 
| kubernetes_groups | A comma-separated list of names for Kubernetes groups in RoleBindings or ClusterRoleBindings. | Optional | 
| tags | A dictionary containing metadata for categorization and organization. Each tag consists of a key and an optional value. | Optional | 
| client_request_token | Unique identifier for idempotency. | Optional | 
| username | Username for Kubernetes authentication. | Optional | 
| type | The type of access entry to create. Possible values are: Standard, FARGATE_LINUX, EC2_LINUX, EC2_WINDOWS. Default is Standard. | Optional | 
| region | The AWS Region. If not specified, the configured region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.CreateAccessEntry.clusterName | String | The name of the cluster. | 
| AWS.EKS.CreateAccessEntry.principalArn | String | The ARN of the IAM principal for the access entry. | 
| AWS.EKS.CreateAccessEntry.kubernetesGroups | String | A list of names that you’ve specified in a Kubernetes RoleBinding or ClusterRoleBinding object so that Kubernetes authorizes the principalARN access to cluster objects. | 
| AWS.EKS.CreateAccessEntry.accessEntryArn | String | The ARN of the access entry. | 
| AWS.EKS.CreateAccessEntry.createdAt | String | The creation date of the object. | 
| AWS.EKS.CreateAccessEntry.modifiedAt | String | The date and time for the last modification to the object. | 
| AWS.EKS.CreateAccessEntry.tags | Object | A dictionary containing metadata for categorization and organization. | 
| AWS.EKS.CreateAccessEntry.username | String | The name of a user that can authenticate to the cluster. | 
| AWS.EKS.CreateAccessEntry.type | String | The type of the access entry. | 

#### Command example
```!aws-eks-create-access-entry cluster_name=CLUSTER_NAME principal_arn=principal_arn```
#### Context Example
```json
{
    "AWS": {
        "EKS": {
            "CreateAccessEntry": {
                "ResponseMetadata": {
                    "clusterName": "clusterName",
                    "principalArn": "principalArn",
                    "kubernetesGroups": [
                        "kubernetesGroups"
                    ],
                    "accessEntryArn": "accessEntryArn",
                    "createdAt": "2024-02-26 09:38:11.578000+00:00",
                    "modifiedAt": "2024-02-26 09:38:11.578000+00:00",
                    "tags": {
                        "string": "string"
                    },
                    "username": "username",
                    "type": "STANDARD"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### The newly created access entry
>|Cluster Name|Principal Arn|Username|Type| Created At           |
>|---|---|---|---|----------------------|
>| clusterName | principalArn | username | STANDARD | 2024-02-26 09:38:11.578000+00:00 |

### aws-eks-associate-access-policy

***
Associates an access policy and its scope to an access entry.

#### Base Command

`aws-eks-associate-access-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | The name of the cluster for which to create an access entry. | Required | 
| principal_arn | The Amazon Resource Name (ARN) of the IAM user or role for the AccessEntry that you’re associating the access policy to. | Required | 
| policy_arn | The ARN of the AccessPolicy that you’re associating. | Required | 
| type | The scope type of an access policy. Possible values are: cluster, namespace. | Required | 
| namespaces | A comma-separated list of Kubernetes namespaces that an access policy is scoped to. A value is required if you specified namespace for type. | Optional | 
| region | The AWS Region. If not specified, the configured region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.AssociatedAccessPolicy.clusterName | String | The name of your cluster. | 
| AWS.EKS.AssociatedAccessPolicy.principalArn | String | The ARN of the IAM principal for the AccessEntry. | 
| AWS.EKS.AssociatedAccessPolicy.policyArn | String | The ARN of the AccessPolicy. | 
| AWS.EKS.AssociatedAccessPolicy.accessScope.type | String | The scope type of an access policy. | 
| AWS.EKS.AssociatedAccessPolicy.accessScope.namespaces | String | A Kubernetes namespace that an access policy is scoped to. | 
| AWS.EKS.AssociatedAccessPolicy.associatedAt | String | The date and time the AccessPolicy was associated with an AccessEntry. | 
| AWS.EKS.AssociatedAccessPolicy.modifiedAt | String | The date and time for the last modification to the object. | 

#### Command example
```!aws-eks-associate-access-policy cluster_name=CLUSTER_NAME principal_arn=principal_arn type=cluster```
#### Context Example
```json
{
    "AWS": {
        "EKS": {
            "AssociatedAccessPolicy": {
                "associatedAccessPolicy": {
                    "accessScope": {
                        "namespaces": [],
                        "type": "cluster"
                    },
                    "associatedAt": "2024-02-26 09:38:11.578000+00:00",
                    "modifiedAt": "2024-02-26 09:38:11.578000+00:00",
                    "policyArn": "policyArn"
                },
                "clusterName": "CLUSTER_NAME",
                "principalArn": "principalArn"
            }
        }
    }
}
```

#### Human Readable Output

>### The access policy was associated to the access entry successfully.
>|Cluster Name|Principal Arn|Policy Arn| associate At           |
>|---|---|-----------|----------------------|
>| clusterName | principalArn | username  | 2024-02-26 09:38:11.578000+00:00 |

### aws-eks-update-access-entry

***
Updates an access entry.

#### Base Command

`aws-eks-update-access-entry`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster_name | The name of the cluster. | Required | 
| principal_arn | ARN of the IAM principal for the AccessEntry. | Required | 
| kubernetes_groups | A comma-separated list of names for Kubernetes groups in RoleBindings or ClusterRoleBindings. | Optional | 
| client_request_token | Unique identifier for idempotency. | Optional | 
| username | Username for Kubernetes authentication. | Optional | 
| region | The AWS Region. If not specified, the configured region will be used. Possible values are: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, eu-west-1, eu-central-1, eu-west-2, ap-northeast-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-south-1, sa-east-1, eu-north-1, eu-west-3. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.EKS.UpdateAccessEntry.clusterName | String | The name of your cluster. | 
| AWS.EKS.UpdateAccessEntry.principalArn | String | The ARN of the IAM principal for the access entry. | 
| AWS.EKS.UpdateAccessEntry.kubernetesGroups | List | A list of names that you’ve specified in a Kubernetes RoleBinding or ClusterRoleBinding object so that Kubernetes authorizes the principalARN access to cluster objects. | 
| AWS.EKS.UpdateAccessEntry.accessEntryArn | String | The ARN of the access entry. | 
| AWS.EKS.UpdateAccessEntry.createdAt | String | The creation date of the object. | 
| AWS.EKS.UpdateAccessEntry.modifiedAt | String | The date and time for the last modification to the object. | 
| AWS.EKS.UpdateAccessEntry.tags | Object | Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. | 
| AWS.EKS.UpdateAccessEntry.username | String | The name of a user that can authenticate to your cluster. | 
| AWS.EKS.UpdateAccessEntry.type | String | The type of the access entry. | 

#### Command example
```!aws-eks-update-access-entry cluster_name=CLUSTER_NAME principal_arn=principal_arn```
#### Context Example
```json
{
    "AWS": {
        "EKS": {
            "UpdateAccessEntry": {
                "accessEntryArn": "accessEntryArn",
                "clusterName": "CLUSTER_NAME",
                "createdAt": "2024-02-26 09:38:11.578000+00:00",
                "kubernetesGroups": [],
                "modifiedAt": "2024-02-26 09:38:11.578000+00:00",
                "principalArn": "principalArn",
                "tags": {},
                "type": "STANDARD",
                "username": "username"
            }
        }
    }
}
```

#### Human Readable Output

>### The updated access entry
>|Cluster Name|Principal Arn|Username|Type|Modified At|
>|---|---|---|---|---|
>| CLUSTER_NAME | principal_arn | username | STANDARD | 2024-02-26 09:38:11.578000+00:00 |
