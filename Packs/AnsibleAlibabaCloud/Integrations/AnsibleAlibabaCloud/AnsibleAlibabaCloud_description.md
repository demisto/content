# Ansible Alibaba Cloud
Manage Alibaba Cloud Elastic Compute Instances.

To use this integration you must generate an Access/Secret token for your Alibaba tenancy.
1. Navigate to the [Resource Access Management](https://ram.console.aliyun.com/users)
2. Create a service account dedicated for XSOAR with Programmatic Access enabled
3. Record the Access and Secret tokens
4. Navigate to [Permmions > Grants](https://ram.console.aliyun.com/permissions)
4. Grant the service account principal either `AliyunECSFullAccess` or `AliyunECSReadOnlyAccess` permissions.
