## GCP Help

This integration enforces GCP security best practices by:

- Disabling insecure or overly permissive firewall rules (e.g., Telnet, FTP, SSH).
- Enabling features like OS Login, VPC Flow Logs, and Kubernetes authorized networks.
- Restricting public access to Cloud Storage buckets and enabling versioning.

### Setup

1. **Enable APIs**:
   - Compute Engine  
   - Cloud Storage  
   - Kubernetes Engine  
   - Cloud Resource Manager

2. **Create a Service Account** with the following permissions by action type:

| Action Type                                 | Permissions                                                                                                                   |
|---------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| **Compute**                                 |                                                                                                                               |
| gcp-compute-firewall-patch                  | compute.firewalls.update, compute.firewalls.get, compute.firewalls.list, compute.networks.updatePolicy, compute.networks.list |
| gcp-compute-subnet-update                   | compute.subnetworks.setPrivateIpGoogleAccess, compute.subnetworks.update, compute.subnetworks.get, compute.subnetworks.list   |
| gcp-compute-instance-metadata-add           | compute.instances.setMetadata, compute.instances.get, compute.instances.list                                                  |
| gcp-compute-instance-service-account-set    | compute.instances.setServiceAccount, compute.instances.get                                                                    |
| gcp-compute-instance-service-account-remove | compute.instances.setServiceAccount, compute.instances.get                                                                    |
| gcp-compute-instance-start                  | compute.instances.start                                                                                                       |
| gcp-compute-instance-stop                   | compute.instances.stop                                                                                                        |
| **Storage**                                 |                                                                                                                               |
| gcp-storage-bucket-policy-delete            | storage.buckets.getIamPolicy, storage.buckets.setIamPolicy                                                                    |
| gcp-storage-bucket-metadata-update          | storage.buckets.update                                                                                                        |
| **Container**                               |                                                                                                                               |
| gcp-container-cluster-security-update       | container.clusters.update, container.clusters.get, container.clusters.list                                                    |
| **IAM**                                     |                                                                                                                               |
| gcp-iam-project-policy-binding-remove       | resourcemanager.projects.getIamPolicy, resourcemanager.projects.setIamPolicy                                                  |
| gcp-iam-project-deny-policy-create          | iam.denypolicies.create                                                                                                       |
| gcp-iam-group-membership-delete             | admin.directory.group.member.delete                                                                                           |
| gcp-iam-service-account-delete              | iam.serviceAccounts.delete                                                                                                    |
| **Admin (Directory API)**                   |                                                                                                                               |
| gcp-admin-user-update                       | admin.directory.user.update                                                                                                   |
| gcp-admin-user-password-reset               | admin.directory.user.security                                                                                                 |
| gcp-admin-user-signout                      | admin.directory.user.security                                                                                                 |


3. **OAuth Scope Required**:  
   `https://www.googleapis.com/auth/cloud-platform`
