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

| Action Type                      | Permissions                                                                 |
|----------------------------------|-----------------------------------------------------------------------------|
| **gcp-compute-firewall-patch**   | `compute.firewalls.update`, `compute.firewalls.get`, `compute.firewalls.list`, `compute.networks.updatePolicy`, `compute.networks.list` |
| **gcp-compute-subnet-update**    | `compute.subnetworks.setPrivateIpGoogleAccess`, `compute.subnetworks.update`, `compute.subnetworks.get`, `compute.subnetworks.list` |
| **gcp-compute-project-metadata-add** | `compute.instances.setMetadata`, `compute.instances.get`, `compute.instances.list` |
| **gcp-storage-bucket-policy-delete** | `storage.buckets.getIamPolicy`, `storage.buckets.setIamPolicy` |
| **gcp-container-cluster-security-update** | `container.clusters.update`, `container.clusters.get`, `container.clusters.list` |
| **gcp-storage-bucket-metadata-update** | `storage.buckets.update` |

3. **OAuth Scope Required**:  
   `https://www.googleapis.com/auth/cloud-platform`
