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

2. **Create a Service Account** with the following permissions:

| Resource Type         | Permissions                                                                 |
|-----------------------|-----------------------------------------------------------------------------|
| **Compute Firewalls**  | `compute.firewalls.get`, `compute.firewalls.list`, `compute.firewalls.update` |
| **Compute Instances**  | `compute.instances.get`, `compute.instances.list`, `compute.instances.setMetadata` |
| **Compute Networks**   | `compute.networks.list`, `compute.networks.updatePolicy`                    |
| **Compute Subnetworks**| `compute.subnetworks.get`, `compute.subnetworks.list`, `compute.subnetworks.setPrivateIpGoogleAccess`, `compute.subnetworks.update` |
| **Kubernetes Clusters**| `container.clusters.get`, `container.clusters.list`, `container.clusters.update` |
| **Cloud Storage Buckets**| `storage.buckets.getIamPolicy`, `storage.buckets.setIamPolicy`, `storage.buckets.update` |

3. **OAuth Scope Required**:  
   `https://www.googleapis.com/auth/cloud-platform`
