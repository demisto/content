## Google Cloud Platform Integration

This integration manages and secures Google Cloud Platform (GCP) resources including Compute Engine, Cloud Storage, GKE, BigQuery, and IAM.

---

### Supported Platforms

| Platform | Authentication | Setup |
|---|---|---|
| **Cortex Cloud** | Automatic via cloud connector (CTS) | Data Sources page |
| **Cortex XSOAR** | Service Account private key JSON | Integration configuration |
| **Cortex XSIAM** | Service Account private key JSON | Integration configuration |

---

### Cortex Cloud Setup

Cloud integrations are installed from the **Data Sources** page.

1. Go to **Settings → Data Sources** and click **Add Data Source**.
2. Select **GCP**, then in **Advanced Settings → Security Capabilities**, enable **Automation**.

Authentication is handled automatically — no credentials are required in the integration configuration.

---

### Cortex XSOAR / Cortex XSIAM Setup

#### Step 1 — Enable Required GCP APIs

In the [Google Cloud Console](https://console.cloud.google.com/apis/library), enable the following APIs for your project:

- **Compute Engine API** (`compute.googleapis.com`)
- **Cloud Storage API** (`storage.googleapis.com`)
- **Kubernetes Engine API** (`container.googleapis.com`)
- **Cloud Resource Manager API** (`cloudresourcemanager.googleapis.com`)
- **Service Usage API** (`serviceusage.googleapis.com`)
- **BigQuery API** (`bigquery.googleapis.com`)

#### Step 2 — Create a Service Account

1. In the Google Cloud Console, go to **IAM & Admin → Service Accounts**.
2. Click **Create Service Account** and give it a descriptive name (e.g., `cortex-xsoar-gcp`).
3. Grant the service account the IAM roles required for the commands you intend to use (see permissions table below).
4. Click **Done**.

#### Step 3 — Create and Download a Private Key

1. Click on the service account you just created.
2. Go to the **Keys** tab and click **Add Key → Create new key**.
3. Select **JSON** format and click **Create**.
4. Save the downloaded `.json` file — you will paste its contents into the integration configuration.

#### Step 4 — Configure the Integration

In the integration instance configuration:

| Field | Value |
|---|---|
| **Service Account Private Key (JSON)** | Paste the full contents of the downloaded JSON key file |
| **GCP Project ID** | Your GCP project ID (e.g., `my-project-123`) |
| **Trust any certificate (not secure)** | Enable only if your environment uses SSL inspection |
| **Use system proxy settings** | Enable if your environment requires a proxy |

Click **Test** to verify connectivity.

---

### Required Permissions

Grant the following permissions to the service account based on which commands you use:

| Command | Required Permissions |
|---|---|
| `gcp-compute-firewall-patch` | `compute.firewalls.update`, `compute.firewalls.get`, `compute.firewalls.list`, `compute.networks.updatePolicy`, `compute.networks.list` |
| `gcp-compute-firewall-insert` | `compute.firewalls.create` |
| `gcp-compute-firewall-list` | `compute.firewalls.list` |
| `gcp-compute-firewall-get` | `compute.firewalls.get` |
| `gcp-compute-subnet-update` | `compute.subnetworks.setPrivateIpGoogleAccess`, `compute.subnetworks.update`, `compute.subnetworks.get`, `compute.subnetworks.list` |
| `gcp-compute-instance-service-account-set` | `compute.instances.setServiceAccount`, `compute.instances.get` |
| `gcp-compute-instance-service-account-remove` | `compute.instances.setServiceAccount`, `compute.instances.get` |
| `gcp-compute-instance-start` | `compute.instances.start` |
| `gcp-compute-instance-stop` | `compute.instances.stop` |
| `gcp-compute-instances-list` | `compute.instances.list` |
| `gcp-compute-instance-get` | `compute.instances.get` |
| `gcp-compute-instance-labels-set` | `compute.instances.setLabels` |
| `gcp-compute-network-tag-set` | `compute.instances.setTags` |
| `gcp-compute-snapshots-list` | `compute.snapshots.list` |
| `gcp-compute-snapshot-get` | `compute.snapshots.get` |
| `gcp-compute-instances-aggregated-list-by-ip` | `cloudasset.assets.searchAllResources` |
| `gcp-compute-network-get` | `compute.networks.get` |
| `gcp-compute-networks-list` | `compute.networks.list` |
| `gcp-compute-network-insert` | `compute.networks.insert` |
| `gcp-compute-image-get` | `compute.images.get` |
| `gcp-compute-instance-group-get` | `compute.instanceGroups.get` |
| `gcp-compute-region-get` | `compute.regions.get` |
| `gcp-compute-zone-get` | `compute.zone.get` |
| `gcp-storage-bucket-list` | `storage.buckets.list` |
| `gcp-storage-bucket-get` | `storage.buckets.get` |
| `gcp-storage-bucket-objects-list` | `storage.objects.list` |
| `gcp-storage-bucket-policy-list` | `storage.buckets.getIamPolicy`, `storage.buckets.get` |
| `gcp-storage-bucket-policy-set` | `storage.buckets.setIamPolicy` |
| `gcp-storage-bucket-policy-delete` | `storage.buckets.getIamPolicy`, `storage.buckets.setIamPolicy` |
| `gcp-storage-bucket-metadata-update` | `storage.buckets.update` |
| `gcp-storage-bucket-object-policy-list` | `storage.objects.getIamPolicy` |
| `gcp-storage-bucket-object-policy-set` | `storage.objects.setIamPolicy` |
| `gcp-container-cluster-security-update` | `container.clusters.update`, `container.clusters.get`, `container.clusters.list` |
| `gcp-iam-project-policy-binding-remove` | `resourcemanager.projects.getIamPolicy`, `resourcemanager.projects.setIamPolicy` |
| `gcp-bq-dataset-policy-remove` | `bigquery.datasets.update`, `bigquery.datasets.get`, `bigquery.datasets.getIamPolicy`, `bigquery.datasets.setIamPolicy` |

**OAuth Scope Required**: `https://www.googleapis.com/auth/cloud-platform`
