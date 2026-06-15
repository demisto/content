## Google Cloud Platform Integration

This integration manages and secures Google Cloud Platform (GCP) resources including Compute Engine, Cloud Storage, GKE, BigQuery, and IAM.

---

### Supported Platforms

| Platform                                          | Authentication | Setup |
|---------------------------------------------------|---|---|
| **Cortex Cloud or Cortex XSIAM (version >= 3.0)** | Automatic via cloud connector (CTS) | Data Sources page |
| **Cortex XSOAR**                                  | Service Account private key JSON | Integration configuration |
| **Cortex XSIAM (version < 3.0)**                  | Service Account private key JSON | Integration configuration |

---

### Cortex Cloud or Cortex XSIAM (version >= 3.0) Setup

Cloud integrations are installed from the **Data Sources** page.

1. Go to **Settings → Data Sources** and click **Add Data Source**.
2. Select **GCP**, then in **Advanced Settings → Security Capabilities**, enable **Automation**.

Authentication is handled automatically — no credentials are required in the integration configuration.

---

### Cortex XSOAR / Cortex XSIAM (version < 3.0) Setup

#### Step 1 — Enable Required GCP APIs

In the [Google Cloud Console](https://console.cloud.google.com/apis/library), enable the following APIs for your project:

- **Compute Engine API** (`compute.googleapis.com`)
- **Cloud Storage API** (`storage.googleapis.com`)
- **Kubernetes Engine API** (`container.googleapis.com`)
- **Cloud Resource Manager API** (`cloudresourcemanager.googleapis.com`)
- **Service Usage API** (`serviceusage.googleapis.com`)
- **BigQuery API** (`bigquery.googleapis.com`)

#### Step 2 — Create a Service Account

1. In the Google Cloud Console, navigate to **IAM & Admin → Service Accounts**.
2. Click **Create Service Account** and give it a descriptive name (e.g., `cortex-xsoar-gcp`).
3. Grant the service account the IAM roles required for the commands you intend to use (see [Required Permissions](#required-permissions) below).
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
| **Service Account Private Key (JSON)** | Paste the full contents of the downloaded JSON key file. |
| **GCP Project ID** | Enter your GCP project ID (e.g., `my-project-123`). |
| **Trust any certificate (not secure)** | Enable only if your environment uses SSL inspection. |
| **Use system proxy settings** | Enable if your environment requires a proxy. |

Click **Test** to verify connectivity.

---

### Required Permissions

Grant the service account only the IAM permissions required by the commands you intend to use.
The full, per-command permission list is maintained in the official documentation:

- [Google Cloud Platform integration reference on xsoar.pan.dev](https://xsoar.pan.dev/docs/reference/integrations/gcp)

#### Locating the Permissions for Your Use Case

Each command's required permissions are listed in its reference documentation. To find what you need:

1. Open the [integration reference](https://xsoar.pan.dev/docs/reference/integrations/gcp) and locate the command you plan to run (e.g., `gcp-compute-firewall-list`).
2. Note the GCP permissions it requires (e.g., `compute.firewalls.list`).
3. Grant a predefined role that includes those permissions, or create a [custom role](https://cloud.google.com/iam/docs/creating-custom-roles) containing exactly the permissions you need (least privilege).

For example, to allow the firewall, instance, and snapshot read commands, the predefined `roles/compute.viewer` role is usually sufficient. For storage commands, use `roles/storage.admin`; for IAM policy commands, use `roles/resourcemanager.projectIamAdmin`.

You can verify which permissions a service account already has on a project with:

```bash
gcloud projects test-iam-permissions [PROJECT_ID] \
  --permissions=compute.firewalls.list,storage.buckets.list \
  --impersonate-service-account=[SA_EMAIL]@[PROJECT_ID].iam.gserviceaccount.com
```

The command returns only the permissions the service account actually holds, so any requested permission missing from the output still needs to be granted.

**OAuth Scope Required**: `https://www.googleapis.com/auth/cloud-platform`
