**To use this integration you must provide exactly one base credential:** a Service Account private key OR a Workload Identity Federation configuration. Optionally, you can impersonate another service account on top of the base credential.

### Getting a Service Account With a Role:
1) Go to [google console](https://console.developers.google.com.).
2) Select your project.
3) From the side-menu go to **IAM & admin** > **Service accounts** > **CREATE SERVICE ACCOUNT**.
5) Type an account name and description and click **CREATE**.
6) From  the drop down list Select a role from one of the following to in the integration:
    - **Project-Owner** or **Project-Editor** or ****Pub/Sub Admin** or **Pub/Sub Editor** - Grants you total access to the Project and allows you to use all the commands in the integration.
7) Click **CONTINUE** and then click **CREATE KEY**.
8) Select **JSON** and click **CREATE**.
 The .json file downloads.
9) Enter the file contents in the **Service account private key (JSON)** integration settings parameter.

### Workload Identity Federation (keyless):
1) In Google Cloud, create a Workload Identity Pool and a Provider (OIDC or AWS) for your external identity.
2) Grant the external identity access to the target service account (or resources) via IAM.
3) Download the generated credential configuration file (type: `external_account`) and paste its contents into the **Workload Identity Federation configuration (JSON)** parameter.

**Note:** Do not configure both the **Service account private key (JSON)** and the **Workload Identity Federation configuration (JSON)** parameters.

### Service Account Impersonation:
1) Configure a base credential for the instance: a **Service account private key (JSON)** or a **Workload Identity Federation configuration (JSON)**. This is the identity that will impersonate the target account. When using a Service Account key, paste the key of the base (caller) service account, not a key of the service account to impersonate.
2) In your Google Cloud project, create the target service account that the integration will act as (for example `pubsub-target@<PROJECT_ID>.iam.gserviceaccount.com`). Impersonation uses only the target's email, so no key is needed for this account.
3) Grant the target service account the Pub/Sub permissions the integration needs, as a project-level role: `roles/pubsub.editor`, or `roles/pubsub.subscriber` together with `roles/pubsub.publisher`.

    ```
    gcloud projects add-iam-policy-binding <PROJECT_ID> \
      --member="serviceAccount:<TARGET_SA_EMAIL>" \
      --role="roles/pubsub.editor"
    ```

4) Allow the base identity to impersonate the target by granting it `roles/iam.serviceAccountTokenCreator` on the target service account itself (a binding on the service account, not on the project). The base identity does not need Pub/Sub permissions.

    ```
    gcloud iam service-accounts add-iam-policy-binding <TARGET_SA_EMAIL> \
      --project=<PROJECT_ID> \
      --member="serviceAccount:<BASE_SA_EMAIL>" \
      --role="roles/iam.serviceAccountTokenCreator"
    ```

    For a Workload Identity Federation base, set `--member` to the federated principal (e.g., `principalSet://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL_ID>/*`).
5) Enable the IAM Service Account Credentials API in the project:

    ```
    gcloud services enable iamcredentials.googleapis.com --project=<PROJECT_ID>
    ```

6) Enter the target service account email in the **Service Account to impersonate** parameter. It must be a service account email (`...@<project>.iam.gserviceaccount.com`). All Pub/Sub calls run as this account.

When set, the **Service Account to impersonate** parameter overrides any `service_account_impersonation_url` embedded in the Workload Identity Federation configuration. When empty, impersonation happens only if the Workload Identity Federation configuration embeds a `service_account_impersonation_url`.
