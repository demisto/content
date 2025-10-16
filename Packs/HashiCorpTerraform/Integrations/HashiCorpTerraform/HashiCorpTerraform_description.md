## HashiCorp Terraform Help

### How to Configure this Integration

- The *API Token* can be generated using the instructions below.
- The *Default Workspace ID* can be taken from *Projects & workspaces* within the selected organization.
- The *Default Organization Name* can be taken from the organizations listed in [organizations](https://app.terraform.io/app/organizations).

---

### How to Generate an API Token

1. Log in with a HashiCorp Cloud Platform account.

2. Click **Tokens** in the sidebar to create, manage, and revoke API tokens. HCP Terraform has multiple types of tokens:

   - Organization tokens
   - Team tokens
   - User tokens
   - Audit trail tokens
   - Agent tokens

   Most commands require a **User** or **Team** token that has admin level access to the workspace.

   <~XSIAM>Fetching audit trail events requires an **Audit trail** or **Organization** token. </~XSIAM>

   For additional details, refer to the integration documentation and [HashiCorp Terraform API Tokens](https://developer.hashicorp.com/terraform/cloud-docs/users-teams-organizations/api-tokens).

3. Click **Create an API token**. The Create API token box appears.

4. Enter a Description that explains what the token is for and click **Create API token**.

5. (Optional) Enter the token's expiration date or time, or create a token that never expires.

6. Copy the token from the box and save it in a secure location. Use it to configure an instance of this integration.

<~XSIAM>
---

### How to Fetch Access Audit Trail Events

The organization should have the `audit-logging` feature entitlement to fetch access audit trail events. Refer to [HashiCorp Terraform Feature Entitlements](https://developer.hashicorp.com/terraform/cloud-docs/api-docs#feature-entitlements).

</~XSIAM>
