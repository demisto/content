# Celonis
 
<~XSIAM>
 
Celonis is a process mining and execution management platform that helps organizations analyze and optimize their business processes for improved efficiency and performance.
 
### This pack includes:
- Collection of Celonis Audit, Studio Adoption and Login History logs
- Log Normalization - XDM mapping for key event types.

## Supported Event Types:
- Login-History
- Platform Adoption
- Audit Log

## How to integrate with XSIAM?
1. Click **Admin & Settings** and select **Applications**.
2. Click **Add New Application** -> **OAuth client** to create your OAuth client.
3. Create a new OAuth client by following the steps below:
   - **Authentication method**: Client secret post
   - **Scopes to select**:
     - `audit.log:read` (for the Audit Log API)
     - `platform-adoption.tracking-events:read` (for the Studio Adoption API)
     - `team.login-history:read` (for the Login History API)

4. Select **New OAuth Client**, and assign the following client scopes: `audit`, `platform-adoption` and `team`.
5. Click **Create** and copy the **Client ID** and **Client Secret** to your clipboard for later use.

For more information, check the Celnios Public API documentation -> [Click here](https://docs.celonis.com/).

 
</~XSIAM>