The XSOAR Health Check pack automatically reviewing the current server and content for issues and best practices. 
The pack goal is to identify potential issues and remediate them before they become a real issue.

The resulting layout tabs will provide the current system status and system diagnostics to identify issues to resolve.
The actionable items report will contain recommendations based on errors found or best practices.

##Prerequisites
**Single Server Deployment**

1. Configure **"Demisto REST API"** Integration Instance with **Admin** user

**Multi-Tenants Deployment**

1. Create API Key on Main Tenant
2. Create **Demisto REST API** integration on Main Tenant and use the API Key you created in previous step.
   On instance settings define in URL field *https://127.0.0.1*
   make sure not to set the tenant name in the URL.
2. Propogate **Demisto REST API** instance to All tenants or to the required tenant using propogation labels.


**How to**:
1. Create new manual Incident
2. pick **System Diagnostics and Health Check** incident type and **create new incident**.
3. Once the playbook is completed, the incident layout will contain the collected data and some improvement suggestions.



