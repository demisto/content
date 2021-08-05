The XSOAR Health Check pack automatically reviewing the current server and content for issues and best practices. 
The pack goal is to identify potential issues and remediate them before they become a real issue.

The resulting layout tabs will be produced to provide current system status and system diagnostics to identify issues to resolve.
The actionable items report will contain recommendations based on errors found or best practices.

**Prerequisites**:
Configure "Demisto REST API" Integration Instance.
For Multi-Tenants Environments there are 2 optiosn to define the "Demisto REST API" Integration Instance 
- Create API Key on Main Tenant and propogate the instance to All or Relevant tenentats using the lables
with the following instance settings:
  
- Create API Key on the relevant Tenant with the following instance settings.
make sure not to specify the tenant name in the settings:

**How to**:
1. Create manually new **System Diagnostics and Health Check** incident type.
2. Once the playbook is finished, the incident layout will contain the collected data and some improvement suggestions.