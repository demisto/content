Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

## CyberArk EPM

### Authentication
To authenticate to EPM, provide the following:

- url: `https://<EPM_server>` (for example: https://login.epm.cyberark.com/login)
- username
- password
- [application ID](https://docs.cyberark.com/Idaptive/Latest/en/Content/Applications/AppsOvw/SpecifyAppID.htm#%23SpecifytheApplicationID)

### Endpoint Information

To specify an endpoint, use the following command arguments: 
- `endpoint_name`
- `endpoint_external_ip`
- In addition, provide a pre-defined risk plan (for example, `Medium_Risk_Plan`).


