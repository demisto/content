Integration with Github using REST API to Gets the audit log for an organization.

## Configuration Parameters

**Server URL**  
Endpoit to get the logs, Replace the `${ORGANIZATION}` value with your organization: ``https://api.github.com/orgs/${ORGANIZATION}/audit-log``

**API Key**  
access toke you created in github, You must be an organization owner, and you must use an access token with the admin:org scope.
GitHub Apps must have the organization_administration read permission to use this endpoint.

For more information see the [Github Documentation](https://docs.github.com/en/rest/orgs/orgs#get-the-audit-log-for-an-organization).