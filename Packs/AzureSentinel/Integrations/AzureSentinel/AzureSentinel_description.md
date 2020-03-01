To allow us access to Azure Sentinel, you need to get an authorization code by entering the following link (and setting the tenant_id and client_id in the relevant parts).
`https://login.microsoftonline.com/{tenant_id}/oauth2/authorize?client_id={client_id}&response_type=code&redirect_uri=https://localhost/myapp&resource=https://management.core.windows.net`
After entering this link, you will be automatically redirected to a URL that begins with `https://localhost/myapp` and holds a code parameter. Copy its value and paste it in the auth_code parameter of your instance.
