## Dynatrace Help

### How to Create a Personal Access Token (Classic Access Token):
Generate an access token
To generate an access token
1. Go to Access Tokens.
2. Select Generate new token.
3. Enter a name for your token.
Dynatrace doesn't enforce unique token names. You can create multiple tokens with the same name. Be sure to provide a meaningful name for each token you generate. Proper naming helps you to efficiently manage your tokens and perhaps delete them when they're no longer needed.
4. Select the required scopes for the token.
5. Select Generate token.
6. Copy the generated token to the clipboard. Store the token in a password manager for future use.
You can only access your token once upon creation. You can't reveal it afterward.

### Required scopes:
For each event type to fetch the according scope needs to be added to the token:

Audit logs events- auditLogs.read scope.

APM events- events.read scope.

### Server URL
Make sure to include the correct url:

For SaaS: https://{your-environment-id}.live.dynatrace.com

For ActiveGate Cluster:
https://{your-activegate-domain}:9999/e/{your-environment-id}


