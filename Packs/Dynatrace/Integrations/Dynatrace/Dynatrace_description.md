## Dynatrace Help

### How to Create a Personal Access Token (Classic Access Token):
Generate an access token:
1. In Dynatrace, go to Access Tokens -> `Generate new token`.
2. Enter a name for your token.
Note that Dynatrace doesn't enforce unique token names. You can create multiple tokens with the same name. Be sure to provide a meaningful name for each token you generate. Proper naming helps you to efficiently manage your tokens and perhaps delete them when they're no longer needed.
3. Select the required scopes for the token.
4. Click on `Generate token`.
5. Copy the generated token to the Collector's instance. Make sure to store the token in a password manager for future use, as you will not be able to access it later.

### Required scopes:
For each event type to fetch the according scope needs to be added to the token:

Audit logs events- auditLogs.read scope.

APM events- events.read scope.

### Server URL
Make sure to include the correct url:

For SaaS: https://{your-environment-id}.live.dynatrace.com

For ActiveGate Cluster:
https://{your-activegate-domain}:9999/e/{your-environment-id}


