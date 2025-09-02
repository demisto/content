# Monday Event Collector

Monday.com is a work operating system that powers teams to run projects and workflows with confidence. Use this pack to fetch activity and audit logs from Monday.com for threat detection and compliance monitoring in Cortex XSIAM.

## What does this pack do?

The Monday Event Collector integration provides comprehensive event collection capabilities for Monday.com:

- **Activity Logs Collection**: Monitor user activities, board interactions, and workspace changes using OAuth 2.0 authentication
- **Audit Logs Collection**: Track administrative actions, security events, and compliance-related activities using API token authentication

## Pack Contents

- `MondayEventCollector` integration - integrates with Monday.com API to fetch logs.

## Supported Event Types

### Activity Logs

Activity logs capture user interactions and operational activities within Monday.com workspaces:

- Board creation, updates, and deletions
- Item and column modifications
- User login and authentication events
- Workspace and team changes
- File uploads and sharing activities

### Audit Logs

Audit logs provide detailed security and administrative event tracking:

- Administrative actions and configuration changes
- User permission modifications
- Security policy updates
- Account management activities
- Compliance and governance events

## Additional Resources

- [Monday.com API Documentation](https://developer.monday.com/api-reference/docs)
- [OAuth 2.0 Authentication Guide](https://developer.monday.com/apps/docs/choosing-auth#method-2-using-oauth-to-issue-access-tokens)
- [Audit Log API Documentation](https://support.monday.com/hc/en-us/articles/4406042650002-Audit-Log-API)
- [Activity Log API Documentation](https://developer.monday.com/api-reference/reference/activity-logs)
- [Monday.com App Creation Guide](https://developer.monday.com/apps/docs/create-an-app#creating-an-app-in-the-developer-center)
