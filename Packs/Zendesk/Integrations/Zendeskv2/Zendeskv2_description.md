Use the Zendesk V2 integration to perform operations related to users, tickets, attachments, and more.

### Required permissions
This integration enables executing commands with different permission levels.
**The Test button does not ensure sufficient permissions for all integration commands.**
please look at the description of the command for more information on the required permission.
To learn more about Zendesk roles refer to:
[Understanding Zendesk Support user roles](https://support.zendesk.com/hc/en-us/articles/4408883763866-Understanding-Zendesk-Support-user-roles#topic_ibd_fdq_cc)
[About team member product roles and access](https://support.zendesk.com/hc/en-us/articles/4408832171034)

### Event Collection (Audit Logs)
This integration supports fetching Zendesk audit log events for XSIAM.
**Allowed for:** Admins on accounts that have audit log access.
To enable event collection, check the **Fetch Events** checkbox in the integration configuration.
The audit logs API uses cursor-based pagination and fetches up to 1000 events per cycle (100 per page × 10 pages).

For more information about Zendesk V2 integration, see the [Integration documentation](https://xsoar.pan.dev/docs/reference/integrations/zendesk-v2)
