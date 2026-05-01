## VerifySupportTicketPermissionWrapper

Wrapper for `VerifySupportTicketPermission`. Calls the inner script via `executeCommand` so it is dispatched through the XSOAR server where the exclusion list is honored.

### Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.SupportTicketPermission.user_csp_permission | Whether the user has CSP permission to manage support tickets. | Boolean |
| Core.SupportTicketPermission.tenant_entitlement_check | Whether the tenant has the entitlement for support ticket management. | Boolean |
| Core.SupportTicketPermission.has_permission | Whether the user has full permission. | Boolean |
