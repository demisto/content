## VerifySupportTicketPermission

Verifies whether the current user has the required permissions to manage support tickets. Checks both user CSP permission and tenant entitlement.

### Outputs

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Core.SupportTicketPermission.user_csp_permission | Whether the user has CSP permission to manage support tickets. | Boolean |
| Core.SupportTicketPermission.tenant_entitlement_check | Whether the tenant has the entitlement for support ticket management. | Boolean |
| Core.SupportTicketPermission.has_permission | Whether the user has full permission (both user CSP permission and tenant entitlement). | Boolean |
