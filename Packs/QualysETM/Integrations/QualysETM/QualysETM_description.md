## Qualys Enterprise TruRisk Management (ETM)

### Prerequisites

1. The Qualys subscription must have the ETM module and API Access enabled (a paid feature).
2. Identify the correct Qualys API Gateway URL for your platform by using the [Qualys Platform Identification page](https://www.qualys.com/platform-identification/). This URL is the **Server URL** parameter.
3. The credentials are the standard Qualys account username and password. The integration exchanges them for a short-lived JSON Web Token (JWT).

### Permissions

To make calls using the ETM API, the account must have the **API Access** permission in its role. This permission is granted from the Administration module when creating a new role or editing an existing role. For more information, see the [Online Help of the Administration module](https://qualysguard.qg2.apps.qualys.com/portal-help/en/admin/index.htm#t=user%2Frole_management.htm).

### Rate Limits

The Qualys ETM API enforces a rate limit of **300 requests per hour** per subscription, and a concurrency limit of **2 concurrent calls** per API per subscription. Note that the ***qualys-etm-report-generate*** command polls the report status repeatedly until the report completes, and each poll consumes a request from this quota.