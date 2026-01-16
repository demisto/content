**Important:** This integration is supported by Palo Alto Networks.

## Saviynt Enterprise Identity Cloud

Collector for Saviynt Enterprise Identity Cloud (EIC) audit logs.
This integration was integrated and tested with the [API Reference for Amsterdam GA Release](https://documenter.getpostman.com/view/40843358/2sAYdctCto) (v5).

## Prerequisites

### Step 1: Creating an Analytics Record
Create a new runtime analytics control (V2) using an SQL query. For more information, see [Creating Elasticsearch-based Analytics Controls (Version 2)](https://docs.saviyntcloud.com/bundle/EIC-Admin-25/page/Content/Chapter17-EIC-Analytics/Managing-Analytics-v232-Earlier/Creating-Elasticsearch-based-Analytics-Controls-Analytics-V2.htm).
While creating an analytics control, copy the following query in the Analytics Query parameter:
```sql
select ua.TYPEOFACCESS as 'Object Type',ua.ActionType as 'Action Taken',u.username as 'Accessed By', ua.IPADDRESS as 'IP Address',ua.ACCESSTIME as 'Event Time',ua.DETAIL as 'Message' from users u , userlogin_access ua, userlogins l where l.loginkey = ua.LOGINKEY and l.USERKEY = u.userkey and ua.AccessTime >= (NOW() - INTERVAL ${timeFrame} Minute) and ua.Detail is not NULL
```

### Step 2: Setting up Permissions
Saviynt recommends that you create a dedicated user with least privileges required to call the Saviynt fetchRuntimeControlsDataV2 API to obtain the audit logs. For example, you can associate a ROLE_ADMIN SAV role or a custom SAV role with required permissions to the user to call the API.
Perform the following steps to set up permissions:

1. Create a user, for example, `siem-sid`. For more information, see [Creating Users](https://docs.saviyntcloud.com/bundle/EIC-Admin-25/page/Content/Chapter03-User-Management/Creating-Users.htm).
2. Change the password for the user. For more information, see [Administrator Functions](https://docs.saviyntcloud.com/bundle/EIC-Admin-25/page/Content/Chapter07-General-Administrator/Administrator-Functions.htm).
3. Create a SAV role, for example, `ROLE_SIEM`.
4. Assign permissions to the newly created SAV role.
   1. Assign the permission to access the web service URL of the Saviynt fetchRuntimeControlsDataV2 API. For more information, see [Understanding the SAV Role Parameters](https://docs.saviyntcloud.com/bundle/EIC-Admin-25/page/Content/Chapter09-SAV-Roles/Understanding-the-SAV-Role-Parameters.htm).
   2. Assign the permission to verify the analytics record that you created. For more information, see [Understanding the SAV Role Parameters](https://docs.saviyntcloud.com/bundle/EIC-Admin-25/page/Content/Chapter09-SAV-Roles/Understanding-the-SAV-Role-Parameters.htm).
5. Associate the SAV role with the user created in Step 1. For more information, see [Understanding the SAV Role Parameters](https://docs.saviyntcloud.com/bundle/EIC-Admin-25/page/Content/Chapter09-SAV-Roles/Understanding-the-SAV-Role-Parameters.htm).

> Note: If you want to associate the `ROLE_ADMIN` SAV role with a user, you need not perform steps 4.1 and 4.2.
