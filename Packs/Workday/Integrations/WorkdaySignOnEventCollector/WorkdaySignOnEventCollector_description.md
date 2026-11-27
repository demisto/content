## Workday Sign On Event Collector

Use this integration to collect Signon events automatically from Workday.

In order to use this integration, you need to enter your Workday credentials in the relevant integration instance parameters.

### Instance Parameters

- **Server URL**: Only the Workday host, without any path, for example, `https://wd5-services1.myworkday.com`. In Workday, run the **View API Clients** report. The **Workday Web Services Endpoint** is shown as `https://<host>/ccx/service/<tenant>`. Use only `https://<host>`.
- **Tenant Name**: The tenant name, for example, `acme` or `acme_preview` (the last part of the web services endpoint).
- **API Version**: The Workday Identity Management web service version, in the format `vXX.X`. Default is `v40.0`.
- **Username / Password**: An integration system user that has permission to the Workday Account sign-ons (Identity Management). Enter the user name **with** the tenant suffix, in the `Username@TenantName` format.
