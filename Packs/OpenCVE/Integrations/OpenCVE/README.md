
Ingests CVEs from an instance of OpenCVE.



## Configure OpenCVE on Cortex XSOAR

1. Navigate to **Settings > Integrations > Servers & Services**.
2. Search for OpenCVE
3. Click **Add instance** to create and configure a new integration instance.
	| Parameter  | Required |
	|------------|:--------:|
	| Server URL |   True   |
	| Username   |   True   |
	| Password   |   True   |
  4. Click **Test** to validate the URL and authentication.

## Commands

The commands available are direct translations of the [official APIs](https://docs.opencve.io/api/).

| Command                 | Description                                               | Arguments                                                                        | Context                                                                    |
|-------------------------|-----------------------------------------------------------|----------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| `cve` or `ocve-get-cve` | Get the details of a specific CVE                         | **`cve_id`**                                                                     | OpenCVE.CVE                                                                |
| `ocve-get-my-vendors`   | List the vendors subscriptions of the authenticated user  | None                                                                             | OpenCVE.myVendors                                                          |
| `ocve-get-my-products`  | List the products subscriptions of the authenticated user | None                                                                             | OpenCVE.myProducts                                                         |
| `ocve-get-vendors`      | List the vendors                                          | None                                                                             | OpenCVE.Vendors                                                            |
| `ocve-get-vendor`       | Get a specific vendor                                     | **`vendor_name`**                                                                | OpenCVE.{vendor}                                                           |
| `ocve-get-vendor-cves`  | Get all CVEs by vendor name                               | **`vendor_name`**<br>`search`<br>`product`<br>`cvss`<br>`cwe`<br>`page`          | OpenCVE.{vendor}.CVE                                                       |
| `ocve-get-products`     | List the products associated to a vendor                  | **`vendor_name`**<br>`search`<br>`page`                                          | OpenCVE.{vendor}.Products                                                  |
| `ocve-get-product`      | Get a specific product of a vendor                        | **`vendor_name`**<br>**`product_name`**                                          | OpenCVE.{vendor}.{product}                                                 |
| `ocve-get-product-cves` | Get the list of CVEs associated to a product              | **`vendor_name`**<br>**`product_name`**<br>`search`<br>`cvss`<br>`cwe`<br>`page` | <nobr>OpenCVE.{vendor}.{product}.CVE</nobr>                                             |
| `ocve-get-reports`      | List the reports of the authenticated user                | None                                                                             | OpenCVE.Reports                                                            |
| `ocve-get-report`       | Get a specific report                                     | **`report_id`**                                                                  | OpenCVE.Reports.{report_id}                                                |
| `ocve-get-alerts`       | List the alerts of a report                               | **`report_id`**<br>`page`                                                        | OpenCVE.Reports.Alerts                                                     |
| `ocve-get-alert`        | Get the details of an alert                               | **`report_id`**<br>**`alert_id`**                                                | <nobr>OpenCVE.Reports.Alerts.{alert_id}</nobr> |