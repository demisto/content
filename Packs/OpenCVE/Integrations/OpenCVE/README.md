Ingests CVEs from an instance of OpenCVE.

## Configure OpenCVE in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Username |  | True |
| Password |  | True |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Trust any certificate (not secure) |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### opencve-latest

***
Returns the latest updated CVEs from your reports.

#### Base Command

`opencve-latest`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of CVEs to display. | Optional | 
| lastRun | Last run. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | number | The CVSS score of the CVE. | 
| CVE.Published | Date | The date the CVE was published. | 
| CVE.Modified | Date | The date that the CVE was last modified. | 
| CVE.Description | String | The description of the CVE. | 
| DBotScore.Indicator | String | The indicator value. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor reporting the score of the indicator. | 

### cve

***
Returns CVE information by CVE ID.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | The CVE ID. For example: CVE-2014-1234. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE. | 
| CVE.CVSS | number | The CVSS score of the CVE. | 
| CVE.Published | Date | The date the CVE was published. | 
| CVE.Modified | Date | The date that the CVE was last modified. | 
| CVE.Description | String | The description of the CVE. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The indicator score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 

### opencve-get-my-vendors

***
List the vendors subscriptions of the authenticated user.

#### Base Command

`opencve-get-my-vendors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCVE.Vendors | unknown | Vendors. | 

### opencve-get-my-products

***
List the products subscriptions of the authenticated user.

#### Base Command

`opencve-get-my-products`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| OpenCVE.Products | unknown | Products. | 

### opencve-get-vendor-cves

***
Get vendor CVEs.

#### Base Command

`opencve-get-vendor-cves`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_name | Vendor name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| vendor_cves | unknown | CVEs for the vendor. | 

### opencve-get-product-cves

***
Get product CVEs.

#### Base Command

`opencve-get-product-cves`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_name | Vendor name. | Required | 
| product_name | Product name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| product_cves | unknown | Product CVEs. | 

### opencve-get-reports

***
List the reports of the authenticated user or get a specific report.

#### Base Command

`opencve-get-reports`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | Report ID. | Optional | 
| page | Specific page to start from. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| reports | unknown | Reports. | 

### opencve-get-alerts

***
List the alerts of a report or get the details of a specific alert.

#### Base Command

`opencve-get-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| report_id | The report ID. | Optional | 
| page | Specific page to start from. | Optional | 
| alert_id | The Alert ID. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| alerts | unknown | The Alerts from the provided Report ID. | 

### opencve-get-products

***
List the products associated to a vendor or get a specific one.

#### Base Command

`opencve-get-products`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_name | Vendor name. | Required | 
| product_name | Product name. | Optional | 
| search | Filter the search by a keyword. | Optional | 
| page | Specific page to start from. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| products | unknown | Products. | 

### opencve-get-vendors

***
List the products associated to a vendor or get a specific product of a vendor by specifying its name.

#### Base Command

`opencve-get-vendors`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_name | Vendor name. | Optional | 
| search | Filter the search by a keyword. | Optional | 
| page | Specific page to start from. | Optional | 
| letter | Filter by the first letter. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| vendors | unknown | Vendors. | 