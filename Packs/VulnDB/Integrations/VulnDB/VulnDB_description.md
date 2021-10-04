## Overview
---

Lists all of the security vulnerabilities for various products (OS,Applications) etc)
This integration was integrated and tested with version xx of VulnDB
## VulnDB Playbook
---

## Use Cases
---

## Configure VulnDB on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for VulnDB.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Hostname, IP address, or server URL__
    * __client_id__
    * __client_secret__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. vulndb-get-vuln-by-id
2. vulndb-get-vendor
3. vulndb-get-product
4. vulndb-get-version
5. vulndb-get-updates-by-dates-or-hours
6. vulndb-get-vuln-by-vendor-and-product-name
7. vulndb-get-vuln-by-vendor-and-product-id
8. vulndb-get-vuln-by-vendor-id
9. vulndb-get-vuln-by-product-id
10. vulndb-get-vuln-by-cve-id
### 1. vulndb-get-vuln-by-id
---
Provides full details about a specific vulnerability by id
##### Base Command

`vulndb-get-vuln-by-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vuln_id | Vulnerability id | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.Vulnerability.ID | string | Vulnerability id | 
| VulnDB.Vulnerability.Title | string | Vulnerability title (only human readable) | 
| VulnDB.Vulnerability.Keywords | string | Vulnerability keywords | 
| VulnDB.Vulnerability.Description | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.Solution | string | Vulnerability solution (only human readable) | 
| VulnDB.Vulnerability.PublishedDate | date | Vulnerability published date | 
| VulnDB.Vulnerability.TDescription | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.SolutionDate | date | Vulnerability solution date | 
| VulnDB.Vulnerability.DiscoveryDate | date | Vulnerability discovery date | 
| VulnDB.Vulnerability.ExploitPublishDate | date | Exploit publish date | 
| VulnDB.CVE-ExtReferences.Value | string | CVE- is a constant string | 
| VulnDB.CvssMetrics.Id | number | Cvss reference value | 
| VulnDB.CvssMetrics.AccessVector | string | Cvss access vector | 
| VulnDB.CvssMetrics.AccessComplexity | string | Cvss access complexity | 
| VulnDB.CvssMetrics.Authentication | string | Cvss metric authentication | 
| VulnDB.CvssMetrics.ConfidentialityImpact | string | Cvss confidentiality impact | 
| VulnDB.cvssMetrics.IntegrityImpact | string | Cvss integrity impact | 
| VulnDB.CvssMetrics.AvailabilityImpact | string | Cvss availability impact | 
| VulnDB.CvssMetrics.GeneratedOn | date | Cvss Metric date | 
| VulnDB.CvssMetrics.Score | number | Cvss score | 
| VulnDB.Vendor.Id | number | Vendor id | 
| VulnDB.Vendor.Name | string | Vendor name | 
| VulnDB.Products.Id | number | Products id | 
| VulnDB.Products.Name | string | Products name | 
| VulnDB.Products.Versions.Id | number | Product version id | 
| VulnDB.Products.Versions.Name | string | Product versions name | 
| VulnDB.Classification.Longname | string | Classification long name | 
| VulnDB.Classification.Description | string | Classification description (only human readable) | 


##### Command Example
```!vulndb-get-vuln-by-id vuln_id="1"```

##### Human Readable Output


### 2. vulndb-get-vendor
---
Provides all or specific vendor details to include vendor name and id
##### Base Command

`vulndb-get-vendor`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_id | specific vendor id | Optional | 
| vendor_name | specific vendor name (only human readable) | Optional | 
| max_size | Maximum number of entries returned from the query, to avoid slow response. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.Results.Id | number | Result id | 
| VulnDB.Results.Name | string | Result name | 
| VulnDB.Results.ShortName | string | Result short name | 
| VulnDB.Results.VendorUrl | string | Result vendor url (only human readable) | 


##### Command Example
```!vulndb-get-vendor max_size="20"```

##### Human Readable Output


### 3. vulndb-get-product
---
Provides a list of versions by product name or id
##### Base Command

`vulndb-get-product`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_id | Vendor id | Optional | 
| vendor_name | Vendor name | Optional | 
| max_size | Maximum number of entries returned from the query, to avoid slow response. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.Results.Id | number | Result id | 
| VulnDB.Results.Name | string | Result name | 


##### Command Example
```!vulndb-get-product vendor_id="2974649" max_size="20"```

##### Human Readable Output


### 4. vulndb-get-version
---
Provides the versions for the specified product by product name or id
##### Base Command

`vulndb-get-version`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product_name | Product name | Optional | 
| product_id | Product id | Optional | 
| max_size | Maximum number of entries returned from the query, to avoid slow response. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.Results.Id | number | Version id | 
| VulnDB.Results.Name | Unknown | Version name | 


##### Command Example
```!vulndb-get-version product_name="1-Search" max_size="20"```

##### Human Readable Output


### 5. vulndb-get-updates-by-dates-or-hours
---
Provides the recent vulnerabilities by dates or hours
##### Base Command

`vulndb-get-updates-by-dates-or-hours`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_date | Date YYYY-MM-dd starting date (earliest) | Optional | 
| end_date | Date YYYY-MM-dd finishing date (latest) | Optional | 
| hours_ago | How many hours ago | Optional | 
| max_size | Maximum number of entries returned from the query, to avoid slow response. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.Vulnerability.ID | string | Vulnerability id | 
| VulnDB.Vulnerability.Title | string | Vulnerability title (only human readable) | 
| VulnDB.Vulnerability.Keywords | string | Vulnerability keywords | 
| VulnDB.Vulnerability.Description | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.Solution | string | Vulnerability solution (only human readable) | 
| VulnDB.Vulnerability.PublishedDate | date | Vulnerability published date | 
| VulnDB.Vulnerability.TDescription | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.SolutionDate | date | Vulnerability solution date | 
| VulnDB.Vulnerability.DiscoveryDate | date | Vulnerability discovery date | 
| VulnDB.Vulnerability.ExploitPublishDate | date | Exploit publish date | 
| VulnDB.CVE-ExtReferences.Value | string | CVE- is a constant string | 
| VulnDB.CvssMetrics.Id | number | Cvss reference value | 
| VulnDB.CvssMetrics.AccessVector | string | Cvss access vector | 
| VulnDB.CvssMetrics.AccessComplexity | string | Cvss access complexity | 
| VulnDB.CvssMetrics.Authentication | string | Cvss metric authentication | 
| VulnDB.CvssMetrics.ConfidentialityImpact | string | Cvss confidentiality impact | 
| VulnDB.cvssMetrics.integrity_impact | string | Cvss integrity impact | 
| VulnDB.CvssMetrics.AvailabilityImpact | string | Cvss  availability impact | 
| VulnDB.CvssMetrics.Generated_on | date | Cvss Metric date | 
| VulnDB.CvssMetrics.Score | number | Cvss score | 
| VulnDB.Vendors.Id | number | Vendor id | 
| VulnDB.Vendor.Name | string | Vendor name | 
| VulnDB.Products.Id | number | Products id | 
| VulnDB.Products.Name | string | Products name | 
| VulnDB.Products.Versions.Id | number | Product version id | 
| VulnDB.Products.Versions.Name | string | Product versions name | 
| VulnDB.Classification.Longname | string | Classification long name | 
| VulnDB.Classification.Description | string | Classification description (only human readable) | 


##### Command Example
```!vulndb-get-updates-by-dates-or-hours start_date="2015-10-27T04:27:22" end_date="2017-10-27T04:27:22" max_size="20"```

##### Human Readable Output


### 6. vulndb-get-vuln-by-vendor-and-product-name
---
Provides full details about a specific vulnerability by vendor and product name
##### Base Command

`vulndb-get-vuln-by-vendor-and-product-name`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_name | Vendor name | Required | 
| product_name | Product name | Required | 
| max_size | Maximum number of entries returned from the query, to avoid slow response. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.Vulnerability.ID | string | Vulnerability id | 
| VulnDB.Vulnerability.Title | string | Vulnerability title (only human readable) | 
| VulnDB.Vulnerability.Keywords | string | Vulnerability keywords | 
| VulnDB.Vulnerability.Description | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.Solution | string | Vulnerability solution (only human readable) | 
| VulnDB.Vulnerability.PublishedDate | date | Vulnerability published date | 
| VulnDB.Vulnerability.TDescription | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.SolutionDate | date | Vulnerability solution date | 
| VulnDB.Vulnerability.DiscoveryDate | date | Vulnerability discovery date | 
| VulnDB.Vulnerability.ExploitPublishDate | date | Exploit publish date | 
| VulnDB.CVE-ExtReferences.Value | string | CVE- is a constant string | 
| VulnDB.CvssMetrics.Id | number | Cvss reference value | 
| VulnDB.CvssMetrics.AccessVector | string | Cvss access vector | 
| VulnDB.CvssMetrics.AccessComplexity | string | Cvss access complexity | 
| VulnDB.CvssMetrics.Authentication | string | Cvss metric authentication | 
| VulnDB.CvssMetrics.ConfidentialityImpact | string | Cvss confidentiality impact | 
| VulnDB.cvssMetrics.integrity_impact | string | Cvss integrity impact | 
| VulnDB.CvssMetrics.AvailabilityImpact | string | Cvss  availability impact | 
| VulnDB.CvssMetrics.Generated_on | date | Cvss Metric date | 
| VulnDB.CvssMetrics.Score | number | Cvss score | 
| VulnDB.Vendors.Id | number | Vendor id | 
| VulnDB.Vendor.Name | string | Vendor name | 
| VulnDB.Products.Id | number | Products id | 
| VulnDB.Products.Name | string | Products name | 
| VulnDB.Products.Versions.Id | number | Product version id | 
| VulnDB.Products.Versions.Name | string | Product versions name | 
| VulnDB.Classification.Longname | string | Classification long name | 
| VulnDB.Classification.Description | string | Classification description (only human readable) | 


##### Command Example
```!vulndb-get-vuln-by-vendor-and-product-name vendor_name="Adobe Systems Incorporated" product_name="ColdFusion" max_size="20"```

##### Human Readable Output


### 7. vulndb-get-vuln-by-vendor-and-product-id
---
Provides full details about a specific vulnerability by vendor and product id
##### Base Command

`vulndb-get-vuln-by-vendor-and-product-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_id | Vendor ID | Required | 
| product_id | Product ID | Required | 
| max_size | Maximum number of entries returned from the query, to avoid slow response. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.Vulnerability.ID | string | Vulnerability id | 
| VulnDB.Vulnerability.Title | string | Vulnerability title (only human readable) | 
| VulnDB.Vulnerability.Keywords | string | Vulnerability keywords | 
| VulnDB.Vulnerability.Description | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.Solution | string | Vulnerability solution (only human readable) | 
| VulnDB.Vulnerability.PublishedDate | date | Vulnerability published date | 
| VulnDB.Vulnerability.TDescription | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.SolutionDate | date | Vulnerability solution date | 
| VulnDB.Vulnerability.DiscoveryDate | date | Vulnerability discovery date | 
| VulnDB.Vulnerability.ExploitPublishDate | date | Exploit publish date | 
| VulnDB.CVE-ExtReferences.Value | string | CVE- is a constant string | 
| VulnDB.CvssMetrics.Id | number | Cvss reference value | 
| VulnDB.CvssMetrics.AccessVector | string | Cvss access vector | 
| VulnDB.CvssMetrics.AccessComplexity | string | Cvss access complexity | 
| VulnDB.CvssMetrics.Authentication | string | Cvss metric authentication | 
| VulnDB.CvssMetrics.ConfidentialityImpact | string | Cvss confidentiality impact | 
| VulnDB.cvssMetrics.integrity_impact | string | Cvss integrity impact | 
| VulnDB.CvssMetrics.AvailabilityImpact | string | Cvss  availability impact | 
| VulnDB.CvssMetrics.Generated_on | date | Cvss Metric date | 
| VulnDB.CvssMetrics.Score | number | Cvss score | 
| VulnDB.Vendors.Id | number | Vendor id | 
| VulnDB.Vendor.Name | string | Vendor name | 
| VulnDB.Products.Id | number | Products id | 
| VulnDB.Products.Name | string | Products name | 
| VulnDB.Products.Versions.Id | number | Product version id | 
| VulnDB.Products.Versions.Name | string | Product versions name | 
| VulnDB.Classification.Longname | string | Classification long name | 
| VulnDB.Classification.Description | string | Classification description (only human readable) | 


##### Command Example
```!vulndb-get-vuln-by-vendor-and-product-id vendor_id="5011" product_id="1777" max_size="20"```

##### Human Readable Output


### 8. vulndb-get-vuln-by-vendor-id
---
Provides full details about vulnerabilities by vendor id
##### Base Command

`vulndb-get-vuln-by-vendor-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vendor_id | Vendor id | Required | 
| max_size | Maximum number of entries returned from the query, to avoid slow response. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.Vulnerability.ID | string | Vulnerability id | 
| VulnDB.Vulnerability.Title | string | Vulnerability title (only human readable) | 
| VulnDB.Vulnerability.Keywords | string | Vulnerability keywords | 
| VulnDB.Vulnerability.Description | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.Solution | string | Vulnerability solution (only human readable) | 
| VulnDB.Vulnerability.PublishedDate | date | Vulnerability published date | 
| VulnDB.Vulnerability.TDescription | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.SolutionDate | date | Vulnerability solution date | 
| VulnDB.Vulnerability.DiscoveryDate | date | Vulnerability discovery date | 
| VulnDB.Vulnerability.ExploitPublishDate | date | Exploit publish date | 
| VulnDB.CVE-ExtReferences.Value | string | CVE- is a constant string | 
| VulnDB.CvssMetrics.Id | number | Cvss reference value | 
| VulnDB.CvssMetrics.AccessVector | string | Cvss access vector | 
| VulnDB.CvssMetrics.AccessComplexity | string | Cvss access complexity | 
| VulnDB.CvssMetrics.Authentication | string | Cvss metric authentication | 
| VulnDB.CvssMetrics.ConfidentialityImpact | string | Cvss confidentiality impact | 
| VulnDB.cvssMetrics.integrity_impact | string | Cvss integrity impact | 
| VulnDB.CvssMetrics.AvailabilityImpact | string | Cvss  availability impact | 
| VulnDB.CvssMetrics.Generated_on | date | Cvss Metric date | 
| VulnDB.CvssMetrics.Score | number | Cvss score | 
| VulnDB.Vendors.Id | number | Vendor id | 
| VulnDB.Vendor.Name | string | Vendor name | 
| VulnDB.Products.Id | number | Products id | 
| VulnDB.Products.Name | string | Products name | 
| VulnDB.Products.Versions.Id | number | Product version id | 
| VulnDB.Products.Versions.Name | string | Product versions name | 
| VulnDB.Classification.Longname | string | Classification long name | 
| VulnDB.Classification.Description | string | Classification description (only human readable) | 


##### Command Example
```!vulndb-get-vuln-by-vendor-id vendor_id="5011" max_size="20"```

##### Human Readable Output


### 9. vulndb-get-vuln-by-product-id
---
Provides full details about vulnerabilities by product id
##### Base Command

`vulndb-get-vuln-by-product-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| product_id | Product id | Required | 
| max_size | Maximum number of entries returned from the query, to avoid slow response. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.Vulnerability.ID | string | Vulnerability id | 
| VulnDB.Vulnerability.Title | string | Vulnerability title (only human readable) | 
| VulnDB.Vulnerability.Keywords | string | Vulnerability keywords | 
| VulnDB.Vulnerability.Description | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.Solution | string | Vulnerability solution (only human readable) | 
| VulnDB.Vulnerability.PublishedDate | date | Vulnerability published date | 
| VulnDB.Vulnerability.TDescription | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.SolutionDate | date | Vulnerability solution date | 
| VulnDB.Vulnerability.DiscoveryDate | date | Vulnerability discovery date | 
| VulnDB.Vulnerability.ExploitPublishDate | date | Exploit publish date | 
| VulnDB.CVE-ExtReferences.Value | string | CVE- is a constant string | 
| VulnDB.CvssMetrics.Id | number | Cvss reference value | 
| VulnDB.CvssMetrics.AccessVector | string | Cvss access vector | 
| VulnDB.CvssMetrics.AccessComplexity | string | Cvss access complexity | 
| VulnDB.CvssMetrics.Authentication | string | Cvss metric authentication | 
| VulnDB.CvssMetrics.ConfidentialityImpact | string | Cvss confidentiality impact | 
| VulnDB.cvssMetrics.integrity_impact | string | Cvss integrity impact | 
| VulnDB.CvssMetrics.AvailabilityImpact | string | Cvss  availability impact | 
| VulnDB.CvssMetrics.Generated_on | date | Cvss Metric date | 
| VulnDB.CvssMetrics.Score | number | Cvss score | 
| VulnDB.Vendors.Id | number | Vendor id | 
| VulnDB.Vendor.Name | string | Vendor name | 
| VulnDB.Products.Id | number | Products id | 
| VulnDB.Products.Name | string | Products name | 
| VulnDB.Products.Versions.Id | number | Product version id | 
| VulnDB.Products.Versions.Name | string | Product versions name | 
| VulnDB.Classification.Longname | string | Classification long name | 
| VulnDB.Classification.Description | string | Classification description (only human readable) | 


##### Command Example
```!vulndb-get-vuln-by-product-id product_id="1777" max_size="20"```

##### Human Readable Output


### 10. vulndb-get-vuln-by-cve-id
---
Provides full details about vulnerabilities by cve id
##### Base Command

`vulndb-get-vuln-by-cve-id`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | CVE id | Required | 
| max_size | Maximum number of entries returned from the query, to avoid slow response. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| VulnDB.Vulnerability.ID | string | Vulnerability id | 
| VulnDB.Vulnerability.Title | string | Vulnerability title (only human readable) | 
| VulnDB.Vulnerability.Keywords | string | Vulnerability keywords | 
| VulnDB.Vulnerability.Description | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.Solution | string | Vulnerability solution (only human readable) | 
| VulnDB.Vulnerability.PublishedDate | date | Vulnerability published date | 
| VulnDB.Vulnerability.TDescription | string | Vulnerability description (only human readable) | 
| VulnDB.Vulnerability.SolutionDate | date | Vulnerability solution date | 
| VulnDB.Vulnerability.DiscoveryDate | date | Vulnerability discovery date | 
| VulnDB.Vulnerability.ExploitPublishDate | date | Exploit publish date | 
| VulnDB.CVE-ExtReferences.Value | string | CVE- is a constant string | 
| VulnDB.CvssMetrics.Id | number | Cvss reference value | 
| VulnDB.CvssMetrics.AccessVector | string | Cvss access vector | 
| VulnDB.CvssMetrics.AccessComplexity | string | Cvss access complexity | 
| VulnDB.CvssMetrics.Authentication | string | Cvss metric authentication | 
| VulnDB.CvssMetrics.ConfidentialityImpact | string | Cvss confidentiality impact | 
| VulnDB.cvssMetrics.integrity_impact | string | Cvss integrity impact | 
| VulnDB.CvssMetrics.AvailabilityImpact | string | Cvss  availability impact | 
| VulnDB.CvssMetrics.Generated_on | date | Cvss Metric date | 
| VulnDB.CvssMetrics.Score | number | Cvss score | 
| VulnDB.Vendors.Id | number | Vendor id | 
| VulnDB.Vendor.Name | string | Vendor name | 
| VulnDB.Products.Id | number | Products id | 
| VulnDB.Products.Name | string | Products name | 
| VulnDB.Products.Versions.Id | number | Product version id | 
| VulnDB.Products.Versions.Name | string | Product versions name | 
| VulnDB.Classification.Longname | string | Classification long name | 
| VulnDB.Classification.Description | string | Classification description (only human readable) | 


##### Command Example
```!vulndb-get-vuln-by-cve-id cve_id="2013-1228" max_size="20"```

##### Human Readable Output


## Additional Information
---

## Known Limitations
---

## Troubleshooting
---