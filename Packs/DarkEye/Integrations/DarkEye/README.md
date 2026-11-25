Search DarkEye for a domain: ransomware leaks and data breaches in HaveIBeenRansom, and ransomware, breach, lead and stealer listings in Breach House. Each product has its own optional API key; at least one is required.
Each record carries its product and category, all in one `DarkEye.Domain` context entry per domain.

Get the HaveIBeenRansom API token from your HaveIBeenRansom profile ([API documentation](https://haveibeenransom.com/howapi)) and the Breach House API token from the Breach House customer panel ([API documentation](https://breach.house/docs)). A product without a key is skipped.

## Configure DarkEye in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| HaveIBeenRansom API Key | API token from your HaveIBeenRansom profile. Leave empty to skip HaveIBeenRansom. | False |
| Breach House API Key | API token from the Breach House customer panel. Leave empty to skip Breach House. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### darkeye-domain-search

***
Searches every configured DarkEye product for a domain. A record means the domain appears in a ransomware leak, a data breach, a lead or a stealer listing, usually as a victim. It does not mean the domain is malicious, and no record does not mean the domain is clean. When one product fails, the records of the other are kept and the failure is listed in DarkEye.Domain.Errors.

#### Base Command

`darkeye-domain-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to search, for example example.com. Accepts a comma-separated list. | Required | 
| max_pages | Maximum number of HaveIBeenRansom result pages to read (20 sources per page, at most 20 pages). Each page is one request. Default is 5. | Optional | 
| limit | Maximum number of Breach House results per section (ransomware, breaches, leads, stealers), at most 200. Default is 25. | Optional | 
| max_records | Maximum number of records kept per product, at most 500. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DarkEye.Domain.Name | String | The domain that was searched. | 
| DarkEye.Domain.Found | Boolean | Whether any product returned a record for the domain. | 
| DarkEye.Domain.Count | Number | The number of records returned. | 
| DarkEye.Domain.Products | String | The products that answered the search. | 
| DarkEye.Domain.CountsByProduct | Unknown | The number of records per product. | 
| DarkEye.Domain.CountsByCategory | Unknown | The number of records per category. | 
| DarkEye.Domain.Truncated | Boolean | Whether more records exist than the limits allowed. | 
| DarkEye.Domain.Errors.Product | String | A product whose search failed. | 
| DarkEye.Domain.Errors.Error | String | Why the search of that product failed. | 
| DarkEye.Domain.Records.Product | String | The product that returned the record \(HaveIBeenRansom or Breach House\). | 
| DarkEye.Domain.Records.Category | String | The record category: ransomware, breach, leads or stealer. Other HaveIBeenRansom leak types keep their own name. | 
| DarkEye.Domain.Records.ID | String | The record ID in the product. | 
| DarkEye.Domain.Records.Title | String | The listing title, usually the affected organization. | 
| DarkEye.Domain.Records.Website | String | The website of the affected organization. | 
| DarkEye.Domain.Records.Group | String | The ransomware group, when known. | 
| DarkEye.Domain.Records.Country | String | The country of the affected organization, when known. | 
| DarkEye.Domain.Records.Discovered | Date | The date the listing was discovered \(YYYY-MM-DD\). | 
