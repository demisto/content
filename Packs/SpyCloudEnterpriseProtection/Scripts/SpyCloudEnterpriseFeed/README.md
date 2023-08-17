This Script execute spycloud-watchlist-command and create incident objects.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.8.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* SpyCloud_Watchlist_Incident

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field. Example:-  YYYY-MM-DD, -1days |
| until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field.<br/> Example:-  YYYY-MM-DD, -1days |
| since_modification_date | This parameter allows you to define the starting point for a date range query on when an already published record was modified \(record_modification_date\). Example:-  YYYY-MM-DD, -1days |
| until_modification_date | This parameter allows you to define the ending point for a date range query on the when an already published record was modified \(record_modification_date\). |
| type | This parameter lets you filter results by type. The allowed values are 'corporate' for corporate records, and 'infected' for infected user records \(from botnet data\). If no value has been provided the API function will, by default, return all record types. |
| watchlist_type | This parameters lets you filter results for only emails or only domains on your watchlist. If no value has been provided, the API will return all watchlist types. |
| severity | This parameter allows you to filter based on the numeric severity code.<br/>Possible values are:<br/>2 -&amp;gt; Email only severity. This record is part of an email-only list.<br/>5 -&amp;gt; Informational severity. This severity value is given to breach records where we have a non-crackable password hash, or no password at all.<br/>20 -&amp;gt;High severity. This severity value is given to breach records where we have an email address and a plaintext password.<br/>25 -&amp;gt; Critical severity. This severity value is given to breach records recovered from an infected machine \(botnet data\). These records will always have a plaintext password and most will have an email address. |
| source_id | This parameter allows you to filter based on a particular breach source. |
| salt | If hashing is enabled for your API key, you have the option to provide a 10 to 24 character, high entropy salt otherwise the pre-configured salt will be used. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Watchlist.Data.type | Incident Type. | string |
| Watchlist.Data.name | Name of the Incident. | string |
| Watchlist.Data.rawJSON | Response object of watchlist command. | string |
| Watchlist.Data.severity | Severity of the incident. | number |
| Watchlist.Data.custom_fields | Custom fields of spycloud incidents. | string |
