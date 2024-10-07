## SpyCloud Enterprise Protection Feed

Create breach and malware incidents in Cortex® XSOAR™ using the SpyCloud Enterprise Protection API.
This integration was integrated and tested with version 3.5 of SpyCloud Enterprise Protection API

## Configure SpyCloud Enterprise Protection Feed in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- |--------------|
| API URL | SpyCloud Enterprise Protection API Base URL | True         |
| API Key | SpyCloud Enterprise Protection API Key | True         |
| Fetch incidents | This is a required field by XSOAR to fetch new Watchlist events from SpyCloud watchlist API | True         |
| Since | This parameter allows you to define the starting point for a date range query on the spycloud_publish_date field.<br/>Example: -1days, now, YYYY-MM-DD. | False        |
| Until | This parameter allows you to define the ending point for a date range query on the spycloud_publish_date field.<br/>Example: -1days, now, YYYY-MM-DD. | False        |
| Since Modification Date | This parameter allows you to define the starting point for a date range query on the when an already published record was modified \(record_modification_date\).<br/>Example: -1days, now, YYYY-MM-DD. | False        |
| Until Modification Date | This parameter allows you to define the ending point for a date range query on the when an already published record was modified \(record_modification_date\).<br/>Example: -1days, now, YYYY-MM-DD. | False        |
| Severity | This parameter allows you to filter based on the numeric severity code. | False        |
| Source ID | This parameter allows you to filter based on a particular breach source.This parameter allows you to filter based on a particular breach source. | False        |
| Salt | If hashing is enabled for your API key, you have the option to provide a 10 to 24 character, high entropy salt otherwise the pre-configured salt will be used. | False        |
| Type | This parameter lets you filter results by type. The allowed values are 'corporate' for corporate records, and 'infected' for infected user records \(from botnet data\). If no value has been provided the API function will, by default, return all record types. | False        |
| Watchlist Type | This parameters lets you filter results for only emails or only domains on your watchlist. The allowed values are: \['email', 'domain', 'subdomain', 'ip'\]. If no value has been provided, the API will return all watchlist types. | False        |
| Trust any certificate (not secure) | Trust any certificate (not secure) | False        |
| Use system proxy settings | Use system proxy settings | False        |
| Incidents Fetch Interval | Incidents Fetch Interval | False        |
| Incident type | Incident type | False        |
