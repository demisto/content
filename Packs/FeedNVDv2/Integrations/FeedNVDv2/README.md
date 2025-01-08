CVE feed from the National Vulnerability Database. 

This integration was built and tested with version 2.0 of National Vulnerability Database API. See [the NVD Developer API documentation](https://nvd.nist.gov/developers/start-here) for more information.

An API key for this feed can be obtained at [the NIST NVD Developer Website](https://nvd.nist.gov/developers/request-an-api-key)

## Configure National Vulnerability Database in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| API Key | API Key from the NIST NVD Website (see above). | True |
| Start_date | Start date for the integration to begin fetching CVEs from (YYYY-MM-DD). | True |
| Return only CVEs that have a KEV | Check this box to only retrieve CVEs in the given date range that have a known exploited vulnerability (KEV) associated with them. Default: FALSE. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | True |
| Indicator Reputation | Indicators from this integration instance will be marked with this reputation. | True |
| Indicator Expiration Method | The method to be used to expire indicators from this feed. Default: Never. | True |
| Feed Fetch Interval | Interval at which this feed will check for new CVE data. Default: 4 Hours. | True |
| Bypass exclusion list | Allow this feed to bypass the Cortex XSOAR integrated exclusion list. | False |
| Trust any certificate (not secure) | Should the feed trust self-signed certificates. | False |
| Use system proxy settings | Use the proxy settings configured on the Cortex XSOAR server. | False |
| Tags | Tag CVE indicators from this instance of the feed with the provided tag. | False |
| Traffic Light Protocol Color | The Traffic Light Protocol \(TLP\) designation to apply to indicators fetched from the feed. | False |
| Log Level | **IMPORTANT** When performing a long initial fetch, it is recommended to set this to **DEBUG**. This will append output to /var/log/demisto/integration_instance.log so you can verify the feed is fetching data from NIST NVD. It is recommended to leave this log setting to **OFF** after the initial fetch. See **NOTE ONE** below for a sample of the debug output. | False |

### NOTE ONE - Sample Debug Output - /var/log/demisto/integration_instance.log

|**Parameter**|**Value**|**Description**|
|---|---|---|
| lastModStartDate|DATE/TIME UTC | The start date for the current CVE fetch cycle. |
| lastModEndDate|DATE/TIME UTC | The end date for the current CVE fetch cycle.|
| Fetch I teration | Integer | Current iteration of the overall fetch from NIST NVD. |
| Iteration Count | Integer | Iteration round through the current fetch cycle. NVD breaks up fetches into chunks to alleviate server load. This is the current count through one of the chunks of CVE data. |
| Total Results for Iteration | Integer | Total results returned for this fetch cycle chunk. |
| Current Total Fetched Indicator Count | Integer | Total number of CVEs fetched overall. |

    lastModStartDate: 2008-09-11T00:00:00.000
    lastModEndDate: 2009-01-09T00:00:00.000 
    Fetch Iteration: 5
    Iteration Count: 0
    Total Results for Iteration: 1
    Current Total Fetched Indicator Count: 4184

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
### nvd-get-indicators
***
Manually retrieve CVEs from NVD using the history parameter for the duration back to fetch.

#### Base Command

`!nvd-get-indicators history="7 days"`

#### Input
|**Argument Name**|**Description**|**Required**|
|---|---|---|
| History | Time back to retrieve CVEs, e.g. `7 days` | True |