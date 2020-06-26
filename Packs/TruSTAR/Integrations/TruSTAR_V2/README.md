Use the TruSTAR v2 integration to manage reports, indicators and phishing submissions.

This integration was integrated and tested with TruSTAR v1.3. (TruSTAR Python SDK.)
## Use Cases

- Search for indicators.
- Retrieve indicators metadata.
- Search for premium intel indicator summaries.
- Add and remove indicators to the whitelist.
- Filter reports using indicators.
- Submit, update, delete, search, and get reports.
- Get Phishing Indicadors and Phishing submissions.


## Prerequisites
Access your TruSTAR environment to obtain an API key and an API secret.

Navigate to **Settings** > **API** > **API Credentials**.
## Configure TruSTAR v2 on Demisto

1. Navigate to **Settings** &gt; **Integrations** &gt; **Servers &amp; Services**.
1. Search for TruSTAR.
1. Click **Add instance** to create and configure a new integration instance.
        
   * **Name:** a textual name for the integration instance
        
   * **Server URL** (example: https://api.trustar.co)
   * **TruSTAR API Key**
   * **TruSTAR API Secret**
   * Do not validate server certificate (not secure)
   * Use system proxy settings
        
1. Click **Test** to validate connectivity and credentials.


## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.


1. [Return a list of related indicators: trustar-related-indicators](#h_3942468361528291405689)
1. [Trending indicators: trustar-trending-indicators](#h_151383312491528291448872)
1. [Find an indicator: trustar-search-indicators](#h_601442914901528291466003)
1. [Submit a report: trustar-submit-report](#h_4295260251301528291478809)
1. [Update a report: trustar-update-report](#h_2390523201661528291493621)
1. [Return report details: trustar-report-details](#h_7239594532001528291506505)
1. [Delete a report: trustar-delete-report](#h_8744143842331528291518588)
1. [Generate a report: trustar-get-reports](#h_9223074962651528291535977)
1. [Return correlated reports: trustar-correlated-reports](#h_6987239092961528291550310)
1. [Search reports: trustar-search-reports](#h_1950779103291528291565200)
1. [Add indicators to whitelist: trustar-add-to-whitelist](#h_185400428431528626499848)
1. [Remove indicators from whitelist: trustar-remove-from-whitelist](#h_2965863533601528291579105)
1. [Get all enclaves: trustar-get-enclaves](#h_564840413901528291593360)
1. [Get indicators metadata: trustar-indicators-metadata](#h_trustar_indicators_metadata)
1. [Get indicator summaries: 
    trustar-indicator-summaries](#h_trustar_indicator_summaries)
1. [Get phishing indicators: trustar-get-phishing-indicators](#h_trustar_phishing_indicators)
1. [Get phishing submissions: trustar-get-phishing-submissions](#h_trustar_phishing_submissions)


**All commands returning indicators, outputs their data on 3 contexts:**
* The standard context. 
* The DBot Context. 
* And the Indicators TruSTAR context were the result it's output as returned.


## 1. Return a list of related indicators
- - -
Returns a list of indicators related to a specified indicator.
#### Command Example

`!trustar-related-indicators indicators=wannacry.exe`

#### Params:

| Param Name  | Description |
| ------------- | ------------- |
| indicators  | Example indicator types: IP address, email address, URL, MD5, SHA-1, SHA-256, registry key, malware name, and so on  |
| enclave_ids  | CSV of enclave IDs. Returns indicators found in reports from these enclaves only (default - all enclaves you have READ access to)  |
| limit  | 	Limit of results to return. Max value possible is 1000.  |

#### Outputs:

| Path  | Description |
| ------------- | ------------- |
| File.Name  | File name  |
| File.MD5  | File MD5  |
| File.SHA1  | File SHA-1  |
| File.SHA256  | File SHA-256  |
| URL.Address  | URL Address  |
| IP.Address  | IP address  |
| Account.Email.Address  | Email address  |
| Registry.Key.Path  | Registry key path  |
| CVE.ID  | CVE ID  |

##### Raw Output
```
[
    {
       "indicatorType": "SOFTWARE",
       "value": "00000000.res"
    }
 ]
```

## 2. Trending indicators
- - -
Returns trending indicators.
#### Command Example
`!trustar-trending-indicators type=MALWARE raw-response=true`

#### Params:

| Param Name  | Description |
| ------------- | ------------- |
| type  | Types of indicators to return (by default, all indicator types except for CVE and MALWARE will be returned)  |
| dats_back  | Number of days to count correlations for  |

#### Outputs:

| Path  | Description |
| ------------- | ------------- |
| File.Name  | File name  |
| File.MD5  | File MD5  |
| File.SHA1  | File SHA-1  |
| File.SHA256  | File SHA-256  |
| URL.Address  | URL Address  |
| IP.Address  | IP address  |
| Account.Email.Address  | Email address  |
| Registry.Key.Path  | Registry key path  |
| CVE.ID  | CVE ID  |


#### Raw Output
```
[  
   {  
      "correlationCount":109,
      "indicatorType":"MALWARE",
      "value":"IEXPLORE"
   }
]
```

## 3. Find an indicator
- - -
Search for a specific indicator.
##### Command Example
`!trustar-search-indicators search-term=IEXPLORE`

Params:

| Param Name  | Description |
| ------------- | ------------- |
| search_term  | Term to search for  |
| enclave_ids  | 	CSV of enclave IDs. Returns indicators found in reports from these enclaves only (default - all enclaves you have READ access to).  |
| limit  | Limit of results to return. Max value possible is 1000.  |

Outputs:

| Path  | Description |
| ------------- | ------------- |
| File.Name  | File name  |
| File.MD5  | File MD5  |
| File.SHA1  | File SHA-1  |
| File.SHA256  | File SHA-256  |
| URL.Address  | URL Address  |
| IP.Address  | IP address  |
| Account.Email.Address  | Email address  |
| Registry.Key.Path  | Registry key path  |
| CVE.ID  | CVE ID  |


#### Raw Output
```
[  
   {  
      "indicatorType":"SOFTWARE",
      "priorityLevel":"HIGH",
      "value":"iexplore.exe",
      "whitelisted":false
   }
]
```

## 4. Submit a report
- - -
Creates a new report. This command does not generate content.
##### Command Example
`!trustar-submit-report report-body=1.2.3.4,domain.com title=DailyReport distribution-type=ENCLAVE enclave-ids=3435626a-d0d6-4ba5-a229-1dd645d34da5`


Params:

| Param Name  | Description |
| ------------- | ------------- |
| title  | Title of the report |
| report_body  | Text content of report  |
| enclave_ids  | CSV of TruSTAR-generated enclave IDs. Mandatory if the distribution type is ENCLAVE. NOTE: Use the enclave ID, not the enclave name. |
| distribution_type  | 	Distribution type of the report  |
| external_url  | URL for the external report that this originated from, if one exists. Limited to 500 alphanumeric characters. Each company must have a unique URL for all of its reports.  |
| time_began | ISO-8601 formatted incident time with timezone (for example: 2016-09-22T11:38:35+00:00) (default is current time)  |

Outputs:

| Path  | Description |
| ------------- | ------------- |
| TruSTAR.Report.title  | Report title  |
| TruSTAR.Report.reportBody  | Report body  |
| TruSTAR.Report.id  | Report id |


##### Raw Output

```
{  
   "id":"ddda0c95-0b87-44b3-b38c-591f387f1be7",
   "reportBody":"1.2.3.4,domain.com",
   "title":"DailyReport"
}
```

## 5. Update a report

Modifies an existing report.


##### Params:

| Param Name  | Description |
| ------------- | ------------- |
| report_id  | TruSTAR report ID or external tracking ID  |
| title  | Title of the report  |
| report_body  | Text content of report  |
| enclave_ids  | 	CSV of TruSTAR-generated enclave IDs. Mandatory if the distribution type is ENCLAVE. NOTE: Use the enclave ID, not the enclave name  |
| external_url  | URL for the external report that this originated from, if one exists. Limit 500 alphanumeric characters. Each company must have a unique URL for all of its reports.  |
| distribution_type  | Distribution type of the report  |
| time_began  | ISO-8601 formatted incident time with timezone (for example: 2016-09-22T11:38:35+00:00) Default is current time.  |

##### Outputs:

| Path  | Description |
| ------------- | ------------- |
| TruSTAR.Report.title  | Report title  |
| TruSTAR.Report.reportBody  | Report body  |
| TruSTAR.Report.id  | Report id |


Raw output
```
{  
   "id":"ddda0c95-0b87-44b3-b38c-591f387f1be7",
   "reportBody":"email@gmail.com",
   "title":"UpdateDailyReport"
}
```


## 6. Return report details
- - -
Returns report metadata.

##### Params:

| Param Name  | Description |
| ------------- | ------------- |
| report_id  | TruSTAR report ID or external tracking ID  |
| id_type  | Type of report ID  |

##### Outputs:

| Path  | Description |
| ------------- | ------------- |
| TruSTAR.Report.title  | Report title  |
| TruSTAR.Report.reportBody  | Report body  |
| TruSTAR.Report.id  | Report id |


##### Raw Output
```
{  
   "created":"2018-04-04 08:09:05",
   "distributionType":"ENCLAVE",
   "enclaveIds":"3435626a-d0d6-4ba5-a229-1dd645d34da5",
   "id":"ddda0c95-0b87-44b3-b38c-591f387f1be7",
   "reportBody":"email@gmail.com",
   "timeBegan":"2018-04-04 08:12:13",
   "title":"UpdateDailyReport",
   "updated":"2018-04-04 08:12:07"
}
```

## 7. Delete a report
- - -
Deletes specified report.


##### Params:

| Param Name  | Description |
| ------------- | ------------- |
| report_id  | TruSTAR report ID or external tracking ID  |
| id_type  | Type of report ID  |


##### Outputs:

There is no context output for this command.

##### Raw Output

Report ddda0c95-0b87-44b3-b38c-591f387f1be7 was successfully deleted


## 8. Get reports

Get reports restricted to the specified params.
##### Command Example
`!trustar-get-reports enclave-ids=3435626a-d0d6-4ba5-a229-1dd645d34da5`

##### Params:

| Param Name  | Description |
| ------------- | ------------- |
| enclave_ids  | 	CSV of TruSTAR-generated enclave IDs. Mandatory if the distribution type is ENCLAVE. NOTE: Use the enclave ID, not the enclave name  |
| distribution_type  | Distribution type of the report  |
| from | Start of time window. Format is YY-MM-DD HH:MM:SS (example: 2018-01-01 10:30:00). Based on updated time, not created time. (Default is 1 day ago). You can also input relative time windows. (e.g. "2 weeks ago"/"5 days ago"/"10 minutes ago", ans s o on...)|
| to | Start of time window. Format is YY-MM-DD HH:MM:SS (example: 2018-01-01 10:30:00). Based on updated time, not created time. (Default is 1 day ago). You can also input relative time windows. (e.g. "2 weeks ago"/"5 days ago"/"10 minutes ago", ans s o on...) |
| tags | Names of tags to filter by. NOTE: only reports containing ALL of these tags are returned. Tags excluded from the report |
| excluded_tags | NOTE: Reports containing ANY of these tags are excluded from the results. |


##### Outputs:

| Path  | Description |
| ------------- | ------------- |
| TruSTAR.Report.title  | Report title  |
| TruSTAR.Report.reportBody  | Report body  |
| TruSTAR.Report.id  | Report id |


Raw output

```
[  
   {  
      "created":"2018-04-04 08:23:05",
      "distributionType":"ENCLAVE",
      "enclaveIds":"3435626a-d0d6-4ba5-a229-1dd645d34da5",
      "id":"d445c743-8cd8-4c38-bcf4-7879f31ca6bf",
      "reportBody":"1.2.3.4,domain.com",
      "timeBegan":"2018-04-04 08:23:12",
      "title":"DailyReport",
      "updated":"2018-04-04 08:23:05"
   }
]
```


## 9. Return correlated reports
- - -
Returns reports correlating to specified indicators.
##### Command Example
`!trustar-correlated-reports indicators=NANOCORE`

##### Params:

| Param Name  | Description |
| ------------- | ------------- |
| indicators  | Indicator value of any type (for example: an IP address, email address, URL, MD5, SHA-1, SHA-256, Registry Key, Malware name)  |
| enclave_ids  | CSV of enclave IDs. returns indicators found in reports from these enclaves only (default: all enclaves the user has READ access to)  |
| limit | Limit of results to return. Max value possible is 1000  |
| distribution_type | Distribution type of the report  |


##### Context Output
There is no context output for this command.

##### Raw Output
```
{  
   "created":"2018-04-04 12:14:31",
   "distributionType":"ENCLAVE",
   "enclaveIds":[  

   ],
   "id":"c7343c52-13d8-4125-8693-e0d4648a2e49",
   "reportBody":"",
   "timeBegan":"2018-04-04 12:14:27",
   "title":"hybridanalysispublicfeed-11a5d43169626282dd899a1bb0f96fe0-2018-04-04 11:24:52",
   "updated":"2018-04-04 12:14:31"
}
```

## 10. Search reports
- - -
Returns reports based on search terms.

Params:

| Param Name  | Description |
| ------------- | ------------- |
| search_term  | Term to search for  |
| enclave_ids  | CSV of enclave IDs. Returns indicators found in reports from these enclaves only (defaults to all of the user’s enclaves)  |


```
[  
   {  
      "created":"2018-01-31 20:04:34",
      "distributionType":"ENCLAVE",
      "enclaveIds":[  

      ],
      "id":"57bffb4b-bcf7-44c8-9e14-4116a46fcb95",
      "timeBegan":"2018-04-04T14:00:05.636840+00:00",
      "title":"CVE-2018-2714",
      "updated":"2018-01-31 20:04:34"
   }
]
```

## 11. Add indicators to whitelist
- - -
Adds indicators to your whitelist.

Params:

| Params Name  | Description |
| ------------- | ------------- |
| indicators  | CSV of indicators to whitelist (example: evil.com, 101.43.52.224)  |

##### Context Output
There is no context output for this command.

## 12. Remove indicators from whitelist
- - -
Remove indicator from your whitelist.

Params:

| Params Name  | Description |
| ------------- | ------------- |
| indicator  | Value of the indicator to delete  |
| indicator_type  | Type of indicator to delete  |

##### Context Output
There is no context output for this command.

##### Raw Output
```
Removed from the whitelist successfully
```

## 13. Get all enclaves
- - -
Returns all enclaves.
##### Input
There is no input for this command.

##### Context Output
There is no context output for this command.

##### Raw output:
```
[  
   {  
      "create":false,
      "id":"0e4443fc-2b50-4756-b5e0-4ea30030bcb3",
      "name":"Broadanalysis",
      "read":true,
      "type":"OPEN",
      "updated":false
   }
]
```


## 14. Get indicators metadata
- - -
Provide metadata associated with a list of indicators, including value, indicatorType, noteCount, enclaves the user making the request has READ access to.
##### Command Example
`!trustar-indicators-metadata indicators=[SOME_INDICATOR]`


#### Params:

| Param Name  | Description |
| ------------- | ------------- |
| indicators  | Comma separated indicator values. Values can be any of the following types; i.e. an IP address, email address, URL, MD5, SHA1, SHA256, Registry Key, Malware name, etc.  |
| enclave_ids  | a list of enclave IDs to restrict to. By default, uses all of the user’s enclaves. |

#### Outputs:

| Path  | Description |
| ------------- | ------------- |
| File.Name  | File name  |
| File.MD5  | File MD5  |
| File.SHA1  | File SHA-1  |
| File.SHA256  | File SHA-256  |
| URL.Address  | URL Address  |
| IP.Address  | IP address  |
| Account.Email.Address  | Email address  |
| Registry.Key.Path  | Registry key path  |
| CVE.ID  | CVE ID  |
\
##### Raw Output

```
JSON Containing Indicator Premium intel summaries.
```

## 16. Get Phishing Indicators

Get phishing indicators that match the given criteria.
##### Command Example
`!trustar-get-phishing-indicators`


#### Params

| Param Name  | Description |
| ------------- | ------------- |
| normalized_indicator_score  | List of Intel scores to restrict the query. Possible values are -1, 0, 1, 2, 3.  |
| priority_event_score  | List of email submissions scores to restrict the query. Possible values are -1, 0, 1, 2, 3.  |
| from_time	| Start of time window (defaults to 24 hours ago) (YYYY-MM-DD HH:MM:SS) You can also input relative time windows. (e.g. "2 weeks ago"/"5 days ago"/"10 minutes ago", ans s o on...)|
| to_time  | End of time window (defaults to current time) (YYYY-MM-DD HH:MM:SS) You can also input relative time windows. (e.g. "2 weeks ago"/"5 days ago"/"10 minutes ago", ans s o on...) |
| status  | A list of triage statuses for submissions; only email submissions marked with at least one of these statuses will be returned. Options are 'UNRESOLVED', 'CONFIRMED', 'IGNORED' |

#### Outputs:

| Path  | Description |
| ------------- | ------------- |
| File.Name  | File name  |
| File.MD5  | File MD5  |
| File.SHA1  | File SHA-1  |
| File.SHA256  | File SHA-256  |
| URL.Address  | URL Address  |
| IP.Address  | IP address  |
| Account.Email.Address  | Email address  |
| Registry.Key.Path  | Registry key path  |
| CVE.ID  | CVE ID  |




## 17. Get Phishing Submissions

Fetches all phishing submissions that fit the given criteria.
##### Command Example
`!trustar-get-phishing-submissions`


#### Params:

| Param Name  | Description |
| ------------- | ------------- |
| priority_event_score  | List of email submissions scores to restrict the query. Possible values are -1, 0, 1, 2, 3.  |
| from_time  | Start of time window (defaults to 24 hours ago) (YYYY-MM-DD HH:MM:SS). You can also input relative time windows. (e.g. "2 weeks ago"/"5 days ago"/"10 minutes ago", ans s o on...)  |
| to_time  | End of time window (defaults to current time) (YYYY-MM-DD HH:MM:SS)You can also input relative time windows. (e.g. "2 weeks ago"/"5 days ago"/"10 minutes ago", ans s o on...) |
| status  | A list of triage statuses for submissions; only email submissions marked with at least one of these statuses will be returned. Options are 'UNRESOLVED', 'CONFIRMED', 'IGNORED' |

#### Outputs:

| Path  | Description |
| ------------- | ------------- |
| File.Name  | File name  |
| File.MD5  | File MD5  |
| File.SHA1  | File SHA-1  |
| File.SHA256  | File SHA-256  |
| URL.Address  | URL Address  |
| IP.Address  | IP address  |
| Account.Email.Address  | Email address  |
| Registry.Key.Path  | Registry key path  |
| CVE.ID  | CVE ID  |
