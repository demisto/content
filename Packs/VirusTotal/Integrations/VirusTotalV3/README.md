DBot Score
---
#### Indicator Thresholds
Configure the default threshold for each indicator type in the instance settings.
You can also specify the threshold as an argument when running relevant commands.
Indicators with positive results equal to or higher than the threshold will be considered malicious.
Indicators with positive results equal to or higher than half of the threshold value, and lower than the threshold, will be considered suspicious.

#### Rules threshold
If the YARA Rules analysis threshold is enabled:
Indicators with positive results the number of found YARA rules results, Sigma analysis or IDS equal to or higher than threshold, will be considered suspicious.
If both the the basic analysis and the rules analysis is suspicious, the indicator will be considered as malicious.
If the indicator found as suspicious only by the rules thresholds, the indicator will be considered as suspicious.


#### Premium analysis: Relationship Files Threshold
If the organization is using the premium subscription of VirusTotal, you can use the premium api analysis.
The premium API analysis will check 3 file relationships of each indicator (domain, url and ip).
If the relationship found malicious, the indicator will be considered as malicious.
If the relationship found suspicious and the basic score is suspicious, the indicator will be considered as malicious.
If the relationship found suspicious, the indicator will be considered as suspicious.

The premium API analysis can call up to 4 api calls per indicator. If you wish to decrease the use of the api quota, you can disable it.


Changes by commands:
---

### Reputation commands: (ip, url, domain and file)
- Will only get the information from vt, will not analyze the indicator if
not exists.
- Added output path: For each command, outputs will be under VirusTotal.:INDICATOR-TYPE:.
- Removed output path: all outputs except for basic (ip, url, domain and file)
- Each reputation command will be use at least 1 api call. For advanced reputation commands, use the premium api.

### vt-comments-get:
- Added argument: resource_type. If not supplied, will try to determine if the *resource* argument is a hash or a url.
- Added argument: limit - gets the latest comments with the given limit.
- New output path:
    - VirusTotal.Comments
- Removed output path: All previous output paths removed (breaks bc)

### vt-comments-add:
- added argument: resource_type to distinguish between resourced type. If not supplied, will try to determine if the *resource* argument is a hash or a url.
- comment: will be the text field in the comment.

### file-rescan:
- New output path: VirusTotal.FileSubmission.id
- Preserved output: vtScanID
- Removed output path: vtLink


### file-scan
- New output path: VirusTotal.FileSubmission
- The old output path (vtScanID) is still preserved for bc
- Removed output path: vtLink

### url-scan 
- New output path: VirusTotal.UrlSubmission
- The old output path (vtScanID) is still preserved for bc
- Removed output path: vtLink

### vt-file-scan-upload-url: 
- New output path: VirusTotal.FileUploadURL
- Removed output path: vtUploadURL

new commands:
---
- vt-search
- vt-ip-passive-dns-data
- vt-file-sandbox-report
- vt-comments-get-by-id
- vt-analysis-get