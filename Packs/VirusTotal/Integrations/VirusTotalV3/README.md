## DBot Score
---

The following information describes DBot Score which is new for this version.

### Indicator Thresholds
Configure the default threshold for each indicator type in the instance settings.
You can also specify the threshold as an argument when running relevant commands.
Indicators with positive results equal to or higher than the threshold will be considered malicious.
Indicators with positive results equal to or higher than half of the threshold value, and lower than the threshold, will be considered suspicious.

### Rules threshold
If the YARA rules analysis threshold is enabled:
Indicators with positive results, the number of found YARA rules results, Sigma analysis, or IDS equal to or higher than the threshold, will be considered suspicious.
If both the the basic analysis and the rules analysis is suspicious, the indicator will be considered as malicious.
If the indicator was found to be suspicious only by the rules thresholds, the indicator will be considered suspicious.


### Premium analysis: Relationship Files Threshold
If the organization is using the premium subscription of VirusTotal, you can use the premium API analysis.
The premium API analysis will check 3 file relationships of each indicator (domain, url, and ip).
If the relationship is found to be malicious, the indicator will be considered malicious.
If the relationship is found to be suspicious and the basic score is suspicious, the indicator will be considered malicious.
If the relationship is found to be suspicious, the indicator will be considered suspicious.

The premium API analysis can call up to 4 API calls per indicator. If you want to decrease the use of the API quota, you can disable it.


## Changes by Commands
---
The following lists the changes in this version according to commands.

### Reputation commands (ip, url, domain, and file)
- Will only get information from VirusTotal. Will not analyze the indicator if it does
not exist.
- Added output paths: For each command, outputs will appear under *VirusTotal.:INDICATOR-TYPE:*.
- Removed output paths: All outputs have been removed except for the following basic outputs: ip, url, domain, and file.
- Each reputation command will use at least 1 API call. For advanced reputation commands, use the premium API.

### vt-comments-get:
- Added the *resource_type* argument. If not supplied, will try to determine if the *resource* argument is a hash or a URL.
- Added the *limit* argument: Gets the latest comments within the given limit.
- New output path: *VirusTotal.Comments*.
- Removed output path: All previous output paths have been removed (breaks backward compatibility).

### vt-comments-add:
- Added the *resource_type* argument:  Distinguishes between resource types. If not supplied, will try to determine if the *resource* argument is a hash or a URL.
- comment: The text field in the comment.

### file-rescan:
- New output path: *VirusTotal.Submission.id*
- Preserved output: *vtScanID*
- Removed output path: *vtLink* - The V3 API does not returns a link to the GUI anymore.


### file-scan
- New output path: *VirusTotal.Submission*
- Preserved output: *vtScanID*
- Removed output path: *vtLink* - The V3 API does not returns a link to the GUI anymore.


### url-scan 
- New output path: *VirusTotal.Submission*
- Preserved output: *vtScanID*
- Removed output path: *vtLink* - The V3 API does not returns a link to the GUI anymore.
 - The V3 API does not returns a link to the GUI anymore.

### vt-file-scan-upload-url: 
- New output path: *VirusTotal.FileUploadURL*
- Preserved output: *vtUploadURL*

## New Commands
---
- ***vt-search***
- ***vt-ip-passive-dns-data***
- ***vt-file-sandbox-report***
- ***vt-comments-get-by-id***
- ***vt-analysis-get***
