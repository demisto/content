Changes by commands:
---

### reputation commands: (ip, url, domain and file)
- Will only get the information from vt, will not analyze the indicator if
not exists.
- Added output path: For each command, outputs will be under VirusTotal.:INDICATOR-TYPE:.
- Removed output path: all outputs except for basic (ip, url, domain and file)
- Each reputation command will be use at least 1 api call. For advanced reputation commands, use the premium api.

### vt-comments-get:
- Added argument: resource_type to distinguish between resources type.
- Added argument: limit - gets the latest comments with the given limit.
- Removed argument: before use 'limit' argument instead (breaks bc)
- New output path: According to the given resource_type:
    - VirusTotal.FileComments
    - VirusTotal.URLComments
    - VirusTotal.IPComments
    - VirusTotal.DomainComments
- Removed output path: All previous output paths removed (breaks bc)

### vt-comments-add:
- added argument: resource_type to distinguish between resourced type.
- comment: will be the text field in the comment.

### file-rescan -> vt-file-rescan:
- New output path: VirusTotal.FileSubmission.id
- Removed output path: vtLink, vtScanID


### file-scan -> vt-file-scan:
- New output path: VirusTotal.FileSubmission.id
- The old output path (vtScanID) is still preserved for bc
- Removed output path: vtLink

### vt-file-scan-upload-url: 
- New output path: VirusTotal.FileUploadURL.id
- Removed output path: vtUploadURL

### url-scan -> vt-url-scan:
- New output path: VirusTotal.UrlSubmission.id
- Removed output path: vtLink, vtScanID

new commands:
---
- vt-search
- vt-ip-passive-dns-data
- vt-file-sandbox-report
- vt-comments-get-by-id
- vt-analysis-get