## [Unreleased]
  - Added **jobID**, **sha256** and **environmentID** arguments to the ***hybrid-analysis-get-report-status*** command.
  - Added the **malicious_threat_levels** argument to the ***hybrid-analysis-detonate-file*** command.
  - The ***hybrid-analysis-detonate-file*** command should now run as expected.

## [19.10.1] - 2019-10-15
Fixed an issue where ***hybrid-analysis-search*** command returned an error without using the *query* argument.


## [19.9.1] - 2019-09-18
#### Enhancememnt
  - Added Calculation for DbotScore.
  - Added 4 new commands:
    - ***hybrid-analysis-quick-scan-url***
    - **hybrid-analysis-quick-scan-url-results***
    - ***hybrid-analysis-submit-url***
    - ***hybrid-analysis-list-scanners*** 
  - Added the *malicious_threat_levels* argument to the ***hybrid-analysis-scan*** command.
  - Added the *min_malicious_scanners* argument to the ***hybrid-analysis-search*** command.
  - Updated outputs in the ***hybrid-analysis-scan*** command.
