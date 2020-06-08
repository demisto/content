## [Unreleased]


## [20.5.2] - 2020-05-26
- Fixed an issue where urls with a comma were parsed incorrectly.
- Fixed an issue where running file related commands would raise an error.


## [20.3.3] - 2020-03-18
Fixed an issue where detections with no positive value were treated as malicious.


## [19.12.0] - 2019-12-10
  - Added batch support for the **ip** and **url** and **domain** commands.
  - Fixed an issue where the DBotScore would create duplications in the incident context. This effects Demisto version 5.5 and higher.


## [19.8.2] - 2019-08-22
  - Added the Virus Total permanent link to the context of the following commands: 
    - url
    - file
    - url-scan
    - file-scan
    - file-rescan


## [19.8.0] - 2019-08-06
  - Updated outputs with new indicator fields.
