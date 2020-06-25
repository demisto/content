## [Unreleased]
- Added a check that verifies whether the Rasterize integration is enabled before attempting to rasterize HTML-formatted emails.
- Simplified the flow of the playbook by merging tasks where possible and renaming tasks to better reflect their purpose.
- Email headers will now show in phishing incident layouts.

## [20.5.2] - 2020-05-26
-


## [19.10.2] - 2019-10-29
- Fixed an issue where the raw HTML field that is displayed in the phishing layout, was not populated by the playbook.
- Rasterizing the email now done in offline mode

## [19.9.0] - 2019-09-04
Changed to use IdentifyAttachedEmail to detect additional email attachment types.


## [19.8.0] - 2019-08-06
  - Added support for EML file attachments with a generic "data" type.
