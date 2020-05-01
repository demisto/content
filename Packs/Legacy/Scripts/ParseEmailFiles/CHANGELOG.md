## [Unreleased]


## [20.4.1] - 2020-04-29
Fixed an issue with base64 headers padding.


## [20.4.0] - 2020-04-14
Improved handling of attachments.

## [20.2.0] - 2020-02-04
Added handling for EML files with no Content-Type header. The script will treat the file as email text with no attachments.

## [19.12.1] - 2019-12-25
Added handling for cases where an attachment has neither the *DisplayName* nor the *AttachFilename* properties.

## [19.12.0] - 2019-12-10
Fixed an issue with handling smime signed files with no attachments.

## [19.11.0] - 2019-11-12
-

## [19.10.0] - 2019-10-03
Improved handling for smime signed file attachments in MSG emails.

## [19.9.1] - 2019-09-18
Removed the hyperlink from links.

## [19.9.0] - 2019-09-04
  - Improved EML file type detection.
  - Added the *Email.AttachmentNames* output, which contains a list of the names of all email attachments.


## [19.8.2] - 2019-08-22
- Fixed an issue in which special characters were missing from MSG emails.


## [19.8.0] - 2019-08-06
  - Added support for EML file attachments with a generic "data" type.
  - Added support for smime signed EML file attachments.
