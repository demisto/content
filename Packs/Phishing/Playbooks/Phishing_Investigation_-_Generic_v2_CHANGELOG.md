## [Unreleased]


## [20.5.2] - 2020-05-26
- The playbook now uses Block Indicators - Generic v2 to block malicious indicators (off by default).
- Replaced the deprecated SendEmail automation with the send-mail command. 

## [20.4.1] - 2020-04-29
- Added the *OnCall* input to assign only users that are on shift.
- Fixed an issue where the playbook was not authenticating emails.


## [20.1.2] - 2020-01-22
Added tasks that predict the phishing incident verdict when a phishing ML model exists. The verdict refers to the phishing category.

## [19.11.0] - 2019-11-12
- Fixed an issue where the task that saves the email address of the reporter of the phishing email, was disconnected from the previous task.
- Fixed an issue where the DT that was used to get the display name of the user who reported the email was invalid.

## [19.10.2] - 2019-10-29
Added a task to save the reporter email address in an incident field, so it can be displayed on the summary page.

## [19.10.0] - 2019-10-03
Fixed an issue where the email authenticity check task failed to find the relevant script.

## [19.9.1] - 2019-09-18
  - Improved the Calculate Severity - Generic v2 playbook to evaluate the severity of an incident more accurately.
  - Added check for email authenticity using SPF, DKIM and DMARC. The verdict will also appear on the summary page of phishing incidents.
