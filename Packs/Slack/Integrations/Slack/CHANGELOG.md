## [Unreleased]
-

## [20.4.0] - 2020-04-14
Reduced the maximum number of threads used by the integration.

## [20.3.4] - 2020-03-30
Fixed a bug where messages were not sent to a channel if it was the dedicated channel for notifications.

## [20.2.3] - 2020-02-18
-

## [20.2.0] - 2020-02-04
-

## [19.12.0] - 2019-12-10
  - Fixed an issue where mirrored investigations contained mismatched user names.
  - Added reporter and reporter email as labels to incidents that are created by direct messages.

## [19.11.1] - 2019-11-26
Added Slack API rate limit call handling.
Added an optional parameter to specify a proxy URL to use with the Slack API. 

## [19.10.1] - 2019-10-15
Added support for changing the display name and icon for the Demisto bot in Slack.

## [19.10.0] - 2019-10-03
Added support for sending blocks (graphical attachments) in messages. For more information see the integration documentation.

## [19.9.1] - 2019-09-18
Direct message - support multiline JSON in incident creation



## [19.9.0] - 2019-09-04
  - Added 6 new commands:
    - ***close-channel*** (now with optional channel argument)
    - ***slack-create-channel***
    - ***slack-invite-to-channel***
    - ***slack-kick-from-channel***
    - ***slack-rename-channel***
    - ***slack-get-user-details***
  - Added support for removing the Slack admin (API token owner) when mirroring an incident.


## [19.8.2] - 2019-08-22
#### New Integration
Sends messages and notifications to your Slack Team.
