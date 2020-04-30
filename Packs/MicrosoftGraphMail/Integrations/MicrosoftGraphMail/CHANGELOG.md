## [Unreleased]


## [20.4.1] - 2020-04-29
-


## [20.4.0] - 2020-04-14
-


## [20.3.4] - 2020-03-30
 - Fixed an issue where the listing emails were not comparing the mail ID.
- Added 4 commands:
    - ***msgraph-mail-create-draft***
    - ***msgraph-mail-send-draft***
    - ***msgraph-mail-reply-ro***
    - ***send-mail***
    - Note: the newly added commands require more permissions, please read the detailed description of the integration for some guidance.
- Added the ability to fetch mails as incidents.
  


## [20.2.0] - 2020-02-04
Fixed an issue where the listing emails were not comparing the mail ID.

## [20.1.2] - 2020-01-22
Added support to authenticate using a self-deployed Azure application.

## [19.12.1] - 2019-12-25
Added content-version and content-name headers to Oproxy request.

## [19.12.0] - 2019-12-10
Added 7 new commands.
  - ***msgraph-mail-list-folders***
  - ***msgraph-mail-list-child-folders***
  - ***msgraph-mail-create-folder***
  - ***msgraph-mail-update-folder***
  - ***msgraph-mail-delete-folder***
  - ***msgraph-mail-move-email***
  - ***msgraph-mail-get-email-as-eml***

## [19.10.1] - 2019-10-15
  - Improved the description of the *search* argument in ***msgraph-mail-list-emails*** command.
  - Fixed an issue where the ***msgraph-mail-delete-email*** command always returned an error.
