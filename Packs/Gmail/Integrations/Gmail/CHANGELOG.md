## [Unreleased]
-

## [20.5.0] - 2020-05-12
-


## [20.4.0] - 2020-04-14
-


## [20.1.0] - 2020-01-07
You can now run the following commands against user accounts when you have admin credentials.
  - ***gmail-delegate-user-mailbox***
  - ***gmail-set-autoreply***

## [19.12.1] - 2019-12-25
  - Added a new command:
    - ***gmail-get-role***
  - Improved the outputs for the following commands:
    - ***gmail-get-user-roles***
    - ***gmail-list-filters*** 
    - ***gmail-add-filter***

## [19.12.0] - 2019-12-10
-

## [19.10.2] - 2019-10-29
  - Added page-token parameter to ***gmail-list-users*** to get further results.
  - ***gmail-search-all-mailboxes*** now runs on all users.
  - Fixed an issue where emails without labels were not retrieved.

## [19.10.1] - 2019-10-15
-

## [19.9.1] - 2019-09-18
  - Added 7 commands:
    - ***gmail-hide-user-in-directory***
    - ***gmail-set-password*** 
    - ***gmail-get-autoreply***
    - ***gmail-set-autoreply***
    - ***gmail-delegate-user-mailbox***
    - ***gmail-remove-delegated-mailbox*** 
    - ***send-mail***
  - Fixed an issue where emails from different timezones occaisonally did not create incidents. This may cause duplicate incidents shortly after upgrading.
   
