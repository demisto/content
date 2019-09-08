## [Unreleased]
  - 7 new commands were added:
     - gmail-hide-user-in-directory - Hide a user in the Global Directory.
     - gmail-set-password - Set password for the user.
     - gmail-get-autoreply - Get the auto-reply message set for the user-account.
     - gmail-set-autoreply - Set auto-reply for the user.
     - gmail-delegate-user-mailbox - Adds a delegate to the mailbox, without sending any verification email.
     - gmail-remove-delegated-mailbox - Removes a delegate from the mailbox, without sending any verification email.
     - send-mail - Send mail using Gmail.
    
    
  - Fixed bug where mails from different timezones sometimes did not create incidents.
     - This will temporarily cause duplicated incidents.