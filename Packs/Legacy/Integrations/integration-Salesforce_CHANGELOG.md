## [Unreleased]
-
- Added integration command !salesforce-get-attachment-by-id - get attachment by Oid
- Added integration command !salesforce-get-attachment - Get all of the attachments of a case
- Added integration command !salesforce-create-caseteammember - create case team member by case + User’s Oid + Role Name in the case
- Added integration command !salesforce-get-user - new fetching by user’s email.
- Added Caching mechanism for users oid and user emails - integration context.
- Added integration command !salesforce-clear-cache - clear integration context 
- Added new integration parameter -  fetch cases by query
- !salesforce-update-case now has etacOwner= parameter - to add an ETAC Owner to the case
