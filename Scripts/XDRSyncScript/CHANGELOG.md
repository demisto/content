## [Unreleased]


## [19.11.0] - 2019-11-12
Fixed an issue where the **XDRSyncScript** script executed the ***xdr-update-incident*** command when required arguments were empty.

## [19.10.2] - 2019-10-29
The **XDRSyncScript** now works as expected.

## [19.9.0] - 2019-09-04
  - Deprecated the *playbook_to_run* argument. When an incident is updated in XDR and the script updates the incident in Demisto, by default, the playbook is rerun. 
  - The next sync is now rescheduled even if the current sync fails.

## [19.8.0] - 2019-08-06
- Added the *verbose* argument.
- All arguments have default incident field names.
- When a playbook is re-run, the previous scheduled task is terminated.
