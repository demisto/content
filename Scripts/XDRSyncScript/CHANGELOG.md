## [Unreleased]
  - Deprecated the *playbook_to_run* argument. When an incident is updated in XDR and the script updates the incident in Demisto, by default, the playbook is rerun. 
  - The next sync is now rescheduled even if the current sync fails.

## [19.8.0] - 2019-08-06
- Added the *verbose* argument.
- All arguments have default incident field names.
- When a playbook is re-run, the previous scheduled task is terminated.
