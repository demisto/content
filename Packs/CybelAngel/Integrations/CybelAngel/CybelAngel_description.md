## Cybelangel
- This section explains how to configure the instance of Cybelangel in Cortex XSOAR.
-  The following integration uses as parameters two values given directly by the Cybelangel API 
(https[:]//platform[.]cybelangel[.]com/api-service)
***
### Commands
- cybelangel-get-reports: Returns all the reports created between a start and an end date, this reports can be filtered by status.
- cybelangel-get-single-report: Returns a single report given a report ID. 
- cybelangel-get-single-attachment: Returns a single attachment from a report
- cybelangel-get-attachments-from-report: Returns all attachments from a report
- cybelangel-update-report-status: Updates the status of a report (open, resolved)
- cybelangel-get-comments: Returns all comments from a report
- cybelangel-create-comment: Creates a comment on a report