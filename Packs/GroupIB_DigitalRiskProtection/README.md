### What does this package do?

* Receives violations from Group-IB Digital Risk Protection.
* Allows manual investigation using Group-IB data through the Cortex XSOAR interface.

This package includes an incident type, a classifier and mapper, a dedicated layout, an automation that updates the existing incident of a violation instead of creating a duplicate and closes it once the violation is over, an automation behind the layout's **Approve Violation** / **Reject Violation** buttons, which sends the decision to Group-IB DRP through the instance that fetched the incident, and an automation that creates the violation's indicator from the incident. The buttons appear only while Group-IB DRP is waiting for your decision. A violation incident is closed as Resolved once Group-IB DRP has resolved the violation, and as False Positive once the violation was rejected or found false. A playbook is also provided to help you respond to violations more efficiently.

![Incident Postprocessing - Group-IB Digital Risk Protection](doc_files/Group-IB_Digital_Risk_Protection_-_Violation_Incident_Postprocessing.png)
