## [Unreleased]
Added new commands:
    - **code42-departingemployee-get-all** that gets all the employees on the Departing Employee List.
    - **code42-highriskemployee-add** that takes a username and adds the employee to the High Risk Employee List.
    - **code42-highriskemployee-remove** that takes a username and remove the employee from the High Risk Employee List.
    - **code42-highriskemployee-get-all** that gets all the employees on the High Risk Employee List. 
        Optionally takes a list of risk tags and only gets employees who have those risk tags.
    - **code42-highriskemployee-add-risk-tags** that takes a username and risk tags and associates the risk tags with the user.
    - **code42-highriskemployee-remove-risk-tags** that takes a username and risk tags and disassociates the risk tags from the user.
Improve error messages for all Commands to include exception detail.

## [20.3.3] - 2020-03-18
#### New Integration
Use the Code42 integration to identify potential data exfiltration from insider threats while speeding investigation and response by providing fast access to file events and metadata across physical and cloud environments.