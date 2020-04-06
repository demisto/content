## [Unreleased]
-


## [20.3.4] - 2020-03-30
#### New Playbook
This playbook runs sub playbooks that send indicators to your SIEM. To select the indicators you want to add, go to playbook inputs, choose “from indicators” and set your query. For example tags:approved_black, approved_white etc. The purpose of the playbook is to send to SIEM only indicators that have been processed and tagged accordingly after an automatic or manual review process. The default playbook query is"
(type:ip or type:file or type:Domain or type:URL) -tags:pending_review and (tags:approved_black or tags:approved_white or tags:approved_watchlist)"
In case more indicator types need to be sent to the SIEM, the query must be edited accordingly.